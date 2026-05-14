import subprocess
import os
import shutil
import time


TOR_UID_CMD = "id -u debian-tor 2>/dev/null || id -u tor 2>/dev/null || echo 0"
TORRC_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "torrc")
SYSTEM_TORRC = "/etc/tor/torrc"

# Private/reserved address ranges to exclude from Tor routing
NON_TOR_NETS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
]

TRANS_PORT = "9040"
DNS_PORT = "9053"


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def is_tor_installed() -> bool:
    return shutil.which("tor") is not None


def is_tor_running() -> bool:
    result = _run(["pgrep", "-x", "tor"], check=False)
    return result.returncode == 0


def get_tor_uid() -> str:
    result = subprocess.run(TOR_UID_CMD, shell=True, capture_output=True, text=True)
    uid = result.stdout.strip()
    return uid if uid and uid != "0" else ""


def _configure_torrc():
    """Always overwrite system torrc with Ghost config."""
    with open(TORRC_PATH, "r") as f:
        ghost_config = f.read()
    with open(SYSTEM_TORRC, "w") as f:
        f.write(ghost_config)


def _tor_port_listening(port: str) -> bool:
    """Return True if Tor is listening on the given port (UDP or TCP)."""
    result = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
    result_udp = subprocess.run(["ss", "-ulnp"], capture_output=True, text=True)
    return f":{port}" in result.stdout or f":{port}" in result_udp.stdout


def _tor_dns_listening() -> bool:
    return _tor_port_listening("9053")


def _tor_socks_listening() -> bool:
    return _tor_port_listening("9050")


def _disable_systemd_resolved():
    """Stop systemd-resolved and replace its symlink with a real resolv.conf."""
    subprocess.run(["systemctl", "stop", "systemd-resolved"], check=False, capture_output=True)
    subprocess.run(["systemctl", "disable", "systemd-resolved"], check=False, capture_output=True)
    # resolv.conf is often a symlink managed by systemd-resolved — replace it
    resolv = "/etc/resolv.conf"
    if os.path.islink(resolv):
        try:
            os.remove(resolv)
            with open(resolv, "w") as f:
                f.write("# Ghost - placeholder\nnameserver 9.9.9.9\n")
        except (IOError, PermissionError):
            pass


def _enable_systemd_resolved():
    subprocess.run(["systemctl", "enable", "systemd-resolved"], check=False, capture_output=True)
    subprocess.run(["systemctl", "start", "systemd-resolved"], check=False, capture_output=True)


def start_tor() -> tuple[bool, str]:
    if not is_tor_installed():
        return False, "Tor is not installed. Run: apt install tor"

    _configure_torrc()

    # Always restart so the new torrc (with SocksPort) takes full effect
    _run(["service", "tor", "stop"], check=False)
    time.sleep(1)
    result = _run(["service", "tor", "start"], check=False)
    time.sleep(3)
    if not is_tor_running():
        return False, f"Failed to start Tor: {result.stderr}"

    # Wait up to 10s for both SOCKS and DNS ports to come up
    for _ in range(10):
        if _tor_dns_listening() and _tor_socks_listening():
            return True, "Tor service started (SOCKS5 :9050 and DNS :9053 ready)"
        time.sleep(1)

    missing = []
    if not _tor_socks_listening():
        missing.append("SOCKS5 :9050")
    if not _tor_dns_listening():
        missing.append("DNS :9053")
    return False, f"Tor started but not listening on: {', '.join(missing)} — check /etc/tor/torrc"


def stop_tor() -> tuple[bool, str]:
    result = _run(["service", "tor", "stop"], check=False)
    return result.returncode == 0, "Tor service stopped"


def enable_routing() -> tuple[bool, str]:
    """Enable all-traffic Tor routing via iptables."""
    tor_uid = get_tor_uid()

    # Stop systemd-resolved so it cannot override resolv.conf
    _disable_systemd_resolved()

    ok, msg = start_tor()
    if not ok:
        return False, msg

    try:
        # Flush any existing Ghost rules first
        _flush_chains()

        # ── PREROUTING: forward port 53 → 9053 for all incoming DNS ──────────
        _run(["iptables", "-t", "nat", "-A", "PREROUTING",
              "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT])
        _run(["iptables", "-t", "nat", "-A", "PREROUTING",
              "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT])

        # ── OUTPUT: direct DNS rules at the top level (not in a sub-chain) ───
        # Exclude Tor's own traffic from being re-routed
        if tor_uid:
            _run(["iptables", "-t", "nat", "-A", "OUTPUT",
                  "-m", "owner", "--uid-owner", tor_uid, "-j", "RETURN"])

        _run(["iptables", "-t", "nat", "-A", "OUTPUT",
              "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT])
        _run(["iptables", "-t", "nat", "-A", "OUTPUT",
              "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT])

        # ── GHOST_OUTPUT chain: TCP traffic through Tor transparent proxy ─────
        _run(["iptables", "-t", "nat", "-N", "GHOST_OUTPUT"], check=False)

        for net in NON_TOR_NETS:
            _run(["iptables", "-t", "nat", "-A", "GHOST_OUTPUT", "-d", net, "-j", "RETURN"])

        _run(["iptables", "-t", "nat", "-A", "GHOST_OUTPUT",
              "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", TRANS_PORT])

        if tor_uid:
            _run(["iptables", "-t", "nat", "-A", "OUTPUT",
                  "-p", "tcp", "-m", "owner", "!", "--uid-owner", tor_uid, "-j", "GHOST_OUTPUT"])
        else:
            _run(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "GHOST_OUTPUT"])

        # ── Write resolv.conf pointing to Tor's local DNS ────────────────────
        _write_resolv_conf()

        # ── Configure proxychains + Firefox prefs ────────────────────────────
        from modules import browser as _browser
        _browser.kill_firefox()
        _browser.apply_all(restore=False)

        return True, "All traffic routed through Tor (DNS port 53 → 9053)"

    except subprocess.CalledProcessError as e:
        return False, f"iptables error: {e}"


def disable_routing() -> tuple[bool, str]:
    """Remove Tor routing rules and restore DNS."""
    try:
        _flush_chains()
        _restore_resolv_conf()
        _enable_systemd_resolved()
        # Restore proxychains + Firefox to original settings
        from modules import browser as _browser
        _browser.kill_firefox()
        _browser.apply_all(restore=True)
        return True, "Tor routing disabled, traffic restored"
    except Exception as e:
        return False, str(e)


def _flush_chains():
    """Remove all Ghost iptables rules."""
    # PREROUTING DNS forward rules
    _run(["iptables", "-t", "nat", "-D", "PREROUTING",
          "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT], check=False)
    _run(["iptables", "-t", "nat", "-D", "PREROUTING",
          "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT], check=False)

    # OUTPUT top-level DNS rules
    _run(["iptables", "-t", "nat", "-D", "OUTPUT",
          "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT], check=False)
    _run(["iptables", "-t", "nat", "-D", "OUTPUT",
          "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT], check=False)

    # Tor owner RETURN rule
    tor_uid = get_tor_uid()
    if tor_uid:
        _run(["iptables", "-t", "nat", "-D", "OUTPUT",
              "-m", "owner", "--uid-owner", tor_uid, "-j", "RETURN"], check=False)
        _run(["iptables", "-t", "nat", "-D", "OUTPUT",
              "-p", "tcp", "-m", "owner", "!", "--uid-owner", tor_uid, "-j", "GHOST_OUTPUT"], check=False)
    else:
        _run(["iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "GHOST_OUTPUT"], check=False)

    # GHOST_OUTPUT custom chain
    _run(["iptables", "-t", "nat", "-F", "GHOST_OUTPUT"], check=False)
    _run(["iptables", "-t", "nat", "-X", "GHOST_OUTPUT"], check=False)

    # Legacy GHOST_DROP chain (kept for backwards compat)
    _run(["iptables", "-D", "OUTPUT", "-j", "GHOST_DROP"], check=False)
    _run(["iptables", "-F", "GHOST_DROP"], check=False)
    _run(["iptables", "-X", "GHOST_DROP"], check=False)


def _write_resolv_conf():
    """Set DNS to Tor's local resolver."""
    backup_path = "/etc/resolv.conf.ghost.bak"
    if not os.path.exists(backup_path):
        try:
            shutil.copy("/etc/resolv.conf", backup_path)
        except (IOError, PermissionError):
            pass
    try:
        with open("/etc/resolv.conf", "w") as f:
            f.write("# Ghost anonymity suite - using Tor DNS\n")
            f.write("nameserver 127.0.0.1\n")
    except (IOError, PermissionError):
        pass


def _restore_resolv_conf():
    """Restore original DNS configuration."""
    backup_path = "/etc/resolv.conf.ghost.bak"
    if os.path.exists(backup_path):
        try:
            shutil.copy(backup_path, "/etc/resolv.conf")
            os.remove(backup_path)
        except (IOError, PermissionError):
            pass


def get_tor_ip() -> str | None:
    """Get current exit IP via Tor check service."""
    try:
        import urllib.request
        req = urllib.request.Request("https://check.torproject.org/api/ip")
        req.add_header("User-Agent", "curl/7.68.0")
        with urllib.request.urlopen(req, timeout=10) as r:
            import json
            data = json.loads(r.read())
            return data.get("IP")
    except Exception:
        return None


def new_tor_identity() -> tuple[bool, str]:
    """Request a new Tor circuit (new exit node)."""
    try:
        result = _run(["pkill", "-HUP", "tor"], check=False)
        time.sleep(3)
        return True, "New Tor identity requested"
    except Exception as e:
        return False, str(e)
