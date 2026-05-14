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
    """Deploy ghost torrc settings."""
    with open(TORRC_PATH, "r") as f:
        ghost_config = f.read()

    # Append to system torrc if not already configured
    try:
        with open(SYSTEM_TORRC, "r") as f:
            current = f.read()
        if "VirtualAddrNetwork 10.192.0.0/10" not in current:
            with open(SYSTEM_TORRC, "w") as f:
                f.write(ghost_config)
    except FileNotFoundError:
        with open(SYSTEM_TORRC, "w") as f:
            f.write(ghost_config)


def start_tor() -> tuple[bool, str]:
    if not is_tor_installed():
        return False, "Tor is not installed. Run: apt install tor"

    _configure_torrc()

    if not is_tor_running():
        result = _run(["service", "tor", "start"], check=False)
        time.sleep(2)
        if not is_tor_running():
            return False, f"Failed to start Tor: {result.stderr}"

    return True, "Tor service started"


def stop_tor() -> tuple[bool, str]:
    result = _run(["service", "tor", "stop"], check=False)
    return result.returncode == 0, "Tor service stopped"


def enable_routing() -> tuple[bool, str]:
    """Enable all-traffic Tor routing via iptables."""
    tor_uid = get_tor_uid()

    ok, msg = start_tor()
    if not ok:
        return False, msg

    try:
        # Flush existing Ghost chains
        _flush_chains()

        # Create new nat chain
        _run(["iptables", "-t", "nat", "-N", "GHOST_OUTPUT"], check=False)

        # Exclude non-routable networks
        for net in NON_TOR_NETS:
            _run(["iptables", "-t", "nat", "-A", "GHOST_OUTPUT", "-d", net, "-j", "RETURN"])

        # Redirect DNS to Tor's DNS resolver
        _run(["iptables", "-t", "nat", "-A", "GHOST_OUTPUT",
              "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", DNS_PORT])

        # Redirect all TCP to Tor transparent proxy
        _run(["iptables", "-t", "nat", "-A", "GHOST_OUTPUT",
              "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", TRANS_PORT])

        # Apply chain to OUTPUT, excluding Tor's own traffic
        if tor_uid:
            _run(["iptables", "-t", "nat", "-A", "OUTPUT",
                  "-m", "owner", "!", "--uid-owner", tor_uid, "-j", "GHOST_OUTPUT"])
        else:
            _run(["iptables", "-t", "nat", "-A", "OUTPUT", "-j", "GHOST_OUTPUT"])

        # Drop non-Tor outbound connections (prevent leaks)
        _run(["iptables", "-N", "GHOST_DROP"], check=False)
        _run(["iptables", "-A", "GHOST_DROP", "-j", "DROP"])

        # Configure DNS resolver to use Tor
        _write_resolv_conf()

        return True, "All traffic routed through Tor"

    except subprocess.CalledProcessError as e:
        return False, f"iptables error: {e}"


def disable_routing() -> tuple[bool, str]:
    """Remove Tor routing rules and restore DNS."""
    try:
        _flush_chains()
        _restore_resolv_conf()
        return True, "Tor routing disabled, traffic restored"
    except Exception as e:
        return False, str(e)


def _flush_chains():
    """Remove Ghost iptables chains."""
    _run(["iptables", "-t", "nat", "-D", "OUTPUT", "-j", "GHOST_OUTPUT"], check=False)
    _run(["iptables", "-t", "nat", "-F", "GHOST_OUTPUT"], check=False)
    _run(["iptables", "-t", "nat", "-X", "GHOST_OUTPUT"], check=False)
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
