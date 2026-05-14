"""
Browser anonymization via proxychains.

proxychains works at the OS syscall level (LD_PRELOAD), intercepting all TCP
connections and routing them through Tor's SOCKS5 port.  It requires zero
Firefox configuration and bypasses DoH entirely — the safest approach.
"""
import os
import glob
import subprocess
import shutil


PROXYCHAINS_CONF = "/etc/proxychains4.conf"
PROXYCHAINS_CONF_ALT = "/etc/proxychains.conf"
PROXYCHAINS_BACKUP = "/etc/proxychains4.conf.ghost.bak"
PROXYCHAINS_BIN = None   # resolved at call time

GHOST_PROXYCHAINS_CONF = """# Ghost anonymity suite — auto-generated
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5  127.0.0.1  9050
"""

# System-wide Firefox locked prefs (fallback, secondary to proxychains)
FIREFOX_PREFS = [
    ('network.proxy.type',                       1),
    ('network.proxy.socks',                      '"127.0.0.1"'),
    ('network.proxy.socks_port',                 9050),
    ('network.proxy.socks_version',              5),
    ('network.proxy.socks_remote_dns',           True),
    ('network.proxy.no_proxies_on',              '""'),
    ('network.trr.mode',                         5),
    ('network.trr.uri',                          '""'),
    ('media.peerconnection.enabled',             False),
    ('media.peerconnection.ice.no_host',         True),
    ('geo.enabled',                              False),
    ('toolkit.telemetry.enabled',                False),
    ('datareporting.healthreport.uploadEnabled', False),
]

SYSTEM_PREF_DIRS = [
    "/usr/lib/firefox-esr/browser/defaults/preferences",
    "/usr/lib/firefox/browser/defaults/preferences",
    "/usr/lib64/firefox/browser/defaults/preferences",
    "/usr/share/firefox-esr/browser/defaults/preferences",
    "/usr/share/firefox/browser/defaults/preferences",
]
SYSTEM_PREF_FILE = "ghost-tor.js"

CHROMIUM_FLAGS = [
    '--proxy-server=socks5://127.0.0.1:9050',
    '--proxy-bypass-list=<-loopback>',
    '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1',
    '--disable-webrtc',
]


# ─── proxychains ──────────────────────────────────────────────────────────────

def _proxychains_bin() -> str | None:
    return shutil.which("proxychains4") or shutil.which("proxychains")


def _proxychains_conf_path() -> str:
    return PROXYCHAINS_CONF if os.path.exists(PROXYCHAINS_CONF) else PROXYCHAINS_CONF_ALT


def configure_proxychains(restore: bool = False) -> tuple[bool, str]:
    conf = _proxychains_conf_path()

    if restore:
        if os.path.exists(PROXYCHAINS_BACKUP):
            try:
                shutil.copy(PROXYCHAINS_BACKUP, conf)
                os.remove(PROXYCHAINS_BACKUP)
                return True, "proxychains config restored"
            except (IOError, OSError) as e:
                return False, str(e)
        return True, "no proxychains backup to restore"

    # Backup original
    if not os.path.exists(PROXYCHAINS_BACKUP) and os.path.exists(conf):
        try:
            shutil.copy(conf, PROXYCHAINS_BACKUP)
        except (IOError, PermissionError):
            pass

    try:
        with open(conf, "w") as f:
            f.write(GHOST_PROXYCHAINS_CONF)
        return True, f"proxychains configured → Tor SOCKS5 :9050"
    except (IOError, PermissionError) as e:
        return False, str(e)


def is_proxychains_installed() -> bool:
    return _proxychains_bin() is not None


# ─── Firefox system-wide prefs (secondary, belt-and-suspenders) ───────────────

def _find_system_pref_dir() -> str | None:
    for d in SYSTEM_PREF_DIRS:
        if os.path.isdir(d):
            return d
    return None


def _find_firefox_profiles() -> list[str]:
    roots = [
        os.path.expanduser("~/.mozilla/firefox"),
        "/root/.mozilla/firefox",
    ] + glob.glob("/home/*/.mozilla/firefox")

    profiles = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for entry in os.listdir(root):
            full = os.path.join(root, entry)
            if os.path.isdir(full) and (
                os.path.exists(os.path.join(full, "prefs.js")) or
                os.path.exists(os.path.join(full, "times.json"))
            ):
                profiles.append(full)
    return list(set(profiles))


def _pref_lines(fn: str = "lockPref") -> list[str]:
    lines = ["// Ghost anonymity suite\n"]
    for pref, value in FIREFOX_PREFS:
        if isinstance(value, bool):
            lines.append(f'{fn}("{pref}", {"true" if value else "false"});\n')
        elif isinstance(value, int):
            lines.append(f'{fn}("{pref}", {value});\n')
        else:
            lines.append(f'{fn}("{pref}", {value});\n')
    return lines


def _write_system_prefs(restore: bool = False) -> tuple[bool, str]:
    pref_dir = _find_system_pref_dir()
    if not pref_dir:
        return False, "Firefox system prefs directory not found"
    pref_file = os.path.join(pref_dir, SYSTEM_PREF_FILE)
    if restore:
        try:
            if os.path.exists(pref_file):
                os.remove(pref_file)
            return True, f"removed {pref_file}"
        except (IOError, PermissionError) as e:
            return False, str(e)
    try:
        with open(pref_file, "w") as f:
            f.writelines(_pref_lines("lockPref"))
        return True, f"wrote {pref_file}"
    except (IOError, PermissionError) as e:
        return False, str(e)


def _write_user_js(profile_dir: str, restore: bool = False) -> bool:
    user_js = os.path.join(profile_dir, "user.js")
    backup  = os.path.join(profile_dir, "user.js.ghost.bak")
    marker  = backup + ".empty"
    if restore:
        try:
            if os.path.exists(marker):
                if os.path.exists(user_js):
                    os.remove(user_js)
                os.remove(marker)
                return True
            elif os.path.exists(backup):
                shutil.copy(backup, user_js)
                os.remove(backup)
                return True
        except (IOError, OSError):
            pass
        return False
    try:
        if os.path.exists(user_js):
            shutil.copy(user_js, backup)
        else:
            open(marker, "w").close()
        lines = ["// Ghost anonymity suite\n"]
        for pref, value in FIREFOX_PREFS:
            if isinstance(value, bool):
                lines.append(f'user_pref("{pref}", {"true" if value else "false"});\n')
            elif isinstance(value, int):
                lines.append(f'user_pref("{pref}", {value});\n')
            else:
                lines.append(f'user_pref("{pref}", {value});\n')
        with open(user_js, "w") as f:
            f.writelines(lines)
        return True
    except (IOError, PermissionError):
        return False


def configure_firefox(restore: bool = False) -> dict[str, bool]:
    results: dict[str, bool] = {}
    ok, label = _write_system_prefs(restore=restore)
    results[label] = ok
    for profile in _find_firefox_profiles():
        results[profile] = _write_user_js(profile, restore=restore)
    return results


# ─── Launch helpers ───────────────────────────────────────────────────────────

def kill_firefox():
    subprocess.run(["pkill", "-f", "firefox-esr"], check=False, capture_output=True)
    subprocess.run(["pkill", "-f", "firefox"],     check=False, capture_output=True)


def launch_firefox_proxychains() -> tuple[bool, str]:
    """
    Primary browser launch method.
    proxychains intercepts syscalls — no Firefox config needed.
    """
    pc = _proxychains_bin()
    if not pc:
        return False, "proxychains not installed — run: apt install proxychains4"

    binary = shutil.which("firefox-esr") or shutil.which("firefox")
    if not binary:
        return False, "Firefox not found"

    subprocess.Popen(
        [pc, binary],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return True, f"Firefox launched via {pc} → Tor SOCKS5"


def launch_firefox_tor() -> tuple[bool, str]:
    """Fallback: env-var proxy hint (less reliable than proxychains)."""
    binary = shutil.which("firefox-esr") or shutil.which("firefox")
    if not binary:
        return False, "Firefox not found"
    env = os.environ.copy()
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env[k] = "socks5h://127.0.0.1:9050"
    subprocess.Popen(
        [binary, "--new-instance", "--no-remote"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return True, "Firefox launched with SOCKS5 env vars"


def launch_tor_browser() -> tuple[bool, str]:
    locations = [
        "/opt/tor-browser/start-tor-browser",
        "/opt/tor-browser_en-US/start-tor-browser",
        os.path.expanduser("~/tor-browser/start-tor-browser"),
        os.path.expanduser("~/tor-browser_en-US/start-tor-browser"),
    ]
    for loc in locations:
        if os.path.exists(loc):
            subprocess.Popen([loc, "--detach"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Tor Browser launched"
    if shutil.which("tor-browser"):
        subprocess.Popen(["tor-browser"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, "Tor Browser launched"
    return False, "Tor Browser not found — install from https://www.torproject.org"


def get_chromium_command() -> str:
    binary = shutil.which("chromium") or shutil.which("chromium-browser") or "chromium"
    pc = _proxychains_bin()
    if pc:
        return f"{pc} {binary}"
    return f"{binary} {' '.join(CHROMIUM_FLAGS)}"


def is_firefox_running() -> bool:
    result = subprocess.run(["pgrep", "-f", "firefox"], capture_output=True, check=False)
    return result.returncode == 0


# ─── Full configure (called by tor_manager on enable/disable) ─────────────────

def apply_all(restore: bool = False) -> dict[str, bool]:
    """Configure proxychains + Firefox prefs in one call."""
    results: dict[str, bool] = {}
    ok, msg = configure_proxychains(restore=restore)
    results[f"proxychains: {msg}"] = ok
    ff_results = configure_firefox(restore=restore)
    results.update(ff_results)
    return results
