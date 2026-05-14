import os
import glob
import subprocess
import shutil


# Firefox preferences to force all traffic through Tor SOCKS5
FIREFOX_PREFS = [
    # ── Proxy: force SOCKS5 through Tor ──────────────────────────────────────
    ('network.proxy.type',                       1),
    ('network.proxy.socks',                      '"127.0.0.1"'),
    ('network.proxy.socks_port',                 9050),
    ('network.proxy.socks_version',              5),
    ('network.proxy.socks_remote_dns',           True),   # DNS through SOCKS (critical)
    ('network.proxy.no_proxies_on',              '""'),   # No bypass list

    # ── DNS-over-HTTPS: disable completely (bypasses system DNS/iptables) ────
    ('network.trr.mode',                         5),      # 5 = disabled
    ('network.trr.uri',                          '""'),

    # ── WebRTC: disable to prevent real-IP leaks ─────────────────────────────
    ('media.peerconnection.enabled',             False),
    ('media.peerconnection.ice.no_host',         True),

    # ── Geolocation / telemetry ───────────────────────────────────────────────
    ('geo.enabled',                              False),
    ('toolkit.telemetry.enabled',                False),
    ('datareporting.healthreport.uploadEnabled', False),
]

# System-wide Firefox defaults directories (applied to ALL profiles, including new ones)
SYSTEM_PREF_DIRS = [
    "/usr/lib/firefox-esr/browser/defaults/preferences",
    "/usr/lib/firefox/browser/defaults/preferences",
    "/usr/lib64/firefox/browser/defaults/preferences",
    "/usr/share/firefox/browser/defaults/preferences",
]

SYSTEM_PREF_FILE = "ghost-tor.js"

# Chromium/Chrome equivalent command-line flags
CHROMIUM_FLAGS = [
    '--proxy-server=socks5://127.0.0.1:9050',
    '--proxy-bypass-list=<-loopback>',
    '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1',
    '--disable-webrtc',
]


def _build_pref_lines(header: str) -> list[str]:
    lines = [f"// {header}\n"]
    for pref, value in FIREFOX_PREFS:
        if isinstance(value, bool):
            lines.append(f'pref("{pref}", {"true" if value else "false"});\n')
        elif isinstance(value, int):
            lines.append(f'pref("{pref}", {value});\n')
        else:
            lines.append(f'pref("{pref}", {value});\n')
    return lines


def _build_user_js_lines() -> list[str]:
    """user.js uses user_pref() not pref()."""
    lines = ["// Ghost anonymity suite\n"]
    for pref, value in FIREFOX_PREFS:
        if isinstance(value, bool):
            lines.append(f'user_pref("{pref}", {"true" if value else "false"});\n')
        elif isinstance(value, int):
            lines.append(f'user_pref("{pref}", {value});\n')
        else:
            lines.append(f'user_pref("{pref}", {value});\n')
    return lines


# ─── System-wide preferences (no profile needed) ──────────────────────────────

def _get_active_system_pref_dir() -> str | None:
    for d in SYSTEM_PREF_DIRS:
        if os.path.isdir(d):
            return d
    return None


def _write_system_prefs(restore: bool = False) -> tuple[bool, str]:
    """
    Write ghost-tor.js into Firefox's system-wide defaults directory.
    This applies to every profile and to Firefox before any profile is created.
    """
    pref_dir = _get_active_system_pref_dir()
    if not pref_dir:
        return False, "Firefox system preferences directory not found"

    pref_file = os.path.join(pref_dir, SYSTEM_PREF_FILE)

    if restore:
        try:
            if os.path.exists(pref_file):
                os.remove(pref_file)
            return True, f"Removed {pref_file}"
        except (IOError, PermissionError) as e:
            return False, str(e)

    try:
        lines = _build_pref_lines("Ghost anonymity suite - system-wide Tor proxy")
        with open(pref_file, "w") as f:
            f.writelines(lines)
        return True, f"Written to {pref_file}"
    except (IOError, PermissionError) as e:
        return False, str(e)


# ─── Per-profile user.js (existing profiles) ──────────────────────────────────

def _find_firefox_profiles() -> list[str]:
    """Return paths to all existing Firefox profile directories."""
    search_roots = [
        os.path.expanduser("~/.mozilla/firefox"),
        "/root/.mozilla/firefox",
        "/home/*/.mozilla/firefox",
    ]
    profiles = []
    for root_pattern in search_roots:
        for root in glob.glob(root_pattern):
            if not os.path.isdir(root):
                continue
            for entry in os.listdir(root):
                full = os.path.join(root, entry)
                # A valid profile dir contains a prefs.js or times.json
                if os.path.isdir(full) and (
                    os.path.exists(os.path.join(full, "prefs.js")) or
                    os.path.exists(os.path.join(full, "times.json"))
                ):
                    profiles.append(full)
    return list(set(profiles))


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
            return False
        return False

    try:
        if os.path.exists(user_js):
            shutil.copy(user_js, backup)
        else:
            open(marker, "w").close()

        with open(user_js, "w") as f:
            f.writelines(_build_user_js_lines())
        return True
    except (IOError, PermissionError):
        return False


# ─── Public API ───────────────────────────────────────────────────────────────

def configure_firefox(restore: bool = False) -> dict[str, bool]:
    """
    Apply or remove Ghost settings.

    Always writes/removes the system-wide pref file (works even with no
    profiles).  Also patches any existing per-profile user.js files so
    already-running instances pick up changes on next launch.

    Returns a dict of {location: success}.
    """
    results: dict[str, bool] = {}

    # System-wide first (covers no-profile case)
    ok, label = _write_system_prefs(restore=restore)
    results[label] = ok

    # Per-profile (existing profiles)
    for profile in _find_firefox_profiles():
        results[profile] = _write_user_js(profile, restore=restore)

    return results


def kill_firefox():
    """Kill running Firefox so updated settings take effect on next launch."""
    subprocess.run(["pkill", "-f", "firefox-esr"], check=False, capture_output=True)
    subprocess.run(["pkill", "-f", "firefox"],     check=False, capture_output=True)


def launch_firefox_tor() -> bool:
    """Launch Firefox with Tor proxy environment variables set."""
    binary = shutil.which("firefox-esr") or shutil.which("firefox")
    if not binary:
        return False
    env = os.environ.copy()
    env["http_proxy"]  = "socks5h://127.0.0.1:9050"
    env["https_proxy"] = "socks5h://127.0.0.1:9050"
    env["HTTP_PROXY"]  = "socks5h://127.0.0.1:9050"
    env["HTTPS_PROXY"] = "socks5h://127.0.0.1:9050"
    subprocess.Popen(
        [binary, "--new-instance", "--no-remote"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return True


def launch_tor_browser() -> bool:
    """Launch Tor Browser if installed."""
    locations = [
        "/opt/tor-browser/start-tor-browser",
        "/opt/tor-browser_en-US/start-tor-browser",
        os.path.expanduser("~/tor-browser/start-tor-browser"),
        os.path.expanduser("~/tor-browser_en-US/start-tor-browser"),
    ]
    for loc in locations:
        if os.path.exists(loc):
            subprocess.Popen(
                [loc, "--detach"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    if shutil.which("tor-browser"):
        subprocess.Popen(["tor-browser"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    return False


def get_chromium_command() -> str:
    binary = shutil.which("chromium") or shutil.which("chromium-browser") or "chromium"
    return f"{binary} {' '.join(CHROMIUM_FLAGS)}"


def is_firefox_running() -> bool:
    result = subprocess.run(["pgrep", "-f", "firefox"], capture_output=True, check=False)
    return result.returncode == 0
