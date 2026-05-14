import os
import glob
import subprocess
import shutil
import json


# Firefox user.js preferences to force all traffic through Tor SOCKS5
FIREFOX_PREFS = [
    # ── Proxy: force SOCKS5 through Tor ──────────────────────────────────────
    ('network.proxy.type',            1),           # Manual proxy config
    ('network.proxy.socks',           '"127.0.0.1"'),
    ('network.proxy.socks_port',      9050),
    ('network.proxy.socks_version',   5),
    ('network.proxy.socks_remote_dns', True),       # DNS through SOCKS (critical)
    ('network.proxy.no_proxies_on',   '""'),        # No bypass list

    # ── DNS-over-HTTPS: disable completely (bypasses system DNS) ─────────────
    ('network.trr.mode',              5),           # 5 = disabled, off
    ('network.trr.uri',               '""'),

    # ── WebRTC: disable to prevent IP leaks ──────────────────────────────────
    ('media.peerconnection.enabled',  False),
    ('media.peerconnection.ice.no_host', True),

    # ── Geolocation / telemetry ───────────────────────────────────────────────
    ('geo.enabled',                   False),
    ('toolkit.telemetry.enabled',     False),
    ('datareporting.healthreport.uploadEnabled', False),
]

# Chromium/Chrome equivalent command-line flags
CHROMIUM_FLAGS = [
    '--proxy-server=socks5://127.0.0.1:9050',
    '--proxy-bypass-list=<-loopback>',
    '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1',
    '--disable-webrtc',
]


def _find_firefox_profiles() -> list[str]:
    """Return paths to all Firefox profile directories."""
    candidates = [
        os.path.expanduser("~/.mozilla/firefox/*.default*"),
        os.path.expanduser("~/.mozilla/firefox/*.default-release*"),
        os.path.expanduser("~/.mozilla/firefox/*.esr*"),
        "/root/.mozilla/firefox/*.default*",
        "/root/.mozilla/firefox/*.default-release*",
    ]
    profiles = []
    for pattern in candidates:
        profiles.extend(glob.glob(pattern))
    return list(set(profiles))


def _write_user_js(profile_dir: str, restore: bool = False) -> bool:
    """Write (or remove) Ghost proxy settings into Firefox user.js."""
    user_js = os.path.join(profile_dir, "user.js")
    backup = os.path.join(profile_dir, "user.js.ghost.bak")

    if restore:
        if os.path.exists(backup):
            try:
                if os.path.exists(backup + ".empty"):
                    os.remove(user_js)
                    os.remove(backup + ".empty")
                else:
                    shutil.copy(backup, user_js)
                    os.remove(backup)
                return True
            except (IOError, OSError):
                return False
        return False

    # Backup existing user.js
    try:
        if os.path.exists(user_js):
            shutil.copy(user_js, backup)
        else:
            # Mark that there was no original file
            open(backup + ".empty", "w").close()

        lines = ["// Ghost anonymity suite - auto-generated, do not edit\n"]
        for pref, value in FIREFOX_PREFS:
            if isinstance(value, bool):
                v = "true" if value else "false"
                lines.append(f'user_pref("{pref}", {v});\n')
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
    """Apply or remove Ghost settings across all Firefox profiles."""
    profiles = _find_firefox_profiles()
    results = {}
    for profile in profiles:
        results[profile] = _write_user_js(profile, restore=restore)
    return results


def kill_firefox():
    """Kill running Firefox so settings take effect on next launch."""
    subprocess.run(["pkill", "-f", "firefox"], check=False, capture_output=True)
    subprocess.run(["pkill", "-f", "firefox-esr"], check=False, capture_output=True)


def launch_firefox_tor() -> bool:
    """Launch Firefox with Tor proxy pre-applied via environment."""
    try:
        env = os.environ.copy()
        # Some builds respect these env vars as fallback
        env["http_proxy"]  = "socks5h://127.0.0.1:9050"
        env["https_proxy"] = "socks5h://127.0.0.1:9050"
        env["HTTP_PROXY"]  = "socks5h://127.0.0.1:9050"
        env["HTTPS_PROXY"] = "socks5h://127.0.0.1:9050"
        subprocess.Popen(
            ["firefox", "--new-instance", "--no-remote"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except FileNotFoundError:
        return False


def launch_tor_browser() -> bool:
    """Launch Tor Browser if installed."""
    locations = [
        "/opt/tor-browser/start-tor-browser.desktop",
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
        subprocess.Popen(
            ["tor-browser"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    return False


def get_chromium_command() -> str:
    """Return a chromium launch command with Tor proxy flags."""
    binary = shutil.which("chromium") or shutil.which("chromium-browser") or "chromium"
    flags = " ".join(CHROMIUM_FLAGS)
    return f"{binary} {flags}"


def is_firefox_running() -> bool:
    result = subprocess.run(["pgrep", "-f", "firefox"], capture_output=True, check=False)
    return result.returncode == 0
