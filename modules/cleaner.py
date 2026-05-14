import os
import subprocess
import glob
import shutil
from pathlib import Path


# Log files and directories to wipe
LOG_TARGETS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/daemon.log",
    "/var/log/messages",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/faillog",
    "/var/log/dpkg.log",
    "/var/log/apt/history.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
]

TEMP_DIRS = [
    "/tmp",
    "/var/tmp",
]

SHELL_HISTORIES = [
    "~/.bash_history",
    "~/.zsh_history",
    "~/.sh_history",
    "~/.fish_history",
    "~/.python_history",
    "~/.mysql_history",
    "~/.psql_history",
    "~/.sqlite_history",
    "~/.lesshst",
    "~/.viminfo",
]

BROWSER_CACHES = [
    "~/.mozilla/firefox/*/cache2",
    "~/.config/chromium/*/Cache",
    "~/.config/google-chrome/*/Cache",
    "~/.cache/mozilla",
    "~/.cache/chromium",
]

THUMBNAIL_CACHE = [
    "~/.cache/thumbnails",
    "~/.thumbnails",
]


def _secure_delete(path: str) -> bool:
    """Overwrite file with zeros then delete."""
    try:
        if os.path.isfile(path):
            size = os.path.getsize(path)
            with open(path, "wb") as f:
                f.write(b"\x00" * size)
            os.remove(path)
            return True
    except (IOError, PermissionError, OSError):
        return False
    return False


def _truncate_log(path: str) -> bool:
    """Truncate a log file to zero bytes (preserves file for daemon writes)."""
    try:
        if os.path.exists(path):
            with open(path, "w") as f:
                f.truncate(0)
            return True
    except (IOError, PermissionError):
        return False
    return False


def clear_shell_history(secure: bool = True) -> dict[str, bool]:
    results = {}
    for pattern in SHELL_HISTORIES:
        expanded = os.path.expanduser(pattern)
        if os.path.exists(expanded):
            if secure:
                results[expanded] = _secure_delete(expanded)
            else:
                results[expanded] = _truncate_log(expanded)

    # Also clear current session history
    try:
        subprocess.run(["bash", "-c", "history -c && history -w"], check=False, capture_output=True)
    except Exception:
        pass

    return results


def clear_system_logs(secure: bool = False) -> dict[str, bool]:
    results = {}
    for log_path in LOG_TARGETS:
        if os.path.exists(log_path):
            results[log_path] = _truncate_log(log_path)

    # Clear systemd journal logs
    try:
        subprocess.run(
            ["journalctl", "--vacuum-time=1s"],
            capture_output=True, check=False
        )
        results["systemd-journal"] = True
    except Exception:
        results["systemd-journal"] = False

    return results


def clear_temp_files() -> dict[str, int]:
    results = {}
    for temp_dir in TEMP_DIRS:
        if os.path.isdir(temp_dir):
            count = 0
            for item in os.listdir(temp_dir):
                item_path = os.path.join(temp_dir, item)
                try:
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                        count += 1
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path, ignore_errors=True)
                        count += 1
                except (IOError, PermissionError, OSError):
                    pass
            results[temp_dir] = count
    return results


def clear_browser_data() -> dict[str, bool]:
    results = {}
    targets = BROWSER_CACHES + THUMBNAIL_CACHE
    for pattern in targets:
        expanded = os.path.expanduser(pattern)
        matched = glob.glob(expanded)
        for path in matched:
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                    results[path] = True
                elif os.path.isfile(path):
                    results[path] = _secure_delete(path)
            except Exception:
                results[path] = False
    return results


def clear_recent_files() -> bool:
    """Clear GNOME/KDE recent files lists."""
    recent_paths = [
        "~/.recently-used",
        "~/.local/share/recently-used.xbel",
        "~/.local/share/RecentDocuments",
    ]
    cleared = False
    for path in recent_paths:
        expanded = os.path.expanduser(path)
        if os.path.exists(expanded):
            try:
                if os.path.isfile(expanded):
                    _truncate_log(expanded)
                    cleared = True
            except Exception:
                pass
    return cleared


def clear_swap() -> tuple[bool, str]:
    """Wipe swap space to remove memory artifacts."""
    try:
        subprocess.run(["swapoff", "-a"], check=True, capture_output=True)
        subprocess.run(["swapon", "-a"], check=True, capture_output=True)
        return True, "Swap cleared and remounted"
    except subprocess.CalledProcessError as e:
        return False, str(e)


def full_clean(secure_logs: bool = False) -> dict:
    """Run all cleaning operations."""
    return {
        "shell_history": clear_shell_history(secure=True),
        "system_logs": clear_system_logs(secure=secure_logs),
        "temp_files": clear_temp_files(),
        "browser_data": clear_browser_data(),
        "recent_files": clear_recent_files(),
    }
