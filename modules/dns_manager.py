import os
import shutil
import subprocess


# Anonymized DNS providers (DoH-compatible, no-log)
DNS_PROVIDERS = {
    "tor_local":   {"primary": "127.0.0.1",   "secondary": "127.0.0.1",   "label": "Tor Local DNS"},
    "cloudflare":  {"primary": "1.1.1.1",     "secondary": "1.0.0.1",     "label": "Cloudflare (no-log)"},
    "quad9":       {"primary": "9.9.9.9",     "secondary": "149.112.112.112", "label": "Quad9 (no-log)"},
    "mullvad":     {"primary": "194.242.2.2", "secondary": "194.242.2.3", "label": "Mullvad DNS"},
}

RESOLV_PATH = "/etc/resolv.conf"
BACKUP_PATH = "/etc/resolv.conf.ghost.bak"


def get_current_dns() -> list[str]:
    servers = []
    try:
        with open(RESOLV_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except (IOError, FileNotFoundError):
        pass
    return servers


def backup_dns():
    if not os.path.exists(BACKUP_PATH):
        try:
            shutil.copy(RESOLV_PATH, BACKUP_PATH)
        except (IOError, PermissionError):
            pass


def set_dns(provider_key: str = "tor_local") -> tuple[bool, str]:
    provider = DNS_PROVIDERS.get(provider_key, DNS_PROVIDERS["quad9"])
    backup_dns()
    try:
        with open(RESOLV_PATH, "w") as f:
            f.write(f"# Ghost anonymity suite - {provider['label']}\n")
            f.write("options edns0 trust-ad\n")
            f.write(f"nameserver {provider['primary']}\n")
            f.write(f"nameserver {provider['secondary']}\n")
        return True, f"DNS set to {provider['label']} ({provider['primary']})"
    except (IOError, PermissionError) as e:
        return False, str(e)


def restore_dns() -> tuple[bool, str]:
    if os.path.exists(BACKUP_PATH):
        try:
            shutil.copy(BACKUP_PATH, RESOLV_PATH)
            os.remove(BACKUP_PATH)
            return True, "Original DNS restored"
        except (IOError, PermissionError) as e:
            return False, str(e)
    return False, "No DNS backup found"


def disable_ipv6() -> tuple[bool, str]:
    """Disable IPv6 to prevent IPv6 leaks."""
    cmds = [
        ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
        ["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"],
        ["sysctl", "-w", "net.ipv6.conf.lo.disable_ipv6=1"],
    ]
    try:
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True, check=True)
        return True, "IPv6 disabled (prevents IPv6 leaks)"
    except subprocess.CalledProcessError as e:
        return False, str(e)


def enable_ipv6() -> tuple[bool, str]:
    cmds = [
        ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"],
        ["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"],
        ["sysctl", "-w", "net.ipv6.conf.lo.disable_ipv6=0"],
    ]
    try:
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True, check=True)
        return True, "IPv6 re-enabled"
    except subprocess.CalledProcessError as e:
        return False, str(e)


def check_dns_leak() -> dict:
    """Check if DNS is leaking real identity."""
    current = get_current_dns()
    is_tor = "127.0.0.1" in current
    is_safe = is_tor or any(
        d["primary"] in current for d in DNS_PROVIDERS.values()
    )
    return {
        "servers": current,
        "using_tor": is_tor,
        "is_safe": is_safe,
    }
