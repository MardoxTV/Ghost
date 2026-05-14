import subprocess
import random
import re
import os


def get_interfaces() -> list[str]:
    """Return list of network interfaces (excluding loopback)."""
    result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    interfaces = re.findall(r"^\d+:\s+(\w+):", result.stdout, re.MULTILINE)
    return [i for i in interfaces if i != "lo"]


def get_current_mac(interface: str) -> str | None:
    result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)
    match = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout)
    return match.group(1) if match else None


def generate_random_mac() -> str:
    # Locally administered, unicast MAC
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] = (mac[0] & 0xfe) | 0x02  # Locally administered, unicast
    return ":".join(f"{b:02x}" for b in mac)


def change_mac(interface: str, new_mac: str | None = None) -> tuple[bool, str, str]:
    """Change MAC for interface. Returns (success, old_mac, new_mac)."""
    old_mac = get_current_mac(interface) or "unknown"
    if new_mac is None:
        new_mac = generate_random_mac()

    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", interface, "address", new_mac], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True, capture_output=True)
        return True, old_mac, new_mac
    except subprocess.CalledProcessError as e:
        return False, old_mac, str(e)


def restore_mac(interface: str, original_mac: str) -> bool:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", interface, "address", original_mac], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def randomize_all_interfaces() -> dict[str, tuple[bool, str, str]]:
    """Randomize MAC on all non-loopback interfaces. Returns {iface: (success, old, new)}."""
    results = {}
    for iface in get_interfaces():
        results[iface] = change_mac(iface)
    return results
