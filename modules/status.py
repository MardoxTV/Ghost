import subprocess
import socket
import os
import urllib.request
import urllib.error
import json
import re


def get_public_ip(timeout: int = 8) -> dict:
    """Fetch public IP info from ipinfo.io."""
    try:
        req = urllib.request.Request("https://ipinfo.io/json")
        req.add_header("User-Agent", "curl/7.68.0")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
            return {
                "ip": data.get("ip", "unknown"),
                "country": data.get("country", "?"),
                "city": data.get("city", "?"),
                "org": data.get("org", "?"),
                "success": True,
            }
    except Exception as e:
        return {"ip": "unreachable", "success": False, "error": str(e)}


def check_tor_status() -> dict:
    """Check if traffic is going through Tor."""
    try:
        req = urllib.request.Request("https://check.torproject.org/api/ip")
        req.add_header("User-Agent", "curl/7.68.0")
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            return {
                "using_tor": data.get("IsTor", False),
                "ip": data.get("IP", "unknown"),
                "success": True,
            }
    except Exception:
        return {"using_tor": False, "ip": "unknown", "success": False}


def get_interfaces_info() -> list[dict]:
    """Get MAC and IP info for all network interfaces."""
    interfaces = []
    result = subprocess.run(["ip", "addr"], capture_output=True, text=True)

    current = None
    for line in result.stdout.splitlines():
        iface_match = re.match(r"^\d+:\s+(\w+):", line)
        if iface_match:
            if current:
                interfaces.append(current)
            name = iface_match.group(1)
            current = {"name": name, "mac": None, "ipv4": None, "ipv6": None, "state": "DOWN"}
            if "UP" in line:
                current["state"] = "UP"

        if current:
            mac_match = re.search(r"link/ether\s+([0-9a-f:]{17})", line)
            if mac_match:
                current["mac"] = mac_match.group(1)

            ipv4_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if ipv4_match and current["name"] != "lo":
                current["ipv4"] = ipv4_match.group(1)

            ipv6_match = re.search(r"inet6\s+([0-9a-f:]+/\d+)\s+scope global", line)
            if ipv6_match:
                current["ipv6"] = ipv6_match.group(1)

    if current:
        interfaces.append(current)

    return [i for i in interfaces if i["name"] != "lo"]


def get_hostname() -> str:
    return socket.gethostname()


def get_dns_servers() -> list[str]:
    servers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except (IOError, FileNotFoundError):
        pass
    return servers


def is_ipv6_disabled() -> bool:
    try:
        with open("/proc/sys/net/ipv6/conf/all/disable_ipv6", "r") as f:
            return f.read().strip() == "1"
    except (IOError, FileNotFoundError):
        return False


def is_tor_running() -> bool:
    result = subprocess.run(["pgrep", "-x", "tor"], capture_output=True, check=False)
    return result.returncode == 0


def check_iptables_active() -> bool:
    result = subprocess.run(
        ["iptables", "-t", "nat", "-L", "GHOST_OUTPUT"],
        capture_output=True, check=False
    )
    return result.returncode == 0


def get_full_status() -> dict:
    """Aggregate all status checks."""
    return {
        "hostname": get_hostname(),
        "interfaces": get_interfaces_info(),
        "dns": get_dns_servers(),
        "ipv6_disabled": is_ipv6_disabled(),
        "tor_running": is_tor_running(),
        "iptables_active": check_iptables_active(),
    }
