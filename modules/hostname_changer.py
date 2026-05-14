import subprocess
import random
import socket
import os


ADJECTIVES = [
    "silent", "shadow", "hidden", "ghost", "phantom", "dark", "stealth",
    "covert", "veiled", "obscure", "blank", "void", "null", "cipher",
    "spectral", "hollow", "masked", "unseen", "fading", "distant"
]

NOUNS = [
    "node", "host", "system", "machine", "station", "terminal", "unit",
    "relay", "router", "client", "server", "endpoint", "agent", "proxy",
    "device", "probe", "sensor", "module", "core", "instance"
]


def get_current_hostname() -> str:
    return socket.gethostname()


def generate_hostname() -> str:
    adj = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    suffix = random.randint(100, 999)
    return f"{adj}-{noun}-{suffix}"


def set_hostname(new_hostname: str) -> tuple[bool, str]:
    old = get_current_hostname()
    try:
        subprocess.run(["hostnamectl", "set-hostname", new_hostname], check=True, capture_output=True)
        # Also update /etc/hosts to prevent resolution delays
        _update_hosts_file(old, new_hostname)
        return True, old
    except subprocess.CalledProcessError as e:
        return False, str(e)


def _update_hosts_file(old_hostname: str, new_hostname: str):
    hosts_path = "/etc/hosts"
    try:
        with open(hosts_path, "r") as f:
            content = f.read()
        content = content.replace(old_hostname, new_hostname)
        with open(hosts_path, "w") as f:
            f.write(content)
    except (IOError, PermissionError):
        pass


def randomize_hostname() -> tuple[bool, str, str]:
    new_hostname = generate_hostname()
    success, result = set_hostname(new_hostname)
    if success:
        return True, result, new_hostname
    return False, result, ""
