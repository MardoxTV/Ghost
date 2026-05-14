# Ghost — Full Anonymity Suite for Kali Linux

A comprehensive anonymity tool that randomizes your digital identity and routes all traffic through Tor.

## Features

| Module | What it does |
|--------|-------------|
| **MAC Changer** | Randomizes hardware MAC addresses per-interface or all at once |
| **Tor Routing** | Routes all TCP/DNS through Tor via iptables (transparent proxy) |
| **DNS Manager** | Switches to anonymous DNS (Tor, Cloudflare, Quad9, Mullvad) + IPv6 leak prevention |
| **Hostname Changer** | Replaces system hostname with a random anonymous string |
| **Footprint Cleaner** | Wipes bash/zsh history, system logs, temp files, browser cache, swap |
| **Ghost Mode** | One-key toggle — enables ALL features simultaneously |
| **Live Status** | Shows current IP, Tor verification, MAC, hostname, DNS state |

## Install

```bash
cd ghost/
sudo bash install.sh
```

## Usage

```bash
# Interactive TUI
sudo ghost

# CLI flags (non-interactive)
sudo ghost --ghost-on          # Enable all anonymity features
sudo ghost --ghost-off         # Restore original settings
sudo ghost --status            # Show current IP and anonymity status
sudo ghost --mac               # Randomize all MAC addresses
sudo ghost --hostname          # Randomize hostname
sudo ghost --tor-on            # Enable Tor routing
sudo ghost --tor-off           # Disable Tor routing
sudo ghost --new-identity      # Request new Tor circuit
sudo ghost --dns tor           # Set DNS to Tor local resolver
sudo ghost --dns cloudflare    # Set DNS to Cloudflare
sudo ghost --clean             # Full footprint wipe
```

## How Tor Routing Works

Ghost creates an `iptables` chain (`GHOST_OUTPUT`) that:
1. Excludes local/private networks (RFC 1918, loopback)
2. Redirects UDP/TCP port 53 (DNS) → Tor DNS port 9053
3. Redirects all TCP traffic → Tor transparent proxy port 9040
4. Blocks Tor's own traffic from being re-routed (avoids loops)

This is the same approach used by tools like `anonsurf` and `kalitorify`.

## Requirements

- Kali Linux (or any Debian-based distro)
- Python 3.10+
- Root access (`sudo`)
- `tor`, `iptables`, `iproute2` (auto-installed by `install.sh`)

## Notes

- **Ghost Mode OFF** restores all original MACs, hostname, DNS, and removes iptables rules.
- IPv6 is disabled while Ghost is active to prevent IPv6 leaks.
- Tor must be running for `--tor-on` to work; install it with `apt install tor`.
- MAC address changes are temporary and reset on reboot.
