#!/usr/bin/env python3
"""Ghost - Full Anonymity Suite for Kali Linux"""

import os
import sys
import time
import threading
import argparse
from typing import Optional

# Enforce root
if os.geteuid() != 0:
    print("[!] Ghost must be run as root. Use: sudo python3 main.py")
    sys.exit(1)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich import box
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.style import Style

from modules import mac_changer, tor_manager, dns_manager, hostname_changer, cleaner, status

console = Console()

BANNER = r"""
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
"""

VERSION = "1.0.0"

# Track original values for restoration
_original_state: dict = {
    "macs": {},
    "hostname": None,
    "tor_was_running": False,
}


# ─────────────────────────────────────────────────────────
# UI Helpers
# ─────────────────────────────────────────────────────────

def print_banner():
    console.print(Align.center(
        Panel(
            Text(BANNER, style="bold red") +
            Text(f"\n  Full Anonymity Suite v{VERSION}  |  Kali Linux\n", style="dim white", justify="center"),
            border_style="red",
            box=box.DOUBLE_EDGE,
        )
    ))


def print_ok(msg: str):
    console.print(f"  [bold green][+][/] {msg}")


def print_fail(msg: str):
    console.print(f"  [bold red][-][/] {msg}")


def print_info(msg: str):
    console.print(f"  [bold cyan][*][/] {msg}")


def print_warn(msg: str):
    console.print(f"  [bold yellow][!][/] {msg}")


def spinner_task(label: str):
    return Progress(
        SpinnerColumn(style="red"),
        TextColumn(f"[bold white]{label}"),
        transient=True,
        console=console,
    )


# ─────────────────────────────────────────────────────────
# Status Display
# ─────────────────────────────────────────────────────────

def show_status(live_ip: bool = False):
    console.rule("[bold red]  SYSTEM STATUS", style="red")

    with spinner_task("Fetching status...") as p:
        task = p.add_task("")
        p.start()
        sys_status = status.get_full_status()
        p.stop()

    # Hostname
    hostname_text = Text(sys_status["hostname"])
    console.print(f"\n  [dim]Hostname    :[/]  [bold white]{sys_status['hostname']}[/]")

    # Network interfaces table
    iface_table = Table(box=box.SIMPLE, show_header=True, header_style="bold red",
                        border_style="dim", padding=(0, 1))
    iface_table.add_column("Interface", style="cyan")
    iface_table.add_column("State", justify="center")
    iface_table.add_column("MAC Address", style="yellow")
    iface_table.add_column("IPv4", style="green")
    iface_table.add_column("IPv6", style="dim")

    for iface in sys_status["interfaces"]:
        state_style = "bold green" if iface["state"] == "UP" else "dim red"
        iface_table.add_row(
            iface["name"],
            Text(iface["state"], style=state_style),
            iface["mac"] or "-",
            iface["ipv4"] or "-",
            iface["ipv6"] or "-",
        )
    console.print(iface_table)

    # DNS
    dns_info = dns_manager.check_dns_leak()
    dns_color = "green" if dns_info["is_safe"] else "bold red"
    dns_label = "[SAFE]" if dns_info["is_safe"] else "[LEAK RISK]"
    console.print(f"  [dim]DNS Servers :[/]  [{dns_color}]{', '.join(dns_info['servers']) or 'none'} {dns_label}[/]")

    # IPv6
    ipv6_label = "[bold green]Disabled (safe)" if sys_status["ipv6_disabled"] else "[bold red]Enabled (leak risk)"
    console.print(f"  [dim]IPv6        :[/]  {ipv6_label}")

    # Tor
    tor_label = "[bold green]Running" if sys_status["tor_running"] else "[dim red]Stopped"
    iptables_label = "[bold green]Active" if sys_status["iptables_active"] else "[dim red]Inactive"
    console.print(f"  [dim]Tor Service :[/]  {tor_label}")
    console.print(f"  [dim]Tor Routing :[/]  {iptables_label}")

    if live_ip:
        console.print()
        with spinner_task("Checking public IP...") as p:
            p.add_task("")
            p.start()
            ip_info = status.get_public_ip()
            p.stop()

        if ip_info["success"]:
            console.print(f"  [dim]Public IP   :[/]  [bold white]{ip_info['ip']}[/]  "
                          f"[dim]{ip_info['city']}, {ip_info['country']} — {ip_info['org']}[/]")
        else:
            print_fail(f"Could not reach public IP check: {ip_info.get('error', '?')}")

        if sys_status["tor_running"]:
            with spinner_task("Verifying Tor...") as p:
                p.add_task("")
                p.start()
                tor_check = status.check_tor_status()
                p.stop()

            if tor_check["success"]:
                if tor_check["using_tor"]:
                    print_ok(f"Confirmed Tor exit: {tor_check['ip']}")
                else:
                    print_warn("Traffic does NOT appear to be going through Tor")
            else:
                print_warn("Could not reach Tor check service")

    console.print()


# ─────────────────────────────────────────────────────────
# Feature Functions
# ─────────────────────────────────────────────────────────

def menu_mac_changer():
    console.rule("[bold red]  MAC ADDRESS CHANGER", style="red")
    interfaces = mac_changer.get_interfaces()

    if not interfaces:
        print_fail("No network interfaces found.")
        return

    console.print("\n  Available interfaces:\n")
    for i, iface in enumerate(interfaces, 1):
        mac = mac_changer.get_current_mac(iface) or "unknown"
        console.print(f"    [bold cyan]{i}.[/]  {iface}  [dim]({mac})[/]")

    console.print(f"    [bold cyan]{len(interfaces)+1}.[/]  Randomize ALL interfaces")
    console.print(f"    [bold cyan]0.[/]  Back\n")

    choice = Prompt.ask("  Select", default="0")

    if choice == "0":
        return
    elif choice == str(len(interfaces) + 1):
        results = mac_changer.randomize_all_interfaces()
        _original_state["macs"].update({k: v[1] for k, v in results.items() if v[0]})
        for iface, (ok, old, new) in results.items():
            if ok:
                print_ok(f"{iface}: {old} → {new}")
            else:
                print_fail(f"{iface}: {new}")
    else:
        try:
            idx = int(choice) - 1
            iface = interfaces[idx]
            custom = Prompt.ask("  Custom MAC (leave blank to randomize)", default="")
            ok, old, new = mac_changer.change_mac(iface, custom or None)
            if ok:
                _original_state["macs"][iface] = old
                print_ok(f"{iface}: {old} → {new}")
            else:
                print_fail(f"Failed: {new}")
        except (IndexError, ValueError):
            print_warn("Invalid selection.")
    console.print()


def menu_tor_routing():
    console.rule("[bold red]  TOR ANONYMIZATION", style="red")
    running = tor_manager.is_tor_running()
    active = status.check_iptables_active()

    console.print(f"\n  [dim]Tor Service :[/]  {'[bold green]Running' if running else '[dim red]Stopped'}")
    console.print(f"  [dim]Routing     :[/]  {'[bold green]Active' if active else '[dim red]Inactive'}\n")

    console.print("    [bold cyan]1.[/]  Enable Tor routing (all traffic through Tor)")
    console.print("    [bold cyan]2.[/]  Disable Tor routing")
    console.print("    [bold cyan]3.[/]  New Tor identity (new exit node)")
    console.print("    [bold cyan]4.[/]  Start Tor service only")
    console.print("    [bold cyan]5.[/]  Stop Tor service")
    console.print("    [bold cyan]0.[/]  Back\n")

    choice = Prompt.ask("  Select", default="0")

    if choice == "1":
        with spinner_task("Enabling Tor routing...") as p:
            p.add_task("")
            p.start()
            ok, msg = tor_manager.enable_routing()
            p.stop()
        (print_ok if ok else print_fail)(msg)

    elif choice == "2":
        with spinner_task("Disabling Tor routing...") as p:
            p.add_task("")
            p.start()
            ok, msg = tor_manager.disable_routing()
            p.stop()
        (print_ok if ok else print_fail)(msg)

    elif choice == "3":
        ok, msg = tor_manager.new_tor_identity()
        (print_ok if ok else print_fail)(msg)

    elif choice == "4":
        with spinner_task("Starting Tor...") as p:
            p.add_task("")
            p.start()
            ok, msg = tor_manager.start_tor()
            p.stop()
        (print_ok if ok else print_fail)(msg)

    elif choice == "5":
        ok, msg = tor_manager.stop_tor()
        (print_ok if ok else print_fail)(msg)

    console.print()


def menu_dns():
    console.rule("[bold red]  DNS MANAGEMENT", style="red")
    current = dns_manager.get_current_dns()
    console.print(f"\n  [dim]Current DNS:[/]  {', '.join(current) or 'none'}\n")

    console.print("    [bold cyan]1.[/]  Set DNS to Tor local resolver (recommended with Tor)")
    console.print("    [bold cyan]2.[/]  Set DNS to Cloudflare (1.1.1.1, no-log)")
    console.print("    [bold cyan]3.[/]  Set DNS to Quad9 (9.9.9.9, no-log)")
    console.print("    [bold cyan]4.[/]  Set DNS to Mullvad (194.242.2.2)")
    console.print("    [bold cyan]5.[/]  Restore original DNS")
    console.print("    [bold cyan]6.[/]  Disable IPv6 (prevent leaks)")
    console.print("    [bold cyan]7.[/]  Enable IPv6")
    console.print("    [bold cyan]0.[/]  Back\n")

    choice = Prompt.ask("  Select", default="0")

    provider_map = {"1": "tor_local", "2": "cloudflare", "3": "quad9", "4": "mullvad"}

    if choice in provider_map:
        ok, msg = dns_manager.set_dns(provider_map[choice])
        (print_ok if ok else print_fail)(msg)
    elif choice == "5":
        ok, msg = dns_manager.restore_dns()
        (print_ok if ok else print_fail)(msg)
    elif choice == "6":
        ok, msg = dns_manager.disable_ipv6()
        (print_ok if ok else print_fail)(msg)
    elif choice == "7":
        ok, msg = dns_manager.enable_ipv6()
        (print_ok if ok else print_fail)(msg)

    console.print()


def menu_hostname():
    console.rule("[bold red]  HOSTNAME CHANGER", style="red")
    current = hostname_changer.get_current_hostname()
    console.print(f"\n  [dim]Current hostname:[/]  [bold white]{current}[/]\n")

    console.print("    [bold cyan]1.[/]  Randomize hostname")
    console.print("    [bold cyan]2.[/]  Set custom hostname")
    console.print("    [bold cyan]0.[/]  Back\n")

    choice = Prompt.ask("  Select", default="0")

    if choice == "1":
        ok, old, new = hostname_changer.randomize_hostname()
        if ok:
            _original_state["hostname"] = old
            print_ok(f"Hostname: {old} → {new}")
        else:
            print_fail(f"Failed: {old}")
    elif choice == "2":
        new_name = Prompt.ask("  Enter new hostname")
        if new_name:
            ok, old = hostname_changer.set_hostname(new_name)
            if ok:
                _original_state["hostname"] = old
                print_ok(f"Hostname: {old} → {new_name}")
            else:
                print_fail(f"Failed: {old}")

    console.print()


def menu_cleaner():
    console.rule("[bold red]  FOOTPRINT CLEANER", style="red")
    console.print()
    console.print("    [bold cyan]1.[/]  Clear shell history (bash, zsh, fish...)")
    console.print("    [bold cyan]2.[/]  Clear system logs")
    console.print("    [bold cyan]3.[/]  Clear temp files (/tmp, /var/tmp)")
    console.print("    [bold cyan]4.[/]  Clear browser cache & data")
    console.print("    [bold cyan]5.[/]  Clear recent files list")
    console.print("    [bold cyan]6.[/]  Clear swap (remove RAM artifacts)")
    console.print("    [bold cyan]7.[/]  [bold red]Full clean[/] (all of the above)")
    console.print("    [bold cyan]0.[/]  Back\n")

    choice = Prompt.ask("  Select", default="0")

    if choice == "1":
        results = cleaner.clear_shell_history()
        cleared = sum(1 for v in results.values() if v)
        print_ok(f"Cleared {cleared} history file(s)")

    elif choice == "2":
        results = cleaner.clear_system_logs()
        cleared = sum(1 for v in results.values() if v)
        print_ok(f"Cleared {cleared} log file(s)")

    elif choice == "3":
        results = cleaner.clear_temp_files()
        total = sum(results.values())
        print_ok(f"Removed {total} item(s) from temp directories")

    elif choice == "4":
        results = cleaner.clear_browser_data()
        cleared = sum(1 for v in results.values() if v)
        print_ok(f"Cleared {cleared} browser data location(s)")

    elif choice == "5":
        ok = cleaner.clear_recent_files()
        (print_ok if ok else print_info)("Recent files list cleared" if ok else "No recent files found")

    elif choice == "6":
        ok, msg = cleaner.clear_swap()
        (print_ok if ok else print_fail)(msg)

    elif choice == "7":
        if Confirm.ask("  [bold red]Run full clean?[/] This will clear logs, history, temp, browser data"):
            with spinner_task("Running full clean...") as p:
                p.add_task("")
                p.start()
                results = cleaner.full_clean()
                p.stop()

            hist = sum(1 for v in results["shell_history"].values() if v)
            logs = sum(1 for v in results["system_logs"].values() if v)
            tmp = sum(results["temp_files"].values())
            browser = sum(1 for v in results["browser_data"].values() if v)
            print_ok(f"History files: {hist} cleared")
            print_ok(f"Log files: {logs} cleared")
            print_ok(f"Temp files: {tmp} removed")
            print_ok(f"Browser data: {browser} location(s) cleared")
            print_ok(f"Recent files: {'cleared' if results['recent_files'] else 'none found'}")

    console.print()


def enable_ghost_mode():
    """Enable all anonymity features at once."""
    console.rule("[bold red]  GHOST MODE - FULL ANONYMITY", style="red")
    console.print()
    print_info("Enabling all anonymity features...")
    console.print()

    # 1. Randomize all MACs
    print_info("Randomizing MAC addresses...")
    mac_results = mac_changer.randomize_all_interfaces()
    _original_state["macs"].update({k: v[1] for k, v in mac_results.items() if v[0]})
    for iface, (ok, old, new) in mac_results.items():
        (print_ok if ok else print_fail)(f"MAC {iface}: {old} → {new}")

    # 2. Randomize hostname
    print_info("Randomizing hostname...")
    ok, old, new = hostname_changer.randomize_hostname()
    if ok:
        _original_state["hostname"] = old
        print_ok(f"Hostname: {old} → {new}")
    else:
        print_fail(f"Hostname: {old}")

    # 3. Disable IPv6
    print_info("Disabling IPv6 (leak prevention)...")
    ok, msg = dns_manager.disable_ipv6()
    (print_ok if ok else print_fail)(msg)

    # 4. Start Tor + enable routing
    print_info("Starting Tor and enabling routing...")
    ok, msg = tor_manager.enable_routing()
    (print_ok if ok else print_fail)(msg)

    # 5. Set DNS to Tor
    print_info("Configuring DNS through Tor...")
    ok, msg = dns_manager.set_dns("tor_local")
    (print_ok if ok else print_fail)(msg)

    # 6. Clear footprints
    print_info("Clearing system footprints...")
    cleaner.clear_shell_history()
    cleaner.clear_temp_files()
    print_ok("Footprints cleared")

    console.print()
    print_ok("[bold green]Ghost Mode ACTIVE — You are anonymous[/]")
    console.print()


def disable_ghost_mode():
    """Restore all original settings."""
    console.rule("[bold red]  RESTORING ORIGINAL STATE", style="red")
    console.print()

    # Restore MACs
    if _original_state["macs"]:
        print_info("Restoring MAC addresses...")
        for iface, orig_mac in _original_state["macs"].items():
            ok = mac_changer.restore_mac(iface, orig_mac)
            (print_ok if ok else print_fail)(f"{iface}: restored to {orig_mac}")
        _original_state["macs"].clear()

    # Restore hostname
    if _original_state["hostname"]:
        print_info("Restoring hostname...")
        ok, old = hostname_changer.set_hostname(_original_state["hostname"])
        (print_ok if ok else print_fail)(f"Hostname restored to {_original_state['hostname']}")
        _original_state["hostname"] = None

    # Disable Tor routing
    print_info("Disabling Tor routing...")
    ok, msg = tor_manager.disable_routing()
    (print_ok if ok else print_fail)(msg)

    # Restore DNS
    print_info("Restoring DNS...")
    ok, msg = dns_manager.restore_dns()
    (print_ok if ok else print_fail)(msg)

    # Re-enable IPv6
    print_info("Re-enabling IPv6...")
    ok, msg = dns_manager.enable_ipv6()
    (print_ok if ok else print_fail)(msg)

    console.print()
    print_ok("All settings restored to original state")
    console.print()


# ─────────────────────────────────────────────────────────
# Main Menu
# ─────────────────────────────────────────────────────────

def main_menu():
    while True:
        os.system("clear")
        print_banner()
        show_status(live_ip=False)

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), border_style="dim")
        table.add_column(justify="right", style="bold cyan", no_wrap=True)
        table.add_column(style="white")
        table.add_column(style="dim")

        table.add_row("1", "Ghost Mode ON",     "Enable all anonymity features at once")
        table.add_row("2", "Ghost Mode OFF",    "Restore original MAC, hostname, DNS, routing")
        table.add_row("─", "─" * 30, "")
        table.add_row("3", "MAC Changer",       "Randomize/set interface MAC addresses")
        table.add_row("4", "Tor Routing",       "Route all traffic through Tor network")
        table.add_row("5", "DNS Manager",       "Configure anonymous DNS, disable IPv6")
        table.add_row("6", "Hostname Changer",  "Randomize system hostname")
        table.add_row("7", "Footprint Cleaner", "Wipe logs, history, temp files, browser data")
        table.add_row("─", "─" * 30, "")
        table.add_row("8", "Live Status",       "Fetch public IP and verify Tor exit")
        table.add_row("9", "New Tor Identity",  "Request new Tor circuit (new exit node)")
        table.add_row("0", "Exit", "")

        console.print(Align.center(table))
        console.print()

        choice = Prompt.ask("  [bold red]ghost[/][dim]>[/]", default="0")

        if choice == "1":
            enable_ghost_mode()
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "2":
            disable_ghost_mode()
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "3":
            os.system("clear")
            menu_mac_changer()
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "4":
            os.system("clear")
            menu_tor_routing()
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "5":
            os.system("clear")
            menu_dns()
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "6":
            os.system("clear")
            menu_hostname()
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "7":
            os.system("clear")
            menu_cleaner()
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "8":
            os.system("clear")
            console.rule("[bold red]  LIVE STATUS CHECK", style="red")
            show_status(live_ip=True)
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "9":
            ok, msg = tor_manager.new_tor_identity()
            (print_ok if ok else print_fail)(msg)
            Prompt.ask("  [dim]Press Enter to continue[/]", default="")
        elif choice == "0":
            if Confirm.ask("\n  [bold yellow]Exit Ghost?[/] Anonymity features will remain active unless you ran Ghost Mode OFF"):
                console.print("\n  [dim]Stay invisible.[/]\n")
                sys.exit(0)


# ─────────────────────────────────────────────────────────
# CLI Entrypoint
# ─────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Ghost - Full Anonymity Suite for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py                  # Interactive TUI
  sudo python3 main.py --ghost-on       # Enable all anonymity features
  sudo python3 main.py --ghost-off      # Disable all, restore originals
  sudo python3 main.py --status         # Show system status
  sudo python3 main.py --mac            # Randomize all MACs
  sudo python3 main.py --new-identity   # Get new Tor circuit
  sudo python3 main.py --clean          # Full footprint clean
        """
    )
    parser.add_argument("--ghost-on",      action="store_true", help="Enable all anonymity features")
    parser.add_argument("--ghost-off",     action="store_true", help="Restore original settings")
    parser.add_argument("--status",        action="store_true", help="Show current status")
    parser.add_argument("--mac",           action="store_true", help="Randomize all MAC addresses")
    parser.add_argument("--hostname",      action="store_true", help="Randomize hostname")
    parser.add_argument("--tor-on",        action="store_true", help="Enable Tor routing")
    parser.add_argument("--tor-off",       action="store_true", help="Disable Tor routing")
    parser.add_argument("--new-identity",  action="store_true", help="Request new Tor identity")
    parser.add_argument("--dns",           choices=["tor", "cloudflare", "quad9", "mullvad"], help="Set DNS provider")
    parser.add_argument("--clean",         action="store_true", help="Full footprint clean")
    return parser.parse_args()


def run_cli(args):
    print_banner()

    if args.ghost_on:
        enable_ghost_mode()

    elif args.ghost_off:
        disable_ghost_mode()

    elif args.status:
        show_status(live_ip=True)

    elif args.mac:
        results = mac_changer.randomize_all_interfaces()
        for iface, (ok, old, new) in results.items():
            (print_ok if ok else print_fail)(f"{iface}: {old} → {new}")

    elif args.hostname:
        ok, old, new = hostname_changer.randomize_hostname()
        (print_ok if ok else print_fail)(f"Hostname: {old} → {new}" if ok else old)

    elif args.tor_on:
        ok, msg = tor_manager.enable_routing()
        (print_ok if ok else print_fail)(msg)

    elif args.tor_off:
        ok, msg = tor_manager.disable_routing()
        (print_ok if ok else print_fail)(msg)

    elif args.new_identity:
        ok, msg = tor_manager.new_tor_identity()
        (print_ok if ok else print_fail)(msg)

    elif args.dns:
        dns_map = {"tor": "tor_local", "cloudflare": "cloudflare", "quad9": "quad9", "mullvad": "mullvad"}
        ok, msg = dns_manager.set_dns(dns_map[args.dns])
        (print_ok if ok else print_fail)(msg)

    elif args.clean:
        with spinner_task("Running full clean...") as p:
            p.add_task("")
            p.start()
            cleaner.full_clean()
            p.stop()
        print_ok("Full clean complete")


if __name__ == "__main__":
    args = parse_args()
    has_flag = any([
        args.ghost_on, args.ghost_off, args.status, args.mac,
        args.hostname, args.tor_on, args.tor_off, args.new_identity,
        args.dns, args.clean
    ])

    if has_flag:
        run_cli(args)
    else:
        main_menu()
