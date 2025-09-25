import os
import platform
import socket
import subprocess
import time
from threading import Thread
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from pyfiglet import Figlet
import argparse
import sys

console = Console()
fig = Figlet(font='slant')
results = []

# === Show Banner ===
def show_banner():
    os.system("cls" if platform.system() == "Windows" else "clear")
    console.print(fig.renderText("Wolf Scanner"), style="bold cyan")
    console.print("[bold green]Created by Wolf Man[/bold green]\n")

# === Ping an IP ===
def is_online(ip):
    param = "-n" if platform.system() == "Windows" else "-c"
    timeout = "-w 1000" if platform.system() == "Windows" else "-W 1"
    return os.system(f"ping {param} 1 {timeout} {ip} > /dev/null 2>&1") == 0

# === Get MAC Address ===
def get_mac(ip):
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["arp", "-a", ip], encoding='utf-8')
        else:
            output = subprocess.check_output(f"arp {ip}", shell=True, encoding='utf-8')
        lines = output.splitlines()
        for line in lines:
            if ip in line:
                return line.split()[3] if platform.system() != "Windows" else line.split()[1]
    except:
        pass
    return "MAC not found"

# === Scan One IP ===
def scan_ip(ip):
    if is_online(ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Hostname not found"
        mac = get_mac(ip)
        results.append({"ip": ip, "hostname": hostname, "mac": mac})
        console.print(f"[green][+][/green] {ip} | {hostname} | {mac}")
    else:
        console.print(f"[dim]- {ip} is offline[/dim]")

# === Nmap Enhanced Scan ===
def run_nmap(ip):
    try:
        output = subprocess.check_output(f"nmap -sS -O {ip}", shell=True, encoding='utf-8')
        return output
    except Exception as e:
        return f"Error running Nmap on {ip}: {e}"

# === Manual Port Scanner ===
def scan_ports(ip, port_range='default'):
    if port_range == 'default':
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    else:
        try:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        except:
            console.print("[red]Invalid port range. Use format like 20-100[/red]")
            return

    console.print(f"\n[bold yellow]Scanning ports on {ip} ({len(ports)} ports)...[/bold yellow]")
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    console.print(f"[green]  [+] Port {port} is open[/green]")
                    open_ports.append(port)
                else:
                    console.print(f"[red]  [-] Port {port} is closed[/red]")
        except Exception as e:
            console.print(f"[red]  [!] Error on port {port}: {e}[/red]")
    return open_ports

# === Scan Subnet ===
def network_scan(subnet_prefix):
    console.print(f"[yellow]Scanning {subnet_prefix}.0/24...[/yellow]")
    threads = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("Pinging devices...", total=None)
        for i in range(1, 255):
            ip = f"{subnet_prefix}.{i}"
            t = Thread(target=scan_ip, args=(ip,))
            t.start()
            threads.append(t)
            time.sleep(0.01)
        for t in threads:
            t.join()
        progress.update(task, description="Scan complete.")

# === Export Results ===
def export_results():
    filename = input("Enter filename to save results (e.g. results.txt): ").strip()
    if not filename:
        filename = "scan_results.txt"
    with open(filename, "w") as f:
        for res in results:
            f.write(f"{res['ip']} | {res['hostname']} | {res['mac']}\n")
    console.print(f"[bold blue]Results saved to [white]{filename}[/white][/bold blue]")

# === Display Results Table ===
def display_results():
    if not results:
        console.print("[red]No online hosts found.[/red]")
        return
    table = Table(title="Scan Results")
    table.add_column("IP Address", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("MAC Address", style="magenta")
    for res in results:
        table.add_row(res['ip'], res['hostname'], res['mac'])
    console.print(table)

# === Argument Parsing ===
def parse_args():
    parser = argparse.ArgumentParser(
        description="Wolf Scanner - Scan local networks or public IPs/domains",
        epilog="Examples:\n"
               "  python wolf_scanner.py --range 192.168.1 --ports 20-100 --export\n"
               "  python wolf_scanner.py --target 8.8.8.8 --nmap",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--range', help='Scan a local /24 subnet (e.g. 192.168.1)', type=str)
    parser.add_argument('--target', help='Scan a single IP or domain (e.g. 8.8.8.8 or google.com)', type=str)
    parser.add_argument('--nmap', help='Run nmap scan on each IP after scan', action='store_true')
    parser.add_argument('--ports', nargs='?', const='default', help='Scan ports (default or custom range like 20-100)')
    parser.add_argument('--export', help='Export results to custom filename', action='store_true')
    return parser.parse_args()

# === Main ===
def main():
    show_banner()
    args = parse_args()

    if not args.range and not args.target:
        console.print("[red]Error: You must specify --range or --target[/red]")
        console.print("Use [bold cyan]--help[/bold cyan] to see usage examples.")
        sys.exit(1)

    if args.range:
        if not args.range.count('.') == 2:
            console.print("[red]Invalid subnet format. Example: 192.168.1[/red]")
            sys.exit(1)
        network_scan(args.range)

    if args.target:
        try:
            ip = socket.gethostbyname(args.target)
            console.print(f"[bold cyan]Scanning target:[/bold cyan] {args.target} -> {ip}")
            scan_ip(ip)
        except Exception as e:
            console.print(f"[red]Invalid target: {e}[/red]")
            sys.exit(1)

    display_results()

    if results and args.export:
        export_results()

    if results and args.ports is not None:
        for res in results:
            scan_ports(res['ip'], args.ports)

    if results and args.nmap:
        for res in results:
            console.print(f"\n[bold green]Nmap scan for {res['ip']}[/bold green]")
            output = run_nmap(res['ip'])
            console.print(output)

# === Run ===
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Scan cancelled by user.[/red]")
