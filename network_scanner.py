import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from tqdm import tqdm
import datetime
import subprocess
import ipaddress
 
init()
 
# ──────────────────────────────────────────
#  Config
# ──────────────────────────────────────────
services = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy",
}
 
windows_ports = {3389: 3, 445: 2, 139: 1}
linux_ports   = {22: 3, 3306: 2, 80: 1, 443: 1}
 
# ──────────────────────────────────────────
#  Globals
# ──────────────────────────────────────────
open_ports  = []
alive_hosts = []
all_results = {}   # { ip: [result lines] }
n           = 3.0  # timeout — set after input
 
# ──────────────────────────────────────────
#  Functions
# ──────────────────────────────────────────
def ping(ip):
    result = subprocess.run(
        ['ping', '-n', '1', '-w', '500', ip],
        capture_output=True, text=True
    )
    if "TTL" in result.stdout:
        alive_hosts.append(ip)
    return "TTL" in result.stdout
 
 
def scan(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(n)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode().strip()
        except:
            banner = "No banner"
        s.close()
        open_ports.append(port)
        line = (Fore.GREEN +
                f"  [OPEN]   {services[port]:<12} Port {port:<5} | {banner}"
                + Style.RESET_ALL)
    except:
        line = (Fore.RED +
                f"  [CLOSED] {services[port]:<12} Port {port}"
                + Style.RESET_ALL)
 
    if ip not in all_results:
        all_results[ip] = []
    all_results[ip].append(line)
 
 
def run_scan(ip):
    with ThreadPoolExecutor(max_workers=100) as executor:
        list(tqdm(
            executor.map(lambda port: scan(ip, port), services),
            total=len(services),
            desc=Fore.CYAN + f"  Scanning {ip}" + Style.RESET_ALL,
            ncols=65,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
        ))
 
 
def print_results(ip):
    windows_score = 0
    linux_score   = 0
 
    for port, score in windows_ports.items():
        if port in open_ports:
            windows_score += score
    for port, score in linux_ports.items():
        if port in open_ports:
            linux_score += score
 
    if windows_score > linux_score:
        os_guess = "Probably Windows"
        os_color = Fore.BLUE
    elif linux_score > windows_score:
        os_guess = "Probably Linux"
        os_color = Fore.YELLOW
    else:
        os_guess = "Unknown"
        os_color = Fore.WHITE
 
    print(Fore.CYAN + "\n╔══════════════════════════════════════════╗")
    print(f"║  🖥  Target : {ip:<28}║")
    print(f"║  🕐  Time   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<28}║")
    print(f"║  💻  OS     : " + os_color + f"{os_guess:<28}" + Fore.CYAN + "║")
    print(f"║  📊  Open   : {str(len(open_ports)) + '/' + str(len(services)):<28}║")
    print("╚══════════════════════════════════════════╝" + Style.RESET_ALL)
 
    for line in all_results.get(ip, []):
        print(line)
 
    open_ports.clear()
 
 
# ──────────────────────────────────────────
#  Banner
# ──────────────────────────────────────────
print(Fore.CYAN + """
╔══════════════════════════════════════════╗
║         🔍  Python Port Scanner          ║
║              github.com/you              ║
╚══════════════════════════════════════════╝
""" + Style.RESET_ALL)
 
# ──────────────────────────────────────────
#  Input
# ──────────────────────────────────────────
IIP    = input(Fore.WHITE + "  Enter IP or Subnet (e.g. 192.168.1.0/24): " + Style.RESET_ALL)
n      = float(input("  Timeout in seconds (e.g. 3): "))
custom = input("  Use default ports? (y/n): ").strip().lower()
 
if custom == "n":
    user_ports = input("  Enter ports (e.g. 80,443,22): ")
    port_list  = [int(p.strip()) for p in user_ports.split(",")]
    services   = {p: services.get(p, "Unknown") for p in port_list}
 
# ──────────────────────────────────────────
#  Run
# ──────────────────────────────────────────
if "/" in IIP:
    network = ipaddress.ip_network(IIP, strict=False)
    print(Fore.CYAN + f"\n  Sweeping {network} for alive hosts...\n" + Style.RESET_ALL)
 
    with ThreadPoolExecutor(max_workers=100) as exc:
        list(tqdm(
            exc.map(lambda host: ping(str(host)), network.hosts()),
            total=network.num_addresses - 2,
            desc="  Ping Sweep",
            ncols=65,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
        ))
 
    print(Fore.GREEN + f"\n  Found {len(alive_hosts)} alive host(s):\n" + Style.RESET_ALL)
    for h in alive_hosts:
        print(Fore.GREEN + f"  ✔ {h}" + Style.RESET_ALL)
 
    for host in alive_hosts:
        run_scan(host)
        print_results(host)
else:
    run_scan(IIP)
    print_results(IIP)
 
