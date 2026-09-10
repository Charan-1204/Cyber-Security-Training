
"""
Network Security IP Range Scanner
--------------------------------
Discovers active hosts within an IP range (CIDR or start-end).
USE ONLY in your own lab or an authorized environment.
"""
import socket
import struct
import argparse
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(n):
    return socket.inet_ntoa(struct.pack("!I", n))

def parse_targets(rng):
    """Accept CIDR (192.168.1.0/24) or range (192.168.1.1-192.168.1.50)."""
    if "/" in rng:
        base, bits = rng.split("/")
        bits = int(bits)
        if not (0 <= bits <= 32):
            raise ValueError("Invalid CIDR prefix length.")
        start = ip_to_int(base) & (0xFFFFFFFF << (32 - bits))
        end = start + (1 << (32 - bits)) - 1
    elif "-" in rng:
        a, b = rng.split("-")
        start, end = ip_to_int(a.strip()), ip_to_int(b.strip())
    else:
        raise ValueError("Provide CIDR (x.x.x.x/24) or range (x.x.x.x-x.x.x.x).")
    if end - start > 4094:
        raise ValueError("Range too large (max 4095 hosts). Use a smaller range.")
    return [int_to_ip(i) for i in range(start, end + 1)]

def ping_host(ip, timeout=1):
    """Ping a host; return True if reachable. Falls back to TCP-443 probe."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(["ping", param, "1", "-W", str(timeout), ip],
                           capture_output=True, timeout=timeout + 2)
        if r.returncode == 0:
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    # Fallback: try connecting to common ports (works where ICMP is blocked)
    for port in (80, 443, 22):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except OSError:
            continue
    return False

def main():
    parser = argparse.ArgumentParser(description="IP range host discovery (authorized use only)")
    parser.add_argument("range", help="CIDR e.g. 192.168.1.0/24 or range 192.168.1.1-192.168.1.50")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("-o", "--timeout", type=float, default=1.0)
    args = parser.parse_args()

    try:
        targets = parse_targets(args.range)
    except ValueError as ve:
        print(f"[!] {ve}")
        return

    print(f"[*] Discovering hosts in {args.range} ({len(targets)} addresses) | {datetime.now()}")
    print("-" * 50)

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        results = list(ex.map(lambda ip: (ip, ping_host(ip, args.timeout)), targets))

    active = [ip for ip, up in results if up]
    for ip in active:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, OSError):
            hostname = "?"
        print(f"[ACTIVE]   {ip:<16} {hostname}")

    print("-" * 50)
    print(f"[*] Done. {len(active)}/{len(targets)} hosts active.")

if __name__ == "__main__":
    main()
