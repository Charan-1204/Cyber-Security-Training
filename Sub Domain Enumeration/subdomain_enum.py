import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "api", "app", "dev", "test", "staging", "beta",
    "admin", "portal", "dashboard", "blog", "shop", "store", "cdn",
    "static", "media", "docs", "help", "support", "vpn", "remote",
    "git", "gitlab", "jenkins", "ci", "db", "database", "backup",
    "status", "monitor", "grafana", "kibana", "webmail", "smtp", "imap",
]

def check_subdomain(domain, sub, timeout=2.0):
    host = f"{sub}.{domain}"
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return host, ips
    except (socket.gaierror, OSError):
        return host, None

def enumerate_subdomains(domain, wordlist, threads, timeout):
    found = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        results = ex.map(lambda w: check_subdomain(domain, w, timeout), wordlist)
        for host, ips in results:
            if ips:
                found.append((host, ips))
                print(f"[FOUND] {host:<40} -> {', '.join(ips)}")
    return found

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain enumeration via DNS (authorized targets only)")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file (one subdomain per line)")
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("-o", "--timeout", type=float, default=2.0)
    parser.add_argument("--out", help="Save results to a file (CSV-ish)")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if not domain or "." not in domain or any(c.isspace() for c in domain):
        print("[!] Invalid domain format.")
        return

    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [w.strip() for w in f if w.strip() and not w.startswith("#")]
        except OSError as e:
            print(f"[!] Cannot read wordlist: {e}")
            return
    else:
        wordlist = DEFAULT_WORDLIST

    print(f"[*] Enumerating subdomains of {domain} using {len(wordlist)} candidates | {datetime.now()}")
    print("-" * 60)
    found = enumerate_subdomains(domain, wordlist, args.threads, args.timeout)
    print("-" * 60)
    print(f"[*] Done. {len(found)} subdomain(s) discovered.")

    if args.out and found:
        with open(args.out, "w") as f:
            f.write("subdomain,ips\n")
            for host, ips in found:
                f.write(f"{host},{';'.join(ips)}\n")
        print(f"[*] Results saved to {args.out}")

if __name__ == "__main__":
    main()
