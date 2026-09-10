
# Subdomain Enumeration Tool

## Problem Statement
Forgotten subdomains (dev, staging, old APIs) are a classic source of vulnerabilities —
they often run outdated software, lack authentication, or expose internal tools.

## Objective
Build a tool that identifies valid subdomains of a target domain during an **authorized**
security assessment, helping map the attack surface.

## Features
- Domain input with validation
- DNS-based enumeration using a built-in or custom wordlist
- Multi-threaded resolution
- Results with resolved IP addresses
- Optional file export, error handling, clear documentation

## Technologies Used
- Python 3 (socket, concurrent.futures, argparse)

## Installation / Setup
```bash
python subdomain_enum.py example.com
python subdomain_enum.py example.com -w wordlist.txt --out results.csv
```

## How the Project Works
1. The target domain is validated and combined with each wordlist candidate
   (`www.example.com`, `api.example.com`, ...).
2. Each candidate is resolved via DNS (`getaddrinfo`) in parallel threads.
3. Candidates that resolve successfully are reported with their IP addresses.
4. Results can be saved to a CSV file for reporting.

## Example Output
```text
[*] Enumerating subdomains of example.com using 36 candidates
[FOUND] www.example.com      -> 93.184.216.34
[FOUND] api.example.com      -> 93.184.216.35
[*] Done. 2 subdomain(s) discovered.
```

## Security Considerations
- **Only enumerate domains you own or have written permission to test.**
- Passive methods (certificate transparency logs, search engines) can be added to
  avoid touching the target's DNS at all.

## Future Improvements
- Certificate Transparency log querying (crt.sh), DNS zone-transfer attempt,
  wildcard-detection filtering, JSON output, integration with port scanner.
