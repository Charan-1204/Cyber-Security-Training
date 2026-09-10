
# Network Security IP Range Scanner

## Problem Statement
Knowing which hosts are alive on a network is fundamental to both attack (enumeration)
and defense (asset inventory, detecting rogue devices).

## Objective
Build a scanner that discovers active/inactive hosts across an IP range, using ping
with a TCP fallback for hosts that block ICMP.

## Features
- IP range input in CIDR (`192.168.1.0/24`) or start–end format
- Host discovery via ICMP ping + TCP probe fallback (ports 80/443/22)
- Reverse-DNS hostname resolution for active hosts
- Multi-threaded scanning, input validation, clear output
- Range-size limits to prevent accidental large scans

## Technologies Used
- Python 3 (socket, struct, subprocess, concurrent.futures)

## Installation / Setup
```bash
python ip_range_scanner.py 192.168.1.0/24
python ip_range_scanner.py 192.168.1.1-192.168.1.50 -t 200
```

## How the Project Works
1. Parses CIDR or range input into a list of IP addresses (validated, max 4095 hosts).
2. Sends one ICMP ping per address; if ICMP is blocked, it tries TCP connects to
   common ports (80, 443, 22) as a fallback discovery method.
3. Performs reverse-DNS lookup on each active host and prints a summary table.

## Screenshots / Demo
```text
[*] Discovering hosts in 192.168.1.0/24 (256 addresses)
[ACTIVE]   192.168.1.1      router.local
[ACTIVE]   192.168.1.15     my-laptop.local
[*] Done. 2/256 hosts active.
```

## Security Considerations
- **Use only in your own lab or an explicitly authorized network.**
- Discovery traffic is visible in network logs and may trigger IDS alerts.
- On some OSes ping requires elevated privileges.

## Future Improvements
- ARP-based discovery for the local LAN (more reliable), JSON/CSV export,
  MAC vendor lookup, integration with a network inventory dashboard.
