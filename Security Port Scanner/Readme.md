
# Network Security Port Scanner

## Problem Statement
Attackers use port scanning as the first step to find exposed services on a network.
Defenders must understand how port scanning works to detect it and close unnecessary
services.

## Objective
Build a TCP port scanner that identifies open/closed ports on a target and maps common
ports to their services — for **authorized security testing only**.

## Features
- Target input (IP or hostname)
- Configurable port range (`-s` / `-e`)
- Multi-threaded scanning for speed
- Open/closed port identification
- Common service name mapping + basic banner grabbing
- Input validation and clear error handling
- Clean, readable results table

## Technologies Used
- Python 3 (socket, concurrent.futures, argparse)

## Installation / Setup
```bash
python port_scanner.py <target> -s 1 -e 1024
```

## How the Project Works
1. Resolves the target host and validates the port range (1–65535).
2. Opens a TCP connection (`connect_ex`) to each port using a thread pool.
3. A successful connection marks the port **OPEN**; the tool attempts a light banner grab.
4. Results are printed with the well-known service for each open port.

## Screenshots / Demo
```text
[*] Scanning scanme.nmap.org ports 1-1024
[OPEN]     22/tcp  SSH
[OPEN]     80/tcp  HTTP
[*] Scan complete. 2 open port(s): [22, 80]
```

## Security Considerations
- **Only scan systems you own or have explicit written permission to test.**
- Unauthorized scanning may be illegal (Computer Misuse Act, IT Act 2000, etc.).
- Scanning generates logs/IDS alerts on the target network.

## Future Improvements
- UDP scanning, SYN (stealth) scanning via raw sockets, service version detection,
  export to CSV/JSON, Nmap XML integration.
