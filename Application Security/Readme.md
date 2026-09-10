
# Application Security Demo

## Problem Statement
Most web breaches exploit basic application flaws: weak input validation, broken
authentication, missing authorization checks, and insecure password storage.

## Objective
Demonstrate core application-security controls in a small working web app.

## Features
- **Input validation** — strict username pattern; note content filter blocks XSS/SQLi
  patterns (`<script>`, `javascript:`, `UNION SELECT`, `'--`)
- **Authentication** — salted password hashing, generic error messages (prevents
  user enumeration)
- **Authorization** — role-based access control (RBAC); only `admin` can reach the
  admin panel/API; users only see their own notes
- **Secure password handling** — hashes via Werkzeug, never plaintext
- **Security headers** — CSP, X-Frame-Options, X-Content-Type-Options, no-store
- **Error handling** — custom 404/500 handlers; no stack traces leaked
- **Audit logging** — logins (success/fail), blocked malicious input, admin access

## Technologies Used
- Python 3, Flask, Werkzeug Security, logging

## Installation / Setup
```bash
pip install flask
python app.py
```
Open http://localhost:5002 — demo accounts: `admin / Admin#1234`, `alice / User#1234`

## How the Project Works
1. Login sets a signed session cookie; the user's role is stored server-side.
2. Every privileged route checks the role decorator (`require_role`).
3. Notes are validated against a malicious-pattern filter before storage.
4. All security-relevant events are written to `security.log`.

## Screenshots
*(Add screenshots: login page, blocked malicious input, admin panel, security.log)*

## Security Recommendations Demonstrated
- Validate all input against allow-lists, not block-lists (block-list here is for demo)
- Use parameterized queries with a real database
- Add CSRF tokens and MFA for production
- Run behind HTTPS with HSTS

## Future Improvements
- Real database with parameterized queries, CSRF protection, brute-force lockout,
  security event dashboard, unit tests for each control.
