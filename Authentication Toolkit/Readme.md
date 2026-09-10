
# Cybersecurity Authentication Toolkit

## Problem Statement
Weak authentication is one of the most common causes of data breaches. Applications that
store passwords in plaintext, skip validation, or lack session controls are easy targets.

## Objective
Build a working prototype that demonstrates **secure authentication** end-to-end:
registration, login, password validation, strength checking, secure hashing, and
session management.

## Features
- User registration & login
- Strict password validation (length, upper/lower/digit/special)
- Password strength meter with improvement feedback
- Secure password storage using salted hashing (Werkzeug `generate_password_hash` / PBKDF2)
- Session management (secure login state, session clearing on logout)
- Login rate limiting (5 attempts / 60 seconds per IP)
- Security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Cache-Control: no-store`)

## Technologies Used
- Python 3, Flask, Werkzeug Security

## Installation / Setup
```bash
pip install flask
python app.py
```
Open http://localhost:5001

## How the Project Works
1. **Register** — username is validated against an allow-list pattern; the password must
   pass the validation rules; only the **salted hash** of the password is stored.
2. **Strength checker** — scores the password 0–5 on length, character variety, and
   repeated-character penalties.
3. **Login** — credentials are checked against the stored hash using constant-time
   comparison. Failed logins are rate-limited per IP.
4. **Session** — Flask's signed session cookie maintains login state; `session.clear()`
   on logout terminates it securely.

## Demo / Live Link
*Demo link : http://localhost:5001*

## Security Considerations
- Passwords are never stored or logged in plaintext (the `strength_sample` field is for
  demo only — remove it in production).
- Use environment variables for `SECRET_KEY` in production.
- Replace the in-memory user store with a real database (parameterized queries only).
- Enforce HTTPS so session cookies travel encrypted.

## Future Improvements
- MFA (TOTP), email verification, password breach-list checking (k-anonymity API),
  account lockout with email recovery, CSRF tokens.
