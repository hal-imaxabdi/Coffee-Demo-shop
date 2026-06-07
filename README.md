# ☕ Coffee-in — Brute Force Attack Demo & Security Showcase

> A full-stack e-commerce web application built to demonstrate the real-world impact of brute-force attacks on authentication systems — and how to stop them.

![Flask](https://img.shields.io/badge/Backend-Flask%20%28Python%29-blue)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

---

##  Overview

**Coffee-in** is a simulated coffee shop e-commerce platform developed in two distinct versions to enable a direct, side-by-side comparison of secure vs. vulnerable authentication design:

| Version | Description |
|---|---|
| `main` branch | ❌ Vulnerable — intentionally insecure, no countermeasures |
| `secure` branch | ✅ Hardened — 7 layered security mechanisms implemented |

The project was developed as part of a Cryptography & Data Security course at **President University**, with the goal of validating how server-side and client-side controls can completely neutralize brute-force attacks.

---

##  What This Project Proves

Against the **vulnerable version**, a custom Python brute-force script cracked **9 out of 10 accounts in just 74.33 seconds** at 4.57 attempts/second.

Against the **secure version**, the same tool ran for 123 seconds across 570 attempts and found **0 valid credentials** — stopped entirely by rate limiting, CSRF protection, and account lockout.

---

## 🛠️ Tech Stack

- **Backend:** Python 3.11, Flask 3.0.0
- **Database:** SQLite 3.x
- **Frontend:** HTML5, CSS3, JavaScript (ES6)
- **Attack Tools:** Custom Python CLI (`Brute_Force.py`), Python GUI (`brute_force_gui.py`), Burp Suite

---

##  Vulnerable Version (main branch)

The vulnerable version replicates common real-world misconfigurations:

- **Plaintext password storage** — passwords stored directly in the database with no hashing
- **No rate limiting** — the login endpoint accepts unlimited requests per second
- **No account lockout** — failed attempts are never tracked or blocked
- **Verbose error messages** — distinct HTTP 401 vs 200 responses allow username enumeration
- **No request throttling** — enables high-speed automated attacks via tools like Hydra or Burp Suite

### Attack Results (Vulnerable)
```
Total attempts:  340
Duration:        74.33 seconds
Speed:           4.57 attempts/second
Credentials found: 9/10 accounts compromised
```

---

## Secure Version (secure branch)

The secure version implements **7 independent defense layers**:

### 1. BCrypt Password Hashing with Per-User Salt
Passwords are never stored in plaintext. Each user gets a unique cryptographically random 32-byte salt. The password is combined with the salt, passed through SHA-256, then hashed with BCrypt at work factor 12 (~250ms per verification). Even a full database leak yields nothing crackable in reasonable time.

### 2. IP-Based Rate Limiting (Flask-Limiter)
- Login endpoint: **10 requests/minute per IP**
- Registration: **5 requests/hour**
- Global limits: **200 requests/day, 50 requests/hour**
- Exceeding limits returns HTTP 429 Too Many Requests, breaking any automated loop

### 3. Account Lockout & IP Blocking
- **Account level:** 5 consecutive failures locks the account for 15 minutes via `locked_until` field
- **Network level:** 5 failed attempts from the same IP within 30 minutes blocks that IP for 30 minutes via `ip_blocks` table
- Successful login resets the failed attempts counter

### 4. JWT Authentication with RSA-256 Digital Signatures
Session management uses JSON Web Tokens signed with a 2048-bit RSA private key (RS256). Tokens expire after 1 hour and have a unique JWT ID (jti). Every issued token's SHA-256 hash is stored in the `auth_tokens` table. Logout explicitly revokes the token.

### 5. CSRF Token Protection
Every login and registration request must include a valid 64-character hex CSRF token fetched from `GET /api/csrf-token`. Tokens are single-use and expire after 1 hour. A brute-force script that skips this step receives HTTP 403 on every attempt.

### 6. Generic Error Messages (User Enumeration Prevention)
All failure cases — wrong email, wrong password, locked account — return the identical HTTP 401 response with `{"error": "Invalid credentials"}` and the same Content-Length, preventing both message-based and timing-based user enumeration.

### 7. Security Headers & Session Hardening
Every response includes a full set of HTTP security headers via `@app.after_request`:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security`
- `Content-Security-Policy`
- Session cookies: `HttpOnly=True`, `SameSite=Strict`, 1-hour duration

### Attack Results (Secure)
```
Total attempts:  570
Duration:        123.07 seconds
Speed:           4.63 attempts/second
Credentials found: 0
```

---

##  Client-Side Security (auth-script.js)

The secure version also defends on the browser side through `auth-script.js`:

- **Real-time password strength enforcement** — blocks weak passwords before they reach the server (min 12 chars, uppercase, lowercase, number, special character, no sequential chars, not a common password)
- **Input sanitization** — all inputs are HTML-encoded via DOM `textContent` before any API call
- **Automatic CSRF token management** — fetches and attaches a token to every login/signup request automatically

---

##  Repository Structure

```
Coffee-Demo-shop/
├── main branch          # Vulnerable version
│   ├── app.py           # Flask app (no security controls)
│   ├── Brute_Force.py   # Python CLI brute-force tool
│   ├── brute_force_gui.py  # Tkinter GUI brute-force tool
│   ├── emails.txt       # Target email wordlist
│   ├── passwords.txt    # Password wordlist
│   └── templates/       # HTML pages
│
└── secure branch        # Hardened version
    ├── app.py           # Flask app (all 7 security mechanisms)
    ├── auth-script.js   # Client-side security module
    ├── seed_user.py     # Database seeding script
    └── templates/       # HTML pages
```

---

##  Setup & Running

### Vulnerable Version
```bash
git clone https://github.com/hal-imaxabdi/Coffee-Demo-shop
cd Coffee-Demo-shop
pip install flask flask-cors
python app.py
```

### Secure Version
```bash
git checkout secure
pip install flask flask-cors flask-limiter bcrypt PyJWT cryptography
python seed_user.py   # Must run before starting the server
python app.py
```

Visit `http://localhost:5000`

---

## ⚔️ Running the Brute-Force Tools

### Python CLI
```bash
python Brute_Force.py \
  --url http://localhost:5000/api/login \
  --email-list emails.txt \
  --password-list passwords.txt \
  --attack-type email \
  --threads 10 \
  --delay 0.1
```

### GUI Tool
```bash
python brute_force_gui.py
```
Configure the target URL, wordlists, thread count, and delay via the Tkinter interface.

---

##  Results Summary

| Metric | Vulnerable | Secure |
|---|---|---|
| Accounts cracked | 9 / 10 | 0 / 10 |
| Attack duration | 74.33s | 123.07s |
| Avg speed | 4.57 req/s | 4.63 req/s |
| Blocked by rate limiter | ❌ | ✅ |
| Password hashing | ❌ Plaintext | ✅ BCrypt + SHA-256 + Salt |
| CSRF protection | ❌ | ✅ |
| Account lockout | ❌ | ✅ |

---

## 🔮 Possible Improvements

- **HMAC with user-specific secret** to further harden against rainbow table attacks
- **CAPTCHA** as an additional layer alongside rate limiting for public-facing systems
- **Adaptive lockout** duration that scales with the number of failed attempts

---

## 👥 Authors

**Group Project:**
- Wilbert Leonard Harriman
- Songjie Li
- Nailha Sakhila Dewi
- Halima Abdirizak Mohamed

---

> ⚠️ **Disclaimer:** The attack tools in this repository are built strictly for educational and research purposes in a controlled local environment. Do not use them against systems you do not own or have explicit permission to test.
