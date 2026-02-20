# Coffee-in — Brute Force Attack Simulator

**Cryptography and Data Security 

> A practical, educational demonstration of brute-force attack vulnerabilities and real-world security countermeasures, built on a functional coffee shop e-commerce web application.

---
## Project Overview

This project simulates a real-world brute-force attack scenario against a web application login system, then demonstrates how proper security controls render such attacks ineffective. The application — a fictional coffee shop called **Coffee-in** — was built twice: once intentionally vulnerable, and once hardened with industry-standard defenses.

The goal is to show, side by side, how quickly an unsecured login system can be compromised and how layered security controls stop the same attack completely.

---

## Repository Structure

This repository uses **two branches** for direct comparison:

| Branch | Description |
|--------|-------------|
| `main` | **Vulnerable version** — no rate limiting, plaintext passwords, verbose errors |
| `secure` | **Secure version** — BCrypt hashing, rate limiting, JWT, CSRF protection, account lockout |

```bash
git checkout main      # vulnerable version
git checkout secure    # secure version
```

**Files included in both branches:**

```
Coffee-Demo-shop/
├── app.py                  # Flask backend (vulnerable or secure depending on branch)
├── Brute_Force.py          # CLI brute-force attack tool (multi-threaded)
├── brute_force_gui.py      # GUI brute-force attack tool (Tkinter)
├── requirements.txt        # Python dependencies
├── static/                 # CSS, JS, images
├── templates/              # HTML pages (login, signup, dashboard, index)
└── seed_user.py            # (secure branch only) Seeds test accounts into the database
```

---

## Attack Results Summary

| Version | Result |
|---------|--------|
| Vulnerable | All 6 demo accounts compromised in **74.33 seconds** (~4.57 attempts/second) |
| Secure | Attack blocked after 10 attempts — **HTTP 429 Too Many Requests** |

---

## Setup Instructions

### Prerequisites

- Python 3.11 or higher — https://www.python.org/downloads/
- Git — https://git-scm.com/downloads

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/hal-imaxabdi/Coffee-Demo-shop.git
cd Coffee-Demo-shop
```

---

### Step 2 — Choose Which Version to Run

**Vulnerable version:**
```bash
git checkout main
```

**Secure version:**
```bash
git checkout secure
```

---

### Step 3 — Create a Virtual Environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Mac/Linux
python3 -m venv .venv
source .venv/bin/activate
```

---

### Step 4 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

### Step 5 — Seed the Database

**Secure branch only** — run this once before starting the server:

```bash
python seed_user.py
```

> The vulnerable (`main`) version seeds test accounts automatically on startup. You can skip this step there.

---

### Step 6 — Start the Flask Server

```bash
python app.py
```

Open your browser and go to: **http://127.0.0.1:5000**

---

## Running the Brute Force Attack

Open a **second terminal**, activate your virtual environment, then pick a tool.

### Option A — Python CLI Tool

First, create your wordlists:

```bash
# Email wordlist
echo alice@test.com > emails.txt
echo bob@test.com >> emails.txt
echo charlie@test.com >> emails.txt
echo diana@test.com >> emails.txt
echo eve@test.com >> emails.txt
echo frank@test.com >> emails.txt

# Password wordlist
echo wrongpass1 > passwords.txt
echo wrongpass2 >> passwords.txt
echo AlicePassword123! >> passwords.txt
echo BobPassword123!! >> passwords.txt
echo CharliePass456@ >> passwords.txt
echo DianaSecure789# >> passwords.txt
echo EvePassword321$ >> passwords.txt
echo FrankLogin654% >> passwords.txt
```

Then run the attack:

```bash
python Brute_Force.py \
  -u http://127.0.0.1:5000/login \
  --attack-type email \
  --email-list emails.txt \
  --password-list passwords.txt \
  --threads 1 \
  --delay 0.1 \
  --debug
```

### Option B — GUI Tool

```bash
python brute_force_gui.py
```

Fill in the target URL, email list, and password list using the file browser, then click **Start Attack**.

---

## What to Observe

### On the Vulnerable Version (`main`)
- Every login attempt goes through with no blocking or delay
- Correct credentials are found and reported in the terminal
- All 6 accounts are cracked in approximately 74 seconds

### On the Secure Version (`secure`)
- The first 10 requests per minute are processed normally
- After 10 attempts: **HTTP 429 Too Many Requests** — rate limiter activates
- After 5 failed attempts on one account: **account locked for 15 minutes**
- After 5 failed attempts from one IP: **IP blocked for 30 minutes**
- Any request missing a valid CSRF token: **HTTP 403 Forbidden**
- All failure responses are identical — no user enumeration possible

---

## Vulnerabilities in the `main` Branch

| Vulnerability | Detail |
|---------------|--------|
| Plaintext password storage | Passwords stored directly in the database with no hashing |
| No rate limiting | Login endpoint accepts unlimited requests per second |
| No account lockout | Unlimited failed attempts allowed per account |
| Verbose error messages | Different responses for wrong username vs wrong password, enabling user enumeration |
| No CSRF protection | Forms accept requests from any origin |

---

## Security Controls in the `secure` Branch

| Control | Implementation |
|---------|---------------|
| Password hashing | BCrypt with SHA-256 pre-hashing + per-user 32-byte salt (work factor 12) |
| Rate limiting | Flask-Limiter — 10 requests/minute per IP on `/api/login` |
| Account lockout | 5 failed attempts → account locked for 15 minutes |
| IP blocking | 5 failed attempts from one IP → blocked for 30 minutes |
| JWT authentication | RSA-256 signed tokens, 1-hour expiry, server-side revocation |
| CSRF protection | Single-use 64-character hex tokens, 1-hour expiry |
| Generic error messages | All failures return identical `"Invalid credentials"` — prevents enumeration |
| Security headers | X-Frame-Options, CSP, X-Content-Type-Options, HttpOnly + SameSite cookies |
| Client-side password strength | Enforces 12+ characters, uppercase, lowercase, number, and special character |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, Flask 3.0.0 |
| Database | SQLite 3 |
| Frontend | HTML5, CSS3, JavaScript (ES6) |
| Security libraries | BCrypt, PyJWT, Flask-Limiter, Flask-Talisman |
| Attack tools | Custom Python CLI + GUI scripts, Burp Suite Professional |

---

## Disclaimer

This project was developed **strictly for educational purposes** as part of a university Cryptography and Data Security course. The brute-force tools in this repository are intended solely for testing against the local demo application included here.

**Do not use these tools against any system you do not own or have explicit written permission to test. Unauthorized use is illegal.**
