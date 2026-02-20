#  Coffee-in — Brute Force Attack Simulator
### Cryptography and Data Security 

> A practical demonstration of brute-force attack vulnerabilities and security countermeasures in web application authentication systems, built as a coffee shop e-commerce site.


---

## Repository Structure

This repository has **two branches** for direct comparison:

| Branch | Description |
|--------|-------------|
| `main` |  **Vulnerable version** — intentionally insecure, no rate limiting, plaintext passwords |
| `secure` |  **Secure version** — bcrypt hashing, rate limiting, JWT, CSRF protection, account lockout |

```
Switch branches:
  git checkout main      # vulnerable version
  git checkout secure    # secure version
```

---

##  Setup Instructions

### Prerequisites
Make sure you have the following installed on your PC:
- Python 3.11 or higher → https://www.python.org/downloads/
- Git → https://git-scm.com/downloads

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

---

### Step 2 — Choose a Version to Run

**To run the vulnerable version:**
```bash
git checkout main
```

**To run the secure version:**
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

> If you get errors on Mac/Linux, try: `pip install -r requirements.txt --break-system-packages`

---

### Step 5 — Seed the Database (Secure Version Only)

If you are on the `secure` branch, run this once to create test user accounts:

```bash
python seed_user.py
```

> For the **vulnerable version** (`main`), test accounts are seeded automatically on startup.

---

### Step 6 — Run the Flask App

```bash
python app.py
```

You should see:
```
* Running on http://127.0.0.1:5000
```

Open your browser and go to: **http://127.0.0.1:5000**

---

##  Running the Brute Force Attack

Open a **second terminal window**, activate your virtual environment, then choose a tool:

### Option A — Python CLI Tool

```bash
# Create email wordlist
echo alice@test.com > emails.txt
echo bob@test.com >> emails.txt
echo charlie@test.com >> emails.txt
echo diana@test.com >> emails.txt
echo eve@test.com >> emails.txt
echo frank@test.com >> emails.txt

# Create password wordlist
echo wrongpass1 > passwords.txt
echo wrongpass2 >> passwords.txt
echo AlicePassword123! >> passwords.txt
echo BobPassword123!! >> passwords.txt
```

```bash
python Brute_Force.py -u http://127.0.0.1:5000/login --attack-type email --email-list emails.txt --password-list passwords.txt --threads 1 --delay 0.1 --debug
```

### Option B — GUI Tool

```bash
python brute_force_gui.py
```

Fill in the fields in the graphical interface and click Start Attack.

---

## 🔍 What to Observe

### On the Vulnerable Version (`main`)
- All login attempts go through without any blocking
- Correct passwords are found and reported
- Attack completes in ~74 seconds for all 6 accounts

### On the Secure Version (`secure`)
- First 10 requests per minute are processed
- After 10 attempts: **429 Too Many Requests** — rate limiter blocks the attack
- After 5 failed attempts on one account: **account locked for 15 minutes**
- After 5 failed attempts from one IP: **IP blocked for 30 minutes**
- Requests without a CSRF token: **403 Forbidden**
- All failure responses return identical messages — no user enumeration possible

---

##  Security Features (Secure Version)

| Feature | Implementation |
|---------|---------------|
| Password Hashing | BCrypt with SHA-256 pre-hashing + per-user salt (work factor 12) |
| Rate Limiting | Flask-Limiter — 10 requests/minute per IP on login endpoint |
| Account Lockout | 5 failed attempts → locked for 15 minutes |
| IP Blocking | 5 failed attempts from same IP → blocked for 30 minutes |
| JWT Authentication | RSA-256 signed tokens, 1 hour expiry, revocation support |
| CSRF Protection | Single-use 64-character hex tokens, 1 hour expiry |
| Generic Errors | All failures return identical "Invalid credentials" — prevents user enumeration |
| Security Headers | X-Frame-Options, CSP, X-Content-Type-Options, HttpOnly cookies |
| Password Strength | Client-side enforcement: 12+ chars, uppercase, lowercase, number, special character |

---

##  Tech Stack

- **Backend:** Python 3.11, Flask 3.0.0
- **Database:** SQLite 3
- **Frontend:** HTML5, CSS3, JavaScript (ES6)
- **Security:** BCrypt, PyJWT, Flask-Limiter, Flask-Talisman
- **Attack Tools:** Custom Python scripts (CLI + GUI), Burp Suite

---

## Disclaimer

This project is developed **strictly for educational purposes** as part of a Cryptography and Data Security course. The brute force tools included are intended only for testing against the local demo application provided in this repository. Do not use these tools against any system you do not own or have explicit permission to test.
