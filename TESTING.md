# 🧪 Security Testing Guide

This guide provides comprehensive security testing procedures for the Coffee Shop application.

## Table of Contents
1. [Manual Testing](#manual-testing)
2. [Automated Testing](#automated-testing)
3. [Penetration Testing](#penetration-testing)
4. [Security Checklist](#security-checklist)

---

## Manual Testing

### 1. Password Strength Testing

#### Test Weak Passwords (Should be REJECTED)

```
Password: "password" 
❌ Too common

Password: "Pass123"
❌ Too short (< 12 characters)

Password: "Password123"
❌ No special character

Password: "Pass@123"
❌ Too short

Password: "abc123def456!"
❌ Sequential characters

Password: "Password@123"
❌ Sequential (123)
```

#### Test Strong Passwords (Should be ACCEPTED)

```
✅ MySecure#Pass2024!
✅ Coffee$Shop@2024
✅ Ultra!Secure#Pass
✅ C0ff33Sh0p!2024
```

**Test Steps**:
1. Navigate to `/signup`
2. Enter each password in the password field
3. Observe the real-time strength indicator
4. Attempt to submit the form
5. Verify appropriate error messages

---

### 2. Brute Force Protection Testing

#### Account Lockout Test

```bash
# Test 1: Multiple Failed Logins
1. Go to /login
2. Enter valid email: admin@coffee.com
3. Enter wrong password 5 times
4. Expected: Account locked for 30 minutes
5. Try again immediately
6. Expected: "Account temporarily locked" message

# Test 2: Progressive Delays
1. Note time before each attempt
2. Attempt 1: Immediate response
3. Attempt 2: ~3 second delay
4. Attempt 3: ~9 second delay
5. Attempt 4: ~27 second delay
6. Attempt 5: Account locked
```

#### IP Blocking Test

```bash
# Create 10+ failed login attempts from same IP
for i in {1..12}; do
    curl -X POST http://localhost:5000/api/login \
        -H "Content-Type: application/json" \
        -d '{"login":"test@test.com","password":"wrong"}' \
        -v
    echo "Attempt $i"
    sleep 2
done

# Expected: IP blocked after 10 attempts
# Verify in database:
sqlite3 secure_coffee_shop.db "SELECT * FROM ip_blocks;"
```

---

### 3. SQL Injection Testing

#### Test Payloads

```sql
# Login field SQL injection attempts
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
admin'--
admin' #
' UNION SELECT NULL--
' AND 1=1--
'; DROP TABLE users; --
```

**Test Steps**:
1. Navigate to `/login`
2. Enter each payload in the login field
3. Enter any password
4. Submit form
5. **Expected**: All should be safely handled, no SQL injection

**Verify in logs**:
```bash
# Check security logs for sanitization
grep "LOGIN_FAILED" security.log
```

---

### 4. Cross-Site Scripting (XSS) Testing

#### Test Payloads

```html
# Name field XSS attempts
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
<iframe src="javascript:alert('XSS')">
"><script>alert('XSS')</script>
<body onload=alert('XSS')>
```

**Test Steps**:
1. Navigate to `/signup`
2. Enter XSS payload in name field
3. Submit form
4. **Expected**: HTML tags stripped, script not executed
5. Check in database:
```sql
SELECT name FROM users WHERE email = 'test@test.com';
```
6. Name should not contain HTML tags

---

### 5. CSRF Protection Testing

#### Test Without CSRF Token

```bash
# Attempt to submit form without CSRF token
curl -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d '{"login":"admin@coffee.com","password":"SecureAdmin@2024"}' \
    -c cookies.txt \
    -v

# Expected: Success with CSRF token in session

# Now try to use session without CSRF token
curl -X POST http://localhost:5000/api/orders \
    -H "Content-Type: application/json" \
    -d '{"item":"Cappuccino","price":"$8.50"}' \
    -b cookies.txt \
    -v

# Expected: CSRF validation may reject (depending on implementation)
```

---

### 6. Session Security Testing

#### Session Hijacking Test

```bash
# Terminal 1: Login and get session
curl -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d '{"login":"admin@coffee.com","password":"SecureAdmin@2024"}' \
    -c session.txt \
    -v

# Extract session cookie from session.txt

# Terminal 2: Try to use session from different IP
# (Use VPN or proxy to simulate different IP)
curl -X GET http://localhost:5000/api/current-user \
    -b session.txt \
    -H "X-Forwarded-For: 203.0.113.1" \
    -v

# Expected: Session invalid due to IP mismatch
```

#### Session Timeout Test

```bash
# 1. Login
# 2. Wait 2+ hours (or adjust SESSION_TIMEOUT in config)
# 3. Try to access protected endpoint
# Expected: Session expired, must re-login
```

---

### 7. Rate Limiting Testing

#### Login Rate Limit (5 per minute)

```bash
# Send 10 requests in quick succession
for i in {1..10}; do
    curl -X POST http://localhost:5000/api/login \
        -H "Content-Type: application/json" \
        -d '{"login":"test@test.com","password":"test"}' \
        -w "\n%{http_code}\n" \
        -o /dev/null
done

# Expected: First 5 succeed (or fail normally), next 5 get 429 error
```

#### Signup Rate Limit (3 per hour)

```bash
# Send 5 signup requests
for i in {1..5}; do
    curl -X POST http://localhost:5000/api/signup \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"Test$i\",\"email\":\"test$i@test.com\",\"phone\":\"+123456789$i\",\"password\":\"SecurePass@123\"}" \
        -w "\n%{http_code}\n"
    sleep 1
done

# Expected: First 3 may process, others get 429 error
```

---

### 8. Input Validation Testing

#### Email Validation

```bash
# Invalid emails (should be rejected)
test@             # No domain
@example.com      # No local part
test..test@ex.com # Double dots
test@example      # No TLD
test space@ex.com # Spaces
test@example.com. # Trailing dot

# Disposable emails (should be rejected)
test@tempmail.com
test@10minutemail.com
test@guerrillamail.com
```

#### Phone Validation

```bash
# Invalid phones (should be rejected)
123              # Too short
+1234567890123456 # Too long
+0123456789      # Starts with 0
abc123456        # Contains letters
+1 (234) 567-890 # Formatting not normalized
```

---

## Automated Testing

### 1. OWASP ZAP Scanner

```bash
# Install ZAP
# Download from: https://www.zaproxy.org/download/

# Start application
python app.py &

# Quick scan
zap-cli quick-scan --self-contained \
    --start-options '-config api.disablekey=true' \
    http://localhost:5000

# Full scan
zap-cli active-scan --recursive \
    http://localhost:5000

# Generate report
zap-cli report -o zap-report.html -f html
```

### 2. Burp Suite

**Setup**:
1. Download Burp Suite Community Edition
2. Configure browser proxy to 127.0.0.1:8080
3. Import Burp's CA certificate
4. Navigate through application

**Tests**:
1. **Spider/Crawl**: Map all endpoints
2. **Active Scan**: Automated vulnerability detection
3. **Intruder**: Brute force and fuzzing
4. **Repeater**: Manual request modification

### 3. SQLMap

```bash
# Install
pip install sqlmap

# Test login endpoint
sqlmap -u "http://localhost:5000/api/login" \
    --data "login=test&password=test" \
    --batch \
    --risk 3 \
    --level 5

# Expected: No SQL injection vulnerabilities found
```

### 4. Nikto Web Scanner

```bash
# Install
apt-get install nikto

# Scan
nikto -h http://localhost:5000 -output nikto-report.html

# Review findings
```

### 5. nmap Port Scan

```bash
# Scan for open ports
nmap -sV -p 1-65535 localhost

# Expected: Only port 5000 (or production ports) open
# No unnecessary services exposed
```

---

## Penetration Testing

### Reconnaissance Phase

```bash
# 1. Enumerate technologies
whatweb http://localhost:5000

# 2. Check robots.txt
curl http://localhost:5000/robots.txt

# 3. Check security headers
curl -I http://localhost:5000

# 4. Directory enumeration
dirb http://localhost:5000 /usr/share/dirb/wordlists/common.txt
```

### Vulnerability Assessment

#### 1. Authentication Bypass

```
Try:
- Default credentials
- Weak passwords
- Password reset flaws
- OAuth misconfigurations
```

#### 2. Authorization Issues

```
Test:
- Horizontal privilege escalation (access other users' data)
- Vertical privilege escalation (access admin functions)
- IDOR (Insecure Direct Object References)
```

#### 3. Business Logic Flaws

```
Test:
- Price manipulation in orders
- Negative quantities
- Race conditions
- Workflow bypasses
```

---

## Security Checklist

### Authentication & Session Management
- [ ] Passwords hashed with strong algorithm
- [ ] Password strength enforced (12+ chars, complexity)
- [ ] Account lockout after failed attempts
- [ ] Progressive delays on failed logins
- [ ] IP-based blocking implemented
- [ ] Session timeout configured (2 hours)
- [ ] Session IDs regenerated after login
- [ ] Sessions tied to IP address
- [ ] Secure cookie flags set (HttpOnly, Secure, SameSite)
- [ ] CSRF protection implemented
- [ ] No session fixation vulnerabilities

### Input Validation
- [ ] All inputs validated server-side
- [ ] Email format validated
- [ ] Phone format validated
- [ ] Name contains only allowed characters
- [ ] Input length limits enforced
- [ ] XSS protection implemented
- [ ] SQL injection prevented (parameterized queries)
- [ ] HTML sanitization in place
- [ ] File upload restrictions (if applicable)

### Output Encoding
- [ ] HTML output properly encoded
- [ ] JSON responses properly formatted
- [ ] Error messages don't leak sensitive info
- [ ] Stack traces disabled in production

### Cryptography
- [ ] Strong secret key (64+ characters)
- [ ] PBKDF2-HMAC-SHA512 for passwords
- [ ] 200,000+ iterations for password hashing
- [ ] Secure random number generation (secrets module)
- [ ] HTTPS enforced in production
- [ ] TLS 1.2+ only

### Security Headers
- [ ] X-Content-Type-Options: nosniff
- [ ] X-Frame-Options: DENY
- [ ] X-XSS-Protection: 1; mode=block
- [ ] Strict-Transport-Security (HSTS)
- [ ] Content-Security-Policy
- [ ] Referrer-Policy
- [ ] Permissions-Policy

### Rate Limiting
- [ ] Global rate limits
- [ ] Login endpoint rate limited
- [ ] Signup endpoint rate limited
- [ ] API endpoints rate limited
- [ ] Rate limit exceeded returns 429

### Logging & Monitoring
- [ ] Security events logged
- [ ] Failed login attempts logged
- [ ] Account lockouts logged
- [ ] IP blocks logged
- [ ] Log rotation configured
- [ ] No sensitive data in logs
- [ ] Centralized logging (production)

### Database Security
- [ ] Parameterized queries everywhere
- [ ] Foreign key constraints enabled
- [ ] Principle of least privilege for DB user
- [ ] No default/weak DB passwords
- [ ] Database backups configured
- [ ] Connection pooling implemented

### Error Handling
- [ ] Generic error messages to users
- [ ] Detailed errors logged server-side
- [ ] No stack traces exposed
- [ ] 404 page doesn't leak info
- [ ] 500 page doesn't leak info

### Dependency Management
- [ ] All dependencies up to date
- [ ] No known vulnerabilities in dependencies
- [ ] Dependencies pinned to specific versions
- [ ] Regular security updates

### Configuration
- [ ] Debug mode disabled in production
- [ ] SECRET_KEY changed from default
- [ ] Database credentials secured
- [ ] .env file not in version control
- [ ] Sensitive config in environment variables

### Infrastructure
- [ ] Firewall configured
- [ ] Only necessary ports open
- [ ] fail2ban configured
- [ ] Reverse proxy (nginx) configured
- [ ] SSL/TLS certificates valid
- [ ] Auto-renewal configured for SSL

---

## Test Results Documentation

### Template

```markdown
# Security Test Results
Date: [DATE]
Tester: [NAME]
Version: [VERSION]

## Summary
- Total Tests: XX
- Passed: XX
- Failed: XX
- Critical Issues: XX

## Critical Issues
1. [Issue Description]
   - Severity: Critical
   - Steps to Reproduce: ...
   - Recommended Fix: ...

## Test Details

### Password Strength
- Status: PASS/FAIL
- Notes: ...

### Brute Force Protection
- Status: PASS/FAIL
- Notes: ...

[Continue for all tests]

## Recommendations
1. [Recommendation]
2. [Recommendation]
```

---

## Continuous Security Testing

### Pre-Commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: '1.7.5'
    hooks:
      - id: bandit
        args: ['-r', 'app.py']
        
  - repo: https://github.com/Lucas-C/pre-commit-hooks-safety
    rev: v1.3.1
    hooks:
      - id: python-safety-dependencies-check
EOF

# Install hooks
pre-commit install
```

### CI/CD Security Scans

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r app.py -f json -o bandit-report.json
          
      - name: Run Safety
        run: |
          pip install safety
          safety check --json
          
      - name: Run OWASP Dependency Check
        run: |
          wget https://github.com/jeremylong/DependencyCheck/releases/download/v7.0.0/dependency-check-7.0.0-release.zip
          unzip dependency-check-7.0.0-release.zip
          ./dependency-check/bin/dependency-check.sh --project "Coffee Shop" --scan .
```

---

**Questions or Issues with Testing?**  
Contact: security@yourdomain.com
