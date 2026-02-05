# ☕ Ultra-Secure Coffee Shop

A production-ready, security-hardened web application for a coffee shop with comprehensive protection against modern web vulnerabilities.

## 🔒 Security Highlights

- **Military-Grade Password Hashing**: PBKDF2-HMAC-SHA512 with 200,000 iterations
- **Brute Force Protection**: Progressive delays, account lockouts, IP blocking
- **SQL Injection Prevention**: Parameterized queries, input sanitization
- **XSS Protection**: Content Security Policy, HTML sanitization, output encoding
- **CSRF Protection**: Token-based validation on all state-changing operations
- **Session Security**: IP binding, user agent validation, secure cookies
- **Rate Limiting**: Multi-layer protection against abuse
- **Comprehensive Logging**: All security events tracked and monitored
- **Strong Password Enforcement**: 12+ character requirement with complexity rules
- **Input Validation**: Client-side and server-side validation for all inputs

## 📋 Requirements

- Python 3.8+
- pip (Python package manager)

## 🚀 Quick Start

### 1. Installation

```bash
# Clone or extract the project
cd secure_coffee_shop

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Development Setup

```bash
# Run the application
python app.py

# Access the application
# Open browser to: http://localhost:5000
```

### 3. First Login

The system initializes with demo accounts (for development only):

```
Email: admin@coffee.com
Password: SecureAdmin@2024
```

**⚠️ IMPORTANT**: Delete demo accounts before production deployment!

## 🛠️ Configuration

### Development Configuration

The application works out-of-the-box for development with secure defaults:
- SQLite database
- Session cookies (without Secure flag for HTTP)
- Console and file logging

### Production Configuration

For production deployment, follow these steps:

1. **Create .env file** (copy from .env.example):
```bash
cp .env.example .env
# Edit .env with your production values
```

2. **Enable HTTPS-only settings** in `app.py`:
```python
app.config['SESSION_COOKIE_SECURE'] = True  # Change to True
```

3. **Uncomment Talisman configuration** in `app.py`:
```python
talisman = Talisman(...)  # Uncomment entire section
```

4. **Update CORS origins** in `app.py`:
```python
CORS(app, origins=['https://yourdomain.com'])
```

5. **Use production WSGI server**:
```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

6. **Set up reverse proxy** (Nginx example):
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🔐 Password Requirements

Passwords must meet ALL of the following criteria:

- ✓ Minimum 12 characters (8 absolute minimum)
- ✓ At least one uppercase letter (A-Z)
- ✓ At least one lowercase letter (a-z)
- ✓ At least one number (0-9)
- ✓ At least one special character (!@#$%^&*...)
- ✓ No sequential characters (abc, 123, etc.)
- ✓ Not a common password

**Good Examples**:
- `MySecure#Pass2024!`
- `Coffee$Shop@2024`
- `Ultra!Secure#2024`

**Bad Examples**:
- `password123` (too common)
- `Password` (no number or special char)
- `Pass123!` (too short)
- `abc123def!` (sequential characters)

## 🧪 Testing Security

### Manual Testing

1. **Test Password Strength**:
```
Navigate to /signup
Try weak passwords - should be rejected
Try strong password - should be accepted
```

2. **Test Brute Force Protection**:
```
Attempt login with wrong password 5+ times
Account should lock for 30 minutes
```

3. **Test Rate Limiting**:
```
Make rapid requests to any endpoint
Should receive 429 error after limits exceeded
```

4. **Test Session Security**:
```
Login from one IP
Try to use session cookie from different IP
Session should be invalidated
```

### Automated Testing with Tools

1. **OWASP ZAP**:
```bash
# Run automated scan
zap-cli quick-scan http://localhost:5000
```

2. **Burp Suite**:
- Configure browser proxy to Burp
- Navigate through application
- Run active scan
- Review findings

3. **SQLMap** (SQL Injection):
```bash
sqlmap -u "http://localhost:5000/api/login" --data "login=test&password=test" --batch
```

## 📊 Security Monitoring

### View Security Logs

```bash
# Real-time security events
tail -f security.log

# All application logs
tail -f app.log

# Search for failed logins
grep "LOGIN_FAILED" security.log

# Search for blocked IPs
grep "IP_BLOCKED" security.log
```

### Security Dashboard

The application logs security events to the database. You can query them:

```python
# In Python shell or create admin dashboard
from app import get_db

conn = get_db()
cursor = conn.cursor()

# Recent security events
cursor.execute('''
    SELECT * FROM security_events 
    ORDER BY timestamp DESC 
    LIMIT 50
''')
events = cursor.fetchall()

# Blocked IPs
cursor.execute('''
    SELECT * FROM ip_blocks 
    WHERE blocked_until > datetime('now')
''')
blocked = cursor.fetchall()

# Locked accounts
cursor.execute('''
    SELECT email, lockout_until FROM users 
    WHERE account_locked = 1
''')
locked = cursor.fetchall()
```

## 🗂️ Project Structure

```
secure_coffee_shop/
├── app.py                      # Main application with security features
├── requirements.txt            # Python dependencies
├── SECURITY.md                 # Detailed security documentation
├── README.md                   # This file
├── .env.example               # Environment variables template
├── security.log               # Security events log
├── app.log                    # Application log
├── secure_coffee_shop.db      # SQLite database
├── static/
│   ├── css/
│   │   ├── styles.css         # Main styles
│   │   ├── auth-styles.css    # Authentication page styles
│   │   └── dashboard.css      # Dashboard styles
│   ├── js/
│   │   ├── auth-script.js     # Secure authentication logic
│   │   └── script.js          # Main application logic
│   └── images/                # Static images
└── templates/
    ├── index.html             # Home page
    ├── login.html             # Login page
    ├── signup.html            # Registration page
    └── dashboard.html         # User dashboard
```

## 🐛 Common Issues & Solutions

### Issue: "Session cookie not set"
**Solution**: For development, ensure `SESSION_COOKIE_SECURE` is `False`. For production with HTTPS, set it to `True`.

### Issue: "Rate limit exceeded"
**Solution**: Wait for the timeout period or adjust rate limits in `SECURITY_CONFIG`.

### Issue: "Account locked"
**Solution**: Wait 30 minutes or manually unlock in database:
```sql
UPDATE users SET account_locked = 0, lockout_until = NULL, failed_attempts = 0 WHERE email = 'user@example.com';
```

### Issue: "IP blocked"
**Solution**: Remove IP block from database:
```sql
DELETE FROM ip_blocks WHERE ip_address = 'xxx.xxx.xxx.xxx';
```

## 🔄 Database Management

### Reset Database
```bash
# Backup first
cp secure_coffee_shop.db secure_coffee_shop.db.backup

# Delete database
rm secure_coffee_shop.db

# Restart application to recreate
python app.py
```

### View Database
```bash
# Install SQLite browser or use command line
sqlite3 secure_coffee_shop.db

# List tables
.tables

# View users (passwords are hashed)
SELECT id, name, email, account_locked, failed_attempts FROM users;

# View security events
SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10;
```

## 📚 API Endpoints

### Public Endpoints
- `GET /` - Home page
- `GET /login` - Login page
- `GET /signup` - Signup page
- `POST /api/login` - Login endpoint (rate limited: 5/min)
- `POST /api/signup` - Registration endpoint (rate limited: 3/hour)
- `POST /api/newsletter` - Newsletter subscription (rate limited: 3/hour)
- `GET /api/csrf-token` - Get CSRF token

### Protected Endpoints (Require Authentication)
- `GET /dashboard` - User dashboard
- `GET /api/current-user` - Get current user info
- `GET /api/orders` - Get user orders
- `POST /api/orders` - Place new order
- `POST /api/logout` - Logout

## 🚨 Security Incident Response

If you discover a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. **DO NOT** discuss publicly
3. Email security concerns to: security@yourdomain.com
4. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## 📝 License

This project is licensed under the MIT License.

## 👥 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

Security-related contributions are especially appreciated!

## ⚠️ Disclaimer

This application implements industry-standard security practices, but no system is 100% secure. Always:
- Keep dependencies updated
- Monitor security logs
- Perform regular security audits
- Follow security best practices
- Stay informed about new vulnerabilities

## 📞 Support

For issues and questions:
- **GitHub Issues**: Technical problems
- **Email**: support@yourdomain.com
- **Documentation**: See SECURITY.md for detailed security info

## 🎯 Roadmap

Future security enhancements:
- [ ] Two-factor authentication (2FA)
- [ ] OAuth 2.0 integration
- [ ] CAPTCHA integration
- [ ] Email verification
- [ ] Password reset functionality
- [ ] Advanced anomaly detection
- [ ] Automated security scanning
- [ ] Real-time security dashboard
- [ ] API key authentication
- [ ] Audit trail for all actions

---

**Version**: 1.0.0  
**Last Updated**: 2024-02-05  
**Author**: Security Team  
**Status**: Production Ready 🚀
