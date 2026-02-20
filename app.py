import os
import sqlite3
import hashlib
import secrets
import logging
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import render_template, Flask, request, jsonify, session, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import jwt
import bcrypt
import base64

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

CORS(app, supports_credentials=True, origins=['http://localhost:5000', 'http://127.0.0.1:5000'])

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

DB_PATH = 'coffee_shop.db'
MAX_LOGIN_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 30
JWT_ALGORITHM = 'RS256'
JWT_EXPIRY_HOURS = 1

RSA_PRIVATE_KEY = None
RSA_PUBLIC_KEY = None


def generate_rsa_keys():
    global RSA_PRIVATE_KEY, RSA_PUBLIC_KEY

    private_key_path = 'private_key.pem'
    public_key_path = 'public_key.pem'

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, 'rb') as f:
            RSA_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(public_key_path, 'rb') as f:
            RSA_PUBLIC_KEY = serialization.load_pem_public_key(f.read(), backend=default_backend())
        logger.info("RSA keys loaded from disk")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    RSA_PRIVATE_KEY = private_key
    RSA_PUBLIC_KEY = public_key
    logger.info("New RSA key pair generated and saved")


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                public_key TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active INTEGER DEFAULT 1,
                failed_attempts INTEGER DEFAULT 0,
                locked_until DATETIME
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                reason TEXT,
                blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                blocked_until DATETIME,
                is_permanent INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                email TEXT,
                success INTEGER DEFAULT 0,
                attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                revoked INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS csrf_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                used INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                item_name TEXT NOT NULL,
                price TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_blocks_ip ON ip_blocks(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash ON auth_tokens(token_hash)')

        conn.commit()
        logger.info("Database initialized")


def check_ip_blocked(ip_address):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM ip_blocks
        WHERE ip_address = ? AND (blocked_until > datetime('now') OR is_permanent = 1)
        ORDER BY blocked_at DESC LIMIT 1
    ''', (ip_address,))
    block = cursor.fetchone()
    if block:
        msg = f"IP blocked until {block['blocked_until']}" if not block['is_permanent'] else "IP permanently blocked"
        return True, msg
    return False, None


def block_ip(ip_address, reason, duration_minutes=None, permanent=False):
    db = get_db()
    blocked_until = None
    if not permanent and duration_minutes:
        blocked_until = (datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)).strftime('%Y-%m-%d %H:%M:%S')
    db.execute('''
        INSERT INTO ip_blocks (ip_address, reason, blocked_until, is_permanent)
        VALUES (?, ?, ?, ?)
    ''', (ip_address, reason, blocked_until, 1 if permanent else 0))
    db.commit()
    logger.warning(f"IP {ip_address} blocked: {reason}")


def count_recent_failed_attempts(ip_address, minutes=30):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT COUNT(*) as count FROM login_attempts
        WHERE ip_address = ? AND success = 0
        AND attempted_at > datetime('now', ?)
    ''', (ip_address, f'-{minutes} minutes'))
    result = cursor.fetchone()
    return result['count'] if result else 0


def log_login_attempt(ip_address, email, success, user_agent=''):
    db = get_db()
    db.execute('''
        INSERT INTO login_attempts (ip_address, email, success, user_agent)
        VALUES (?, ?, ?, ?)
    ''', (ip_address, email, 1 if success else 0, user_agent))
    db.commit()


def generate_jwt_token(user_id, email):
    payload = {
        'sub': str(user_id),
        'email': email,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        'jti': secrets.token_hex(16)
    }

    private_key_pem = RSA_PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    token = jwt.encode(payload, private_key_pem, algorithm=JWT_ALGORITHM)

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS)).strftime('%Y-%m-%d %H:%M:%S')

    db = get_db()
    db.execute('''
        INSERT INTO auth_tokens (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
    ''', (user_id, token_hash, expires_at))
    db.commit()

    return token


def verify_jwt_token(token):
    try:
        public_key_pem = RSA_PUBLIC_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        payload = jwt.decode(token, public_key_pem, algorithms=[JWT_ALGORITHM])

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            SELECT * FROM auth_tokens
            WHERE token_hash = ? AND revoked = 0 AND expires_at > datetime('now')
        ''', (token_hash,))
        stored_token = cursor.fetchone()

        if not stored_token:
            return None, "Token not found or revoked"

        return payload, None

    except jwt.ExpiredSignatureError:
        return None, "Token expired"
    except jwt.InvalidTokenError as e:
        return None, f"Invalid token: {str(e)}"


def create_digital_signature(data: str) -> str:
    data_bytes = data.encode('utf-8')
    signature = RSA_PRIVATE_KEY.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')


def verify_digital_signature(data: str, signature_b64: str) -> bool:
    try:
        data_bytes = data.encode('utf-8')
        signature = base64.b64decode(signature_b64)
        RSA_PUBLIC_KEY.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Authorization required'}), 401

        token = auth_header[7:]
        payload, error = verify_jwt_token(token)
        if error:
            return jsonify({'success': False, 'error': error}), 401

        g.current_user_id = int(payload['sub'])
        g.current_user_email = payload['email']
        return f(*args, **kwargs)
    return decorated


def generate_csrf_token():
    token = secrets.token_hex(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    db.execute('INSERT INTO csrf_tokens (token, expires_at) VALUES (?, ?)', (token, expires_at))
    db.commit()
    return token


def check_csrf_token(token):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT id FROM csrf_tokens
        WHERE token = ? AND used = 0 AND expires_at > datetime('now')
    ''', (token,))
    return cursor.fetchone() is not None


def consume_csrf_token(token):
    db = get_db()
    db.execute('UPDATE csrf_tokens SET used = 1 WHERE token = ?', (token,))
    db.commit()


def validate_csrf_token(token):
    if not check_csrf_token(token):
        return False
    consume_csrf_token(token)
    return True


@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf_token()
    return jsonify({'csrf_token': token})


@app.route('/api/register', methods=['POST'])
@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    phone = data.get('phone', '').strip()
    password = data.get('password', '')
    csrf_token = data.get('csrf_token', '')

    if not name or not email or not password:
        return jsonify({'error': 'Name, email and password are required'}), 400

    if len(password) < 12:
        return jsonify({'error': 'Password must be at least 12 characters'}), 400

    if not check_csrf_token(csrf_token):
        return jsonify({'error': 'Invalid or expired CSRF token'}), 403

    consume_csrf_token(csrf_token)

    salt = secrets.token_hex(32)
    salted = hashlib.sha256((password + salt).encode('utf-8')).digest()
    password_hash = bcrypt.hashpw(salted, bcrypt.gensalt(rounds=12)).decode('utf-8')

    user_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    user_public_key_pem = user_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    try:
        db = get_db()
        db.execute('''
            INSERT INTO users (name, phone, email, password_hash, salt, public_key)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, phone, email, password_hash, salt, user_public_key_pem))
        db.commit()

        logger.info(f"New user registered: {email}")
        return jsonify({'message': 'Registration successful'}), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 409
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    ip_address = get_remote_address()
    user_agent = request.headers.get('User-Agent', '')
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    is_blocked, block_message = check_ip_blocked(ip_address)
    if is_blocked:
        logger.warning(f"Blocked IP login attempt: {ip_address}")
        return jsonify({'error': 'Too many failed attempts. Please try again later.'}), 403

    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    csrf_token = data.get('csrf_token', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    if not check_csrf_token(csrf_token):
        return jsonify({'error': 'Invalid or expired CSRF token'}), 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ? AND is_active = 1', (email,))
    user = cursor.fetchone()

    if user and user['locked_until']:
        locked_until = datetime.strptime(user['locked_until'], '%Y-%m-%d %H:%M:%S')
        if locked_until > datetime.now(timezone.utc).replace(tzinfo=None):
            log_login_attempt(ip_address, email, False, user_agent)
            return jsonify({'error': 'Account temporarily locked. Try again later.'}), 403

    auth_failed = True
    if user:
        try:
            stored_hash = user['password_hash'].encode('utf-8')
            salted = hashlib.sha256((password + user['salt']).encode('utf-8')).digest()
            if bcrypt.checkpw(salted, stored_hash):
                auth_failed = False
        except Exception:
            pass

    if auth_failed:
        log_login_attempt(ip_address, email, False, user_agent)
        logger.warning(f"Failed login attempt | IP: {ip_address} | User: {email}")

        failed_count = count_recent_failed_attempts(ip_address, minutes=30)
        if failed_count >= MAX_LOGIN_ATTEMPTS:
            block_ip(ip_address, f"Too many failed login attempts ({failed_count})", duration_minutes=BLOCK_DURATION_MINUTES)

        if user:
            new_attempts = user['failed_attempts'] + 1
            locked_until_val = None
            if new_attempts >= 5:
                locked_until_val = (datetime.now(timezone.utc) + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
            db.execute(
                'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                (new_attempts, locked_until_val, user['id'])
            )
            db.commit()

        time.sleep(0.5)
        return jsonify({'error': 'Invalid credentials'}), 401

    consume_csrf_token(csrf_token)

    token = generate_jwt_token(user['id'], user['email'])
    login_timestamp = datetime.now(timezone.utc).isoformat()
    signature = create_digital_signature(f"{user['id']}:{user['email']}:{login_timestamp}")

    db.execute('''
        UPDATE users SET last_login = datetime('now'), failed_attempts = 0, locked_until = NULL
        WHERE id = ?
    ''', (user['id'],))
    db.commit()

    log_login_attempt(ip_address, email, True, user_agent)
    logger.info(f"Login success | IP: {ip_address} | User: {email}")

    return jsonify({
        'token': token,
        'signature': signature,
        'timestamp': login_timestamp,
        'user': {
            'id': user['id'],
            'email': user['email'],
            'name': user['name']
        }
    }), 200


@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:]
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    db = get_db()
    db.execute('UPDATE auth_tokens SET revoked = 1 WHERE token_hash = ?', (token_hash,))
    db.commit()

    logger.info(f"User {g.current_user_email} logged out")
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/api/current-user', methods=['GET'])
@require_auth
def current_user():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, name, email, last_login, created_at FROM users WHERE id = ?', (g.current_user_id,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'last_login': user['last_login'],
            'created_at': user['created_at']
        }
    }), 200


@app.route('/api/orders', methods=['GET'])
@require_auth
def get_orders():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM orders WHERE user_id = ? ORDER BY order_date DESC
    ''', (g.current_user_id,))
    orders = cursor.fetchall()
    return jsonify({
        'success': True,
        'orders': [dict(o) for o in orders]
    }), 200


@app.route('/api/orders', methods=['POST'])
@require_auth
def create_order():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400

    item_name = data.get('item', '').strip()
    price = data.get('price', '').strip()

    if not item_name or not price:
        return jsonify({'success': False, 'error': 'Item and price required'}), 400

    db = get_db()
    db.execute('''
        INSERT INTO orders (user_id, item_name, price) VALUES (?, ?, ?)
    ''', (g.current_user_id, item_name, price))
    db.commit()

    return jsonify({'success': True, 'message': 'Order placed successfully'}), 201


@app.route('/api/verify-signature', methods=['POST'])
def verify_signature_endpoint():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    message = data.get('message', '')
    signature = data.get('signature', '')

    if not message or not signature:
        return jsonify({'error': 'Message and signature required'}), 400

    is_valid = verify_digital_signature(message, signature)
    return jsonify({'valid': is_valid}), 200


@app.route('/api/public-key', methods=['GET'])
def get_public_key():
    public_key_pem = RSA_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return jsonify({'public_key': public_key_pem}), 200


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/signup')
@app.route('/register')
def register_page():
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')


if __name__ == '__main__':
    generate_rsa_keys()
    init_db()
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=False
    )