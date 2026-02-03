from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # We will change in improvement implementation
CORS(app, supports_credentials=True)

# Database setup
DATABASE = 'coffee_shop.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            price TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Login attempts table (for tracking brute force attempts)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_or_phone TEXT NOT NULL,
            ip_address TEXT,
            success INTEGER DEFAULT 0,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Newsletter subscribers
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS newsletter_subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert demo users with PLAIN TEXT passwords 
    demo_users = [
        ('Admin User', 'admin@coffee.com', '+1111111111', 'admin123'),
        ('John Doe', 'john@test.com', '+2222222222', 'password'),
        ('Jane Smith', 'jane@test.com', '+3333333333', '123456'),
        ('Bob Wilson', 'bob@demo.com', '+4444444444', 'qwerty'),
        ('Alice Brown', 'alice@test.com', '+5555555555', 'letmein')
    ]
    
    for user in demo_users:
        try:
            cursor.execute('''
                INSERT INTO users (name, email, phone, password)
                VALUES (?, ?, ?, ?)
            ''', user)
        except sqlite3.IntegrityError:
            pass
    
    # Insert demo orders
    demo_orders = [
        (1, 'Cappuccino', '$8.50', 'completed'),
        (1, 'Espresso', '$8.50', 'pending'),
        (2, 'Chai Latte', '$8.50', 'completed'),
        (3, 'Macchiato', '$8.50', 'pending')
    ]
    
    for order in demo_orders:
        try:
            cursor.execute('''
                INSERT INTO orders (user_id, item_name, price, status)
                VALUES (?, ?, ?, ?)
            ''', order)
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    conn.close()


@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login')
def login_page():
    """Login page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard_page'))
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    """Signup page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard_page'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard_page():
    """Dashboard page - requires login"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html')


@app.route('/api/login', methods=['POST'])
def login():
    """Login endpoint - VULNERABLE for demo"""
    data = request.get_json()
    login_input = data.get('login')
    password = data.get('password')
    ip_address = request.remote_addr
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM users 
        WHERE (email = ? OR phone = ?) AND password = ?
    ''', (login_input, login_input, password))
    
    user = cursor.fetchone()
    
    cursor.execute('''
        INSERT INTO login_attempts (email_or_phone, ip_address, success)
        VALUES (?, ?, ?)
    ''', (login_input, ip_address, 1 if user else 0))
    
    conn.commit()
    
    if user:
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user['name']
        
        conn.close()
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'phone': user['phone']
            }
        }), 200
    else:
        conn.close()
        return jsonify({
            'success': False,
            'message': 'Invalid email/phone or password'
        }), 401

@app.route('/api/signup', methods=['POST'])
def signup():
    """Signup endpoint"""
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM users WHERE email = ? OR phone = ?', (email, phone))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            return jsonify({
                'success': False,
                'message': 'User with this email or phone already exists'
            }), 400
        
        cursor.execute('''
            INSERT INTO users (name, email, phone, password)
            VALUES (?, ?, ?, ?)
        ''', (name, email, phone, password))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Sign up successful',
            'user': {
                'id': user_id,
                'name': name,
                'email': email,
                'phone': phone
            }
        }), 201
        
    except Exception as e:
        conn.close()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/logout', methods=['POST', 'GET'])
def logout():
    """Logout endpoint"""
    session.clear()
    return jsonify({
        'success': True,
        'message': 'Logged out successfully'
    }), 200

@app.route('/api/current-user', methods=['GET'])
def current_user():
    """Get current logged-in user"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'phone': user['phone']
            }
        }), 200
    else:
        return jsonify({'success': False, 'message': 'User not found'}), 404

@app.route('/api/orders', methods=['GET', 'POST'])
def orders():
    """Orders endpoint"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('''
            SELECT o.* FROM orders o
            WHERE o.user_id = ?
            ORDER BY o.order_date DESC
        ''', (session['user_id'],))
        
        orders = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'orders': [dict(order) for order in orders]
        }), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        item_name = data.get('item')
        price = data.get('price')
        
        cursor.execute('''
            INSERT INTO orders (user_id, item_name, price, status)
            VALUES (?, ?, ?, 'pending')
        ''', (session['user_id'], item_name, price))
        
        conn.commit()
        order_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Order placed successfully',
            'order_id': order_id
        }), 201

@app.route('/api/newsletter', methods=['POST'])
def newsletter():
    """Newsletter subscription endpoint"""
    data = request.get_json()
    email = data.get('email')
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO newsletter_subscribers (email)
            VALUES (?)
        ''', (email,))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Successfully subscribed to newsletter'
        }), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({
            'success': False,
            'message': 'Email already subscribed'
        }), 400

@app.route('/api/admin/login-attempts', methods=['GET'])
def get_login_attempts():
    """Get all login attempts for monitoring"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM login_attempts 
        ORDER BY attempt_time DESC 
        LIMIT 100
    ''')
    
    attempts = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'attempts': [dict(attempt) for attempt in attempts]
    }), 200

@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    """Get all users for monitoring"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, email, phone, password FROM users')
    users = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'users': [dict(user) for user in users]
    }), 200

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
        print("Database initialized with demo data!")
        print("\nDemo User Credentials:")
        print("1. admin@coffee.com / admin123")
        print("2. john@test.com / password")
        print("3. jane@test.com / 123456")
        print("4. bob@demo.com / qwerty")
        print("5. alice@test.com / letmein")
    
    print("Coffee-in Flask Server Starting...")
    print("\n Access your website at:")
    print("    http://localhost:5000")
    print("    http://127.0.0.1:5000")
    

    app.run(debug=True, host='0.0.0.0', port=5000)
