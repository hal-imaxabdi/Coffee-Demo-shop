import sqlite3
import hashlib
import secrets
import bcrypt

DB_PATH = 'coffee_shop.db'
TEST_USERS = [
    ('Alice Johnson',  'alice@test.com',   '0111-000-001', 'AlicePassword123!'),
    ('Bob Smith',      'bob@test.com',     '0111-000-002', 'BobPassword123!!'),
    ('Charlie Brown',  'charlie@test.com', '0111-000-003', 'CharliePass123!!'),
    ('Diana Prince',   'diana@test.com',   '0111-000-004', 'DianaPassword123!'),
    ('Eve Adams',      'eve@test.com',     '0111-000-005', 'EvePassword12345'),
    ('Frank Castle',   'frank@test.com',   '0111-000-006', 'FrankPassword123!'),
]

def hash_password(password: str):
    salt = secrets.token_hex(32)
    salted = hashlib.sha256((password + salt).encode('utf-8')).digest()
    password_hash = bcrypt.hashpw(salted, bcrypt.gensalt(rounds=12)).decode('utf-8')
    return password_hash, salt

def seed():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print(f"{'Email':<25} {'Password':<25} {'Status'}")
    print("-" * 65)

    for name, email, phone, password in TEST_USERS:
        try:
            password_hash, salt = hash_password(password)
            cursor.execute('''
                INSERT INTO users (name, phone, email, password_hash, salt, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
            ''', (name, phone, email, password_hash, salt))
            conn.commit()
            print(f"{email:<25} {password:<25}  Inserted")
        except sqlite3.IntegrityError:
            print(f"{email:<25} {password:<25} Already exists (skipped)")
        except Exception as e:
            print(f"{email:<25} {password:<25} Error: {e}")

    conn.close()
    print("\nDone! You can now test login with any of the emails/passwords above.")
    print("For brute-force testing, the account locks after 5 failed attempts,")
    print("and the IP gets blocked after 5 failed attempts within 30 minutes.")


if __name__ == '__main__':
    seed()