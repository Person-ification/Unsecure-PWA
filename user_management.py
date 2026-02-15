import sqlite3
import os
import pyotp
import re
from werkzeug.security import generate_password_hash, check_password_hash

DB_FOLDER = 'database_files'
DB_PATH = os.path.join(DB_FOLDER, 'database.db')

def get_db():
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            dateOfBirth TEXT,
            email TEXT,
            mfa_secret TEXT
        )
    ''')
    conn.execute('CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, feedback TEXT)')
    conn.commit()
    conn.close()

def validate_username(username):
    # Only allow letters, numbers, underscore, dot, hyphen (3-20 chars)
    return bool(re.match(r'^[a-zA-Z0-9_.-]{3,20}$', username))

def register_user(username, password, dob, email=None):
    if not validate_username(username):
        return False, None

    conn = get_db()
    cur = conn.cursor()
    hashed_password = generate_password_hash(password)
    mfa_secret = pyotp.random_base32()

    try:
        cur.execute(
            "INSERT INTO users (username, password, dateOfBirth, email, mfa_secret) VALUES (?, ?, ?, ?, ?)",
            (username, hashed_password, dob, email, mfa_secret)
        )
        conn.commit()
        return True, mfa_secret
    except sqlite3.IntegrityError:
        return False, None
    finally:
        conn.close()

def retrieveUsers(username, password):
    if not validate_username(username):
        return False

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        return True
    return False

def verify_totp(username, input_code):
    if not validate_username(username):
        return False

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    result = cur.fetchone()
    conn.close()

    if result and result['mfa_secret']:
        totp = pyotp.TOTP(result['mfa_secret'])
        return totp.verify(input_code)
    return False

def insertFeedback(feedback_text):
    if not isinstance(feedback_text, str):
        return False

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback_text,))
    conn.commit()
    conn.close()
    return True

def listFeedback():
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM feedback").fetchall()
    conn.close()
    return rows
