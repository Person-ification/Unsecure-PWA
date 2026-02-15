import sqlite3
import os
import pyotp  # Library for Google Authenticator logic
from werkzeug.security import generate_password_hash, check_password_hash

# Database setup
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
    # Updated table: Stores 'mfa_secret' instead of email codes
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

# --- SECURE USER FUNCTIONS ---

def register_user(username, password, dob, email):
    """
    Creates a user and generates a unique MFA secret for Google Authenticator.
    Returns: (Success_Boolean, Secret_String)
    """
    conn = get_db()
    cur = conn.cursor()
    
    # SECURE: Password Hashing
    hashed_password = generate_password_hash(password)
    
    # SECURE: Generate a random Base32 secret for TOTP
    # This secret is shared between the server and the Google Authenticator app
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
    """Verifies password only. Returns True if password matches."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()

    if user:
        if check_password_hash(user['password'], password):
            return True
    return False

# --- TOTP FUNCTIONS ---

def verify_totp(username, input_code):
    """
    Verifies the 6-digit code from Google Authenticator.
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    result = cur.fetchone()
    conn.close()
    
    if result and result['mfa_secret']:
        secret = result['mfa_secret']
        totp = pyotp.TOTP(secret)
        
        # Verify the code (allows for slight time skew)
        return totp.verify(input_code)
            
    return False

def insertFeedback(feedback_text):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback_text,))
    conn.commit()
    conn.close()

def listFeedback():
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM feedback").fetchall()
    conn.close()
    return rows
