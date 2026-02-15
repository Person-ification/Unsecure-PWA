import sqlite3
import os
import secrets
import time
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
    # Updated: Added email, otp_code, and otp_expiry
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, 
            password TEXT, 
            dateOfBirth TEXT,
            email TEXT,
            otp_code TEXT,
            otp_expiry REAL
        )
    ''')
    conn.execute('CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, feedback TEXT)')
    conn.commit()
    conn.close()

# --- SECURE FUNCTIONS ---

def insertUser(username, password, dob, email):
    conn = get_db()
    cur = conn.cursor()
    
    hashed_password = generate_password_hash(password)
    
    try:
        # Added email to query
        cur.execute(
            "INSERT INTO users (username, password, dateOfBirth, email) VALUES (?, ?, ?, ?)", 
            (username, hashed_password, dob, email)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        print("User already exists")
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
        stored_hash = user['password']
        if check_password_hash(stored_hash, password):
            return True
    return False

# --- 2FA FUNCTIONS ---

def set_otp(username):
    """Generates a secure 6-digit code and saves it to the DB."""
    # SECURE: Use secrets module for cryptographically strong random numbers
    otp = str(secrets.SystemRandom().randint(100000, 999999))
    
    # Set expiry for 5 minutes from now
    expiry = time.time() + 300 
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET otp_code = ?, otp_expiry = ? WHERE username = ?", (otp, expiry, username))
    
    # Fetch email to 'send' the code
    cur.execute("SELECT email FROM users WHERE username = ?", (username,))
    result = cur.fetchone()
    conn.commit()
    conn.close()
    
    if result:
        # EDUCATIONAL NOTE: In a real app, use smtplib here.
        # For this lab, we print to console to simulate sending.
        print(f"📧 [SIMULATION] Email sent to {result['email']} with code: {otp}")
        return True
    return False

def verify_otp(username, input_code):
    """Checks if the OTP matches and hasn't expired."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT otp_code, otp_expiry FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    
    if user:
        stored_code = user['otp_code']
        expiry = user['otp_expiry']
        
        # Check if code matches AND time is valid
        if stored_code == input_code and time.time() < expiry:
            # Optional: Clear the code so it can't be used twice
            return True
            
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
