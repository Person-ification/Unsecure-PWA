import sqlite3
import os
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
    # Users table
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, dateOfBirth TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, feedback TEXT)')
    conn.commit()
    conn.close()

# --- SECURE FUNCTIONS ---

def insertUser(username, password, dob):
    conn = get_db()
    cur = conn.cursor()
    
    # SECURE: Password Hashing
    hashed_password = generate_password_hash(password)
    
    try:
        # SECURE: Parameterized Query (prevents SQL Injection)
        cur.execute(
            "INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)", 
            (username, hashed_password, dob)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        print("User already exists")
    finally:
        conn.close()

def retrieveUsers(username, password):
    conn = get_db()
    cur = conn.cursor()
    
    # SECURE: Parameterized Query
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()

    if user:
        # SECURE: Verify Hash (never compare plain text)
        stored_hash = user['password']
        if check_password_hash(stored_hash, password):
            return True
            
    return False

def insertFeedback(feedback_text):
    conn = get_db()
    cur = conn.cursor()
    
    # SECURE: Parameterized Query
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback_text,))
    conn.commit()
    conn.close()
    # Note: We removed the file writing to prevent local file attacks.

def listFeedback():
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM feedback").fetchall()
    conn.close()
    return rows
