import sqlite3
import time
import random
import os

# Database Configuration
DB_FOLDER = 'database_files'
DB_PATH = os.path.join(DB_FOLDER, 'database.db')

def get_db():
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)
    conn = sqlite3.connect(DB_PATH)
    return conn

def init_db():
    conn = get_db()
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, dateOfBirth TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, feedback TEXT)')
    conn.commit()
    conn.close()

# ---------------------------------------------------------
# VULNERABLE FUNCTIONS
# ---------------------------------------------------------

def insertUser(username, password, dob):
    conn = get_db()
    cur = conn.cursor()
    
    # FLAW 1: SQL Injection (Unsafe Insert) using f-strings
    # Also stores password in PLAIN TEXT (Flaw 3)
    query = f"INSERT INTO users (username, password, dateOfBirth) VALUES ('{username}', '{password}', '{dob}')"
    print(f"Executing SQL: {query}") # Debug print to help students see the injection
    
    # executescript is used to allow multiple statements (dangerous!)
    cur.executescript(query)
    
    conn.commit()
    conn.close()

def retrieveUsers(username, password):
    conn = get_db()
    cur = conn.cursor()
    
    # FLAW 1: SQL Injection (Unsafe Select)
    # Allows bypassing login: admin' OR '1'='1
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing SQL: {query}")
    
    user = cur.execute(query).fetchone()
    conn.close()

    # FLAW 6: Side Channel Attack (Timing)
    if user:
        time.sleep(random.randint(100, 200) / 1000)
        return True
    else:
        return False

def insertFeedback(feedback_text):
    conn = get_db()
    
    # FLAW 2: Stored XSS
    # NO sanitisation (bleach removed).
    query = f"INSERT INTO feedback (feedback) VALUES ('{feedback_text}')"
    conn.executescript(query)
    conn.commit()
    conn.close()
    
    # FLAW 7: File Write Vulnerability
    try:
        with open("feedback_log.txt", "a") as f:
            f.write(feedback_text + "\n")
    except Exception as e:
        print(f"Log error: {e}")

def listFeedback():
    conn = get_db()
    cur = conn.cursor()
    # Returns raw HTML/JS from database
    rows = cur.execute("SELECT * FROM feedback").fetchall()
    conn.close()
    return rows
