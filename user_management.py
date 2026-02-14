import sqlite3 as sql
import time
import html
import random
import hmac
import bleach
from werkzeug.security import generate_password_hash, check_password_hash


def insertUser(username, password, DoB):
    hashed_password = generate_password_hash(password)
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()

def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    if row:
        stored_hash = row[0]
        return check_password_hash(stored_hash, password)
    return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    clean_feedback = bleach.clean(feedback)  # strips dangerous HTML/JS

    cur.execute(
        "INSERT INTO feedback (feedback) VALUES (?)",
        (clean_feedback,),
    )

    con.commit()
    con.close()




def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    return data  # Return raw data
