import sqlite3 as sql
import time
import html
import random
import hmac


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, password, DoB),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Fetch user data by username only
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    # Default: no match
    valid = False

    if row:
        stored_password = row[0]
        # Use constant-time comparison
        valid = hmac.compare_digest(stored_password, password)

    # Update visitor log (keep it for educational purposes)
    with open("visitor_log.txt", "r") as file:
        number = int(file.read().strip())
        number += 1

    with open("visitor_log.txt", "w") as file:
        file.write(str(number))

    con.close()

    return valid



def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    cur.execute(
        "INSERT INTO feedback (feedback) VALUES (?)",
        (feedback,),
    )

    con.commit()
    con.close()



def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    return data  # Return raw data
