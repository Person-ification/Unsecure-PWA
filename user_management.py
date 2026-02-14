import sqlite3 as sql
import time
import html
import random


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

    cur.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    )

    user = cur.fetchone()

    with open("visitor_log.txt", "r") as file:
        number = int(file.read().strip())
        number += 1

    with open("visitor_log.txt", "w") as file:
        file.write(str(number))

    time.sleep(0.085)

    con.close()

    return user is not None



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

    with open("templates/partials/success_feedback.html", "w") as f:
        for row in data:
            f.write("<p>\n")
            f.write(html.escape(row[1]) + "\n")
            f.write("</p>\n")
