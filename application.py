import os

import sqlite3 as sql
from flask import Flask, flash, jsonify, redirect, render_template, request, session

from flask_session import Session
from tempfile import mkdtemp
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

import random, string

# Configure application
app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Connect to database
con = sql.connect('who.db', check_same_thread = False)
db = con.cursor()


# requires login
def login_required(f):
    """
    Decorate routes to require login.
    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/register")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def index():
    db.execute("SELECT * FROM vaccines WHERE id = ?")
    vaccines = db.fetchone()
    return render_template("index.html", vaccines = vaccines)


@app.route("/welcome", methods=["GET", "POST"])
def welcome():
    return render_template("welcome.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        db = con.cursor()

        # Declare variables
        username = request.form.get("username")
        account_type = request.form.get("account")
        x = db.execute("SELECT * FROM users WHERE username = ?", [username])
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        name = request.form.get("name")
        email = request.form.get("email")

        # Ensure username was submitted
        if not request.form.get("username"):
            flash('Must provide username')

        # Check if username already exists
        elif x != 0:
            flash('Username is already taken')

        # Ensure password was submitted
        elif not password:
            flash('Must provide password')

        # Ensure confirmation was submitted
        elif not confirmation:
            flash('Please confirm password')

        # Ensure password and confirmation match
        elif password != confirmation:
            flash('Passwords must match')

        password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Insert new user
        db.execute("INSERT INTO users (username, hash, name, email) VALUES (?, ?, ?, ?)", (username, password_hash, name, email))

        con.commit()

        # Redirect user to home page
        return render_template("login.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    db = con.cursor()

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("email"):
            flash('Must provide email address')

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash('Must provide password')

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = ?", [request.form.get("email")])

        # Ensure username exists and password is correct
        if rows != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash('Invalide email and/or password')

        # Remember which user has logged in
        user = db.fetchone()
        session["user_id"] = user[0]

        db.execute("SELECT * FROM vaccines")
        vaccines = db.fetchall()

        # Redirect user to home page
        return render_template("index.html", vaccines = vaccines)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    db = con.cursor()

    if request.method == 'POST':
        vaccine = request.form.get("vaccine")
        place = request.form.get("place")
        doses = request.form.get("doses")

        # Add to table
        db.execute("INSERT INTO vaccines (name, place, doses) VALUES(?, ?, ?)", (vaccine, place, doses))
        con.commit()

        rows = db.execute("SELECT * FROM vaccines")
        vaccines = db.fetchall()

        return render_template("index.html", vaccines = vaccines)
    return render_template("add.html")
