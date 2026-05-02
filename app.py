from datetime import datetime, timedelta
import os
import sqlite3

import bcrypt
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from markupsafe import Markup


app = Flask(__name__)
app.secret_key = "student-portal-demo-secret"

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "database.db")
LOG_PATH = os.path.join(BASE_DIR, "logs.txt")
LOCK_SECONDS = 45
MAX_FAILED_ATTEMPTS = 3


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def utc_now():
    return datetime.utcnow()


def to_db_time(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def parse_db_time(value):
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def write_log(action, user_id=None):
    timestamp = to_db_time(utc_now())
    line = f"[{timestamp}] user_id={user_id or '-'} action={action}\n"

    with open(LOG_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(line)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs (user_id, action, timestamp) VALUES (?, ?, ?)",
        (user_id, action, timestamp),
    )
    conn.commit()
    conn.close()


def init_db():
    if os.path.exists(DB_PATH):
        return

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'admin')),
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lock_until TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            marks INTEGER NOT NULL,
            attendance INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )

    users = [
        ("admin", hash_password("admin123"), "admin"),
        ("alice", hash_password("alicepass"), "student"),
        ("bob", hash_password("bobpass"), "student"),
    ]
    cur.executemany(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        users,
    )

    cur.executemany(
        "INSERT INTO records (user_id, subject, marks, attendance) VALUES (?, ?, ?, ?)",
        [
            (2, "Mathematics", 91, 96),
            (2, "Cyber Security", 88, 93),
            (2, "Database Systems", 84, 90),
            (3, "Mathematics", 76, 86),
            (3, "Cyber Security", 82, 89),
            (3, "Database Systems", 79, 84),
        ],
    )

    conn.commit()
    conn.close()

    if not os.path.exists(LOG_PATH):
        open(LOG_PATH, "w", encoding="utf-8").close()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    return user


def login_required():
    user = current_user()
    if not user:
        return None
    return user


def admin_required():
    user = login_required()
    if not user:
        return None
    if user["role"] != "admin":
        write_log("unauthorized admin access blocked", user["id"])
        abort(403)
    return user


def get_students():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE role = 'student' ORDER BY username")
    students = cur.fetchall()
    conn.close()
    return students


def calculate_summary(records):
    if not records:
        return {"gpa": 0, "average_marks": 0, "average_attendance": 0}

    avg_marks = sum(row["marks"] for row in records) / len(records)
    avg_attendance = sum(row["attendance"] for row in records) / len(records)
    gpa = round((avg_marks / 100) * 10, 2)
    return {
        "gpa": gpa,
        "average_marks": round(avg_marks, 2),
        "average_attendance": round(avg_attendance, 2),
    }


init_db()


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(query)
            user = cur.fetchone()
        except sqlite3.Error as exc:
            user = None
            message = f"SQL error: {exc}"
        conn.close()

        if user:
            session["user_id"] = user["id"]
            write_log("vulnerable login success", user["id"])
            return redirect(url_for("dashboard"))

        if not message:
            message = "Login failed. Try the SQL injection demo: username admin'--"
        write_log(f"vulnerable login failed for username={username}")

    note = "Vulnerable login: builds SQL with raw input. Demo username: admin'--"
    return render_template("login.html", message=message, note=note, secure=False)


@app.route("/secure-login", methods=["GET", "POST"])
def secure_login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if not user:
            conn.close()
            write_log(f"secure login failed unknown username={username}")
            message = "Invalid username or password."
            return render_template("login.html", message=message, note="Secure login with parameterized SQL, bcrypt, and lockout.", secure=True)

        lock_until = parse_db_time(user["lock_until"])
        if lock_until and lock_until > utc_now():
            remaining = int((lock_until - utc_now()).total_seconds())
            conn.close()
            write_log("secure login blocked by account lock", user["id"])
            message = f"Account locked. Try again in {remaining} seconds."
            return render_template("login.html", message=message, note="Secure login with parameterized SQL, bcrypt, and lockout.", secure=True)

        if check_password(password, user["password_hash"]):
            cur.execute(
                "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            conn.close()
            session["user_id"] = user["id"]
            write_log("secure login success", user["id"])
            return redirect(url_for("dashboard"))

        failed_attempts = user["failed_attempts"] + 1
        lock_value = None
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            lock_time = utc_now() + timedelta(seconds=LOCK_SECONDS)
            lock_value = to_db_time(lock_time)
            failed_attempts = 0
            write_log(f"account locked for {LOCK_SECONDS} seconds", user["id"])

        cur.execute(
            "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE id = ?",
            (failed_attempts, lock_value, user["id"]),
        )
        conn.commit()
        conn.close()
        write_log("secure login failed bad password", user["id"])
        message = "Invalid username or password."

    note = "Secure login: parameterized SQL, bcrypt password check, and 45-second lock after 3 failures."
    return render_template("login.html", message=message, note=note, secure=True)


@app.route("/dashboard")
def dashboard():
    user = login_required()
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    if user["role"] == "admin":
        cur.execute(
            """
            SELECT records.*, users.username
            FROM records
            JOIN users ON users.id = records.user_id
            ORDER BY users.username, records.subject
            """
        )
    else:
        cur.execute("SELECT records.*, ? AS username FROM records WHERE user_id = ? ORDER BY subject", (user["username"], user["id"]))
    records = cur.fetchall()
    conn.close()

    summary = calculate_summary(records)
    return render_template("dashboard.html", user=user, records=records, summary=summary)


@app.route("/search", methods=["GET", "POST"])
def search():
    user = login_required()
    if not user:
        return redirect(url_for("login"))

    search_term = ""
    results = []
    output = ""

    if request.method == "POST":
        search_term = request.form.get("search_term", "")
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT records.*, users.username
            FROM records
            JOIN users ON users.id = records.user_id
            WHERE users.username LIKE ? OR records.subject LIKE ?
            ORDER BY users.username, records.subject
            """,
            (f"%{search_term}%", f"%{search_term}%"),
        )
        results = cur.fetchall()
        conn.close()
        output = Markup(f"You searched for: {search_term}")
        write_log(f"vulnerable search query={search_term}", user["id"])

    note = "Vulnerable search: renders user input as safe HTML, so reflected XSS can execute."
    return render_template("search.html", results=results, search_term=search_term, output=output, vulnerable=True, note=note)


@app.route("/secure-search", methods=["GET", "POST"])
def secure_search():
    user = login_required()
    if not user:
        return redirect(url_for("login"))

    search_term = ""
    results = []
    output = ""

    if request.method == "POST":
        search_term = request.form.get("search_term", "")[:80]
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT records.*, users.username
            FROM records
            JOIN users ON users.id = records.user_id
            WHERE users.username LIKE ? OR records.subject LIKE ?
            ORDER BY users.username, records.subject
            """,
            (f"%{search_term}%", f"%{search_term}%"),
        )
        results = cur.fetchall()
        conn.close()
        output = f"You searched for: {search_term}"
        write_log(f"secure search query={search_term}", user["id"])

    note = "Secure search: user input is escaped by the template engine."
    return render_template("search.html", results=results, search_term=search_term, output=output, vulnerable=False, note=note)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    user = admin_required()
    if not user:
        return redirect(url_for("login"))

    message = ""
    error = ""
    mode = request.args.get("mode", "secure")
    students = get_students()

    if request.method == "POST":
        mode = request.form.get("mode", "secure")
        user_id = request.form.get("user_id", "")
        subject = request.form.get("subject", "")
        marks = request.form.get("marks", "")
        attendance = request.form.get("attendance", "")

        if mode == "vulnerable":
            conn = get_db()
            cur = conn.cursor()
            try:
                # Convert to integers, or use 0 if conversion fails (demonstrating vulnerability)
                try:
                    marks_val = int(marks) if marks else 0
                except ValueError:
                    marks_val = 0
                try:
                    attendance_val = int(attendance) if attendance else 0
                except ValueError:
                    attendance_val = 0
                
                cur.execute(
                    "INSERT INTO records (user_id, subject, marks, attendance) VALUES (?, ?, ?, ?)",
                    (user_id, subject, marks_val, attendance_val),
                )
                conn.commit()
                conn.close()
                write_log(f"vulnerable admin added record subject={subject}", user["id"])
                message = "Record added through vulnerable form with no validation."
            except Exception as exc:
                conn.close()
                message = f"Error (this is expected if validation is missing): {str(exc)}"
                write_log(f"vulnerable admin error: {exc}", user["id"])
        else:
            errors = []
            if not user_id.isdigit():
                errors.append("Select a valid student.")
            if not (1 <= len(subject.strip()) <= 50):
                errors.append("Subject must be 1 to 50 characters.")
            if not marks.isdigit() or not (0 <= int(marks) <= 100):
                errors.append("Marks must be between 0 and 100.")
            if not attendance.isdigit() or not (0 <= int(attendance) <= 100):
                errors.append("Attendance must be between 0 and 100.")

            if errors:
                error = " ".join(errors)
                write_log(f"secure admin validation failed: {error}", user["id"])
            else:
                conn = get_db()
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO records (user_id, subject, marks, attendance) VALUES (?, ?, ?, ?)",
                    (int(user_id), subject.strip(), int(marks), int(attendance)),
                )
                conn.commit()
                conn.close()
                write_log(f"secure admin added record subject={subject.strip()}", user["id"])
                message = "Record added securely after validation."

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT records.*, users.username
        FROM records
        JOIN users ON users.id = records.user_id
        ORDER BY records.id DESC
        """
    )
    records = cur.fetchall()
    conn.close()

    return render_template("admin.html", user=user, students=students, records=records, mode=mode, message=message, error=error)


@app.route("/logout")
def logout():
    if "user_id" in session:
        write_log("logout", session["user_id"])
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(_error):
    return render_template("403.html"), 403


if __name__ == "__main__":
    app.run(debug=True)
