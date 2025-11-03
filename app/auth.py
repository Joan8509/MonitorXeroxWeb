import sqlite3, os
from functools import wraps
from flask import session, redirect, url_for, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

AUTH_DB_PATH = os.getenv("AUTH_DB_PATH", "auth.db")

def _db():
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_auth_db():
    with _db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""")

def bootstrap_admin_from_env():
    user = os.getenv("ADMIN_USER")
    pw = os.getenv("ADMIN_PASSWORD")
    if user and pw:
        with _db() as conn:
            row = conn.execute("SELECT 1 FROM users WHERE username=?", (user,)).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (user, generate_password_hash(pw))
                )
                print(f"[bootstrap] Created admin user '{user}' from ENV")

def verify_user(username, password):
    with _db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return False
        return check_password_hash(row["password_hash"], password)

def find_user_id(username):
    with _db() as conn:
        row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        return int(row["id"]) if row else None

def update_username(user_id, new_username):
    try:
        with _db() as conn:
            conn.execute("UPDATE users SET username=? WHERE id=?", (new_username.strip(), user_id))
        return None
    except sqlite3.IntegrityError:
        return "Username already exists."

def update_password(user_id, new_password):
    with _db() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                     (generate_password_hash(new_password), user_id))

def login_required(endpoint_name=""):
    def deco(fn):
        @wraps(fn)
        def _wrap(*args, **kwargs):
            if not session.get("user_id"):
                if request.path.startswith("/api/") or request.headers.get("Accept", "").startswith("application/json"):
                    return jsonify({"error": "Unauthorized"}), 401
                nxt = request.full_path if request.query_string else request.path
                return redirect(url_for("routes.login", next=nxt))
            return fn(*args, **kwargs)
        return _wrap
    return deco
