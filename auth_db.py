"""
auth_db.py
Real multi-user authentication for PortWatch, backed by SQLite
(portwatch_auth.db, created automatically next to app.py).

Replaces the old single-shared admin/portwatch login with actual user
accounts: anyone can sign up, each account has its own password, and
each user's recent activity (logins, rescans, renames...) is recorded
and kept for 3 days, then automatically pruned.

Passwords are hashed with werkzeug's generate_password_hash (never
stored in plaintext). This is still a local/personal-use auth system --
good enough for a project demo or small team, not audited for
production-grade multi-tenant security.
"""

import os
import re
import sqlite3
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

import database

if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DB_FILE = "/tmp/portwatch_auth.db"
else:
    DB_FILE = os.path.join(os.path.dirname(__file__), "portwatch_auth.db")
ACTIVITY_RETENTION_SECONDS = 3 * 24 * 60 * 60  # 3 days
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 15 * 60  # 15 minutes

# Dummy password hash used to mitigate timing side-channels when checking non-existent users
_DUMMY_HASH = generate_password_hash("dummy-credential-for-timing-defense")

_lock = threading.Lock()


def _connect():
    if database.is_cloud_db_active():
        return database.get_cloud_connection()
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db():
    if database.is_cloud_db_active():
        database.init_all_tables()
        return

    with _lock:
        conn = _connect()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT DEFAULT '',
                password_hash TEXT NOT NULL,
                created_at REAL,
                last_login_at REAL,
                last_ip TEXT DEFAULT '',
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                detail TEXT,
                timestamp REAL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        for col_def in [
            "email TEXT DEFAULT ''",
            "last_ip TEXT DEFAULT ''",
            "failed_login_attempts INTEGER DEFAULT 0",
            "locked_until REAL DEFAULT 0",
        ]:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass
        conn.commit()
        conn.close()


class UsernameTaken(Exception):
    pass


class WeakPassword(Exception):
    pass


class AccountLocked(Exception):
    pass


def validate_username(username):
    """Enforces minimum length, maximum length, and allowed characters for usernames."""
    username = (username or "").strip()
    if len(username) < 3:
        raise WeakPassword("Username must be at least 3 characters.")
    if len(username) > 32:
        raise WeakPassword("Username cannot exceed 32 characters.")
    if not re.match(r"^[A-Za-z0-9_.-]+$", username):
        raise WeakPassword("Username may only contain letters, numbers, dots, underscores, and hyphens.")
    return username


def validate_password_strength(password):
    """Enforces password length and complexity (letters + digits required)."""
    if len(password) < 6:
        raise WeakPassword("Password must be at least 6 characters.")
    if len(password) > 128:
        raise WeakPassword("Password cannot exceed 128 characters.")
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise WeakPassword("Password must contain both letters and numbers.")
    return True


def create_user(username, password, email="", ip=""):
    """Creates a new account. Raises UsernameTaken or WeakPassword on
    failure. Returns the new user's row (dict) on success."""
    username = validate_username(username)
    email = (email or "").strip()
    validate_password_strength(password)

    now = time.time()
    with _lock:
        conn = _connect()
        existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            conn.close()
            raise UsernameTaken(f'The username "{username}" is already taken.')
        cur = conn.execute(
            """
            INSERT INTO users (username, email, password_hash, created_at, last_login_at, last_ip, failed_login_attempts, locked_until)
            VALUES (?, ?, ?, ?, ?, ?, 0, 0)
            """,
            (username, email, generate_password_hash(password), now, now, ip or ""),
        )
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
    return {
        "id": user_id,
        "username": username,
        "email": email,
        "created_at": now,
        "last_login_at": now,
        "last_ip": ip or "",
    }


def verify_login(username, password, ip=""):
    """Returns the user's row (dict) on success, or None on invalid credentials.
    Raises AccountLocked if the account has exceeded failed login thresholds.
    Also mitigates timing side channels on non-existent users."""
    cleaned_username = (username or "").strip()
    now = time.time()
    with _lock:
        conn = _connect()
        row = conn.execute("SELECT * FROM users WHERE username=?", (cleaned_username,)).fetchone()
        if not row:
            conn.close()
            # Perform dummy hash verification to preserve constant timing
            check_password_hash(_DUMMY_HASH, password)
            return None

        keys = row.keys()
        locked_until = row["locked_until"] if "locked_until" in keys and row["locked_until"] else 0
        if locked_until > now:
            conn.close()
            remaining_mins = max(1, int((locked_until - now) / 60) + 1)
            raise AccountLocked(f"Account is temporarily locked due to multiple failed login attempts. Try again in {remaining_mins} minute(s).")

        if not check_password_hash(row["password_hash"], password):
            current_failures = (row["failed_login_attempts"] if "failed_login_attempts" in keys and row["failed_login_attempts"] else 0) + 1
            new_lockout = (now + LOCKOUT_DURATION_SECONDS) if current_failures >= MAX_FAILED_ATTEMPTS else 0
            conn.execute(
                "UPDATE users SET failed_login_attempts=?, locked_until=? WHERE id=?",
                (current_failures, new_lockout, row["id"]),
            )
            conn.commit()
            conn.close()
            if current_failures >= MAX_FAILED_ATTEMPTS:
                raise AccountLocked("Too many failed login attempts. Account temporarily locked for 15 minutes.")
            return None

        # Reset failed attempts on valid login
        conn.execute(
            "UPDATE users SET last_login_at=?, last_ip=?, failed_login_attempts=0, locked_until=0 WHERE id=?",
            (now, ip or "", row["id"]),
        )
        conn.commit()
        conn.close()

    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"] if "email" in keys else "",
        "created_at": row["created_at"],
        "last_login_at": now,
        "last_ip": ip or (row["last_ip"] if "last_ip" in keys else ""),
    }


def get_user_by_id(user_id):
    with _lock:
        conn = _connect()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        conn.close()
    if not row:
        return None
    keys = row.keys()
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"] if "email" in keys else "",
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
        "last_ip": row["last_ip"] if "last_ip" in keys else "",
    }


def get_user_by_username(username):
    cleaned = (username or "").strip()
    with _lock:
        conn = _connect()
        row = conn.execute("SELECT * FROM users WHERE username=?", (cleaned,)).fetchone()
        conn.close()
    if not row:
        return None
    keys = row.keys()
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"] if "email" in keys else "",
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
        "last_ip": row["last_ip"] if "last_ip" in keys else "",
    }


def change_password(user_id, current_password, new_password):
    """Returns (ok: bool, error_message_or_None)."""
    try:
        validate_password_strength(new_password)
    except WeakPassword as e:
        return False, str(e)

    if current_password == new_password:
        return False, "New password must be different from current password."

    with _lock:
        conn = _connect()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not check_password_hash(row["password_hash"], current_password):
            conn.close()
            return False, "Current password is incorrect."
        conn.execute(
            "UPDATE users SET password_hash=?, failed_login_attempts=0, locked_until=0 WHERE id=?",
            (generate_password_hash(new_password), user_id),
        )
        conn.commit()
        conn.close()
    return True, None


def user_count():
    with _lock:
        conn = _connect()
        n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
    return n


def log_activity(user_id, action, detail=""):
    """Records one activity event for a user. Also opportunistically
    prunes anything older than the 3-day retention window so the table
    doesn't grow forever."""
    now = time.time()
    with _lock:
        conn = _connect()
        conn.execute(
            "INSERT INTO activity_log (user_id, action, detail, timestamp) VALUES (?, ?, ?, ?)",
            (user_id, action, detail, now),
        )
        conn.execute("DELETE FROM activity_log WHERE timestamp < ?", (now - ACTIVITY_RETENTION_SECONDS,))
        conn.commit()
        conn.close()


def get_recent_activity(user_id, days=3):
    """This user's activity from the last `days` days, newest first."""
    cutoff = time.time() - days * 24 * 60 * 60
    with _lock:
        conn = _connect()
        rows = conn.execute(
            "SELECT * FROM activity_log WHERE user_id=? AND timestamp >= ? ORDER BY timestamp DESC",
            (user_id, cutoff),
        ).fetchall()
        conn.close()
    return [{"action": r["action"], "detail": r["detail"], "timestamp": r["timestamp"]} for r in rows]
