"""
routes/auth.py — Authentication Blueprint for PortWatch.
Handles user registration, authentication, sessions, account profiles,
and password management with brute-force protection.
"""

import functools
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import auth_db
from extensions import limiter
from scanner_service import ACTIVE_USER_IDS

auth_bp = Blueprint("auth", __name__)

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def is_valid_mac(mac: str) -> bool:
    """Validates that a MAC address has standard 6-octet hexadecimal format."""
    return bool(mac and MAC_REGEX.match(mac.strip()))


def get_safe_redirect(target_url: str, default: str = "dashboard") -> str:
    """Prevents Open Redirect vulnerabilities by verifying the target URL is local."""
    if not target_url:
        return url_for(default)
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target_url))
    if test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc:
        return target_url
    return url_for(default)


def current_user_id():
    """Retrieve currently authenticated user's ID from session."""
    return session.get("user_id")


def login_required(view):
    """Enforces authentication and refreshes sliding activity session lifetime."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        session.permanent = True
        uid = session.get("user_id")
        if uid:
            ACTIVE_USER_IDS.add(uid)
        return view(*args, **kwargs)
    return wrapped


@auth_bp.route("/signup", methods=["GET", "POST"])
@limiter.limit("10 per minute", exempt_when=lambda: bool(current_app.config.get("TESTING") or current_app.testing))
def signup():
    raw_next = request.args.get("next") or request.form.get("next") or url_for("dashboard")
    next_url = get_safe_redirect(raw_next)
    if request.method == "POST":
        username = request.form.get("username", "")
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if password != confirm:
            return render_template("signup.html", error="Passwords don't match.", next=next_url)
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        try:
            user = auth_db.create_user(username, password, email=email, ip=client_ip)
        except (auth_db.UsernameTaken, auth_db.WeakPassword) as e:
            return render_template("signup.html", error=str(e), next=next_url)

        session["logged_in"] = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["email"] = user.get("email", "")
        session.permanent = True
        ACTIVE_USER_IDS.add(user["id"])
        auth_db.log_activity(user["id"], "signup", "Account created")
        auth_db.log_activity(user["id"], "login", f"Initial login from {client_ip or 'localhost'}")
        return redirect(get_safe_redirect(next_url))

    return render_template("signup.html", error=None, next=next_url)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per minute", exempt_when=lambda: bool(current_app.config.get("TESTING") or current_app.testing))
def login():
    raw_next = request.args.get("next") or request.form.get("next") or url_for("dashboard")
    next_url = get_safe_redirect(raw_next)
    timeout = request.args.get("timeout")
    prompt = request.args.get("prompt")
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        try:
            user = auth_db.verify_login(username, password, ip=client_ip)
            if user:
                session["logged_in"] = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["email"] = user.get("email", "")
                session.permanent = True
                ACTIVE_USER_IDS.add(user["id"])
                auth_db.log_activity(user["id"], "login", f"Logged in from {client_ip or 'localhost'}")
                return redirect(get_safe_redirect(next_url))
            error = "Incorrect username or password."
        except auth_db.AccountLocked as e:
            error = str(e)
    return render_template("login.html", error=error, next=next_url, timeout=timeout, prompt=prompt)


@auth_bp.route("/logout")
def logout():
    timed_out = request.args.get("timeout")
    uid = current_user_id()
    if uid:
        ACTIVE_USER_IDS.discard(uid)
        if timed_out:
            auth_db.log_activity(uid, "logout", "Session expired due to inactivity")
        else:
            auth_db.log_activity(uid, "logout", "Manual logout")
    session.clear()
    if timed_out:
        return redirect(url_for("login", timeout="1"))
    return redirect(url_for("landing"))


@auth_bp.route("/account", methods=["GET", "POST"])
@limiter.limit("20 per minute", exempt_when=lambda: bool(current_app.config.get("TESTING") or current_app.testing))
@login_required
def account():
    uid = current_user_id()
    user = auth_db.get_user_by_id(uid)
    if not user:
        return redirect(url_for("logout"))

    error = None
    success = None
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if new != confirm:
            error = "New passwords don't match."
        else:
            ok, err = auth_db.change_password(uid, current, new)
            if ok:
                success = "Password updated successfully."
                auth_db.log_activity(uid, "change_password", "Password updated successfully")
            else:
                error = err

    activity = auth_db.get_recent_activity(uid, days=3)
    for item in activity:
        ts = item.get("timestamp", 0)
        item["time_str"] = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"

    user_created_str = (
        datetime.fromtimestamp(user["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        if user.get("created_at")
        else "N/A"
    )
    user_last_login_str = (
        datetime.fromtimestamp(user["last_login_at"]).strftime("%Y-%m-%d %H:%M:%S")
        if user.get("last_login_at")
        else "N/A"
    )

    return render_template(
        "account.html",
        user=user,
        user_created_str=user_created_str,
        user_last_login_str=user_last_login_str,
        activity=activity,
        error=error,
        success=success,
    )


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    return redirect(url_for("account"))
