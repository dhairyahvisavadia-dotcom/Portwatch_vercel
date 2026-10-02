"""
PortWatch — Production Application Factory & Runtime Orchestrator.
Enterprise network hardware monitor for mobile hotspots, IoT devices,
and dynamic wireless clients.
"""

import logging
import sys
import threading
from typing import Optional, Type

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    url_for,
)

import auth_db
import config
import db
from extensions import csrf, limiter
from routes import register_routes
from routes.auth import (
    current_user_id,
    get_safe_redirect,
    is_valid_mac,
    login_required,
)
from scanner_service import (
    ACTIVE_USER_IDS,
    LATEST_SCANNED_DEVICES,
    LATEST_SEEN_MACS,
    SCAN_INTERVAL_SECONDS,
    STATUS,
    build_device_record,
    fast_scan,
    scan_loop,
    scan_once,
    sync_scan_results_to_db,
)

# Structured Application Logging
logger = logging.getLogger("portwatch")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def create_app(config_class: Optional[Type[config.BaseConfig]] = None) -> Flask:
    """Application Factory initializing Flask with configuration, security middleware,
    extensions, global error handlers, and modular blueprints.
    """
    app = Flask(__name__)

    # Load configuration
    cfg = config_class if config_class is not None else config.get_config()
    app.config.from_object(cfg)

    # Initialize persistence databases
    auth_db.init_auth_db()
    db.init_db()

    # Automatically seed demo telemetry in demo / cloud environments
    if app.config.get("DEMO_MODE"):
        try:
            from scripts.seed_demo_data import seed_demo_network
            seed_demo_network()
        except Exception as seed_err:
            logger.warning(f"Could not auto-seed demo telemetry: {seed_err}")

    # Initialize security extensions
    csrf.init_app(app)
    limiter.init_app(app)

    # Security Headers Middleware
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if request.path.startswith("/api/") or request.path in ("/account", "/dashboard"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    # Global Error Handlers (Structured JSON for APIs, Brutalist HTML for Browser)
    @app.errorhandler(400)
    def bad_request_handler(e):
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "Bad Request",
                "status_code": 400,
                "message": getattr(e, "description", "Invalid or malformed request payload."),
            }), 400
        return render_template("404.html", error=getattr(e, "description", "Bad Request")), 400

    @app.errorhandler(404)
    def not_found_handler(e):
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "Not Found",
                "status_code": 404,
                "message": "The requested API endpoint does not exist.",
            }), 404
        return render_template("404.html"), 404

    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "Rate Limit Exceeded",
                "status_code": 429,
                "message": "Too many requests. Please wait a moment before retrying.",
            }), 429
        next_url = get_safe_redirect(request.args.get("next") or url_for("dashboard"))
        return render_template(
            "login.html",
            error="Too many requests. Please wait a minute and try again.",
            next=next_url,
        ), 429

    @app.errorhandler(500)
    def server_error_handler(e):
        logger.error(f"Internal server error on {request.path}: {e}")
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "Internal Server Error",
                "status_code": 500,
                "message": "An unexpected server condition occurred.",
            }), 500
        return render_template("500.html"), 500

    # Register modular blueprints and endpoint aliases
    register_routes(app)

    return app


# Default application instance for WSGI servers and automated test runners
app = create_app()

SESSION_MINUTES = config.BaseConfig.SESSION_MINUTES
PORTWATCH_SECRET_KEY = app.secret_key

# Module exports for 100% backward compatibility with existing tests and scripts
__all__ = [
    "app",
    "create_app",
    "csrf",
    "limiter",
    "STATUS",
    "ACTIVE_USER_IDS",
    "LATEST_SCANNED_DEVICES",
    "LATEST_SEEN_MACS",
    "SCAN_INTERVAL_SECONDS",
    "SESSION_MINUTES",
    "build_device_record",
    "fast_scan",
    "scan_once",
    "scan_loop",
    "sync_scan_results_to_db",
    "login_required",
    "current_user_id",
    "get_safe_redirect",
    "is_valid_mac",
]


if __name__ == "__main__":
    threading.Thread(target=scan_loop, daemon=True).start()
    logger.info("Launching PortWatch server on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
