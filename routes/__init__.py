"""
routes/__init__.py — Blueprint registration & URL routing orchestrator for PortWatch.
Registers views, auth, and dual-mounted versioned API blueprints (/api and /api/v1)
while preserving top-level URL aliases for seamless backward compatibility.
"""

from flask import Flask

from routes.api import api_bp
from routes.auth import (
    account,
    auth_bp,
    change_password,
    login,
    logout,
    signup,
)
from routes.views import (
    about,
    connections,
    dashboard,
    landing,
    map3d,
    nearby,
    views_bp,
)


def register_routes(app: Flask) -> None:
    """Register all modular blueprints and configure top-level alias endpoints."""
    # Register core blueprints
    app.register_blueprint(views_bp)
    app.register_blueprint(auth_bp)

    # Mount API under both standard /api and versioned /api/v1 prefixes
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(api_bp, url_prefix="/api/v1", name="api_v1")

    # Configure top-level endpoint aliases so templates and tests calling
    # url_for('dashboard') and url_for('views.dashboard') resolve identically.
    aliases = {
        "landing": ("/", landing, ["GET"]),
        "dashboard": ("/dashboard", dashboard, ["GET"]),
        "connections": ("/connections", connections, ["GET"]),
        "map3d": ("/map3d", map3d, ["GET"]),
        "nearby": ("/nearby", nearby, ["GET"]),
        "about": ("/about", about, ["GET"]),
        "login": ("/login", login, ["GET", "POST"]),
        "signup": ("/signup", signup, ["GET", "POST"]),
        "logout": ("/logout", logout, ["GET"]),
        "account": ("/account", account, ["GET", "POST"]),
        "change_password": ("/change-password", change_password, ["GET", "POST"]),
    }

    for endpoint, (rule, func, methods) in aliases.items():
        if endpoint not in app.view_functions:
            app.add_url_rule(rule, endpoint=endpoint, view_func=func, methods=methods)


__all__ = ["views_bp", "auth_bp", "api_bp", "register_routes"]
