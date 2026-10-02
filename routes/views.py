"""
routes/views.py — Presentation & Template View Blueprint for PortWatch.
Renders landing, live dashboard, 2D topology, 3D orbital map, radio spectrum,
and methodology documentation.
"""

from flask import (
    Blueprint,
    Response,
    redirect,
    render_template,
    session,
    url_for,
)

import auth_db
from routes.auth import current_user_id, login_required

views_bp = Blueprint("views", __name__)


@views_bp.route("/")
def landing():
    """Landing showcase page presenting methodology, architecture, and live tool entrypoints."""
    return render_template("landing.html")


@views_bp.route("/dashboard")
@login_required
def dashboard():
    """Real-time network dashboard displaying discovered devices, latency, and telemetry."""
    auth_db.log_activity(current_user_id(), "view_dashboard", "Opened Live Dashboard")
    return render_template("index.html")


@views_bp.route("/connections")
@login_required
def connections():
    """2D vector topology connection fanout mapping devices to hotspot gateway."""
    auth_db.log_activity(current_user_id(), "view_connections", "Viewed 2D Connection Map")
    return render_template("connections.html")


@views_bp.route("/map3d")
@login_required
def map3d():
    """Interactive 3D orbital sphere visualization placing nodes radially by RF RTT distance."""
    auth_db.log_activity(current_user_id(), "view_map3d", "Viewed 3D Live Map")
    return render_template("map3d.html")


@views_bp.route("/nearby")
@login_required
def nearby():
    """Radio frequency spectrum scanner displaying adjacent Wi-Fi BSSIDs and signal strengths."""
    auth_db.log_activity(current_user_id(), "view_nearby", "Viewed Nearby WiFi Networks")
    return render_template("nearby.html")


@views_bp.route("/about")
@login_required
def about():
    """Defensible network engineering documentation and OUI resolution methodology."""
    auth_db.log_activity(current_user_id(), "view_about", "Viewed About / Methodology")
    return render_template("about.html")


@views_bp.route("/index")
def index_redirect():
    """Redirect helper routing authenticated users to dashboard and guests to landing."""
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("landing"))


@views_bp.route("/favicon.ico")
def favicon():
    """Serve embedded PW hardware monospace mark vector icon."""
    svg_icon = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect width="32" height="32" rx="6" fill="#000000"/>'
        '<text x="16" y="22" font-family="monospace" font-weight="900" font-size="14" fill="#FF7A18" text-anchor="middle">PW</text>'
        '</svg>'
    )
    return Response(svg_icon, mimetype="image/svg+xml")
