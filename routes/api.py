"""
routes/api.py — REST API & Telemetry Blueprint for PortWatch.
Handles device inventory, live Wi-Fi measurements, hardware lookup,
deep service fingerprinting, on-demand rescans, and database health telemetry.
Supports dual-mounted versioned access via /api/ and /api/v1/.
"""

import csv
import io
import html
import json
import logging
import time

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
    send_file,
)

import auth_db
import database
import db
import device_scan
import device_service
from extensions import limiter
from routes.auth import current_user_id, is_valid_mac, login_required
from scanner_service import (
    ACTIVE_USER_IDS,
    STATUS,
    fast_scan,
    scan_once,
    sync_scan_results_to_db,
)

logger = logging.getLogger("portwatch.api")
api_bp = Blueprint("api", __name__)


@api_bp.route("/health")
def api_health():
    """System & Database Health Check telemetry endpoint for cloud & uptime monitoring."""
    db_health = database.check_database_health()
    is_healthy = db_health.get("status") == "healthy"
    return jsonify({
        "status": "healthy" if is_healthy else "degraded",
        "timestamp": time.time(),
        "database": db_health,
        "active_users": len(ACTIVE_USER_IDS),
        "scanning": STATUS.get("scanning", False),
    }), 200 if is_healthy else 503


@api_bp.route("/status")
@login_required
def api_status():
    """Returns current subnet detection and scanning state."""
    uid = current_user_id()
    if uid:
        ACTIVE_USER_IDS.add(uid)
    return jsonify({**STATUS, "count": db.get_online_count(user_id=uid)})


@api_bp.route("/user/me")
@login_required
def api_user_me():
    """Returns profile metadata and active session parameters for the current user."""
    uid = current_user_id()
    user = auth_db.get_user_by_id(uid)
    if not user:
        return jsonify({"error": "User not found"}), 404
    activity = auth_db.get_recent_activity(uid, days=3)
    session_minutes = current_app.config.get("SESSION_MINUTES", 2)
    return jsonify({
        "user": user,
        "activity_count": len(activity),
        "session_timeout_minutes": session_minutes,
    })


@api_bp.route("/activity")
@login_required
def api_activity():
    """Returns recent security and management activity log records."""
    return jsonify(auth_db.get_recent_activity(current_user_id(), days=3))


@api_bp.route("/devices")
@login_required
def api_devices():
    """Returns all network devices recorded for the authenticated user."""
    uid = current_user_id()
    if uid:
        ACTIVE_USER_IDS.add(uid)

    from scanner_service import LATEST_SCANNED_DEVICES, LATEST_SEEN_MACS
    if not current_app.config.get("TESTING"):
        if not LATEST_SCANNED_DEVICES:
            fast_scan(sync_db=True, user_id=uid)
        elif LATEST_SCANNED_DEVICES:
            sync_scan_results_to_db(LATEST_SCANNED_DEVICES, LATEST_SEEN_MACS, user_ids=uid)

    devs = db.get_all(user_id=uid)
    return jsonify(devs)


@api_bp.route("/devices/<mac>/timeline")
@login_required
def api_device_timeline(mac: str):
    """Retrieve full historical timeline and lifecycle events for a specific MAC address."""
    if not is_valid_mac(mac):
        return jsonify({"error": "Invalid MAC address format"}), 400
    uid = current_user_id()
    timeline = db.get_device_timeline(mac, user_id=uid)
    if not timeline:
        return jsonify({"error": "Device not found"}), 404
    return jsonify(timeline)


@api_bp.route("/devices/lookup", methods=["GET", "POST"])
@login_required
def api_device_lookup():
    """Locate any device by MAC address or IP address across active nodes and historical database."""
    uid = current_user_id()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        query = data.get("query") or data.get("mac") or data.get("ip") or ""
    else:
        query = request.args.get("q") or request.args.get("mac") or request.args.get("ip") or ""

    is_testing = bool(current_app.config.get("TESTING") or current_app.testing)
    _, payload, status_code = device_service.lookup_device(query, user_id=uid, is_testing=is_testing)
    return jsonify(payload), status_code


@api_bp.route("/devices/<mac>/deep-scan", methods=["POST"])
@limiter.limit("15 per minute", exempt_when=lambda: bool(current_app.config.get("TESTING") or current_app.testing))
@login_required
def api_device_deep_scan(mac: str):
    """Trigger on-demand deep fingerprinting (Nmap / socket service probe) for a device."""
    if not is_valid_mac(mac):
        return jsonify({"error": "Invalid MAC address format"}), 400
    uid = current_user_id()
    _, payload, status_code = device_service.perform_device_deep_scan(mac, user_id=uid)
    return jsonify(payload), status_code


@api_bp.route("/rescan", methods=["POST"])
@limiter.limit("12 per minute", exempt_when=lambda: bool(current_app.config.get("TESTING") or current_app.testing))
@login_required
def api_rescan():
    """Trigger immediate parallel ARP sweep and launch asynchronous subnet background ping-sweep."""
    import threading
    uid = current_user_id()
    if uid:
        ACTIVE_USER_IDS.add(uid)

    fast_scan(sync_db=True, user_id=uid)
    threading.Thread(target=lambda: scan_once(user_id=uid), daemon=True).start()
    auth_db.log_activity(uid, "rescan", "manual rescan triggered")
    return jsonify({"ok": True})


@api_bp.route("/devices/<mac>", methods=["PATCH"])
@login_required
def api_label_device(mac: str):
    """Manually update a device's display name or device type."""
    if not is_valid_mac(mac):
        return jsonify({"error": "Invalid MAC address format"}), 400
    mac = mac.upper()
    uid = current_user_id()
    data = request.get_json(force=True)
    raw_name = data.get("name")
    raw_type = data.get("type")
    cleaned_name = html.escape(str(raw_name).strip())[:64] if raw_name is not None else None
    cleaned_type = html.escape(str(raw_type).strip().lower())[:32] if raw_type is not None else None
    db.set_label(mac, cleaned_name, cleaned_type, user_id=uid)
    auth_db.log_activity(uid, "relabel_device", f"{mac} -> {cleaned_name} ({cleaned_type})")
    return jsonify({"ok": True})


@api_bp.route("/devices/<mac>", methods=["DELETE"])
@login_required
def api_forget_device(mac: str):
    """Permanently delete a device and its history from the user's isolated inventory."""
    if not is_valid_mac(mac):
        return jsonify({"error": "Invalid MAC address format"}), 400
    mac = mac.upper()
    uid = current_user_id()
    db.forget_device(mac, user_id=uid)
    auth_db.log_activity(uid, "forget_device", mac)
    return jsonify({"ok": True})


@api_bp.route("/local-wifi")
@login_required
def api_local_wifi():
    """Live scan of networks the host Wi-Fi interface can currently hear."""
    try:
        results = device_scan.scan_wifi_networks()
        return jsonify({"results": results})
    except Exception as e:
        logger.error(f"Wi-Fi scan failed: {e}")
        return jsonify({"error": f"Could not scan WiFi: {e}"}), 500


@api_bp.route("/export/json")
@login_required
def api_export_json():
    """Export device inventory and network state as formatted JSON."""
    uid = current_user_id()
    auth_db.log_activity(uid, "export_json", "Exported device list to JSON")
    payload = {
        "exported_at": time.time(),
        "subnet": STATUS["subnet"],
        "own_connection": STATUS["own_connection"],
        "devices": db.get_all(user_id=uid),
        "limitations": [
            "Vendor identification uses the comprehensive IEEE OUI database (58,000+ entries) with local overrides.",
            "Device type is derived from multi-signal correlation (vendor, hostname, open ports, TTL baseline).",
            "Distance is estimated using an empirical Wi-Fi RTT propagation model.",
            "Bandwidth capacity is estimated based on RTT turnaround latency and 802.11 modulation index downshifts.",
        ],
    }
    buf = io.BytesIO(json.dumps(payload, indent=2).encode())
    return send_file(
        buf,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"portwatch_export_{int(time.time())}.json",
    )


@api_bp.route("/export/csv")
@login_required
def api_export_csv():
    """Export device inventory as downloadable CSV spreadsheet."""
    uid = current_user_id()
    auth_db.log_activity(uid, "export_csv", "Exported device list to CSV")
    devices = db.get_all(user_id=uid)
    buf = io.StringIO()
    fieldnames = [
        "mac",
        "ip",
        "name",
        "vendor",
        "type",
        "hostname",
        "online",
        "first_seen",
        "last_seen",
        "ttl",
        "ttl_confidence",
        "rtt_ms",
        "rtt_distance_m",
        "distance_band",
        "bandwidth_mbps",
        "bandwidth_grade",
        "open_ports",
        "os_guess",
        "likely_hotspot",
        "hotspot_note",
        "vendor_confidence",
        "vendor_source",
        "type_confidence",
        "type_reason",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for d in devices:
        writer.writerow(d)
    mem = io.BytesIO(buf.getvalue().encode())
    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"portwatch_export_{int(time.time())}.csv",
    )
