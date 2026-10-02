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
import re
import subprocess
import time
from typing import Any, Dict

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
from extensions import limiter
from routes.auth import current_user_id, is_valid_mac, login_required
from scanner_service import (
    ACTIVE_USER_IDS,
    STATUS,
    build_device_record,
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

    query = query.strip()
    if not query:
        return jsonify({"ok": False, "error": "Please provide a MAC or IP address to search."}), 400

    devs = db.get_all(user_id=uid)
    q_upper = query.upper()
    q_clean_mac = re.sub(r"[:-]", "", q_upper)

    matched = None
    # 1. Exact MAC match
    for d in devs:
        d_mac = d["mac"].upper()
        if d_mac == q_upper or re.sub(r"[:-]", "", d_mac) == q_clean_mac:
            matched = d
            break

    # 2. Exact IP match
    if not matched:
        for d in devs:
            if d.get("ip") == query:
                matched = d
                break

    # 3. Partial match on name / hostname / IP / MAC
    if not matched:
        for d in devs:
            if (
                query.lower() in (d.get("name") or "").lower()
                or query.lower() in (d.get("hostname") or "").lower()
                or query.lower() in (d.get("ip") or "").lower()
                or q_upper in d.get("mac", "").upper()
            ):
                matched = d
                break

    is_new = False
    if not matched:
        is_new = True
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query))
        is_mac = bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", query)) or len(q_clean_mac) == 12

        if is_ip:
            target_ip = query
            arp_table = dict(device_scan.read_arp_table())
            target_mac = arp_table.get(target_ip, "")
            if not target_mac:
                target_mac = f"02:00:00:{target_ip.replace('.', ':')}"[:17].upper()

            record = build_device_record(target_ip, target_mac)
            db.upsert_scan(
                target_mac,
                target_ip,
                record["vendor"],
                record["type"],
                record["hostname"],
                ttl=record.get("ttl"),
                likely_hotspot=record.get("likely_hotspot", False),
                hotspot_note=record.get("hotspot_note", ""),
                rtt_ms=record.get("rtt_ms"),
                rtt_distance_m=record.get("rtt_distance_m"),
                distance_band=record.get("distance_band", ""),
                bandwidth_mbps=record.get("bandwidth_mbps"),
                bandwidth_grade=record.get("bandwidth_grade", ""),
                user_id=uid,
            )
            db.log_timeline_event(
                target_mac, "discovered", f"Located and added via IP search ({target_ip})", user_id=uid
            )
            matched = next((d for d in db.get_all(user_id=uid) if d["mac"].upper() == target_mac.upper()), None)
        elif is_mac:
            import vendor_lookup
            if len(q_clean_mac) == 12:
                target_mac = ":".join(q_clean_mac[i:i + 2] for i in range(0, 12, 2))
            else:
                target_mac = q_upper.replace("-", ":")

            v_info = vendor_lookup.lookup_vendor_detailed(target_mac)
            vendor_name = v_info.get("vendor") or "Unknown"

            arp_table = dict(device_scan.read_arp_table())
            found_ip = ""
            for ip_addr, mac_addr in arp_table.items():
                if mac_addr.upper() == target_mac.upper():
                    found_ip = ip_addr
                    break

            if found_ip:
                record = build_device_record(found_ip, target_mac)
                db.upsert_scan(
                    target_mac,
                    found_ip,
                    record["vendor"],
                    record["type"],
                    record["hostname"],
                    ttl=record.get("ttl"),
                    rtt_ms=record.get("rtt_ms"),
                    rtt_distance_m=record.get("rtt_distance_m"),
                    distance_band=record.get("distance_band", ""),
                    bandwidth_mbps=record.get("bandwidth_mbps"),
                    bandwidth_grade=record.get("bandwidth_grade", ""),
                    user_id=uid,
                )
            else:
                db.upsert_scan(target_mac, "", vendor_name, "unknown", "", user_id=uid)
                db.mark_offline_except([], user_id=uid)

            db.log_timeline_event(
                target_mac, "discovered", f"Located and registered via MAC search ({target_mac})", user_id=uid
            )
            matched = next((d for d in db.get_all(user_id=uid) if d["mac"].upper() == target_mac.upper()), None)
        else:
            return jsonify({
                "ok": False,
                "found": False,
                "message": f"No device matching '{query}' found. Please enter a valid MAC or IPv4 address.",
            }), 404

    if not matched:
        return jsonify({"ok": False, "found": False, "message": "Device could not be located."}), 404

    # Live ping check to get instantaneous fresh latency and distance
    if matched.get("ip") and not current_app.config.get("TESTING"):
        try:
            ping_res = subprocess.run(
                ["ping", "-n", "1", "-w", "250", matched["ip"]],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            m_rtt = re.search(r"time[<=](\d+)ms", ping_res.stdout, re.IGNORECASE)
            if m_rtt:
                live_rtt = float(m_rtt.group(1))
                dist_m, dist_band, _, _ = device_scan.estimate_distance_from_rtt(live_rtt)
                bw_mbps, bw_grade, _ = device_scan.estimate_bandwidth(live_rtt)
                matched["rtt_ms"] = live_rtt
                matched["rtt_distance_m"] = dist_m
                matched["distance_band"] = dist_band
                matched["bandwidth_mbps"] = bw_mbps
                matched["bandwidth_grade"] = bw_grade
                matched["online"] = True
                db.upsert_scan(
                    matched["mac"],
                    matched["ip"],
                    matched["vendor"],
                    matched["type"],
                    matched["hostname"],
                    rtt_ms=live_rtt,
                    rtt_distance_m=dist_m,
                    distance_band=dist_band,
                    bandwidth_mbps=bw_mbps,
                    bandwidth_grade=bw_grade,
                    user_id=uid,
                )
        except Exception as e:
            logger.debug(f"Instantaneous ping check error: {e}")

    timeline = db.get_device_timeline(matched["mac"], user_id=uid)
    is_online = bool(matched.get("online"))
    dist_m = matched.get("rtt_distance_m")
    dist_band = matched.get("distance_band") or ("Nearby (~1-3m)" if is_online else "Out of Range (Offline)")
    rtt_ms = matched.get("rtt_ms")

    location_info = {
        "is_online": is_online,
        "distance_m": dist_m,
        "distance_formatted": f"~{dist_m}m" if dist_m is not None else ("~1.5m (Direct Radio Link)" if is_online else "Out of Immediate Range"),
        "distance_band": dist_band,
        "rtt_ms": rtt_ms,
        "rtt_formatted": f"{rtt_ms} ms" if rtt_ms is not None else ("< 5 ms" if is_online else "No ping reply"),
        "status_label": "Online / Connected to Hotspot" if is_online else "Offline / In Orbit",
        "topology_zone": "Direct Wi-Fi Link (Fanout Right)" if is_online else "Outer Orbital Ring (No Active Link)",
        "coordinates_hint": "Mapped radially from central LAPTOP by ping latency RTT" if is_online else "Floating in orbital ring (unconnected)",
        "map3d_url": f"/map3d?mac={matched['mac']}",
        "connections_url": f"/connections?mac={matched['mac']}",
    }

    return jsonify({
        "ok": True,
        "found": True,
        "is_new": is_new,
        "device": matched,
        "location": location_info,
        "timeline": timeline,
    })


@api_bp.route("/devices/<mac>/deep-scan", methods=["POST"])
@limiter.limit("15 per minute", exempt_when=lambda: bool(current_app.config.get("TESTING") or current_app.testing))
@login_required
def api_device_deep_scan(mac: str):
    """Trigger on-demand deep fingerprinting (Nmap / socket service probe) for a device."""
    if not is_valid_mac(mac):
        return jsonify({"error": "Invalid MAC address format"}), 400
    uid = current_user_id()
    mac = mac.upper()
    devs = db.get_all(user_id=uid)
    target = next((d for d in devs if d["mac"].upper() == mac), None)
    if not target or not target.get("ip"):
        return jsonify({"error": "Device IP not available for scanning"}), 404

    ip = target["ip"]
    fp = device_scan.deep_fingerprint_device(ip)
    if not fp:
        fp = {
            "engine": "socket_probe",
            "open_ports": [],
            "services": [],
            "os_guess": target.get("os_guess") or "",
            "type": target.get("type", "unknown"),
            "confidence": "low",
            "reason": "All standard service ports closed or filtered.",
            "target_ip": ip,
            "target_mac": mac,
            "target_name": target.get("name") or target.get("hostname") or "Unknown Device",
        }
        return jsonify({
            "ok": True,
            "message": "No open service ports identified",
            "fingerprint": fp,
            "device": target,
            "updated": False,
        })

    fp["target_ip"] = ip
    fp["target_mac"] = mac
    fp["target_name"] = target.get("name") or target.get("hostname") or "Device"

    open_ports_str = ",".join(str(p) for p in fp.get("open_ports", []))
    os_guess = fp.get("os_guess", "")
    new_type = fp.get("type") or target["type"]

    db.upsert_scan(
        mac,
        ip,
        target["vendor"],
        new_type,
        target["hostname"],
        ttl=target.get("ttl"),
        likely_hotspot=target.get("likely_hotspot", False),
        hotspot_note=target.get("hotspot_note", ""),
        rtt_ms=target.get("rtt_ms"),
        rtt_distance_m=target.get("rtt_distance_m"),
        distance_band=target.get("distance_band", ""),
        bandwidth_mbps=target.get("bandwidth_mbps"),
        bandwidth_grade=target.get("bandwidth_grade", ""),
        open_ports=open_ports_str,
        os_guess=os_guess,
        type_confidence=fp.get("confidence", "high"),
        type_reason=fp.get("reason", "Deep scan fingerprint"),
        user_id=uid,
    )

    db.log_timeline_event(
        mac,
        "deep_scan",
        f"Deep {fp.get('engine', 'probe')} scan: Ports [{open_ports_str}], OS: '{os_guess or 'n/a'}'",
        user_id=uid,
    )
    auth_db.log_activity(uid, "deep_scan", f"Deep scan on {mac} ({ip}) - {fp.get('engine')}")

    updated_dev = next((d for d in db.get_all(user_id=uid) if d["mac"].upper() == mac), None)
    return jsonify({"ok": True, "fingerprint": fp, "device": updated_dev})


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
