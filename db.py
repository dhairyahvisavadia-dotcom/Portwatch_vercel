"""
db.py
Persistent storage for PortWatch's device table and historical timeline.

SQLite database (portwatch.db) tracking:
- Device inventory (MAC, IP, Vendor, Guessed Type, Hostname, Custom Labels)
- First-seen & last-seen timestamps and historical session timeline
- RF propagation & latency metrics (TTL, RTT, estimated distance, estimated bandwidth)
- Device security fingerprinting (open ports, OS guess)
- Multi-user isolation and historical event audit logging
"""

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

import database

if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DB_FILE = "/tmp/portwatch.db"
else:
    DB_FILE = os.path.join(os.path.dirname(__file__), "portwatch.db")

_lock = threading.Lock()


def _connect():
    """Establish and configure raw connection to SQLite or Cloud database."""
    if database.is_cloud_db_active():
        return database.get_cloud_connection()
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    return conn


@contextmanager
def get_connection():
    """Context manager guaranteeing connection termination even during exceptions."""
    conn = _connect()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db() -> None:
    """Initialize schema tables and apply additive migrations."""
    if database.is_cloud_db_active():
        database.init_all_tables()
        return

    with _lock:
        with get_connection() as conn:
            # Check if devices table exists and if user_id column exists
            cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
            if "user_id" not in cols:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS devices_v2 (
                        user_id INTEGER NOT NULL DEFAULT 1,
                        mac TEXT NOT NULL,
                        ip TEXT,
                        vendor TEXT,
                        guessed_type TEXT,
                        hostname TEXT,
                        label_name TEXT,
                        label_type TEXT,
                        first_seen REAL,
                        last_seen REAL,
                        online INTEGER DEFAULT 0,
                        ttl INTEGER,
                        likely_hotspot INTEGER DEFAULT 0,
                        hotspot_note TEXT,
                        rtt_ms REAL,
                        rtt_distance_m REAL,
                        distance_band TEXT,
                        bandwidth_mbps REAL,
                        bandwidth_grade TEXT,
                        open_ports TEXT DEFAULT '',
                        os_guess TEXT DEFAULT '',
                        ttl_confidence TEXT,
                        vendor_confidence TEXT,
                        vendor_source TEXT,
                        type_confidence TEXT,
                        type_reason TEXT,
                        PRIMARY KEY (user_id, mac)
                    )
                    """
                )
                has_old = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices'").fetchone()
                if has_old:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO devices_v2 (
                            user_id, mac, ip, vendor, guessed_type, hostname, label_name, label_type,
                            first_seen, last_seen, online, ttl, likely_hotspot, hotspot_note,
                            rtt_ms, rtt_distance_m, distance_band, ttl_confidence, vendor_confidence,
                            vendor_source, type_confidence, type_reason
                        )
                        SELECT
                            1, mac, ip, vendor, guessed_type, hostname, label_name, label_type,
                            first_seen, last_seen, online, ttl, likely_hotspot, hotspot_note,
                            rtt_ms, rtt_distance_m, distance_band, ttl_confidence, vendor_confidence,
                            vendor_source, type_confidence, type_reason
                        FROM devices
                        """
                    )
                    conn.execute("DROP TABLE devices")
                conn.execute("ALTER TABLE devices_v2 RENAME TO devices")
                conn.commit()

            # Migrate any missing extra columns
            existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
            for col, decl in (
                ("rtt_distance_m", "REAL"),
                ("distance_band", "TEXT"),
                ("bandwidth_mbps", "REAL"),
                ("bandwidth_grade", "TEXT"),
                ("open_ports", "TEXT DEFAULT ''"),
                ("os_guess", "TEXT DEFAULT ''"),
            ):
                if col not in existing_cols:
                    conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {decl}")

            # Create device timeline events table for tracking device lifecycle history
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_timeline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    mac TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_timeline_lookup ON device_timeline_events(user_id, mac, timestamp DESC)"
            )
            conn.commit()


def log_timeline_event(
    mac: str,
    event_type: str,
    description: str,
    user_id: int = 1,
    now: Optional[float] = None,
) -> None:
    """Log an event in the device's historical lifecycle timeline."""
    now = now if now is not None else time.time()
    mac = (mac or "").upper()
    with _lock:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO device_timeline_events (user_id, mac, event_type, description, timestamp) VALUES (?, ?, ?, ?, ?)",
                (user_id, mac, event_type, description, now),
            )
            conn.commit()


def upsert_scan(
    mac: str,
    ip: str,
    vendor: str,
    guessed_type: str,
    hostname: str,
    ttl: Optional[int] = None,
    likely_hotspot: bool = False,
    hotspot_note: str = "",
    rtt_ms: Optional[float] = None,
    rtt_distance_m: Optional[float] = None,
    distance_band: str = "",
    bandwidth_mbps: Optional[float] = None,
    bandwidth_grade: str = "",
    open_ports: str = "",
    os_guess: str = "",
    ttl_confidence: str = "",
    vendor_confidence: str = "",
    vendor_source: str = "",
    type_confidence: str = "",
    type_reason: str = "",
    label_name: Optional[str] = None,
    label_type: Optional[str] = None,
    now: Optional[float] = None,
    user_id: int = 1,
) -> None:
    """Record that `mac` was seen in this scan pass for `user_id`. Creates the row if
    it's a brand-new device for this user (sets first_seen), otherwise updates its
    latest scan data and marks it online. Existing manual labels are left untouched."""
    now = now if now is not None else time.time()
    mac = (mac or "").upper()

    # Automatically derive distance & bandwidth from RTT if missing
    import device_scan
    if rtt_ms is not None:
        if rtt_distance_m is None or not distance_band:
            calc_dist, calc_band, _, _ = device_scan.estimate_distance_from_rtt(rtt_ms)
            rtt_distance_m = rtt_distance_m if rtt_distance_m is not None else calc_dist
            distance_band = distance_band or calc_band or ""
        if bandwidth_mbps is None or not bandwidth_grade:
            calc_bw, calc_grade, _ = device_scan.estimate_bandwidth(rtt_ms)
            bandwidth_mbps = bandwidth_mbps if bandwidth_mbps is not None else calc_bw
            bandwidth_grade = bandwidth_grade or calc_grade or ""

    with _lock:
        with get_connection() as conn:
            # Check existing state for timeline event logging
            prev = conn.execute(
                "SELECT ip, online FROM devices WHERE user_id=? AND mac=?",
                (user_id, mac),
            ).fetchone()

            if not prev:
                conn.execute(
                    "INSERT INTO device_timeline_events (user_id, mac, event_type, description, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (user_id, mac, "discovered", f"First detected on network at IP {ip or 'unknown'}", now),
                )
            else:
                if prev["online"] == 0:
                    conn.execute(
                        "INSERT INTO device_timeline_events (user_id, mac, event_type, description, timestamp) VALUES (?, ?, ?, ?, ?)",
                        (user_id, mac, "connected", f"Device reconnected online at IP {ip or 'unknown'}", now),
                    )
                if prev["ip"] and ip and prev["ip"] != ip:
                    conn.execute(
                        "INSERT INTO device_timeline_events (user_id, mac, event_type, description, timestamp) VALUES (?, ?, ?, ?, ?)",
                        (user_id, mac, "ip_change", f"IP address changed from {prev['ip']} to {ip}", now),
                    )

            conn.execute(
                """
                INSERT INTO devices (user_id, mac, ip, vendor, guessed_type, hostname, label_name, label_type,
                                      first_seen, last_seen, online,
                                      ttl, likely_hotspot, hotspot_note, rtt_ms, rtt_distance_m, distance_band,
                                      bandwidth_mbps, bandwidth_grade, open_ports, os_guess,
                                      ttl_confidence, vendor_confidence, vendor_source, type_confidence, type_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, mac) DO UPDATE SET
                    ip=excluded.ip,
                    vendor=excluded.vendor,
                    guessed_type=excluded.guessed_type,
                    hostname=excluded.hostname,
                    label_name=COALESCE(devices.label_name, excluded.label_name),
                    label_type=COALESCE(devices.label_type, excluded.label_type),
                    last_seen=excluded.last_seen,
                    online=1,
                    ttl=COALESCE(excluded.ttl, devices.ttl),
                    likely_hotspot=excluded.likely_hotspot,
                    hotspot_note=excluded.hotspot_note,
                    rtt_ms=COALESCE(excluded.rtt_ms, devices.rtt_ms),
                    rtt_distance_m=COALESCE(excluded.rtt_distance_m, devices.rtt_distance_m),
                    distance_band=COALESCE(NULLIF(excluded.distance_band, ''), devices.distance_band),
                    bandwidth_mbps=COALESCE(excluded.bandwidth_mbps, devices.bandwidth_mbps),
                    bandwidth_grade=COALESCE(NULLIF(excluded.bandwidth_grade, ''), devices.bandwidth_grade),
                    open_ports=CASE WHEN excluded.open_ports != '' THEN excluded.open_ports ELSE devices.open_ports END,
                    os_guess=CASE WHEN excluded.os_guess != '' THEN excluded.os_guess ELSE devices.os_guess END,
                    ttl_confidence=excluded.ttl_confidence,
                    vendor_confidence=excluded.vendor_confidence,
                    vendor_source=excluded.vendor_source,
                    type_confidence=excluded.type_confidence,
                    type_reason=excluded.type_reason
                """,
                (
                    user_id, mac, ip, vendor, guessed_type, hostname, label_name, label_type, now, now, ttl, int(likely_hotspot), hotspot_note,
                    rtt_ms, rtt_distance_m, distance_band, bandwidth_mbps, bandwidth_grade, open_ports or "", os_guess or "",
                    ttl_confidence, vendor_confidence, vendor_source, type_confidence, type_reason,
                ),
            )
            conn.commit()


def mark_offline_except(

    seen_macs: List[str],
    user_id: Optional[int] = None,
    grace_seconds: int = 0,
) -> None:
    """Any device not in this scan pass gets flagged offline for user_id (or all users if None).
    Logs a disconnected event in the timeline for devices that go offline."""
    now = time.time()
    cutoff = (now - grace_seconds) if (grace_seconds and grace_seconds > 0) else None
    upper_macs = [m.upper() for m in seen_macs] if seen_macs else []

    with _lock:
        with get_connection() as conn:
            # Find online devices that will be marked offline
            query = "SELECT user_id, mac, ip FROM devices WHERE online=1"
            params: List[Any] = []
            if user_id is not None:
                query += " AND user_id=?"
                params.append(user_id)
            if upper_macs:
                placeholders = ",".join("?" for _ in upper_macs)
                query += f" AND mac NOT IN ({placeholders})"
                params.extend(upper_macs)
            if cutoff is not None:
                query += " AND last_seen < ?"
                params.append(cutoff)

            disconnecting = conn.execute(query, params).fetchall()
            for d in disconnecting:
                conn.execute(
                    "INSERT INTO device_timeline_events (user_id, mac, event_type, description, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (d["user_id"], d["mac"], "disconnected", f"Device went offline (last active at {d['ip'] or 'unknown'})", now),
                )

            # Update online status
            if user_id is not None:
                if upper_macs:
                    placeholders = ",".join("?" for _ in upper_macs)
                    if cutoff is not None:
                        conn.execute(
                            f"UPDATE devices SET online=0 WHERE user_id=? AND mac NOT IN ({placeholders}) AND last_seen < ?",
                            (user_id, *upper_macs, cutoff),
                        )
                    else:
                        conn.execute(
                            f"UPDATE devices SET online=0 WHERE user_id=? AND mac NOT IN ({placeholders})",
                            (user_id, *upper_macs),
                        )
                else:
                    if cutoff is not None:
                        conn.execute("UPDATE devices SET online=0 WHERE user_id=? AND last_seen < ?", (user_id, cutoff))
                    else:
                        conn.execute("UPDATE devices SET online=0 WHERE user_id=?", (user_id,))
            else:
                if upper_macs:
                    placeholders = ",".join("?" for _ in upper_macs)
                    if cutoff is not None:
                        conn.execute(
                            f"UPDATE devices SET online=0 WHERE mac NOT IN ({placeholders}) AND last_seen < ?",
                            (*upper_macs, cutoff),
                        )
                    else:
                        conn.execute(
                            f"UPDATE devices SET online=0 WHERE mac NOT IN ({placeholders})",
                            tuple(upper_macs),
                        )
                else:
                    if cutoff is not None:
                        conn.execute("UPDATE devices SET online=0 WHERE last_seen < ?", (cutoff,))
                    else:
                        conn.execute("UPDATE devices SET online=0")

            conn.commit()


def set_label(
    mac: str,
    name: Optional[str],
    device_type: Optional[str],
    user_id: Optional[int] = None,
) -> None:
    """Manually apply custom label name and device type classification."""
    mac = (mac or "").upper()
    now = time.time()
    with _lock:
        with get_connection() as conn:
            if user_id is not None:
                conn.execute(
                    "UPDATE devices SET label_name=?, label_type=? WHERE user_id=? AND mac=?",
                    (name, device_type, user_id, mac),
                )
                conn.execute(
                    "INSERT INTO device_timeline_events (user_id, mac, event_type, description, timestamp) VALUES (?, ?, 'relabel', ?, ?)",
                    (user_id, mac, f"Relabeled as '{name}' ({device_type})", now),
                )
            else:
                conn.execute(
                    "UPDATE devices SET label_name=?, label_type=? WHERE mac=?",
                    (name, device_type, mac),
                )
                conn.execute(
                    "INSERT INTO device_timeline_events (user_id, mac, event_type, description, timestamp) VALUES (1, ?, 'relabel', ?, ?)",
                    (mac, f"Relabeled as '{name}' ({device_type})", now),
                )
            conn.commit()


def forget_device(mac: str, user_id: Optional[int] = None) -> None:
    """Permanently delete a device's history for user_id (user-initiated only)."""
    mac = (mac or "").upper()
    with _lock:
        with get_connection() as conn:
            if user_id is not None:
                conn.execute("DELETE FROM devices WHERE user_id=? AND mac=?", (user_id, mac))
                conn.execute("DELETE FROM device_timeline_events WHERE user_id=? AND mac=?", (user_id, mac))
            else:
                conn.execute("DELETE FROM devices WHERE mac=?", (mac,))
                conn.execute("DELETE FROM device_timeline_events WHERE mac=?", (mac,))
            conn.commit()


def get_device_timeline(mac: str, user_id: int = 1) -> Optional[Dict[str, Any]]:
    """Return complete lifecycle timeline and connection history for a device."""
    mac = (mac or "").upper()
    with _lock:
        with get_connection() as conn:
            dev = conn.execute(
                "SELECT * FROM devices WHERE user_id=? AND mac=?",
                (user_id, mac),
            ).fetchone()

            events_rows = conn.execute(
                "SELECT * FROM device_timeline_events WHERE user_id=? AND mac=? ORDER BY timestamp DESC LIMIT 50",
                (user_id, mac),
            ).fetchall()

    if not dev:
        return None

    first_seen = dev["first_seen"]
    last_seen = dev["last_seen"]
    now = time.time()
    total_known_seconds = max(0, (last_seen or now) - (first_seen or now))

    events = [
        {
            "id": r["id"],
            "event_type": r["event_type"],
            "description": r["description"],
            "timestamp": r["timestamp"],
        }
        for r in events_rows
    ]

    return {
        "mac": mac,
        "name": dev["label_name"] or dev["hostname"] or dev["vendor"] or "Device",
        "ip": dev["ip"],
        "online": bool(dev["online"]),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "total_known_seconds": total_known_seconds,
        "events": events,
    }


def _row_to_device(row: Any) -> Dict[str, Any]:
    """Convert database row to enriched presentation device dictionary."""
    rtt_ms = row["rtt_ms"]
    rtt_distance_m = None
    distance_band = ""
    bandwidth_mbps = None
    bandwidth_grade = ""
    open_ports = ""
    os_guess = ""

    try:
        rtt_distance_m = row["rtt_distance_m"]
        distance_band = row["distance_band"] or ""
        bandwidth_mbps = row["bandwidth_mbps"]
        bandwidth_grade = row["bandwidth_grade"] or ""
        open_ports = row["open_ports"] or ""
        os_guess = row["os_guess"] or ""
    except (IndexError, KeyError):
        pass

    # Dynamically compute distance and bandwidth if missing from record
    import device_scan
    if rtt_ms is not None:
        if rtt_distance_m is None or not distance_band:
            calc_dist, calc_band, _, _ = device_scan.estimate_distance_from_rtt(rtt_ms)
            rtt_distance_m = calc_dist
            distance_band = calc_band or ""
        if bandwidth_mbps is None or not bandwidth_grade:
            calc_bw, calc_grade, _ = device_scan.estimate_bandwidth(rtt_ms)
            bandwidth_mbps = calc_bw
            bandwidth_grade = calc_grade or ""

    dev_type = row["label_type"] or row["guessed_type"] or "unknown"
    vendor = row["vendor"] or "—"
    hostname = row["hostname"] or "—"
    mac = row["mac"]

    # Intelligent friendly disciplined display name, vendor, and hardware type
    import device_service
    name, vendor, dev_type = device_service.resolve_disciplined_device_name(
        label_name=row["label_name"],
        hostname=hostname,
        vendor=vendor,
        dev_type=dev_type,
        ip=row["ip"],
        mac=mac,
        ttl=row["ttl"],
        likely_hotspot=bool(row["likely_hotspot"]),
        hotspot_note=row["hotspot_note"] or "",
    )

    return {

        "mac": row["mac"],
        "ip": row["ip"],
        "vendor": vendor,
        "type": dev_type,
        "name": name,
        "hostname": hostname,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "online": bool(row["online"]),
        "ttl": row["ttl"],
        "likely_hotspot": bool(row["likely_hotspot"]),
        "hotspot_note": row["hotspot_note"] or "",
        "rtt_ms": rtt_ms,
        "rtt_distance_m": rtt_distance_m,
        "distance_band": distance_band,
        "bandwidth_mbps": bandwidth_mbps,
        "bandwidth_grade": bandwidth_grade,
        "open_ports": open_ports,
        "os_guess": os_guess,
        "ttl_confidence": row["ttl_confidence"] or "",
        "vendor_confidence": row["vendor_confidence"] or "",
        "vendor_source": row["vendor_source"] or "",
        "type_confidence": row["type_confidence"] or "",
        "type_reason": row["type_reason"] or "",
        "type_is_manual": bool(row["label_type"]),
    }


def get_all(user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Devices seen for user_id (or all devices if user_id is None) -- online ones first,
    then most recently seen offline devices first."""
    with _lock:
        with get_connection() as conn:
            if user_id is not None:
                rows = conn.execute(
                    "SELECT * FROM devices WHERE user_id=? ORDER BY online DESC, last_seen DESC",
                    (user_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM devices ORDER BY online DESC, last_seen DESC"
                ).fetchall()
    return [_row_to_device(r) for r in rows]


def get_online_count(user_id: Optional[int] = None) -> int:
    """Return count of currently online devices."""
    with _lock:
        with get_connection() as conn:
            if user_id is not None:
                n = conn.execute("SELECT COUNT(*) FROM devices WHERE user_id=? AND online=1", (user_id,)).fetchone()[0]
            else:
                n = conn.execute("SELECT COUNT(*) FROM devices WHERE online=1").fetchone()[0]
    return n


def get_device_count(user_id: Optional[int] = None) -> int:
    """Return total count of registered devices for user_id (or all users)."""
    with _lock:
        with get_connection() as conn:
            if user_id is not None:
                n = conn.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (user_id,)).fetchone()[0]
            else:
                n = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    return n


def set_device_online_status(mac: str, online: bool, user_id: Optional[int] = None) -> None:
    """Explicitly override online status for a device."""
    mac = (mac or "").upper()
    val = 1 if online else 0
    with _lock:
        with get_connection() as conn:
            if user_id is not None:
                conn.execute("UPDATE devices SET online=? WHERE user_id=? AND mac=?", (val, user_id, mac))
            else:
                conn.execute("UPDATE devices SET online=? WHERE mac=?", (val, mac))
            conn.commit()
