"""
scripts/seed_demo_data.py
Database seeder for PortWatch cloud showcase & demonstration environments.

Populates SQLite or PostgreSQL with realistic Wi-Fi hotspot clients, historical
session timelines, latency metrics, and a preconfigured recruiter demo account:
  Username: demo
  Password: DemoAdmin123!
"""

import argparse
import logging
import os
import sys
import time

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auth_db
import database
import db

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [portwatch.seeder] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("portwatch.seeder")

DEMO_DEVICES_DATA = [
    {
        "mac": "AA:BB:CC:11:22:33",
        "ip": "192.168.137.1",
        "vendor": "Hotspot Gateway (Host Phone)",
        "type": "phone",
        "hostname": "Hotspot-Gateway",
        "label_name": "Host iPhone 15 Pro",
        "label_type": "phone",
        "ttl": 64,
        "likely_hotspot": True,
        "hotspot_note": "Confirmed default gateway hosting the mobile hotspot network",
        "rtt_ms": 2.1,
        "dist_m": 1.0,
        "dist_band": "immediate",
        "bandwidth_mbps": 185.0,
        "bandwidth_grade": "A+",
        "open_ports": "53,80",
        "os_guess": "iOS / Darwin Kernel",
        "ttl_confidence": "high",
        "vendor_confidence": "high",
        "vendor_source": "gateway",
        "type_confidence": "high",
        "type_reason": "Default gateway signature & mobile hotspot beacon",
        "online": True,
    },
    {
        "mac": "38:F9:D3:55:66:77",
        "ip": "192.168.137.45",
        "vendor": "Apple, Inc.",
        "type": "laptop",
        "hostname": "siddha-macbook-pro",
        "label_name": "MacBook Pro M3",
        "label_type": "laptop",
        "ttl": 64,
        "likely_hotspot": False,
        "hotspot_note": "Standard client endpoint",
        "rtt_ms": 4.8,
        "dist_m": 2.4,
        "dist_band": "near",
        "bandwidth_mbps": 142.0,
        "bandwidth_grade": "A",
        "open_ports": "22,5000,7000",
        "os_guess": "macOS Sonoma (Darwin 23)",
        "ttl_confidence": "medium",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "Hostname and OUI match Apple workstation",
        "online": True,
    },
    {
        "mac": "74:78:27:12:34:56",
        "ip": "192.168.137.89",
        "vendor": "Dell Inc.",
        "type": "laptop",
        "hostname": "dell-xps-engineer",
        "label_name": "Dell XPS 15",
        "label_type": "laptop",
        "ttl": 128,
        "likely_hotspot": False,
        "hotspot_note": "Windows workstation client",
        "rtt_ms": 7.2,
        "dist_m": 3.6,
        "dist_band": "near",
        "bandwidth_mbps": 98.0,
        "bandwidth_grade": "B+",
        "open_ports": "135,445,3389",
        "os_guess": "Microsoft Windows 11 Enterprise",
        "ttl_confidence": "high",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "TTL 128 signature + Dell OUI match",
        "online": True,
    },
    {
        "mac": "B8:27:EB:AB:CD:EF",
        "ip": "192.168.137.102",
        "vendor": "Raspberry Pi Foundation",
        "type": "single-board computer",
        "hostname": "homeassistant-pi4",
        "label_name": "Home Assistant Server",
        "label_type": "single-board computer",
        "ttl": 64,
        "likely_hotspot": False,
        "hotspot_note": "Linux ARM appliance",
        "rtt_ms": 8.5,
        "dist_m": 4.2,
        "dist_band": "near",
        "bandwidth_mbps": 75.0,
        "bandwidth_grade": "B",
        "open_ports": "22,80,8123",
        "os_guess": "Linux 6.1 (Debian Bookworm ARM64)",
        "ttl_confidence": "medium",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "Raspberry Pi OUI + port 8123 IoT automation",
        "online": True,
    },
    {
        "mac": "D8:3A:DD:44:55:66",
        "ip": "192.168.137.115",
        "vendor": "Google, Inc.",
        "type": "phone",
        "hostname": "pixel8-pro-5g",
        "label_name": "Google Pixel 8 Pro",
        "label_type": "phone",
        "ttl": 64,
        "likely_hotspot": False,
        "hotspot_note": "Android client",
        "rtt_ms": 12.4,
        "dist_m": 6.2,
        "dist_band": "medium",
        "bandwidth_mbps": 62.0,
        "bandwidth_grade": "B",
        "open_ports": "8008,8009",
        "os_guess": "Android 14 (Google Pixel OS)",
        "ttl_confidence": "medium",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "Google Cast sockets (8008/8009) and Pixel hostname",
        "online": True,
    },
    {
        "mac": "00:17:88:88:99:AA",
        "ip": "192.168.137.130",
        "vendor": "Philips Lighting BV",
        "type": "IoT device",
        "hostname": "hue-bridge-v2",
        "label_name": "Philips Hue Smart Bridge",
        "label_type": "IoT device",
        "ttl": 64,
        "likely_hotspot": False,
        "hotspot_note": "Smart home hub",
        "rtt_ms": 18.2,
        "dist_m": 9.1,
        "dist_band": "medium",
        "bandwidth_mbps": 35.0,
        "bandwidth_grade": "C",
        "open_ports": "80,443",
        "os_guess": "Embedded Linux / Zigbee Coordinator",
        "ttl_confidence": "low",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "Philips Lighting OUI match",
        "online": True,
    },
    {
        "mac": "24:4B:FE:01:23:45",
        "ip": "192.168.137.142",
        "vendor": "Espressif Inc.",
        "type": "IoT device",
        "hostname": "esp32-temp-node",
        "label_name": "ESP32 Environmental Node",
        "label_type": "IoT device",
        "ttl": 255,
        "likely_hotspot": False,
        "hotspot_note": "Microcontroller sensor endpoint",
        "rtt_ms": 22.0,
        "dist_m": 11.0,
        "dist_band": "far",
        "bandwidth_mbps": 18.0,
        "bandwidth_grade": "D",
        "open_ports": "80,1883",
        "os_guess": "FreeRTOS / ESP-IDF v5.1",
        "ttl_confidence": "medium",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "Espressif OUI + MQTT port 1883",
        "online": True,
    },
    {
        "mac": "00:D9:D1:66:77:88",
        "ip": "192.168.137.158",
        "vendor": "Sony Interactive Entertainment Inc.",
        "type": "tv/other",
        "hostname": "ps5-console-living",
        "label_name": "Sony PlayStation 5",
        "label_type": "tv/other",
        "ttl": 64,
        "likely_hotspot": False,
        "hotspot_note": "Gaming console",
        "rtt_ms": 11.5,
        "dist_m": 5.7,
        "dist_band": "medium",
        "bandwidth_mbps": 120.0,
        "bandwidth_grade": "A",
        "open_ports": "9295,9296,9304",
        "os_guess": "FreeBSD-derived PlayStation OS",
        "ttl_confidence": "medium",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "Sony Interactive Entertainment OUI match",
        "online": True,
    },
    {
        "mac": "00:11:32:99:AA:BB",
        "ip": "192.168.137.170",
        "vendor": "Synology Incorporated",
        "type": "storage/nas",
        "hostname": "synology-ds920p",
        "label_name": "Synology DiskStation NAS",
        "label_type": "storage/nas",
        "ttl": 64,
        "likely_hotspot": False,
        "hotspot_note": "Network Attached Storage",
        "rtt_ms": 6.1,
        "dist_m": 3.0,
        "dist_band": "near",
        "bandwidth_mbps": 110.0,
        "bandwidth_grade": "A",
        "open_ports": "5000,5001,445",
        "os_guess": "Synology DSM 7.2 (Linux Kernel)",
        "ttl_confidence": "high",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "Synology OUI + DiskStation Manager ports",
        "online": False,
    },
    {
        "mac": "70:B3:D5:CC:DD:EE",
        "ip": "192.168.137.210",
        "vendor": "Canon Inc.",
        "type": "printer",
        "hostname": "canon-pixma-ts",
        "label_name": "Canon PIXMA Wireless",
        "label_type": "printer",
        "ttl": 255,
        "likely_hotspot": False,
        "hotspot_note": "Network printer in sleep mode",
        "rtt_ms": 34.6,
        "dist_m": 17.3,
        "dist_band": "far",
        "bandwidth_mbps": 24.0,
        "bandwidth_grade": "C",
        "open_ports": "80,515,631,9100",
        "os_guess": "Embedded Canon Firmware",
        "ttl_confidence": "medium",
        "vendor_confidence": "high",
        "vendor_source": "ieee_db",
        "type_confidence": "high",
        "type_reason": "Canon OUI + IPP port 631",
        "online": False,
    },
]


def ensure_demo_user(username: str = "demo", password: str = "DemoAdmin123!", email: str = "demo@portwatch.local") -> int:
    """Ensure a demo recruiter user exists and return its user_id."""
    auth_db.init_auth_db()
    existing = auth_db.get_user_by_username(username)
    if existing:
        return existing["id"]

    try:
        user = auth_db.create_user(username, password, email=email, ip="127.0.0.1")
        logger.info(f"Created demo account '{username}' (ID: {user['id']})")
        return user["id"]
    except Exception as e:
        logger.warning(f"Demo user creation notice: {e}")
        user = auth_db.get_user_by_username(username)
        return user["id"] if user else 1


def seed_demo_network(target_user_id=None, force: bool = False) -> int:
    """Populates the database with realistic demo devices and session history."""
    database.init_all_tables()
    auth_db.init_auth_db()
    db.init_db()

    demo_uid = ensure_demo_user()
    user_ids = set()
    if target_user_id is not None:
        user_ids.add(int(target_user_id))
    user_ids.add(demo_uid)
    user_ids.add(1)  # Default fallback user

    total_inserted = 0
    now = time.time()

    for uid in user_ids:
        # Check if already seeded and not force
        current_count = db.get_device_count(user_id=uid)
        if current_count >= 8 and not force:
            logger.info(f"User {uid} already contains {current_count} devices. Skipping re-seed.")
            continue

        for i, d in enumerate(DEMO_DEVICES_DATA):
            # Stagger historical first_seen timestamps (1-3 days ago)
            first_seen_offset = (len(DEMO_DEVICES_DATA) - i) * 14400 + 86400
            first_seen = now - first_seen_offset
            last_seen = now - (30 if d["online"] else 43200)

            db.upsert_scan(
                mac=d["mac"],
                ip=d["ip"],
                vendor=d["vendor"],
                guessed_type=d["type"],
                hostname=d["hostname"],
                ttl=d["ttl"],
                likely_hotspot=d["likely_hotspot"],
                hotspot_note=d["hotspot_note"],
                rtt_ms=d["rtt_ms"],
                rtt_distance_m=d["dist_m"],
                distance_band=d["dist_band"],
                bandwidth_mbps=d["bandwidth_mbps"],
                bandwidth_grade=d["bandwidth_grade"],
                open_ports=d["open_ports"],
                os_guess=d["os_guess"],
                ttl_confidence=d["ttl_confidence"],
                vendor_confidence=d["vendor_confidence"],
                vendor_source=d["vendor_source"],
                type_confidence=d["type_confidence"],
                type_reason=d["type_reason"],
                now=last_seen,
                user_id=uid,
            )

            # Set custom labels if provided
            if d.get("label_name") or d.get("label_type"):
                db.set_label(
                    d["mac"],
                    d.get("label_name", ""),
                    d.get("label_type", ""),
                    user_id=uid,
                )

            # Explicitly set offline state if configured
            if not d["online"]:
                db.set_device_online_status(d["mac"], False, user_id=uid)

            # Populate timeline events
            db.log_timeline_event(
                d["mac"],
                "discovered",
                f"Discovered {d['label_name']} via Wi-Fi subnet sweep (IP {d['ip']})",
                user_id=uid,
                now=first_seen,
            )
            db.log_timeline_event(
                d["mac"],
                "probe",
                f"Verified IEEE OUI manufacturer: {d['vendor']} (RTT: {d['rtt_ms']}ms)",
                user_id=uid,
                now=first_seen + 3600,
            )
            if d.get("open_ports"):
                db.log_timeline_event(
                    d["mac"],
                    "fingerprint",
                    f"Port scan confirmed services on ports: {d['open_ports']}",
                    user_id=uid,
                    now=last_seen - 1800,
                )

            total_inserted += 1

        auth_db.log_activity(uid, "seed_demo", "Initialized demo network telemetry showcase")

    logger.info(f"Successfully seeded demo telemetry ({total_inserted} device profiles across users).")
    return total_inserted


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed PortWatch demo data for showcase.")
    parser.add_argument("--force", action="store_true", help="Force overwrite/re-seed existing devices")
    parser.add_argument("--user-id", type=int, default=None, help="Target specific user ID")
    args = parser.parse_args()

    count = seed_demo_network(target_user_id=args.user_id, force=args.force)
    print(f"[SUCCESS] Seeded {count} demo records. Demo credentials: demo / DemoAdmin123!")
