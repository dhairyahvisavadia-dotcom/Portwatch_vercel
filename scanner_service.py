"""
scanner_service.py — Subnet sweep engine & background device probing pipeline.
Handles passive ARP inspection, active ICMP ping sweeps, mobile signature
detection, and database synchronization for multi-tenant users.
"""

import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Set, Tuple

import auth_db
import db
import device_scan
import vendor_lookup

logger = logging.getLogger("portwatch.scanner")

# Global device and connection telemetry
STATUS: Dict[str, Any] = {
    "subnet": None,
    "last_scan": None,
    "scanning": False,
    "own_connection": None,
}

ACTIVE_USER_IDS: Set[int] = set()
LATEST_SCANNED_DEVICES: List[Dict[str, Any]] = []
LATEST_SEEN_MACS: List[str] = []
SCAN_INTERVAL_SECONDS: int = int(os.environ.get("PORTWATCH_SCAN_INTERVAL", "20"))


def get_all_user_ids() -> List[int]:
    """Retrieve all registered user IDs from the authentication database."""
    try:
        with auth_db._lock:
            conn = auth_db._connect()
            rows = conn.execute("SELECT id FROM users").fetchall()
            conn.close()
        return [r[0] for r in rows] if rows else [1]
    except Exception as e:
        logger.warning(f"Failed to query all user IDs: {e}")
        return [1]


def build_device_record(
    ip: str,
    mac: str,
    gateway_ip: Optional[str] = None,
    ping_info: Optional[Dict[str, Any]] = None,
    deep_fingerprint: bool = False,
) -> Dict[str, Any]:
    """Unified pipeline to probe and construct an enriched device record.
    Resolves IEEE OUI vendor, measured latency, TTL hop classification,
    and mobile service signatures.
    """
    is_gw = bool(gateway_ip and ip == gateway_ip)

    # 1. Vendor resolution (IEEE OUI database + local table + randomized MAC detection)
    vendor_info = vendor_lookup.lookup_vendor_detailed(mac)
    vendor = vendor_info["vendor"]
    if is_gw:
        vendor = "Hotspot Gateway (Host Phone)"
        vendor_info["confidence"] = "high"
        vendor_info["source"] = "gateway"

    # 2. Ping info (TTL & RTT)
    ttl = None
    rtt_ms = None
    ttl_confidence = "low"
    if ping_info:
        ttl = ping_info.get("ttl")
        ttl_confidence = ping_info.get("confidence", "low")
        rtt_ms = ping_info.get("rtt_ms")
        # Fast double ping probe (350ms) to wake up mobile power-save radios
        try:
            ping_out = subprocess.run(
                ["ping", "-n", "2", "-w", "350", ip],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            m_ttl = re.search(r"TTL=(\d+)", ping_out.stdout, re.IGNORECASE)
            if m_ttl:
                ttl = int(m_ttl.group(1))
                ttl_confidence = "medium"
            times = [float(t) for t in re.findall(r"time[<=](\d+)ms", ping_out.stdout, re.IGNORECASE)]
            if times:
                rtt_ms = min(times)
        except Exception as e:
            logger.debug(f"Fast ping probe failed on {ip}: {e}")

    # 3. Mobile signatures (Apple lockdownd, Google Cast, Android ADB)
    sig = device_scan.probe_mobile_signatures(ip)
    if not is_gw and sig and sig.get("vendor"):
        vendor = sig["vendor"]
        vendor_info["confidence"] = sig["confidence"]
        vendor_info["source"] = "service_signature"

    # 4. Hostname resolution
    hostname = device_scan.resolve_hostname(ip, ttl=ttl)
    if not hostname and sig:
        hostname = sig.get("name")
    if not hostname and is_gw:
        hostname = "Hotspot-Gateway"

    # 5. Distance and Bandwidth models
    dist_m, dist_band, _, _ = device_scan.estimate_distance_from_rtt(rtt_ms)
    bandwidth_mbps, bandwidth_grade, _ = device_scan.estimate_bandwidth(rtt_ms)

    # 6. TTL Classification
    likely_hotspot, hotspot_note = device_scan.classify_ttl(ttl, ttl_confidence)
    if is_gw:
        likely_hotspot = True
        hotspot_note = "Confirmed default gateway hosting the mobile hotspot network"

    # 7. Type Guessing
    type_info = vendor_lookup.guess_type_detailed(
        vendor, hostname, mac=mac, ttl=ttl, is_gateway=is_gw
    )
    if sig and sig.get("type"):
        type_info = {
            "type": sig["type"],
            "confidence": sig["confidence"],
            "reason": sig["reason"],
        }

    open_ports_str = ""
    os_guess = ""

    # 8. Deep Fingerprint (Nmap / socket probe) if requested or if device type remains unknown
    if deep_fingerprint or (type_info["type"] == "unknown" and not is_gw):
        fp = device_scan.deep_fingerprint_device(ip)
        if fp:
            if fp.get("open_ports"):
                open_ports_str = ",".join(str(p) for p in fp["open_ports"])
            if fp.get("os_guess"):
                os_guess = fp["os_guess"]
            if fp.get("type"):
                type_info = {
                    "type": fp["type"],
                    "confidence": fp.get("confidence", "high"),
                    "reason": fp.get("reason", f"Fingerprinted via {fp.get('engine', 'deep_scan')}"),
                }
            if fp.get("name") and (not hostname or hostname == "—"):
                hostname = fp["name"]

    return {
        "mac": mac,
        "ip": ip,
        "vendor": vendor,
        "type": type_info["type"],
        "hostname": hostname,
        "ttl": ttl,
        "likely_hotspot": likely_hotspot,
        "hotspot_note": hotspot_note,
        "rtt_ms": rtt_ms,
        "dist_m": dist_m,
        "dist_band": dist_band,
        "bandwidth_mbps": bandwidth_mbps,
        "bandwidth_grade": bandwidth_grade,
        "open_ports": open_ports_str,
        "os_guess": os_guess,
        "ttl_confidence": ttl_confidence,
        "vendor_confidence": vendor_info["confidence"],
        "vendor_source": vendor_info["source"],
        "type_confidence": type_info["confidence"],
        "type_reason": type_info["reason"],
    }


def sync_scan_results_to_db(
    scanned_devices: List[Dict[str, Any]],
    seen_macs: List[str],
    user_ids: Any = None,
    now: Optional[float] = None,
) -> None:
    """Centralized database synchronization for scan results.
    Inserts/updates devices and flags offline nodes for isolated user workspaces.
    """
    now = now if now is not None else time.time()
    if user_ids is None:
        user_ids = list(ACTIVE_USER_IDS) if ACTIVE_USER_IDS else get_all_user_ids()
    elif isinstance(user_ids, (int, str)):
        user_ids = [int(user_ids)]

    for uid in user_ids:
        for d in scanned_devices:
            db.upsert_scan(
                d["mac"],
                d["ip"],
                d["vendor"],
                d["type"],
                d["hostname"],
                ttl=d.get("ttl"),
                likely_hotspot=d.get("likely_hotspot", False),
                hotspot_note=d.get("hotspot_note", ""),
                rtt_ms=d.get("rtt_ms"),
                rtt_distance_m=d.get("dist_m"),
                distance_band=d.get("dist_band", ""),
                bandwidth_mbps=d.get("bandwidth_mbps"),
                bandwidth_grade=d.get("bandwidth_grade", ""),
                open_ports=d.get("open_ports", ""),
                os_guess=d.get("os_guess", ""),
                ttl_confidence=d.get("ttl_confidence", ""),
                vendor_confidence=d.get("vendor_confidence", ""),
                vendor_source=d.get("vendor_source", ""),
                type_confidence=d.get("type_confidence", ""),
                type_reason=d.get("type_reason", ""),
                label_name=d.get("label_name"),
                label_type=d.get("label_type"),
                now=now,
                user_id=uid,
            )
        if seen_macs:
            db.mark_offline_except(seen_macs, user_id=uid, grace_seconds=0)


def is_demo_mode_active() -> bool:
    """Returns True if cloud demo simulation mode is explicitly enabled."""
    return (
        os.environ.get("PORTWATCH_DEMO_MODE", "").lower() in ("1", "true", "yes")
        or bool(os.environ.get("VERCEL"))
    )


def generate_demo_scan() -> Tuple[List[Dict[str, Any]], List[str]]:
    """Generates realistic simulated devices with subtle dynamic latency jitter for cloud showcase."""
    import random
    from scripts.seed_demo_data import DEMO_DEVICES_DATA
    scanned_devices = []
    seen_macs = []
    for d in DEMO_DEVICES_DATA:
        jitter = round(random.uniform(-0.6, 0.6), 2)
        rtt = max(1.1, round(d["rtt_ms"] + jitter, 2))
        dist_m, dist_band, _, _ = device_scan.estimate_distance_from_rtt(rtt)
        bandwidth_mbps, bandwidth_grade, _ = device_scan.estimate_bandwidth(rtt)
        rec = {
            "mac": d["mac"],
            "ip": d["ip"],
            "vendor": d["vendor"],
            "type": d["type"],
            "hostname": d["hostname"],
            "label_name": d.get("label_name"),
            "label_type": d.get("label_type"),
            "ttl": d["ttl"],
            "likely_hotspot": d["likely_hotspot"],
            "hotspot_note": d["hotspot_note"],
            "rtt_ms": rtt,
            "dist_m": dist_m,
            "dist_band": dist_band,
            "bandwidth_mbps": bandwidth_mbps,
            "bandwidth_grade": bandwidth_grade,
            "open_ports": d["open_ports"],
            "os_guess": d["os_guess"],
            "ttl_confidence": d["ttl_confidence"],
            "vendor_confidence": d["vendor_confidence"],
            "vendor_source": d["vendor_source"],
            "type_confidence": d["type_confidence"],
            "type_reason": d["type_reason"],
        }
        scanned_devices.append(rec)
        if d.get("online", True):
            seen_macs.append(d["mac"])
    return scanned_devices, seen_macs


def fast_scan(sync_db: bool = False, user_id: Any = None) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Ultra-fast parallel scan of connected gateway and ARP subnet devices."""
    global LATEST_SCANNED_DEVICES, LATEST_SEEN_MACS

    if is_demo_mode_active():
        STATUS["subnet"] = "192.168.137"
        STATUS["demo_mode"] = True
        STATUS["own_connection"] = {
            "ip": "192.168.137.45",
            "gateway": "192.168.137.1",
            "adapter": "Wi-Fi 6E (Demo Virtual Adapter 802.11ax)",
            "ssid": "PortWatch-Hotspot-Demo",
            "state": "connected",
        }
        scanned_devices, seen_macs = generate_demo_scan()
        LATEST_SCANNED_DEVICES = scanned_devices
        LATEST_SEEN_MACS = seen_macs
        if sync_db:
            sync_scan_results_to_db(scanned_devices, seen_macs, user_ids=user_id)
        STATUS["last_scan"] = time.time()
        STATUS["scanning"] = False
        return scanned_devices, seen_macs

    STATUS["demo_mode"] = False
    subnet = device_scan.find_hotspot_subnet()
    STATUS["subnet"] = subnet
    STATUS["own_connection"] = device_scan.get_own_connection_info()
    if not subnet:
        return [], []

    device_scan.wake_subnet(subnet)
    entries = device_scan.read_arp_table_reliable(subnet, retries=1, delay_seconds=0.15)
    gateway_ip = device_scan.get_default_gateway()

    if len(entries) <= 1:
        device_scan.wake_hosts_fast(subnet)
        entries = device_scan.read_arp_table_reliable(subnet, retries=1, delay_seconds=0.2)

    arp_dict = dict(entries)
    if gateway_ip and gateway_ip not in arp_dict:
        try:
            subprocess.run(["ping", "-n", "1", "-w", "250", gateway_ip], capture_output=True)
            entries = device_scan.read_arp_table(subnet)
        except Exception:
            pass

    seen_macs = [mac for _, mac in entries]
    with ThreadPoolExecutor(max_workers=10) as executor:
        scanned_devices = list(
            executor.map(
                lambda item: build_device_record(item[0], item[1], gateway_ip=gateway_ip),
                entries,
            )
        )

    if scanned_devices:
        LATEST_SCANNED_DEVICES = scanned_devices
        LATEST_SEEN_MACS = seen_macs

    if sync_db:
        sync_scan_results_to_db(scanned_devices, seen_macs, user_ids=user_id)

    return scanned_devices, seen_macs


def scan_once(user_id: Any = None, deep_fingerprint: bool = False) -> None:
    """Full background ping-sweep scan across the /24 subnet."""
    global LATEST_SCANNED_DEVICES, LATEST_SEEN_MACS
    STATUS["scanning"] = True

    if is_demo_mode_active():
        STATUS["subnet"] = "192.168.137"
        STATUS["demo_mode"] = True
        STATUS["own_connection"] = {
            "ip": "192.168.137.45",
            "gateway": "192.168.137.1",
            "adapter": "Wi-Fi 6E (Demo Virtual Adapter 802.11ax)",
            "ssid": "PortWatch-Hotspot-Demo",
            "state": "connected",
        }
        scanned_devices, seen_macs = generate_demo_scan()
        LATEST_SCANNED_DEVICES = scanned_devices
        LATEST_SEEN_MACS = seen_macs
        sync_scan_results_to_db(scanned_devices, seen_macs, user_ids=user_id)
        STATUS["last_scan"] = time.time()
        STATUS["scanning"] = False
        logger.info(f"Demo sweep complete: {len(scanned_devices)} simulated nodes refreshed")
        return

    STATUS["demo_mode"] = False
    subnet = device_scan.find_hotspot_subnet()
    STATUS["subnet"] = subnet
    STATUS["own_connection"] = device_scan.get_own_connection_info()

    if not subnet:
        STATUS["scanning"] = False
        return

    logger.info(f"Initiating full sweep on subnet {subnet}.0/24")
    ping_results = device_scan.ping_sweep(subnet)
    entries = device_scan.read_arp_table_reliable(subnet)
    gateway_ip = device_scan.get_default_gateway()

    seen_macs = [mac for _, mac in entries]
    with ThreadPoolExecutor(max_workers=12) as executor:
        scanned_devices = list(
            executor.map(
                lambda item: build_device_record(
                    item[0],
                    item[1],
                    gateway_ip=gateway_ip,
                    ping_info=ping_results.get(item[0]),
                    deep_fingerprint=deep_fingerprint,
                ),
                entries,
            )
        )

    LATEST_SCANNED_DEVICES = scanned_devices
    LATEST_SEEN_MACS = seen_macs

    sync_scan_results_to_db(scanned_devices, seen_macs, user_ids=user_id)

    STATUS["last_scan"] = time.time()
    STATUS["scanning"] = False
    logger.info(f"Sweep complete on {subnet}.0/24: {len(scanned_devices)} active nodes found")


def scan_loop() -> None:
    """Daemon thread loop for continuous background network monitoring."""
    logger.info(f"Starting background scanner daemon (interval={SCAN_INTERVAL_SECONDS}s)")
    while True:
        try:
            scan_once()
        except Exception as e:
            logger.error(f"Error during scheduled network scan: {e}")
        time.sleep(SCAN_INTERVAL_SECONDS)
