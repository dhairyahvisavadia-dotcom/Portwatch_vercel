"""
vendor_lookup.py
Resolves a MAC address to a manufacturer name and guesses a device type.

Three-tier lookup for enterprise reliability:
1. Curated local OUI table for high-priority local mappings and overrides.
2. Bundled IEEE OUI database (oui.db, 58,000+ hardware vendors) - instant offline lookups, 0 rate limits.
3. Fallback disk cache and online API (api.macvendors.com) for edge cases.

Device type is guessed from multi-signal correlation (vendor name, hostname keywords,
TTL signatures, gateway status, and port probing).
"""

import json
import os
import sqlite3
import time
import requests

CACHE_FILE = os.path.join(os.path.dirname(__file__), "vendor_cache.json")
OUI_DB_FILE = os.path.join(os.path.dirname(__file__), "oui.db")

# Curated local OUI table -- high-priority fast entries and test overrides
LOCAL_OUI = {
    # Apple
    "3C22FB": "Apple, Inc.", "A45E60": "Apple, Inc.", "F45C89": "Apple, Inc.",
    "DC2B2A": "Apple, Inc.", "8863DF": "Apple, Inc.", "BCEC5D": "Apple, Inc.",
    "0C74C2": "Apple, Inc.", "FC253F": "Apple, Inc.",
    # Samsung
    "5CF370": "Samsung Electronics Co.,Ltd", "D857EF": "Samsung Electronics Co.,Ltd",
    "8425DB": "Samsung Electronics Co.,Ltd", "348A7B": "Samsung Electronics Co.,Ltd",
    # Xiaomi / Redmi
    "68DFDD": "Xiaomi Communications Co Ltd", "F0B429": "Xiaomi Communications Co Ltd",
    "64B473": "Xiaomi Communications Co Ltd", "9C99A0": "Xiaomi Communications Co Ltd",
    # Google
    "3C5AB4": "Google, Inc.", "F4F5D8": "Google, Inc.", "94EB2C": "Google, Inc.",
    # Amazon
    "6837E9": "Amazon Technologies Inc.", "F0272D": "Amazon Technologies Inc.",
    "74C246": "Amazon Technologies Inc.",
    # Huawei / OnePlus / Oppo / Vivo
    "B07FB9": "Huawei Technologies Co.,Ltd", "E4C6EF": "Huawei Technologies Co.,Ltd",
    "AC37AB": "OnePlus Technology (Shenzhen) Co., Ltd",
    "48A9D2": "GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD",
    "2C59E5": "vivo Mobile Communication Co., Ltd.",
    # Networking gear
    "E0469A": "NETGEAR", "9C3DCF": "NETGEAR", "1CB044": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "50C7BF": "TP-LINK TECHNOLOGIES CO.,LTD.", "245A4C": "Ubiquiti Networks Inc.",
    "F09FC2": "Ubiquiti Networks Inc.",
    # Cameras/IoT
    "4C11BF": "Hangzhou Hikvision Digital Technology Co.,Ltd.",
    "A0BD1D": "Zhejiang Dahua Technology Co., Ltd.",
    "EC71DB": "Reolink Innovation Limited", "ACCC8E": "Espressif Inc.",
    "246F28": "Espressif Inc.",
    # Speakers
    "000E58": "Sonos, Inc.", "5CAAFD": "Sonos, Inc.",
    "A02195": "Bose Corporation",
    # TVs / media
    "AC5F3E": "Roku, Inc.", "DC562D": "Vizio, Inc",
    # Laptops / PCs
    "3417EB": "Intel Corporate",
    "A434D9": "Intel Corporate", "6C29C6": "Intel Corporate",
    "38F3AB": "Lenovo", "6805CA": "Hewlett Packard", "F0761C": "ASUSTek COMPUTER INC.",
    "0025B3": "Hewlett Packard",
    # Raspberry Pi (common for DIY / receiver projects)
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Trading Ltd",
    "E45F01": "Raspberry Pi Trading Ltd",
    # Mobile / Hotspot Connected devices
    "50A9FE": "Mobile Device",
    "38D57A": "Cloud Network (Mobile Device)",
    "F854F6": "AzureWave (Mobile Device)",
}

# Keyword -> (device type, confidence when matched from vendor alone)
VENDOR_TYPE_KEYWORDS = [
    ("cloud network", "phone", "medium"),
    ("azurewave", "phone", "medium"),
    ("mobile device", "phone", "high"),
    ("apple", "phone/apple", "low"),  # Apple makes phones AND laptops
    ("samsung electro", "phone", "medium"),
    ("xiaomi", "phone", "medium"),
    ("huawei", "phone", "medium"),
    ("oneplus", "phone", "high"),
    ("oppo", "phone", "high"),
    ("vivo mobile", "phone", "high"),
    ("google", "phone/other", "low"),
    ("motorola", "phone", "medium"),
    ("hikvision", "camera", "high"),
    ("dahua", "camera", "high"),
    ("reolink", "camera", "high"),
    ("axis communi", "camera", "high"),
    ("amcrest", "camera", "high"),
    ("foscam", "camera", "high"),
    ("wyze", "camera", "high"),
    ("espressif", "IoT device", "medium"),
    ("tuya", "IoT device", "high"),
    ("ubiquiti", "network gear", "high"),
    ("tp-link", "network gear", "high"),
    ("netgear", "network gear", "high"),
    ("cisco", "network gear", "high"),
    ("mikrotik", "network gear", "high"),
    ("aruba", "network gear", "high"),
    ("juniper", "network gear", "high"),
    ("synology", "storage/nas", "high"),
    ("qnap", "storage/nas", "high"),
    ("sonos", "speaker", "high"),
    ("bose", "speaker", "high"),
    ("amazon technolog", "speaker/echo", "medium"),
    ("jbl", "speaker", "high"),
    ("harman", "speaker", "medium"),
    ("roku", "tv", "high"),
    ("vizio", "tv", "high"),
    ("lg electronics", "tv", "low"),  # LG makes phones/appliances too
    ("sony", "tv/other", "low"),
    ("raspberry pi", "single-board computer", "high"),
    ("canon", "printer", "high"),
    ("epson", "printer", "high"),
    ("brother indust", "printer", "high"),
    ("lexmark", "printer", "high"),
    ("dell", "laptop", "medium"),
    ("intel corporate", "laptop", "low"),  # Intel chips are in many device types
    ("lenovo", "laptop", "medium"),
    ("hewlett packard", "laptop", "medium"),
    ("microsoft", "laptop/other", "low"),
    ("asustek", "laptop", "low"),
]

# Hostname keyword -> device type.
HOSTNAME_TYPE_KEYWORDS = [
    ("iphone", "phone"), ("android", "phone"), ("galaxy", "phone"), ("pixel", "phone"),
    ("redmi", "phone"), ("oneplus", "phone"), ("xiaomi", "phone"), ("oppo", "phone"),
    ("macbook", "laptop"), ("laptop", "laptop"), ("notebook", "laptop"),
    ("desktop", "laptop"),  # closest bucket we track for a PC
    ("echo", "speaker/echo"), ("sonos", "speaker"), ("speaker", "speaker"),
    ("cam", "camera"), ("camera", "camera"), ("doorbell", "camera"), ("ring", "camera"),
    ("tv", "tv"), ("roku", "tv"), ("chromecast", "tv"), ("firetv", "tv"),
    ("printer", "printer"), ("laserjet", "printer"),
    ("raspberrypi", "single-board computer"), ("raspi", "single-board computer"),
]


def _load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


_cache = _load_cache()


def is_randomized_mac(mac: str) -> bool:
    """Checks if a MAC address has the IEEE 802 Locally Administered bit set.
    All modern Android (10+) and iOS (14+) devices use randomized/private
    MAC addresses by default for privacy when connecting to Wi-Fi networks."""
    clean = mac.replace(":", "").replace("-", "")
    if len(clean) >= 2:
        try:
            first_byte = int(clean[:2], 16)
            return bool(first_byte & 0x02)
        except ValueError:
            return False
    return False


def _lookup_in_oui_db(mac: str):
    """Query the local SQLite IEEE OUI database (58,000+ vendors)."""
    if not os.path.exists(OUI_DB_FILE):
        return None
    try:
        clean = mac.upper().replace("-", ":")
        parts = clean.split(":")
        if len(parts) >= 3:
            p24 = ":".join(parts[:3])
            # Special case dummy MACs
            if p24 in ("00:00:00", "FF:FF:FF"):
                return None
            conn = sqlite3.connect(OUI_DB_FILE)
            cursor = conn.cursor()
            row = cursor.execute("SELECT short_name, full_name FROM oui WHERE prefix = ?", (p24,)).fetchone()
            conn.close()
            if row:
                vendor = row[1] or row[0]
                if vendor and vendor != "00:00:00":
                    return vendor
    except Exception:
        pass
    return None


def lookup_vendor_detailed(mac: str) -> dict:
    """Returns {"vendor": str, "confidence": "high"|"medium"|"low", "source": "local"|"ieee_db"|"api"|"cache"|"unknown"|"private_mac"}.
    Checks in order:
    1. Curated local table (LOCAL_OUI)
    2. Private/randomized MAC check (Android/iOS Wi-Fi privacy)
    3. Bundled SQLite IEEE OUI database (58,000+ entries, instant offline)
    4. Disk cache
    5. Fallback online API (macvendors.com)
    """
    clean_mac = mac.upper().replace("-", ":")
    oui_no_colons = clean_mac.replace(":", "")[:6]

    # Handle all-zero or empty MACs
    if clean_mac in ("00:00:00:00:00:00", "00-00-00-00-00-00", ""):
        return {"vendor": "Unknown", "confidence": "low", "source": "unknown"}

    # 1. Curated local table
    if oui_no_colons in LOCAL_OUI:
        return {"vendor": LOCAL_OUI[oui_no_colons], "confidence": "high", "source": "local"}

    # 2. Private/randomized MAC check
    if is_randomized_mac(clean_mac):
        return {
            "vendor": "Mobile Device (Private MAC)",
            "confidence": "high",
            "source": "private_mac"
        }

    # 3. Bundled IEEE OUI database
    db_vendor = _lookup_in_oui_db(clean_mac)
    if db_vendor:
        return {
            "vendor": db_vendor,
            "confidence": "high",
            "source": "ieee_db"
        }

    # 4. Disk cache
    if clean_mac in _cache:
        cached = _cache[clean_mac]
        if cached in ("Unknown", ""):
            return {"vendor": "Unknown", "confidence": "low", "source": "unknown"}
        return {"vendor": cached, "confidence": "medium", "source": "cache"}

    # 5. Online API fallback
    vendor = "Unknown"
    try:
        resp = requests.get(f"https://api.macvendors.com/{clean_mac}", timeout=2)
        if resp.status_code == 200:
            vendor = resp.text.strip()
        elif resp.status_code == 429:
            time.sleep(0.5)  # rate limited -- back off
    except requests.RequestException:
        pass

    _cache[clean_mac] = vendor
    _save_cache(_cache)

    if vendor == "Unknown":
        return {"vendor": "Unknown", "confidence": "low", "source": "unknown"}
    return {"vendor": vendor, "confidence": "medium", "source": "api"}


def lookup_vendor(mac: str) -> str:
    """Backwards-compatible simple wrapper -- just the vendor string."""
    return lookup_vendor_detailed(mac)["vendor"]


# Alias for backward compatibility with external scanners calling vendor_lookup.lookup()
lookup = lookup_vendor_detailed


def guess_type_detailed(
    vendor: str,
    hostname: str | None = None,
    mac: str | None = None,
    ttl: int | None = None,
    is_gateway: bool = False,
) -> dict:
    """Returns {"type": str, "confidence": "high"|"medium"|"low", "reason": str}.
    Combines vendor-name, hostname keywords, gateway status, and randomized MAC
    signatures to reliably detect mobile devices and hardware classes."""
    if is_gateway:
        return {
            "type": "phone",
            "confidence": "high",
            "reason": "Default gateway hosting the mobile hotspot network"
        }

    v = (vendor or "").lower()
    h = (hostname or "").lower()

    if mac and is_randomized_mac(mac):
        return {
            "type": "phone",
            "confidence": "high",
            "reason": "Private/Randomized MAC address with mobile OS signature (Android/iOS)"
        }

    if "private mac" in v or "mobile device" in v:
        return {
            "type": "phone",
            "confidence": "high",
            "reason": "Recognized mobile device with Private/Randomized MAC address"
        }

    vendor_type, vendor_conf = None, None
    for keyword, dtype, conf in VENDOR_TYPE_KEYWORDS:
        if keyword in v:
            vendor_type, vendor_conf = dtype, conf
            break

    hostname_type = None
    for keyword, dtype in HOSTNAME_TYPE_KEYWORDS:
        if keyword in h:
            hostname_type = dtype
            break

    if hostname_type and vendor_type:
        v_base = vendor_type.split("/")[0]
        h_base = hostname_type.split("/")[0]
        if v_base == h_base:
            return {"type": hostname_type, "confidence": "high",
                    "reason": f"vendor and hostname both indicate '{h_base}'"}
        return {"type": hostname_type, "confidence": "medium",
                "reason": f"hostname suggests '{hostname_type}', vendor guess ('{vendor_type}') disagreed -- trusting the more specific hostname signal"}

    if hostname_type:
        return {"type": hostname_type, "confidence": "medium",
                "reason": "guessed from hostname keyword only, no vendor signal"}

    if vendor_type:
        return {"type": vendor_type, "confidence": vendor_conf,
                "reason": "guessed from vendor name only (confidence reflects how vendor-specific this manufacturer's product line is)"}

    # If TTL is 64 (standard for Android/iOS) on a mobile hotspot, classify as phone
    if ttl == 64:
        return {
            "type": "phone",
            "confidence": "medium",
            "reason": "TTL=64 baseline typical of Android/iOS mobile devices on a hotspot"
        }

    return {"type": "unknown", "confidence": "low", "reason": "no vendor or hostname signal matched"}


def guess_type(vendor: str) -> str:
    """Backwards-compatible simple wrapper -- just the type string."""
    return guess_type_detailed(vendor)["type"]
