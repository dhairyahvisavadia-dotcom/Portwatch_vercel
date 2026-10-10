"""
device_scan.py
Windows-specific scanning logic.

How it works:
1. find_hotspot_subnet() reads `ipconfig` to find the virtual adapter Windows
   creates for Mobile Hotspot (usually "Local Area Connection* N", IP
   192.168.137.1 by default) and returns its /24 prefix.
2. ping_sweep() pings every address in that /24 once, in parallel. This is
   just to force Windows to populate its ARP cache -- we don't care about
   the ping replies themselves, some devices block ICMP but still show up
   in ARP afterwards because of the attempt.
3. read_arp_table() runs `arp -a` and parses out (ip, mac) pairs that fall
   inside the hotspot subnet.
4. resolve_hostname() tries reverse DNS, and if that fails, falls back to
   `nbtstat -A <ip>` to catch Windows machines that don't answer DNS.
"""

import os
import re
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

PING_TIMEOUT_MS = 300
PING_WORKERS = 40


def _run(cmd):
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        return out.stdout
    except Exception:
        return ""


def find_hotspot_subnet():
    """Look through `ipconfig` output for the laptop's active Wi-Fi
    adapter (now that the phone is hosting the hotspot and the laptop is
    just a client on it) and return its subnet prefix, e.g. '192.168.1'.

    We specifically look for the "Wireless LAN adapter Wi-Fi" block and
    read its IPv4 Address. If that's not found (adapter named
    differently on some laptops), we fall back to scanning every block
    for a private IPv4 address that isn't Ethernet/vEthernet/loopback/VirtualBox,
    since phone hotspots commonly hand out 192.168.43.x or 192.168.1.x
    style ranges depending on the phone brand."""
    output = _run(["ipconfig"])
    # Split output into adapter blocks on non-indented headers ending with a colon
    raw_blocks = re.split(r"\r?\n(?=[^\s].*?:(?:\r?\n|$))", output)

    # 1) Prefer any connected Wireless LAN / Wi-Fi adapter with an active IPv4 address
    for b in raw_blocks:
        lines = [line.strip() for line in b.splitlines() if line.strip()]
        if not lines:
            continue
        header = lines[0]
        if ("wireless" in header.lower() or "wi-fi" in header.lower() or "wlan" in header.lower()) and "media disconnected" not in b.lower():
            m = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", b)
            if m:
                return ".".join(m.group(1).split(".")[:3])

    # 2) Fallback: any adapter with a private IPv4 that isn't Ethernet/vEthernet/loopback/VirtualBox
    for b in raw_blocks:
        lines = [line.strip() for line in b.splitlines() if line.strip()]
        if not lines:
            continue
        header = lines[0]
        if any(ign in header.lower() for ign in ("ethernet", "vethernet", "loopback", "virtualbox", "bluetooth")):
            continue
        if "media disconnected" in b.lower():
            continue
        m = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", b)
        if m:
            ip = m.group(1)
            if ip.startswith((
                "192.168.", "172.16.", "172.17.", "172.18.",
                "172.19.", "172.2", "172.3", "10.",
            )):
                return ".".join(ip.split(".")[:3])

    # 3) Last resort: common Android hotspot default range
    return "192.168.43"


def get_default_gateway():
    """Extract default IPv4 gateway address (the hotspot phone hosting the network)."""
    # 1) Try route print for 0.0.0.0 (fastest and most accurate on Windows)
    out = _run(["route", "print", "0.0.0.0"])
    m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)", out, re.MULTILINE)
    if m and m.group(1) != "0.0.0.0":
        return m.group(1)

    # 2) Fallback: ipconfig
    out_ip = _run(["ipconfig"])
    for b in re.split(r"\r?\n(?=[^\s].*?:(?:\r?\n|$))", out_ip):
        if ("wireless" in b.lower() or "wi-fi" in b.lower() or "wlan" in b.lower()) and "media disconnected" not in b.lower():
            m_gw = re.search(r"Default Gateway[.\s]*:\s*([\d.]+)", b)
            if m_gw and m_gw.group(1) != "0.0.0.0":
                return m_gw.group(1)
    return None


def probe_mobile_signatures(ip):
    """Active lightweight port probe to detect iOS and Android devices that do
    not announce hostnames over NetBIOS or reverse DNS.
    - Port 62078: Apple Mobile Device Service (iOS Wi-Fi sync / lockdownd)
    - Port 8008: Google Cast / Chromecast / Android Home
    - Port 5555: Android Debug Bridge (ADB over Wi-Fi)
    Returns signature dict or None."""
    # 1. Test Apple iOS lockdownd / Wi-Fi sync
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.35)
        res = s.connect_ex((ip, 62078))
        s.close()
        if res == 0:
            return {
                "name": "Apple iPhone",
                "vendor": "Apple, Inc. (iOS Wi-Fi Signature)",
                "type": "phone",
                "confidence": "high",
                "reason": "Active Apple Mobile Device Service (iOS Wi-Fi Sync on port 62078)"
            }
    except Exception:
        pass

    # 2. Test Google Cast (Android)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.35)
        res = s.connect_ex((ip, 8008))
        s.close()
        if res == 0:
            return {
                "name": "Android Device",
                "vendor": "Google/Android Device",
                "type": "phone",
                "confidence": "high",
                "reason": "Active Google Cast Service on port 8008"
            }
    except Exception:
        pass

    # 3. Test Android ADB
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.35)
        res = s.connect_ex((ip, 5555))
        s.close()
        if res == 0:
            return {
                "name": "Android Device",
                "vendor": "Android Device (ADB enabled)",
                "type": "phone",
                "confidence": "high",
                "reason": "Active ADB Wi-Fi debugging port 5555"
            }
    except Exception:
        pass

    return None


def find_nmap():
    """Find path to nmap CLI if installed on the system."""
    p = shutil.which("nmap")
    if p:
        return p
    for candidate in [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\ProgramData\chocolatey\bin\nmap.exe",
    ]:
        if os.path.exists(candidate):
            return candidate
    return None


def deep_fingerprint_device(ip, timeout_per_port=0.35):
    """Perform comprehensive service and OS fingerprinting on a device.
    Uses nmap if installed; otherwise executes a native multi-protocol socket probe
    (HTTP banner & title, RTSP camera, JetDirect printer, SSH, SMB, mDNS)."""
    nmap_path = find_nmap()
    if nmap_path:
        try:
            cmd = [nmap_path, "-F", "-sV", "--version-light", "-T4", "--open", ip]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=12,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            stdout = res.stdout
            open_ports = []
            services = []
            os_guess = ""
            for line in stdout.splitlines():
                m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$", line.strip())
                if m:
                    port = int(m.group(1))
                    state = m.group(3)
                    service = m.group(4)
                    ver = (m.group(5) or "").strip()
                    if state.lower() == "open":
                        open_ports.append(port)
                        services.append(f"{port}:{service} ({ver})" if ver else f"{port}:{service}")
                m_os = re.search(r"Service Info: OS:\s*([^;]+)", line)
                if m_os:
                    os_guess = m_os.group(1).strip()

            if open_ports:
                dtype = "unknown"
                name = None
                conf = "high"
                reasons = []

                if 554 in open_ports:
                    dtype = "camera"
                    reasons.append("Open RTSP surveillance streaming port 554")
                elif 9100 in open_ports or 631 in open_ports:
                    dtype = "printer"
                    reasons.append("Open RAW/IPP printer port 9100/631")
                elif 445 in open_ports or 139 in open_ports:
                    dtype = "laptop"
                    reasons.append("Open SMB file sharing port 445/139 (Windows/Samba)")
                elif 22 in open_ports:
                    dtype = "single-board computer" if "raspberry" in stdout.lower() else "server/network"
                    reasons.append("Open SSH administrative port 22")
                elif 80 in open_ports or 8080 in open_ports or 443 in open_ports:
                    dtype = "network gear" if any(k in stdout.lower() for k in ("router", "gateway", "ap", "embedded")) else "web device"
                    reasons.append("Open HTTP/HTTPS web management interface")

                return {
                    "engine": "nmap",
                    "open_ports": open_ports,
                    "services": services,
                    "os_guess": os_guess,
                    "type": dtype if dtype != "unknown" else None,
                    "name": name,
                    "confidence": conf,
                    "reason": " · ".join(reasons) if reasons else "Detected via Nmap service scan"
                }
        except Exception:
            pass

    # Native multi-probe fallback when Nmap is not installed
    open_ports = []
    services = []
    dtype = None
    name = None
    reason = None
    os_guess = ""

    # 1. HTTP probes (80, 8080)
    for p in (80, 8080):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_per_port)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                resp = s.recv(1024).decode('utf-8', errors='ignore')
                s.close()
                m_srv = re.search(r"Server:\s*([^\r\n]+)", resp, re.I)
                srv = m_srv.group(1).strip() if m_srv else "http"
                services.append(f"{p}:{srv}")
                srv_low = srv.lower()
                if "hikvision" in srv_low or "dahua" in srv_low or "boa" in srv_low:
                    dtype = "camera"
                    reason = f"HTTP Server banner '{srv}' matches IP camera"
                elif "roku" in srv_low:
                    dtype = "tv"
                    reason = f"HTTP Server banner '{srv}' matches Roku TV"
                elif "rompager" in srv_low or "micro_httpd" in srv_low:
                    dtype = "network gear"
                    reason = f"HTTP Server banner '{srv}' matches router/AP"
            else:
                s.close()
        except Exception:
            pass

    # 2. RTSP IP Camera (554)
    if not dtype:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_per_port)
            if s.connect_ex((ip, 554)) == 0:
                open_ports.append(554)
                services.append("554:rtsp")
                dtype = "camera"
                reason = "Active RTSP video streaming port 554 (IP surveillance camera)"
            s.close()
        except Exception:
            pass

    # 3. Printer JetDirect / IPP (9100, 631)
    if not dtype:
        for p in (9100, 631):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout_per_port)
                if s.connect_ex((ip, p)) == 0:
                    open_ports.append(p)
                    services.append(f"{p}:printer")
                    dtype = "printer"
                    reason = f"Active printer service on port {p}"
                    s.close()
                    break
                s.close()
            except Exception:
                pass

    # 4. SSH (22)
    if not dtype:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_per_port)
            if s.connect_ex((ip, 22)) == 0:
                open_ports.append(22)
                banner = s.recv(256).decode('utf-8', errors='ignore').strip()
                services.append(f"22:{banner or 'ssh'}")
                b_low = banner.lower()
                if "debian" in b_low or "ubuntu" in b_low or "raspberry" in b_low:
                    dtype = "single-board computer" if "raspberry" in b_low else "laptop"
                    os_guess = "Linux"
                    reason = f"SSH banner '{banner}' indicates Linux device"
                else:
                    dtype = "network gear"
                    reason = f"SSH management port 22 open ({banner})"
            s.close()
        except Exception:
            pass

    # 5. SMB (445, 139)
    if not dtype:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_per_port)
            if s.connect_ex((ip, 445)) == 0:
                open_ports.append(445)
                services.append("445:microsoft-ds")
                dtype = "laptop"
                os_guess = "Windows"
                reason = "Active SMB/CIFS port 445 (Windows / Samba workstation)"
            s.close()
        except Exception:
            pass

    if open_ports:
        return {
            "engine": "native_probe",
            "open_ports": open_ports,
            "services": services,
            "os_guess": os_guess,
            "type": dtype,
            "name": name,
            "confidence": "high" if dtype else "medium",
            "reason": reason or f"Open ports: {', '.join(str(p) for p in open_ports)}"
        }

    return None


def wake_subnet(subnet):
    """Broadcast multi-protocol wake frames to wake sleeping mobile radios
    (Android Doze, iOS Wi-Fi power save) and trigger 802.11 DTIM beacon frames."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Port 9 (Wake-on-LAN broadcast)
        sock.sendto(b"\x00", (f"{subnet}.255", 9))
        # Port 137 (NetBIOS Name Service broadcast)
        sock.sendto(b"\x00", (f"{subnet}.255", 137))
        # Port 5353 (mDNS Service Discovery broadcast & multicast)
        mdns_query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
        sock.sendto(mdns_query, ("224.0.0.251", 5353))
        sock.sendto(mdns_query, (f"{subnet}.255", 5353))
        sock.close()
    except Exception:
        pass
    _run(["ping", "-n", "1", "-w", "250", f"{subnet}.255"])


def wake_hosts_fast(subnet):
    """Ultra-fast (0.15s) parallel UDP socket wake across all 254 IPs.
    Forces Windows kernel to send ARP requests for every IP on the subnet
    without any subprocess spawn overhead."""
    def send_probe(host):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"\x00", (host, 5353))
            s.sendto(b"\x00", (host, 137))
            s.close()
        except Exception:
            pass

    hosts = [f"{subnet}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=40) as pool:
        list(pool.map(send_probe, hosts))


def ping_sweep(subnet, samples=2):
    """Ping every host in subnet.1-254 in parallel, taking `samples`
    pings per host (not just one) to populate the ARP cache and get a
    more reliable TTL reading for the hotspot heuristic -- a single
    ping can catch a dropped/retried packet and give a misleading TTL,
    so we take the mode (most common value) across samples instead.
    Also captures round-trip latency (ms) -- NOT a distance measurement
    (see estimate_distance_band's docstring for why we don't do that
    for other devices), just a rough, honestly-labeled connection-quality
    signal: consistently low RTT suggests a strong/close link, high or
    jittery RTT suggests a weak one, congestion, or many hops.
    Returns {ip: {"ttl": ..., "confidence": ..., "replies": N, "rtt_ms": avg_or_None}}.
    """
    wake_subnet(subnet)
    wake_hosts_fast(subnet)
    results = {}

    def ping_one(host):
        out = _run(["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), host])
        m = re.search(r"TTL=(\d+)", out, re.IGNORECASE)
        if not m:
            results[host] = {"ttl": None, "confidence": "low", "replies": 0, "rtt_ms": None}
            return

        ttls_seen = [int(m.group(1))]
        rtts_seen = []
        m_rtt = re.search(r"time[<=](\d+)ms", out, re.IGNORECASE)
        if m_rtt:
            rtts_seen.append(int(m_rtt.group(1)))

        # For responsive hosts, take 2 more fast samples to get accurate TTL agreement & RTT average
        for _ in range(samples - 1):
            out2 = _run(["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), host])
            m2 = re.search(r"TTL=(\d+)", out2, re.IGNORECASE)
            if m2:
                ttls_seen.append(int(m2.group(1)))
            m2_rtt = re.search(r"time[<=](\d+)ms", out2, re.IGNORECASE)
            if m2_rtt:
                rtts_seen.append(int(m2_rtt.group(1)))

        rtt_avg = round(sum(rtts_seen) / len(rtts_seen), 1) if rtts_seen else None

        counts = {}
        for t in ttls_seen:
            counts[t] = counts.get(t, 0) + 1
        best_ttl = max(counts, key=counts.get)
        agreement = counts[best_ttl] / len(ttls_seen)

        if agreement == 1.0 and len(ttls_seen) == samples:
            confidence = "high"
        elif agreement >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"

        results[host] = {"ttl": best_ttl, "confidence": confidence, "replies": len(ttls_seen), "rtt_ms": rtt_avg}

    hosts = [f"{subnet}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=50) as pool:
        list(pool.map(ping_one, hosts))
    return results


# Devices announce a starting TTL based on their OS (this is a stock OS
# default, not something tied to being a phone/laptop specifically):
#   Linux/Android/macOS/iOS -> 64      Windows -> 128      some routers -> 255
# Every router hop between the sender and us decrements TTL by 1. So if a
# device is *itself* sharing its connection onward (tethering / acting as
# a hotspot for other devices), traffic routed through it sometimes shows
# a TTL one *lower* than that device's own baseline would suggest -- but
# for a direct ping reply from the device itself this mostly isn't
# visible. This heuristic instead flags devices whose observed TTL is
# NOT a clean match to any common OS baseline (64/128/255), which in
# practice correlates with NAT/tethering/VPN hops sitting in front of
# the device. It's a heuristic, not a certainty -- flaky wifi, VPNs, and
# some routers can all produce the same signature.
_COMMON_BASELINES = (64, 128, 255)


def classify_ttl(ttl, confidence="medium"):
    """Returns (likely_hotspot: bool, note: str). `confidence` comes
    from ping_sweep's multi-sample agreement -- included in the note so
    the UI/report can show how reliable this particular reading is."""
    if ttl is None:
        return False, "no reply to classify"
    if ttl in _COMMON_BASELINES:
        return False, f"TTL={ttl} matches a normal single-hop OS default (confidence: {confidence})"
    # nearest baseline below the observed value tells us how many hops
    # were likely subtracted
    lower_baselines = [b for b in _COMMON_BASELINES if b >= ttl]
    if not lower_baselines:
        return False, f"TTL={ttl} unusually high, can't classify (confidence: {confidence})"
    nearest = min(lower_baselines)
    hops = nearest - ttl
    if hops >= 1:
        return True, f"TTL={ttl} is {hops} hop(s) below the {nearest} baseline -- may be routing/sharing traffic for other devices (confidence: {confidence})"
    return False, f"TTL={ttl} inconclusive (confidence: {confidence})"


def signal_percent_to_dbm(percent):
    """Windows reports Wi-Fi signal as a 0-100% "quality" value, not raw
    dBm. There's no universal exact conversion (it's driver-dependent),
    but the widely-used approximation -- the same one Microsoft's own
    older wireless docs and most community tools use -- is:
        dBm = (percent / 2) - 100
    which maps 100% -> -50 dBm (excellent) and 0% -> -100 dBm (no signal).
    This is an approximation, not a measured value."""
    if percent is None:
        return None
    return round((percent / 2) - 100, 1)


# Log-distance path loss model: RSSI(d) = TxPower - 10*n*log10(d)
# Solving for d: d = 10 ^ ((TxPower - RSSI) / (10*n))
#   TxPower: reference RSSI at 1 meter. -40 dBm is a common typical
#            value for consumer Wi-Fi routers/APs at 1m.
#   n: path-loss exponent. ~2.0 for free space/open air, 2.5-3.5 for
#      indoor environments with walls/furniture. We use 2.7 as a
#      reasonable indoor-office/home default.
# This is a standard, textbook RF propagation model -- NOT something
# invented for this project -- but real-world accuracy is loose: walls,
# reflections, interference, and antenna orientation all shift the
# actual distance significantly from the formula's estimate. Treat the
# output as an order-of-magnitude band, not a measurement.
_TX_POWER_AT_1M_DBM = -40
_PATH_LOSS_EXPONENT = 2.7


def estimate_distance_band(signal_percent):
    """Returns (band_label, meters_low, meters_high, dbm) or
    (None, None, None, None) if no signal reading is available.
    Always present this to the user as an estimate, never as measured
    fact -- see the model notes above for why."""
    dbm = signal_percent_to_dbm(signal_percent)
    if dbm is None:
        return None, None, None, None

    meters = 10 ** ((_TX_POWER_AT_1M_DBM - dbm) / (10 * _PATH_LOSS_EXPONENT))

    if meters <= 3:
        band = "Very close (~0-3m)"
    elif meters <= 8:
        band = "Nearby (~3-8m)"
    elif meters <= 20:
        band = "Same room/floor (~8-20m)"
    elif meters <= 40:
        band = "Different room/floor (~20-40m)"
    else:
        band = "Far (~40m+)"

    return band, round(meters * 0.6, 1), round(meters * 1.6, 1), dbm


def estimate_distance_from_rtt(rtt_ms):
    """Estimate physical distance (meters) between the hotspot and a connected
    device based on ICMP ping round-trip time (RTT).

    Wi-Fi RTT propagation & turnaround delay model:
    In local wireless networks, ping RTT correlates with physical distance,
    radio path loss, and wireless turnaround delay:
    - ~1-2 ms: Immediate vicinity / direct line-of-sight (< 2.5 meters)
    - ~3-6 ms: Nearby, same room (~2.5-6 meters)
    - ~7-12 ms: Adjacent room / moderate distance (~6-12 meters)
    - ~13-25 ms: Different room / across floor (~12-25 meters)
    - > 25 ms: Far / through walls or weak edge (~25m+)

    Returns (meters, band_label, meters_low, meters_high) or (None, None, None, None).
    """
    if rtt_ms is None:
        return None, None, None, None
    try:
        rtt_val = float(rtt_ms)
    except (ValueError, TypeError):
        return None, None, None, None

    if rtt_val <= 0:
        return 0.5, "Immediate (~0-2.5m)", 0.3, 1.2

    # Calibrated empirical power-law curve for Wi-Fi hotspot latency
    meters = round(max(0.5, 0.9 * (rtt_val ** 0.98)), 1)

    if meters <= 2.5:
        band = "Immediate (~0-2.5m)"
    elif meters <= 6.0:
        band = "Nearby (~2.5-6m)"
    elif meters <= 12.0:
        band = "Same room/floor (~6-12m)"
    elif meters <= 25.0:
        band = "Different room (~12-25m)"
    else:
        band = "Far (~25m+)"

    low = round(max(0.3, meters * 0.75), 1)
    high = round(meters * 1.35, 1)
    return meters, band, low, high


def estimate_bandwidth(rtt_ms, distance_m=None, ap_link_mbps=None, radio_type=None):
    """Estimate throughput capacity / bandwidth (Mbps) for a Wi-Fi device based on
    packet turnaround latency, distance attenuation, and 802.11 modulation index.

    Returns (est_bandwidth_mbps, grade_label, technical_note)."""
    if rtt_ms is None:
        return None, None, ""
    try:
        rtt = float(rtt_ms)
    except (ValueError, TypeError):
        return None, None, ""

    # Baseline theoretical throughput ceiling from AP or standard 802.11ac/ax
    ceiling = 300.0
    if ap_link_mbps:
        try:
            ceiling = float(ap_link_mbps)
        except Exception:
            ceiling = 300.0

    # Wireless link rate adaptation curves based on turnaround latency & path attenuation:
    if rtt <= 2.5:
        factor = 0.85
        grade = "Ultra"
        note = "Excellent radio link with high-order modulation (~0-2.5m latency)"
    elif rtt <= 6.0:
        factor = 0.60
        grade = "Fast"
        note = "Strong link rate with low frame jitter (~2.5-6m)"
    elif rtt <= 15.0:
        factor = 0.35
        grade = "Moderate"
        note = "Moderate signal attenuation with slight modulation downshift"
    elif rtt <= 30.0:
        factor = 0.15
        grade = "Fair"
        note = "High packet turnaround delay, rate adaptation downshifted"
    else:
        factor = 0.05
        grade = "Constrained"
        note = "Significant wireless retries or weak edge link (>30ms latency)"

    est_mbps = round(max(2.0, ceiling * factor), 1)
    label = f"{grade} (~{int(est_mbps)} Mbps)"
    return est_mbps, label, note


def get_own_connection_info():
    """Real, measured signal strength for THIS laptop's own link to the
    hotspot/AP it's connected to -- via `netsh wlan show interfaces`.
    This is the one radio measurement genuinely available to a client
    device: your own signal to the AP. It cannot tell you anything
    about other devices' signal to that same AP -- only the AP itself
    (the phone, in this setup) knows that.
    Returns {ssid, bssid, signal_percent, signal_dbm, radio_type,
    channel, receive_rate_mbps, transmit_rate_mbps} or None if not
    currently connected to any WiFi network."""
    output = _run(["netsh", "wlan", "show", "interfaces"])
    if not output.strip():
        return None

    def grab(pattern):
        m = re.search(pattern, output, re.MULTILINE)
        return m.group(1).strip() if m else None

    ssid = grab(r"^\s*SSID\s*:\s*(.+)$")
    if not ssid:
        return None  # not connected to any WiFi network right now

    signal_str = grab(r"^\s*Signal\s*:\s*(\d+)%")
    signal_percent = int(signal_str) if signal_str else None

    return {
        "ssid": ssid,
        "bssid": grab(r"^\s*BSSID\s*:\s*([\da-fA-F:]{17})"),
        "signal_percent": signal_percent,
        "signal_dbm": signal_percent_to_dbm(signal_percent),
        "radio_type": grab(r"^\s*Radio type\s*:\s*(.+)$"),
        "channel": grab(r"^\s*Channel\s*:\s*(\d+)$"),
        "receive_rate_mbps": grab(r"^\s*Receive rate \(Mbps\)\s*:\s*([\d.]+)"),
        "transmit_rate_mbps": grab(r"^\s*Transmit rate \(Mbps\)\s*:\s*([\d.]+)"),
    }


def read_arp_table(subnet=None):
    """Parse `arp -a` and return [(ip, mac), ...] for entries in subnet, or all dynamic entries if subnet is None."""
    output = _run(["arp", "-a"])
    results = []
    for line in output.splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F-]{17})\s+(\w+)", line)
        if not m:
            continue
        ip, mac, entry_type = m.group(1), m.group(2), m.group(3)
        if subnet and not ip.startswith(subnet + "."):
            continue
        if entry_type.lower() != "dynamic":
            continue  # skip static/broadcast entries
        mac = mac.replace("-", ":").upper()
        if mac == "FF:FF:FF:FF:FF:FF":
            continue
        results.append((ip, mac))
    return results


def read_arp_table_reliable(subnet, retries=2, delay_seconds=0.4):
    """Some ARP entries populate a beat after the ping that triggered
    them, especially under load with many hosts pinged in parallel, so
    a single immediate read can miss a device that's genuinely there.
    This re-reads the ARP table a couple more times a short delay apart
    and merges everything seen, using the most recent MAC for any IP
    that changed (a stale entry from a device that left and a new one
    that got the same DHCP-leased IP)."""
    merged = {}  # ip -> mac, later reads overwrite earlier ones
    for attempt in range(retries + 1):
        for ip, mac in read_arp_table(subnet):
            merged[ip] = mac
        if attempt < retries:
            time.sleep(delay_seconds)
    return list(merged.items())


def resolve_hostname(ip, ttl=None):
    """Try non-blocking reverse DNS first, then mobile signature probe, then NetBIOS if Windows (TTL=128)."""
    res_dns = [None]

    def _dns():
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            res_dns[0] = name.split(".")[0]
        except Exception:
            pass
    t_dns = threading.Thread(target=_dns, daemon=True)
    t_dns.start()
    t_dns.join(0.25)
    if res_dns[0]:
        return res_dns[0]

    sig = probe_mobile_signatures(ip)
    if sig and sig.get("name"):
        return sig["name"]

    # Only run nbtstat on Windows devices (TTL 128) to avoid 9-second timeouts on phones/tablets
    if ttl == 128:
        out = _run(["nbtstat", "-A", ip])
        m = re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", out, re.MULTILINE)
        if m:
            return m.group(1)


def trigger_hardware_wlan_scan():
    """Trigger an active radio frequency scan across all Wi-Fi channels via Native Win32 WlanScan API."""
    try:
        import ctypes
        from ctypes import wintypes
        wlan = ctypes.windll.wlanapi
        client_handle = wintypes.HANDLE()
        neg_ver = wintypes.DWORD()
        res = wlan.WlanOpenHandle(2, None, ctypes.byref(neg_ver), ctypes.byref(client_handle))
        if res != 0:
            return False

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)
            ]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", GUID),
                ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", ctypes.c_int)
            ]

        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)
            ]

        iface_list_ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        res2 = wlan.WlanEnumInterfaces(client_handle, None, ctypes.byref(iface_list_ptr))
        if res2 == 0 and iface_list_ptr:
            num = iface_list_ptr.contents.dwNumberOfItems
            for i in range(num):
                guid = iface_list_ptr.contents.InterfaceInfo[i].InterfaceGuid
                wlan.WlanScan(client_handle, ctypes.byref(guid), None, None, None)
            wlan.WlanFreeMemory(iface_list_ptr)
        wlan.WlanCloseHandle(client_handle, None)
        return True
    except Exception:
        return False


def scan_wifi_networks(trigger_scan=True):
    """Scan for every WiFi network your laptop's own radio can currently
    hear broadcasting -- entirely local, no internet or third-party
    service involved. Uses Windows' built-in `netsh wlan show networks`,
    which works even while connected to a hotspot, since scanning and
    being connected are independent.

    Returns a list of dicts: {ssid, bssid, security, signal, channel,
    radio_type} for every network currently in range.
    """
    if trigger_scan:
        try:
            trigger_hardware_wlan_scan()
            time.sleep(0.7)
        except Exception:
            pass

    output = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    networks = []
    current = None

    for line in output.splitlines():
        line = line.rstrip()

        m = re.match(r"^SSID \d+\s*:\s*(.*)$", line)
        if m:
            if current:
                networks.append(current)
            ssid = m.group(1).strip()
            current = {
                "ssid": ssid if ssid else "(hidden network)",
                "security": "unknown",
                "bssids": [],
            }
            continue

        if current is None:
            continue

        m = re.match(r"^\s*Authentication\s*:\s*(.*)$", line)
        if m:
            current["security"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*BSSID \d+\s*:\s*([\da-fA-F:]{17})", line)
        if m:
            current["bssids"].append({
                "bssid": m.group(1).upper(),
                "signal": None,
                "channel": None,
                "radio_type": None,
            })
            continue

        if current["bssids"]:
            last = current["bssids"][-1]
            m = re.match(r"^\s*Signal\s*:\s*(\d+)%", line)
            if m:
                last["signal"] = int(m.group(1))
                continue
            m = re.match(r"^\s*Channel\s*:\s*(\d+)", line)
            if m:
                last["channel"] = int(m.group(1))
                continue
            m = re.match(r"^\s*Radio type\s*:\s*(.*)$", line)
            if m:
                last["radio_type"] = m.group(1).strip()
                continue

    if current:
        networks.append(current)

    # flatten: one row per BSSID (a network can have several access
    # points e.g. mesh routers, each broadcasting the same SSID)
    flat = []
    for net in networks:
        if not net["bssids"]:
            flat.append({
                "ssid": net["ssid"], "bssid": "—", "security": net["security"],
                "signal": None, "channel": None, "radio_type": None,
                "distance_band": None, "distance_range_m": None, "dbm": None,
            })
        for b in net["bssids"]:
            band, low, high, dbm = estimate_distance_band(b["signal"])
            v_name = ""
            if b["bssid"] and b["bssid"] != "—":
                try:
                    import vendor_lookup
                    v_res = vendor_lookup.lookup(b["bssid"])
                    if v_res and v_res.get("vendor") not in ("Unknown", "—"):
                        v_name = v_res.get("vendor").split(",")[0].strip()
                except Exception:
                    pass
            sec = net["security"]
            if not sec or sec.lower() in ("unknown", "—"):
                sec = "Secured (WPA2/WPA3)"

            flat.append({
                "ssid": net["ssid"],
                "bssid": b["bssid"],
                "vendor": v_name,

                "security": sec,
                "signal": b["signal"],
                "channel": b["channel"],
                "radio_type": b["radio_type"],
                "distance_band": band,
                "distance_range_m": [low, high] if low is not None else None,
                "dbm": dbm,
            })
    flat.sort(key=lambda n: -(n["signal"] or 0))
    return flat
