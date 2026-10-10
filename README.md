# PortWatch

<div align="center">

**Real-Time Wi-Fi Subnet & Mobile Hotspot Reconnaissance Station**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework: Flask 3.0](https://img.shields.io/badge/framework-Flask%203.0-black.svg)](https://flask.palletsprojects.com/)
[![Validation: Pydantic 2.0](https://img.shields.io/badge/validation-Pydantic%202.0-e92063.svg)](https://docs.pydantic.dev/)
[![ORM: SQLAlchemy 2.0](https://img.shields.io/badge/ORM-SQLAlchemy%202.0-red.svg)](https://www.sqlalchemy.org/)
[![Database: PostgreSQL / SQLite WAL](https://img.shields.io/badge/database-PostgreSQL%20%7C%20SQLite%20WAL-blue.svg)](https://www.postgresql.org/)
[![Docker Compose](https://img.shields.io/badge/docker-ready-2496ED.svg)](https://www.docker.com/)
[![Tests: Pytest & Flake8](https://img.shields.io/badge/tests-90%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*A full-stack network monitoring dashboard and telemetry engine designed to detect, fingerprint, and visualize connected client devices on Wi-Fi subnets and mobile hotspots in real time.*

[Features](#-key-features) •
[Architecture](#-system-architecture) •
[Environment Variables](#-environment-variables-reference) •
[Quickstart](#-quickstart) •
[Docker](#-docker-deployment) •
[Cloud Deployment](#-cloud-deployment-vercel--supabase) •
[API Reference](#-rest-api-reference) •
[Testing & QA](#-test-suite--quality-assurance)

</div>

---

## 📌 Executive Summary

Modern mobile operating systems (iOS and Android) provide native personal hotspot capabilities, but provide virtually **zero visibility** into what devices are actively connected, their bandwidth usage, their physical proximity, or their hardware origins.

**PortWatch** addresses this visibility gap. Running as an unprivileged client on a workstation joined to the hotspot or LAN, PortWatch combines passive ARP cache inspection, multi-threaded ICMP echo sweeps, socket-level service fingerprinting, and a local 58,000+ IEEE OUI database to reconstruct an accurate inventory of connected nodes.

Built as a production-grade full-stack network engineering system, PortWatch incorporates:
- **Application Factory Architecture**: Clean Flask modular blueprint separation (`routes/views.py`, `routes/auth.py`, `routes/api.py`).
- **Decoupled Service Layer**: Isolated business logic in `device_service.py` separating HTTP transport from data models.
- **Type-Safe Configuration**: Strict environment validation using `pydantic-settings` with informative startup diagnostics.
- **Concurrency & Persistence Hardening**: SQLite WAL-mode concurrency, zero connection leaks via context managers, and pooled PostgreSQL support.
- **Production Containerization**: Multi-stage hardened Docker builds executing under an unprivileged non-root user (`portwatch:1001`).
- **OWASP-Aligned Hardening**: CSRF tokens, token-bucket rate limiters, anti-timing dummy hashes, and secure HTTP headers.

---

## ⚡ Key Features

- **Layer 2/3 Network Discovery**:
  - Automatically identifies local default gateways and resolves `/24` hotspot subnets (`192.168.137.0/24`, `192.168.43.0/24`, `172.20.10.0/24`).
  - ThreadPool-driven parallel ping sweeps with power-save wakeups to reliably probe sleeping mobile clients.
  - ARP table delta tracking that preserves disconnected devices as offline nodes with exact "last seen" timestamps.

- **Multi-Signal Hardware Fingerprinting**:
  - **Local IEEE OUI Database**: Bundled offline SQLite database with **58,000+ hardware vendor entries** for zero-latency, rate-limit-free manufacturer resolution.
  - **MAC Privacy Awareness**: Automatically detects IEEE 802 Locally Administered Bits (LABs) to classify private/randomized MAC addresses used by modern Android 10+ and iOS 14+ devices.
  - **TTL Hop Classification**: Evaluates IP Time-To-Live (TTL) baselines (64 for iOS/Linux/Android, 128 for Windows, 255 for network gear) to detect tethering and downstream network bridges.
  - **Mobile Service Signatures**: Non-invasive socket probes for Apple MobileDevice (`lockdownd`), Google Cast (`8008/8009`), and Android ADB (`5555`).

- **RF Propagation & Link Estimation**:
  - Direct Wi-Fi telemetry integration via native OS interfaces (`netsh wlan show interfaces`).
  - Distance estimation using standard log-distance path-loss models based on measured round-trip time (RTT).
  - Bandwidth throughput grading based on dynamic latency jitter analysis.

- **Security & Multi-Tenancy**:
  - Multi-user authentication with isolated tenant workspaces.
  - Strict CSRF token validation on state-changing requests (`Flask-WTF`).
  - Defense against timing side-channels via dummy password hash evaluation on non-existent users.
  - Exponential brute-force lockout policy (locks account for 15 minutes after 5 failed attempts).
  - Production security headers: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`.

- **Brutalist Cyber-Hardware Interface**:
  - Flipper Zero / Wireshark-inspired brutalist tactile UI with instant light/dark mode switching.
  - Real-time client-side filter toolbar (live search, category tabs: All, Online, Offline, Phones, Laptops, IoT).
  - Click-to-copy utility for MAC and IP addresses with instant toast feedback.
  - Interactive Three.js 3D network topology map visualizing client hop relationships and signal radii.

- **Dual-Mode Cloud Deployment**:
  - **Local Hardware Mode**: Real-time passive/active network probing on physical network adapters.
  - **Cloud Showcase Mode**: Automatic serverless simulation mode (Vercel / Render / Railway) that generates dynamic, realistic client telemetry with live jitter for technical evaluations without physical hardware dependencies.

---

## 🏛 System Architecture

The PortWatch platform is architected around a 5-tier layered design adhering to separation of concerns:

```mermaid
graph TD
    subgraph "Presentation Tier (Browser)"
        UI["Brutalist Cyber UI / Three.js 3D Map"]
        Filter["Real-time Filter & Search Toolbar"]
        Toast["Clipboard & Toast Manager"]
    end

    subgraph "Transport & Routing Tier (Flask 3.0+ Application Factory)"
        App["create_app Factory (app.py)"]
        AuthBP["routes/auth.py — Authentication & RBAC"]
        ViewsBP["routes/views.py — HTML Templates"]
        ApiBP["routes/api.py — REST API (/api/ & /api/v1/)"]
        SecExt["extensions.py — CSRF & Token-Bucket Rate Limiter"]
    end

    subgraph "Service Layer Tier"
        DeviceService["device_service.py — Lookup & Telemetry Service"]
        Scanner["scanner_service.py — Subnet Sweep Engine"]
    end

    subgraph "Network Probing & Fingerprinting Pipeline"
        DeviceScan["device_scan.py — ARP & ICMP Probing"]
        VendorLookup["vendor_lookup.py — IEEE OUI & MAC Privacy"]
        DemoEngine["scripts/seed_demo_data.py — Telemetry Simulator"]
    end

    subgraph "Data Access & Persistence Tier (SQLAlchemy 2.0 ORM)"
        DBAdapter["database.py — Dual-Engine Adapter & Connection Pool"]
        DBStore["db.py / auth_db.py — WAL-Safe Data Access Layer"]
        DevModel[("Device & Timeline Events")]
        UserModel[("User Accounts & Activity Audit")]
        Engines[("PostgreSQL 16 Pool / Zero-Conf SQLite WAL")]
        OUIDB[("oui.db — 58,000+ IEEE Vendors")]
    end

    UI <-->|JSON REST API & CSRF| ApiBP
    UI <-->|Jinja2 Templates| ViewsBP
    ApiBP <--> SecExt
    ApiBP --> DeviceService
    DeviceService --> DBStore
    DeviceService --> DeviceScan
    AuthBP --> DBStore
    Scanner --> DeviceScan
    DeviceScan --> VendorLookup
    VendorLookup --> OUIDB
    Scanner --> DBStore
    DemoEngine -.->|Cloud Simulation| Scanner
    DBStore --> DBAdapter
    DBAdapter --> Engines
```

---

## ⚙ Environment Variables Reference

Environment configurations are centrally loaded and validated via `pydantic-settings` in [config.py](file:///c:/Users/SIDDHA/OneDrive/Desktop/portwatch_2/config.py). Incorrect types or out-of-range values raise clear startup exceptions.

| Variable | Type | Allowed Values | Default | Description |
|:---------|:-----|:---------------|:--------|:------------|
| `PORTWATCH_SECRET_KEY` | `string` | Min 32 chars hex / string | *Generated (Development)* | Secret key for signing session cookies and CSRF tokens. |
| `PORTWATCH_SESSION_MINUTES` | `integer` | `1` to `1440` | `2` | Session inactivity timeout in minutes (sliding window). |
| `PORTWATCH_ENV` | `string` | `development`, `testing`, `production` | `development` | Deployment environment. Setting to `production` enforces HTTPS secure cookies. |
| `PORTWATCH_HOST` | `string` | Valid IP / hostname | `0.0.0.0` | Host bind address for WSGI server. |
| `PORTWATCH_PORT` | `integer` | `1` to `65535` | `5000` | Port to bind the web server. |
| `FLASK_DEBUG` | `integer` | `0` or `1` | `0` | Enable or disable Flask debug mode. Keep `0` in production. |
| `DATABASE_URL` | `string` | Valid URI | *Empty (Local SQLite)* | Remote PostgreSQL connection string (Neon, Supabase, Railway). |
| `PORTWATCH_SCAN_INTERVAL` | `integer` | `1` to `3600` | `20` | Interval in seconds between background subnet sweep cycles. |
| `PORTWATCH_DEMO_MODE` | `boolean` | `true`, `false`, `1`, `0` | `false` | Enable virtual client nodes and latency simulation for cloud showcase. |

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Windows, Linux, or macOS workstation

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/your-username/portwatch.git
cd portwatch

# Create and activate virtual environment
python -m venv .venv
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install production dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 2. Configure Environment

Copy the pre-configured template:
```bash
cp .env.example .env
```
*(Default settings automatically run in local zero-configuration SQLite WAL mode).*

### 3. Launch PortWatch

```bash
python app.py
```
Open **[http://localhost:5000](http://localhost:5000)** in your browser.

- Sign up for a personal account, or use the preconfigured demonstration credentials:
  - **Username**: `demo`
  - **Password**: `DemoAdmin123!`

---

## 🐳 Docker Deployment

PortWatch features a **multi-stage, security-hardened Dockerfile** and a complete `docker-compose.yml` service specification with PostgreSQL 16.

### Architectural Hardening Highlights:
- **Multi-Stage Build (`builder` -> `runtime`)**: Compiles dependencies in an isolated build container, producing a minimal, clean runtime image without compiler bloat.
- **Unprivileged Non-Root User**: Runs under dedicated service account `portwatch` (UID `1001`, GID `1001`).
- **Linux Capabilities**: Grants granular `cap_net_raw+ep` to `/bin/ping` so the non-root user can perform ICMP probes without requiring root privileges.
- **Automated Healthchecks**: Validates database and HTTP responsiveness via `/api/health` every 30 seconds.

### Start the Full-Stack Application:
```bash
docker compose up -d --build
```

### Check Service Health:
```bash
docker compose ps
```
The application will automatically wait for PostgreSQL to become healthy, run database migrations, and expose the web dashboard on port `5000`.

### Stop Services:
```bash
docker compose down
```

---

## ☁ Cloud Deployment (Vercel & Supabase)

PortWatch is architected to run seamlessly on modern serverless cloud infrastructure:

### 1. Database Setup (Supabase or Neon)
1. Create a free PostgreSQL database on [Supabase](https://supabase.com/) or [Neon](https://neon.tech/).
2. Copy your pooled connection URI:
   ```
   postgresql://postgres:[PASSWORD]@[HOST]:5432/postgres
   ```

### 2. Deploying to Vercel
1. Fork or push this repository to your GitHub account.
2. Import the repository into [Vercel](https://vercel.com/).
3. In Project Settings → Environment Variables, add:
   - `DATABASE_URL`: Your Supabase/Neon PostgreSQL connection URI.
   - `PORTWATCH_SECRET_KEY`: A random 64-character secret key.
   - `PORTWATCH_DEMO_MODE`: `true` (enables dynamic cloud showcase telemetry).
   - `PORTWATCH_ENV`: `production`
4. Click **Deploy**. Vercel will automatically build the serverless WSGI bridge (`api/index.py`) using `vercel.json`.

---

## 📡 REST API Reference

PortWatch provides dual-mounted, versioned RESTful APIs accessible concurrently via `/api/` and `/api/v1/`.

| Method | Endpoint | Description | Auth Required | Rate Limit |
|:-------|:---------|:------------|:-------------:|:----------:|
| `GET` | `/api/v1/health` | System and database connection pool health check | No | None |
| `GET` | `/api/v1/status` | Current subnet discovery and background sweep state | Yes | Default |
| `GET` | `/api/v1/devices` | Full inventory of discovered network devices | Yes | Default |
| `GET` | `/api/v1/devices/<mac>/timeline` | Lifecycle history and connect/disconnect events | Yes | Default |
| `POST` | `/api/v1/devices/<mac>/deep-scan` | On-demand service port scan and OS fingerprinting | Yes | 15 / min |
| `POST` | `/api/v1/devices/lookup` | Hardware MAC / vendor resolution and locator | Yes | Default |
| `PATCH` | `/api/v1/devices/<mac>` | Manually apply custom label name and device type | Yes | Default |
| `DELETE` | `/api/v1/devices/<mac>` | Delete persistent history for a device | Yes | Default |
| `POST` | `/api/v1/rescan` | Trigger an immediate asynchronous subnet sweep | Yes | 12 / min |
| `GET` | `/api/v1/user/me` | Current authenticated user session parameters | Yes | Default |
| `GET` | `/api/v1/export/csv` | Download complete network audit report (CSV) | Yes | Default |
| `GET` | `/api/v1/export/json` | Download complete network audit report (JSON) | Yes | Default |

---

## 🧪 Test Suite & Quality Assurance

PortWatch maintains an automated test suite with **90 unit and integration tests** achieving complete coverage across routing, authentication, security hardening, database pooling, and cloud deployment:

```bash
# Run the complete test suite with Pytest
pytest -v

# Or using Python's built-in unittest discovery runner
python -m unittest discover tests -v

# Run Flake8 PEP 8 code quality linter (Configured for 0 warnings/errors)
flake8 .
```

### Test Suite Structure:
- `tests/test_modernization_and_hardening.py`: Pydantic settings validation, service layer decoupling, database connection safety, and container specs.
- `tests/test_architecture_phase4.py`: Application Factory pattern, Blueprint registration, and structured JSON error handlers.
- `tests/test_security.py`: CSRF enforcement, account lockout defense, open redirect prevention, and XSS sanitization.
- `tests/test_auth_and_landing.py`: Multi-user session lifetime, inactivity logout, password policy, and user isolation.
- `tests/test_core.py`: TTL hop classification, ping sweep parsing, ARP extraction, and IEEE OUI lookups.
- `tests/test_database_layer.py`: Dual-mode CloudConnection adapter, SQLAlchemy 2.0 ORM CRUD, and connection pooling.
- `tests/test_deployment_phase5.py`: Vercel serverless entrypoint, container configuration verification, and demo data seeder.
- `tests/test_ui_phase3.py`: Brutalist cyber UI components, telemetry badges, and interactive toolbars.

---

## 🛡 Ethical Security & Transparency Notice

PortWatch is strictly designed for **authorized personal network monitoring, mobile hotspot management, and network diagnostics**:
- **Zero Raw Sniffing**: Does not place wireless interfaces into 802.11 monitor mode or capture third-party data frames.
- **Zero Cryptographic Attacks**: Does not perform WPA handshake capture or decryption.
- **Zero Cache Poisoning**: Does not generate spoofed ARP responses or manipulate network routing.
- All hardware resolution is conducted using standard OS sockets, local ARP caches, and public IEEE registry assignments.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
