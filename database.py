"""
database.py
Unified, production-ready Database Architecture and ORM layer for PortWatch.

Supports:
1. Local development and offline testing with SQLite (portwatch.db / portwatch_auth.db)
2. Production cloud deployment with PostgreSQL (Neon, Supabase, Railway, Vercel Postgres)
   via standard DATABASE_URL with pure-Python pg8000 driver fallback
3. Connection pooling (QueuePool with pool_pre_ping for auto-reconnection)
4. Declarative SQLAlchemy 2.0+ ORM Models: User, ActivityLog, Device, DeviceTimelineEvent
5. Automatic schema creation and migration across all supported SQL engines
"""

import os
import re
import time
from contextlib import contextmanager

from sqlalchemy import (
    Column,
    Float,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
from sqlalchemy.pool import QueuePool, StaticPool

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

Base = declarative_base()


# ============================================================================
# Declarative ORM Domain Models
# ============================================================================

class User(Base):
    """User account domain model with authentication and brute-force tracking."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), default="")
    password_hash = Column(String(255), nullable=False)
    created_at = Column(Float, default=time.time)
    last_login_at = Column(Float, default=time.time)
    last_ip = Column(String(64), default="")
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(Float, default=0.0)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email or "",
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
            "last_ip": self.last_ip or "",
            "failed_login_attempts": self.failed_login_attempts or 0,
            "locked_until": self.locked_until or 0.0,
        }


class ActivityLog(Base):
    """Audit log entry capturing user activity and security events (3-day rolling window)."""
    __tablename__ = "activity_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, index=True)
    action = Column(String(64), nullable=False)
    detail = Column(Text, default="")
    timestamp = Column(Float, nullable=False, index=True)

    __table_args__ = (
        Index("idx_activity_user_time", "user_id", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "detail": self.detail or "",
            "timestamp": self.timestamp,
        }


class Device(Base):
    """Network device inventory tracking connection state, RF metrics, and fingerprints."""
    __tablename__ = "devices"

    user_id = Column(Integer, primary_key=True, nullable=False, default=1)
    mac = Column(String(32), primary_key=True, nullable=False)
    ip = Column(String(64), index=True)
    vendor = Column(String(128), default="")
    guessed_type = Column(String(64), default="unknown")
    hostname = Column(String(128), default="")
    label_name = Column(String(128), nullable=True)
    label_type = Column(String(64), nullable=True)
    first_seen = Column(Float)
    last_seen = Column(Float, index=True)
    online = Column(Integer, default=0, index=True)
    ttl = Column(Integer, nullable=True)
    likely_hotspot = Column(Integer, default=0)
    hotspot_note = Column(Text, default="")
    rtt_ms = Column(Float, nullable=True)
    rtt_distance_m = Column(Float, nullable=True)
    distance_band = Column(String(64), default="")
    bandwidth_mbps = Column(Float, nullable=True)
    bandwidth_grade = Column(String(32), default="")
    open_ports = Column(Text, default="")
    os_guess = Column(Text, default="")
    ttl_confidence = Column(String(32), default="")
    vendor_confidence = Column(String(32), default="")
    vendor_source = Column(String(64), default="")
    type_confidence = Column(String(32), default="")
    type_reason = Column(Text, default="")

    __table_args__ = (
        Index("idx_device_user_online", "user_id", "online"),
        Index("idx_device_user_last_seen", "user_id", "last_seen"),
    )

    def to_dict(self):
        import device_service
        name, vendor, dev_type = device_service.resolve_disciplined_device_name(
            label_name=self.label_name,
            hostname=self.hostname,
            vendor=self.vendor,
            dev_type=self.label_type or self.guessed_type or "unknown",
            ip=self.ip,
            mac=self.mac,
            ttl=self.ttl,
            likely_hotspot=bool(self.likely_hotspot),
            hotspot_note=self.hotspot_note or "",
        )
        return {
            "user_id": self.user_id,
            "mac": self.mac,
            "ip": self.ip or "",
            "vendor": vendor or self.vendor or "",
            "guessed_type": self.guessed_type or "unknown",
            "hostname": self.hostname or "",
            "label_name": self.label_name,
            "label_type": self.label_type,
            "name": name,
            "type": dev_type,

            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "online": bool(self.online),
            "ttl": self.ttl,
            "likely_hotspot": bool(self.likely_hotspot),
            "hotspot_note": self.hotspot_note or "",
            "rtt_ms": self.rtt_ms,
            "rtt_distance_m": self.rtt_distance_m,
            "distance_band": self.distance_band or "",
            "bandwidth_mbps": self.bandwidth_mbps,
            "bandwidth_grade": self.bandwidth_grade or "",
            "open_ports": self.open_ports or "",
            "os_guess": self.os_guess or "",
            "ttl_confidence": self.ttl_confidence or "",
            "vendor_confidence": self.vendor_confidence or "",
            "vendor_source": self.vendor_source or "",
            "type_confidence": self.type_confidence or "",
            "type_reason": self.type_reason or "",
        }


class DeviceTimelineEvent(Base):
    """Event log recording device life-cycle changes (discovered, connected, disconnected, renamed)."""
    __tablename__ = "device_timeline_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, index=True)
    mac = Column(String(32), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    description = Column(Text, nullable=False)
    timestamp = Column(Float, nullable=False, index=True)

    __table_args__ = (
        Index("idx_timeline_user_mac_time", "user_id", "mac", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "mac": self.mac,
            "event_type": self.event_type,
            "description": self.description,
            "timestamp": self.timestamp,
        }


# ============================================================================
# Database Engine & Connection Management
# ============================================================================

_ENGINE = None
_SESSION_FACTORY = None


def normalize_database_url(url=None):
    """Resolves and normalizes the target database URL.
    Handles Heroku/Supabase/Neon 'postgres://' prefixes and selects driver."""
    raw_url = url or os.environ.get("DATABASE_URL") or os.environ.get("PORTWATCH_DATABASE_URL")

    if not raw_url or not raw_url.strip():
        # Default to local SQLite database
        base_dir = os.path.dirname(os.path.abspath(__file__))
        sqlite_path = os.path.join(base_dir, "portwatch.db").replace("\\", "/")
        return f"sqlite:///{sqlite_path}"

    raw_url = raw_url.strip()

    # Cloud providers like Heroku/Supabase often output 'postgres://' which SQLAlchemy 1.4+ rejects
    if raw_url.startswith("postgres://"):
        raw_url = "postgresql://" + raw_url[len("postgres://"):]

    # Use pure-python pg8000 driver if psycopg2 is not installed and driver is omitted
    if raw_url.startswith("postgresql://") and not raw_url.startswith("postgresql+"):
        try:
            import psycopg2  # noqa: F401
        except ImportError:
            # Fall back to pure-python pg8000
            raw_url = "postgresql+pg8000://" + raw_url[len("postgresql://"):]

    return raw_url


def is_postgres(url=None):
    """Returns True if the configured database is PostgreSQL."""
    resolved = normalize_database_url(url)
    return "postgres" in resolved.lower()


def get_engine(db_url=None, echo=False):
    """Returns a configured SQLAlchemy engine with connection pooling and health pre-ping."""
    global _ENGINE
    resolved_url = normalize_database_url(db_url)

    if _ENGINE is not None:
        # Check if URL matches cached engine
        if str(_ENGINE.url) == resolved_url:
            return _ENGINE

    if resolved_url.startswith("sqlite"):
        # SQLite configuration
        if ":memory:" in resolved_url:
            engine = create_engine(
                resolved_url,
                echo=echo,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            engine = create_engine(
                resolved_url,
                echo=echo,
                connect_args={"check_same_thread": False},
                pool_pre_ping=True,
            )
    else:
        # PostgreSQL / MySQL configuration with production connection pooling
        engine = create_engine(
            resolved_url,
            echo=echo,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_timeout=30,
            pool_recycle=1800,
            pool_pre_ping=True,
        )

    if db_url is None:
        _ENGINE = engine
    return engine


def get_session_factory(engine=None):
    """Returns a thread-safe scoped session factory bound to the engine."""
    global _SESSION_FACTORY
    eng = engine or get_engine()
    if _SESSION_FACTORY is None or _SESSION_FACTORY.session_factory.kw.get("bind") != eng:
        _SESSION_FACTORY = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=eng))
    return _SESSION_FACTORY


@contextmanager
def session_scope(engine=None):
    """Provide a transactional scope around a series of database operations."""
    session = get_session_factory(engine)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_all_tables(engine=None):
    """Idempotently creates all tables and indexes across any supported database engine."""
    eng = engine or get_engine()
    Base.metadata.create_all(bind=eng)
    return True


def check_database_health(engine=None):
    """Validates connectivity to the active database backend."""
    eng = engine or get_engine()
    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {
            "status": "healthy",
            "backend": "postgresql" if is_postgres(str(eng.url)) else "sqlite",
            "url": str(eng.url).split("@")[-1] if "@" in str(eng.url) else str(eng.url),
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "backend": "postgresql" if is_postgres(str(eng.url)) else "sqlite",
        }


def is_cloud_db_active():
    """Returns True if a remote/cloud DATABASE_URL is configured."""
    url = os.environ.get("DATABASE_URL") or os.environ.get("PORTWATCH_DATABASE_URL")
    return bool(url and ("postgres" in url.lower() or "mysql" in url.lower()))


class DictRow(dict):
    """Dictionary-like row supporting both column name access (row['mac']) and positional index (row[0])."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)

    def keys(self):
        return super().keys()


class CloudCursor:
    """Cursor wrapper for SQLAlchemy Result proxy mimicking sqlite3.Cursor."""
    def __init__(self, result, lastrowid=None):
        self._result = result
        self.lastrowid = lastrowid
        self.rowcount = result.rowcount if hasattr(result, "rowcount") else 0

    def __iter__(self):
        if not self._result or not self._result.returns_rows:
            return
        for m in self._result.mappings():
            yield DictRow(m)

    def fetchone(self):
        if not self._result or not self._result.returns_rows:
            return None
        m = self._result.mappings().fetchone()
        return DictRow(m) if m is not None else None

    def fetchall(self):
        if not self._result or not self._result.returns_rows:
            return []
        return [DictRow(m) for m in self._result.mappings().fetchall()]

    def close(self):
        """Close result proxy."""
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class CloudConnection:
    """Connection wrapper for SQLAlchemy engine mimicking sqlite3.Connection with transaction management."""
    def __init__(self, engine=None):
        eng = engine or get_engine()
        self._conn = eng.connect()
        self._trans = self._conn.begin()

    def execute(self, query, params=None):
        params = params or ()
        if isinstance(params, (list, tuple)):
            idx = 0

            def repl(m):
                nonlocal idx
                res = f":p_{idx}"
                idx += 1
                return res
            named_sql = re.sub(r"\?", repl, query)
            param_dict = {f"p_{i}": val for i, val in enumerate(params)}
        else:
            named_sql = query
            param_dict = params

        res = self._conn.execute(text(named_sql), param_dict)
        lastrowid = getattr(res, "lastrowid", None)
        return CloudCursor(res, lastrowid=lastrowid)

    def commit(self):
        if self._trans:
            self._trans.commit()
            self._trans = self._conn.begin()

    def rollback(self):
        if self._trans:
            self._trans.rollback()
            self._trans = self._conn.begin()

    def close(self):
        if self._trans:
            try:
                self._trans.rollback()
            except Exception:
                pass
            self._trans = None
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()
        self.close()


def get_cloud_connection(engine=None):
    """Returns a new CloudConnection adapter connected to the pooled engine."""
    return CloudConnection(engine)
