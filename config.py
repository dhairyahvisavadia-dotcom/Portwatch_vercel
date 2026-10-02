"""
config.py — Enterprise configuration management hierarchy for PortWatch.
Supports Development, Testing, and Production environments with clean defaults.
"""

import os
import secrets
from datetime import timedelta
from typing import Dict, Type

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class BaseConfig:
    """Base configuration common to all execution environments."""

    # Core Application
    APP_NAME = "PortWatch"
    VERSION = "2.1.0"

    # Secret Key (Environment variable prioritized, cryptographic fallback)
    SECRET_KEY = os.environ.get("PORTWATCH_SECRET_KEY") or os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        SECRET_KEY = secrets.token_hex(32)

    # Session Security & Cookie Policies
    SESSION_MINUTES = int(os.environ.get("PORTWATCH_SESSION_MINUTES", "2"))
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_MINUTES)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Overridden in Production

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # Bound to session lifetime

    # Rate Limiting Policies
    RATELIMIT_DEFAULT = ["1000 per hour", "200 per minute"]
    RATELIMIT_STORAGE_URI = "memory://"

    # Database Settings
    DATABASE_URL = os.environ.get("DATABASE_URL")

    # Network Sweep Configuration
    SCAN_INTERVAL_SECONDS = int(os.environ.get("PORTWATCH_SCAN_INTERVAL", "20"))

    # Demonstration & Cloud Showcase Mode (enabled on Vercel or via env flag)
    DEMO_MODE = (
        os.environ.get("PORTWATCH_DEMO_MODE", "").lower() in ("1", "true", "yes")
        or bool(os.environ.get("VERCEL"))
    )


class DevelopmentConfig(BaseConfig):
    """Configuration for local development and live hotspot testing."""

    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False


class TestingConfig(BaseConfig):
    """Configuration for automated test runners and CI/CD pipelines."""

    DEBUG = False
    TESTING = True
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    SECRET_KEY = "test-phase4-factory-secret"


class ProductionConfig(BaseConfig):
    """Configuration for production cloud deployment (Railway/Render/Vercel)."""

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


CONFIG_BY_NAME: Dict[str, Type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(env_name: str = None) -> Type[BaseConfig]:
    """Resolve configuration class by environment name with intelligent fallbacks."""
    if not env_name:
        env_name = (
            os.environ.get("PORTWATCH_ENV")
            or os.environ.get("FLASK_ENV")
            or "development"
        ).lower()
    return CONFIG_BY_NAME.get(env_name, DevelopmentConfig)
