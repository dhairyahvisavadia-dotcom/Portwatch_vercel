"""
config.py — Enterprise configuration management hierarchy for PortWatch.
Supports Development, Testing, and Production environments with type-safe validation.
"""

import logging
import os
import secrets
from datetime import timedelta
from typing import Any, Dict, Optional, Type

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from pydantic import Field, field_validator
    from pydantic_settings import BaseSettings, SettingsConfigDict
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

logger = logging.getLogger("portwatch.config")


class ConfigurationError(ValueError):
    """Raised when environment configuration fails validation."""
    pass


if HAS_PYDANTIC:
    class AppSettings(BaseSettings):
        """Type-safe application settings validated via Pydantic."""
        model_config = SettingsConfigDict(
            env_prefix="",
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore",
        )

        PORTWATCH_SECRET_KEY: Optional[str] = None
        SECRET_KEY: Optional[str] = None
        PORTWATCH_SESSION_MINUTES: int = Field(default=2, ge=1, le=1440)
        PORTWATCH_ENV: str = Field(default="development")
        FLASK_ENV: Optional[str] = None
        PORTWATCH_HOST: str = Field(default="0.0.0.0")
        PORTWATCH_PORT: int = Field(default=5000, ge=1, le=65535)
        DATABASE_URL: Optional[str] = None
        PORTWATCH_DATABASE_URL: Optional[str] = None
        PORTWATCH_SCAN_INTERVAL: int = Field(default=20, ge=1, le=3600)
        PORTWATCH_DEMO_MODE: Optional[str] = None
        VERCEL: Optional[str] = None
        FLASK_DEBUG: Optional[str] = None

        @field_validator("PORTWATCH_ENV", mode="before")
        @classmethod
        def validate_env(cls, v):
            if v and str(v).lower() not in ("development", "testing", "production", "default"):
                logger.warning(f"Unrecognized PORTWATCH_ENV='{v}', defaulting to 'development'")
            return str(v).lower() if v else "development"


def _load_validated_settings() -> Dict[str, Any]:
    """Loads and validates settings from environment variables."""
    if HAS_PYDANTIC:
        try:
            settings = AppSettings()
            return settings.model_dump()
        except Exception as err:
            raise ConfigurationError(
                f"Invalid environment configuration: {err}. "
                f"Please check your .env file or environment variables."
            ) from err

    # Fallback loader if pydantic is not present
    try:
        session_mins = int(os.environ.get("PORTWATCH_SESSION_MINUTES", "2"))
        if session_mins < 1:
            raise ValueError("PORTWATCH_SESSION_MINUTES must be >= 1")
    except ValueError as e:
        raise ConfigurationError(f"Invalid PORTWATCH_SESSION_MINUTES: {e}") from e

    try:
        scan_interval = int(os.environ.get("PORTWATCH_SCAN_INTERVAL", "20"))
        if scan_interval < 1:
            raise ValueError("PORTWATCH_SCAN_INTERVAL must be >= 1")
    except ValueError as e:
        raise ConfigurationError(f"Invalid PORTWATCH_SCAN_INTERVAL: {e}") from e

    return {
        "PORTWATCH_SECRET_KEY": os.environ.get("PORTWATCH_SECRET_KEY"),
        "SECRET_KEY": os.environ.get("SECRET_KEY"),
        "PORTWATCH_SESSION_MINUTES": session_mins,
        "PORTWATCH_ENV": os.environ.get("PORTWATCH_ENV", "development"),
        "PORTWATCH_HOST": os.environ.get("PORTWATCH_HOST", "0.0.0.0"),
        "PORTWATCH_PORT": int(os.environ.get("PORTWATCH_PORT", "5000")),
        "DATABASE_URL": os.environ.get("DATABASE_URL"),
        "PORTWATCH_SCAN_INTERVAL": scan_interval,
        "PORTWATCH_DEMO_MODE": os.environ.get("PORTWATCH_DEMO_MODE"),
        "VERCEL": os.environ.get("VERCEL"),
    }


# Evaluate settings at import time
_ENV = _load_validated_settings()


class BaseConfig:
    """Base configuration common to all execution environments."""

    # Core Application
    APP_NAME = "PortWatch"
    VERSION = "2.1.0"

    # Secret Key (Environment variable prioritized, cryptographic fallback)
    SECRET_KEY = _ENV.get("PORTWATCH_SECRET_KEY") or _ENV.get("SECRET_KEY") or os.environ.get("PORTWATCH_SECRET_KEY") or os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        SECRET_KEY = secrets.token_hex(32)

    # Session Security & Cookie Policies
    SESSION_MINUTES = int(_ENV.get("PORTWATCH_SESSION_MINUTES", 2))
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
    DATABASE_URL = _ENV.get("DATABASE_URL") or os.environ.get("DATABASE_URL")

    # Network Sweep Configuration
    SCAN_INTERVAL_SECONDS = int(_ENV.get("PORTWATCH_SCAN_INTERVAL", 20))

    # Demonstration & Cloud Showcase Mode (enabled on Vercel or via env flag)
    DEMO_MODE = (
        str(_ENV.get("PORTWATCH_DEMO_MODE") or os.environ.get("PORTWATCH_DEMO_MODE", "")).lower() in ("1", "true", "yes")
        or bool(_ENV.get("VERCEL") or os.environ.get("VERCEL"))
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


def get_config(env_name: Optional[str] = None) -> Type[BaseConfig]:
    """Resolve configuration class by environment name with intelligent fallbacks."""
    if not env_name:
        env_name = (
            os.environ.get("PORTWATCH_ENV")
            or os.environ.get("FLASK_ENV")
            or _ENV.get("PORTWATCH_ENV")
            or "development"
        ).lower()
    return CONFIG_BY_NAME.get(env_name, DevelopmentConfig)
