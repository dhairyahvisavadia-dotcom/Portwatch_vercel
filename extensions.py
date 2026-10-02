"""
extensions.py — Flask extensions instance registry for PortWatch.
Provides decoupled instances of CSRF protection and rate limiting.
"""

from flask import current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect


class AppCSRFProtect(CSRFProtect):
    """Custom CSRF protector that automatically respects testing mode configuration."""

    def protect(self, apply_exemptions=False):
        try:
            if current_app and (current_app.config.get("TESTING") or current_app.testing):
                return
        except RuntimeError:
            pass
        super().protect(apply_exemptions=apply_exemptions)


csrf = AppCSRFProtect()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour", "200 per minute"],
    default_limits_exempt_when=lambda: bool(
        current_app and (current_app.config.get("TESTING") or current_app.testing)
    ) if current_app else False,
    storage_uri="memory://",
)
