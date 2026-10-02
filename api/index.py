"""
api/index.py — Vercel Serverless WSGI Entrypoint for PortWatch.
Bridges incoming serverless HTTP requests to the PortWatch Flask application factory.
"""

import os
import sys

# Ensure repository root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Enable cloud showcase demo mode by default in serverless cloud container
os.environ.setdefault("PORTWATCH_DEMO_MODE", "true")
os.environ.setdefault("PORTWATCH_ENV", "production")

from app import create_app

# WSGI Application callable exported for Vercel Serverless Python runtime
app = create_app()
