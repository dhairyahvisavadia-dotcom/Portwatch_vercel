"""
tests/test_deployment_phase5.py
Automated test suite verifying Phase 5 cloud deployment readiness, Vercel serverless
entrypoint, interactive demo mode simulation, database seeder, and DevOps container assets.
"""

import json
import os
import unittest
from unittest.mock import patch

import auth_db
import config
import db
import scanner_service
from app import create_app
from config import TestingConfig
from scripts.seed_demo_data import seed_demo_network


class TestDeploymentPhase5(unittest.TestCase):
    """Test suite covering cloud deployment configurations and demo showcase capabilities."""

    def setUp(self):
        self.app = create_app(TestingConfig)
        self.client = self.app.test_client()

    def test_demo_mode_scanner_generates_telemetry(self):
        """Verify fast_scan generates simulated devices with jitter when DEMO_MODE is active."""
        with patch.dict(os.environ, {"PORTWATCH_DEMO_MODE": "true"}):
            devices, seen_macs = scanner_service.fast_scan(sync_db=False)
            self.assertTrue(len(devices) >= 8)
            self.assertTrue(len(seen_macs) >= 5)
            self.assertEqual(scanner_service.STATUS.get("subnet"), "192.168.137")
            self.assertTrue(scanner_service.STATUS.get("demo_mode"))
            self.assertIsNotNone(scanner_service.STATUS.get("own_connection"))

    def test_vercel_serverless_entrypoint(self):
        """Verify api/index.py imports successfully and exports a WSGI app."""
        import api.index
        self.assertTrue(hasattr(api.index, "app"))
        self.assertIsNotNone(api.index.app)

    def test_demo_seeder_populates_account_and_devices(self):
        """Verify seed_demo_network provisions demo user and devices."""
        count = seed_demo_network(target_user_id=1, force=False)
        self.assertGreaterEqual(count, 0)
        demo_user = auth_db.get_user_by_username("demo")
        self.assertIsNotNone(demo_user)
        self.assertEqual(demo_user["username"], "demo")

        auth = auth_db.verify_login("demo", "DemoAdmin123!")
        self.assertIsNotNone(auth)
        self.assertEqual(auth["id"], demo_user["id"])

    def test_login_page_renders_demo_credentials_hint(self):
        """Verify login template exposes one-click recruiter credentials helper."""
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        content = resp.get_data(as_text=True)
        self.assertIn("Fill Demo Credentials", content)
        self.assertIn("DemoAdmin123!", content)

    def test_base_template_has_demo_badge(self):
        """Verify base template includes the brutalist demo mode telemetry badge."""
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = 1
            sess["username"] = "tester"
            sess["last_activity"] = 9999999999
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        content = resp.get_data(as_text=True)
        self.assertIn('id="demoModeBadge"', content)

    def test_deployment_artifacts_exist_and_valid(self):
        """Verify Vercel, Docker, Compose, and License configuration files exist and are valid."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # Vercel configuration
        vercel_json_path = os.path.join(base_dir, "vercel.json")
        self.assertTrue(os.path.exists(vercel_json_path))
        with open(vercel_json_path, "r") as f:
            v_cfg = json.load(f)
            self.assertIn("rewrites", v_cfg)

        # Dockerfile
        dockerfile_path = os.path.join(base_dir, "Dockerfile")
        self.assertTrue(os.path.exists(dockerfile_path))
        with open(dockerfile_path, "r") as f:
            d_content = f.read()
            self.assertIn("FROM", d_content)
            self.assertIn("HEALTHCHECK", d_content)

        # Docker Compose
        compose_path = os.path.join(base_dir, "docker-compose.yml")
        self.assertTrue(os.path.exists(compose_path))
        with open(compose_path, "r") as f:
            c_content = f.read()
            self.assertIn("services:", c_content)
            self.assertIn("postgres:", c_content)

        # License
        license_path = os.path.join(base_dir, "LICENSE")
        self.assertTrue(os.path.exists(license_path))
        with open(license_path, "r") as f:
            l_content = f.read()
            self.assertIn("MIT License", l_content)


if __name__ == "__main__":
    unittest.main()
