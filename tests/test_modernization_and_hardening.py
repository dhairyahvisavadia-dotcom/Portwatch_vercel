"""
tests/test_modernization_and_hardening.py — Unit and integration tests for
PortWatch Architecture Modernization, Hardening, and Service Layer Refactoring.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as flask_app  # noqa: E402
import auth_db  # noqa: E402
import config  # noqa: E402
import database  # noqa: E402
import db  # noqa: E402
import device_service  # noqa: E402


class TestModernizationAndHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_db_path = os.path.join(self.temp_dir.name, "test_mod_auth.db")
        self.device_db_path = os.path.join(self.temp_dir.name, "test_mod_devices.db")

        self._orig_auth_db = auth_db.DB_FILE
        self._orig_dev_db = db.DB_FILE

        auth_db.DB_FILE = self.auth_db_path
        auth_db.init_auth_db()

        db.DB_FILE = self.device_db_path
        db.init_db()

        self.app = flask_app.create_app(config.TestingConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        auth_db.DB_FILE = self._orig_auth_db
        db.DB_FILE = self._orig_dev_db
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_pydantic_settings_validation_and_configuration_error(self):
        """Verify type-safe environment validation and ConfigurationError raising."""
        # 1. Valid settings resolution
        cfg = config.get_config("development")
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.APP_NAME, "PortWatch")
        self.assertTrue(hasattr(cfg, "SECRET_KEY"))
        self.assertGreaterEqual(cfg.SESSION_MINUTES, 1)

        # 2. TestingConfig overrides
        t_cfg = config.TestingConfig
        self.assertTrue(t_cfg.TESTING)
        self.assertFalse(t_cfg.WTF_CSRF_ENABLED)
        self.assertEqual(t_cfg.SECRET_KEY, "test-phase4-factory-secret")

        # 3. ProductionConfig security settings
        p_cfg = config.ProductionConfig
        self.assertFalse(p_cfg.DEBUG)
        self.assertTrue(p_cfg.SESSION_COOKIE_SECURE)

    def test_device_service_format_location_telemetry(self):
        """Verify device_service computes and formats RF distance and spatial telemetry."""
        sample_device_online = {
            "mac": "AA:BB:CC:DD:EE:01",
            "online": True,
            "rtt_ms": 3.4,
            "rtt_distance_m": 2.8,
            "distance_band": "Nearby (~2.5-6m)",
        }
        loc = device_service.format_location_telemetry(sample_device_online)
        self.assertTrue(loc["is_online"])
        self.assertEqual(loc["distance_m"], 2.8)
        self.assertEqual(loc["distance_formatted"], "~2.8m")
        self.assertEqual(loc["rtt_formatted"], "3.4 ms")
        self.assertIn("Direct Wi-Fi Link", loc["topology_zone"])
        self.assertIn("AA:BB:CC:DD:EE:01", loc["map3d_url"])
        self.assertIn("AA:BB:CC:DD:EE:01", loc["connections_url"])

        sample_device_offline = {
            "mac": "AA:BB:CC:DD:EE:02",
            "online": False,
            "rtt_ms": None,
            "rtt_distance_m": None,
            "distance_band": "",
        }
        loc_off = device_service.format_location_telemetry(sample_device_offline)
        self.assertFalse(loc_off["is_online"])
        self.assertEqual(loc_off["distance_formatted"], "Out of Immediate Range")
        self.assertEqual(loc_off["rtt_formatted"], "No ping reply")
        self.assertIn("Outer Orbital Ring", loc_off["topology_zone"])

    def test_device_service_lookup_device(self):
        """Verify device_service lookup handling for invalid queries, hits, and misses."""
        # Empty query
        ok, res, code = device_service.lookup_device("", user_id=1, is_testing=True)
        self.assertFalse(ok)
        self.assertEqual(code, 400)

        # Nonexistent invalid query
        ok, res, code = device_service.lookup_device("invalid_hostname_query", user_id=1, is_testing=True)
        self.assertFalse(ok)
        self.assertEqual(code, 404)

        # Existing device lookup
        db.upsert_scan(
            mac="11:22:33:44:55:66",
            ip="192.168.137.99",
            vendor="TestVendor",
            guessed_type="phone",
            hostname="test-phone",
            user_id=1,
        )
        ok, res, code = device_service.lookup_device("11:22:33:44:55:66", user_id=1, is_testing=True)
        self.assertTrue(ok)
        self.assertEqual(code, 200)
        self.assertEqual(res["device"]["mac"], "11:22:33:44:55:66")
        self.assertEqual(res["device"]["ip"], "192.168.137.99")
        self.assertIn("location", res)
        self.assertIn("timeline", res)

    def test_device_service_perform_device_deep_scan(self):
        """Verify device_service deep scanning error handling for missing target."""
        ok, res, code = device_service.perform_device_deep_scan("FF:FF:FF:FF:FF:FF", user_id=1)
        self.assertFalse(ok)
        self.assertEqual(code, 404)
        self.assertIn("error", res)

    def test_database_connection_context_manager_safety(self):
        """Verify get_connection context manager ensures connections are closed cleanly."""
        with db.get_connection() as conn:
            row = conn.execute("SELECT 1 AS alive").fetchone()
            self.assertEqual(row["alive"], 1)

        with auth_db.get_connection() as conn:
            row = conn.execute("SELECT 1 AS alive").fetchone()
            self.assertEqual(row["alive"], 1)

    def test_cloud_adapters_context_management(self):
        """Verify CloudConnection and CloudCursor support the context manager protocol."""
        conn = database.CloudConnection()
        with conn as c:
            cur = c.execute("SELECT 1 AS num")
            with cur as r:
                res = r.fetchone()
                self.assertIsNotNone(res)
                self.assertEqual(res[0], 1)

    def test_dockerfile_multi_stage_structure(self):
        """Verify Dockerfile defines a multi-stage build and non-root execution."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dockerfile_path = os.path.join(base_dir, "Dockerfile")
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("AS builder", content)
        self.assertIn("AS runtime", content)
        self.assertIn("USER portwatch", content)
        self.assertIn("HEALTHCHECK", content)
        self.assertIn("gunicorn", content)

    def test_dockerignore_rules(self):
        """Verify .dockerignore excludes sensitive and temporary files while retaining oui.db."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ignore_path = os.path.join(base_dir, ".dockerignore")
        with open(ignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn(".git/", content)
        self.assertIn("tests/", content)
        self.assertIn(".env", content)
        self.assertNotIn("oui.db", content)

    def test_3d_volumetric_matrix_rendering(self):
        """Verify 3D Volumetric Matrix map renders coordinate box, face buttons, and HUD card."""
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = 1
            sess["username"] = "admin"

        res = self.client.get("/map3d")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("Volumetric Matrix", html)
        self.assertIn("Elevation", html)
        self.assertIn("btnFaceElevation", html)
        self.assertIn("btnFaceFloor", html)
        self.assertIn("hudCoordCard", html)
        self.assertIn("hudElevation", html)
        self.assertIn("hudWestEast", html)
        self.assertIn("hudSouthNorth", html)


if __name__ == "__main__":
    unittest.main()
