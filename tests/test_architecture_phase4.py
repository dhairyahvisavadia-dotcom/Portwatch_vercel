"""
test_architecture_phase4.py — Unit and integration tests for Phase 4 Architecture.
Verifies Application Factory pattern, Blueprint modularization, dual versioned API routes
(/api and /api/v1), config hierarchies, structured error responses, and logging.
"""

import logging
import os
import tempfile
import unittest

import app as flask_app
import auth_db
import config
import db


class TestArchitecturePhase4(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_db_path = os.path.join(self.temp_dir.name, "test_arch_auth.db")
        self.device_db_path = os.path.join(self.temp_dir.name, "test_arch_devices.db")

        self._orig_auth_db = auth_db.DB_FILE
        self._orig_dev_db = db.DB_FILE

        auth_db.DB_FILE = self.auth_db_path
        auth_db.init_auth_db()

        db.DB_FILE = self.device_db_path
        db.init_db()

        # Initialize test application using Application Factory with TestingConfig
        self.app = flask_app.create_app(config.TestingConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        auth_db.DB_FILE = self._orig_auth_db
        db.DB_FILE = self._orig_dev_db
        self.temp_dir.cleanup()

    def test_application_factory_creates_app_with_config(self):
        """Verify create_app respects custom configuration objects."""
        self.assertTrue(self.app.config["TESTING"])
        self.assertFalse(self.app.config["WTF_CSRF_ENABLED"])
        self.assertEqual(self.app.config["SECRET_KEY"], "test-phase4-factory-secret")

        prod_app = flask_app.create_app(config.ProductionConfig)
        self.assertFalse(prod_app.config["DEBUG"])
        self.assertTrue(prod_app.config["SESSION_COOKIE_SECURE"])

    def test_blueprint_registration_and_endpoints(self):
        """Verify auth, views, and api blueprints are registered on the app."""
        blueprint_names = set(self.app.blueprints.keys())
        self.assertIn("views", blueprint_names)
        self.assertIn("auth", blueprint_names)
        self.assertIn("api", blueprint_names)
        self.assertIn("api_v1", blueprint_names)

    def test_versioned_api_routes(self):
        """Verify dual API mounting: both /api and /api/v1 endpoints return identical data."""
        # /api/health
        res_v0 = self.client.get("/api/health")
        self.assertEqual(res_v0.status_code, 200)
        data_v0 = res_v0.get_json()

        # /api/v1/health
        res_v1 = self.client.get("/api/v1/health")
        self.assertEqual(res_v1.status_code, 200)
        data_v1 = res_v1.get_json()

        self.assertEqual(data_v0["status"], data_v1["status"])
        self.assertEqual(data_v0["database"]["status"], data_v1["database"]["status"])

    def test_api_structured_json_404_error(self):
        """Verify API 404 returns structured JSON error while browser route returns HTML."""
        # API 404
        res_api = self.client.get("/api/nonexistent-endpoint")
        self.assertEqual(res_api.status_code, 404)
        data = res_api.get_json()
        self.assertIsNotNone(data)
        self.assertEqual(data["error"], "Not Found")
        self.assertEqual(data["status_code"], 404)
        self.assertIn("message", data)

        # Web page 404
        res_page = self.client.get("/nonexistent-page-url")
        self.assertEqual(res_page.status_code, 404)
        self.assertIn("404", res_page.get_data(as_text=True))

    def test_backward_compatibility_module_exports(self):
        """Verify all critical module-level exports in app.py remain intact."""
        self.assertTrue(hasattr(flask_app, "app"))
        self.assertTrue(hasattr(flask_app, "create_app"))
        self.assertTrue(hasattr(flask_app, "STATUS"))
        self.assertTrue(hasattr(flask_app, "fast_scan"))
        self.assertTrue(hasattr(flask_app, "scan_once"))
        self.assertTrue(hasattr(flask_app, "scan_loop"))
        self.assertTrue(hasattr(flask_app, "login_required"))
        self.assertTrue(hasattr(flask_app, "is_valid_mac"))
        self.assertTrue(hasattr(flask_app, "get_safe_redirect"))

    def test_structured_logger_configured(self):
        """Verify standard logging instance is configured with custom name and format."""
        logger = logging.getLogger("portwatch")
        self.assertGreaterEqual(len(logger.handlers), 1)
        self.assertEqual(logger.name, "portwatch")


if __name__ == "__main__":
    unittest.main()
