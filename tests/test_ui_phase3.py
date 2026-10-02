"""
test_ui_phase3.py — Unit and integration tests for Phase 3 UI/UX enhancements.
Verifies real-time filtering elements, brutalist empty state, click-to-copy,
system telemetry badge, and absence of generic AI/emoji clutter.
"""

import os
import unittest
import tempfile
import app as flask_app
import auth_db
import db


class TestPhase3UI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_db_path = os.path.join(self.temp_dir.name, "test_ui_auth.db")
        self.device_db_path = os.path.join(self.temp_dir.name, "test_ui_devices.db")

        self._orig_auth_db = auth_db.DB_FILE
        self._orig_dev_db = db.DB_FILE

        auth_db.DB_FILE = self.auth_db_path
        auth_db.init_auth_db()

        db.DB_FILE = self.device_db_path
        db.init_db()

        flask_app.app.config["TESTING"] = True
        flask_app.app.config["WTF_CSRF_ENABLED"] = False
        flask_app.app.config["SECRET_KEY"] = "test-phase3-secret"
        self.client = flask_app.app.test_client()

        # Create and log in test user
        self.client.post("/signup", data={
            "username": "phase3_tester",
            "password": "testerpassword123",
            "confirm_password": "testerpassword123",
            "email": "tester@pw.internal"
        }, follow_redirects=True)

    def tearDown(self):
        auth_db.DB_FILE = self._orig_auth_db
        db.DB_FILE = self._orig_dev_db
        self.temp_dir.cleanup()

    def test_filter_toolbar_and_segments_present(self):
        """Verify real-time filter search bar and segment buttons are properly rendered."""
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # Real-time search filter input
        self.assertIn('id="deviceTableFilter"', html)
        self.assertIn('handleFilterInput()', html)

        # Category segment buttons
        self.assertIn('id="segBtnAll"', html)
        self.assertIn('id="segBtnOnline"', html)
        self.assertIn('id="segBtnPhone"', html)
        self.assertIn('id="segBtnLaptop"', html)
        self.assertIn('id="segBtnOther"', html)
        self.assertIn('id="segBtnHotspot"', html)

        # Live counter badge
        self.assertIn('id="filterCountBadge"', html)
        self.assertIn('id="deviceMainTable"', html)

    def test_database_telemetry_badge_in_base_header(self):
        """Verify the database engine and health telemetry badge appears in bezel header."""
        res = self.client.get("/dashboard")
        html = res.get_data(as_text=True)

        self.assertIn('id="dbHealthStatus"', html)
        self.assertIn('id="dbStatusDot"', html)
        self.assertIn('id="dbStatusEngine"', html)
        self.assertIn('refreshHealth()', html)
        self.assertIn('/api/health', html)

    def test_global_toast_and_clipboard_utilities_present(self):
        """Verify global toast box and click-to-copy helper are rendered in DOM and script."""
        res = self.client.get("/dashboard")
        html = res.get_data(as_text=True)

        self.assertIn('id="toastBox"', html)
        self.assertIn('copyToClipboard', html)
        self.assertIn('.copy-cell', html)
        self.assertIn('.copy-hint', html)

    def test_no_unnecessary_ai_emojis_in_headings_and_actions(self):
        """Verify modal headers and deep search buttons do not have unnecessary emojis."""
        res = self.client.get("/dashboard")
        html = res.get_data(as_text=True)

        # Modal headers should be clean without clock or pencil emojis
        self.assertIn('<h3>Device Historical Timeline</h3>', html)
        self.assertNotIn('<h3>🕒 Device Historical Timeline</h3>', html)

        self.assertIn('<h3>Edit Device Details</h3>', html)
        self.assertNotIn('<h3>✏️ Edit Device Details</h3>', html)

        # Deep search label is clean
        self.assertIn('>Deep Search<', html)
        self.assertNotIn('>🔍 Deep Search<', html)

    def test_empty_state_and_diagnostic_checklist_script(self):
        """Verify the brutalist diagnostic empty state checklist is embedded in the template."""
        res = self.client.get("/dashboard")
        html = res.get_data(as_text=True)

        self.assertIn('Subnet Sweep Complete', html)
        self.assertIn('Troubleshooting Checklist', html)
        self.assertIn('Passive ARP + ICMP Ping', html)


if __name__ == "__main__":
    unittest.main()
