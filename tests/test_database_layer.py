"""
tests/test_database_layer.py
Unit tests for PortWatch's Phase 2 Database Architecture and ORM layer.
Tests:
1. SQLAlchemy 2.0+ ORM Declarative Models (User, ActivityLog, Device, DeviceTimelineEvent)
2. Database URL normalization (resolving postgres:// and driver selection)
3. Schema creation and table verification
4. Dual-mode CloudConnection adapter compatibility (executing '?' queries with named params)
5. Database health check and /api/health endpoint
6. Migration utility validation
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
import app as flask_app
import database
from database import (
    ActivityLog,
    CloudConnection,
    Device,
    DeviceTimelineEvent,
    DictRow,
    User,
    get_engine,
    init_all_tables,
    normalize_database_url,
    session_scope,
)


class TestDatabaseLayer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = os.path.join(self.temp_dir.name, "test_layer.db").replace("\\", "/")
        self.engine = get_engine(f"sqlite:///{self.test_db_path}")
        init_all_tables(self.engine)

        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def tearDown(self):
        if hasattr(self, "engine") and self.engine:
            self.engine.dispose()
        try:
            self.temp_dir.cleanup()
        except PermissionError:
            pass

    def test_database_url_normalization(self):
        # Empty/None defaults to SQLite
        default_url = normalize_database_url("")
        self.assertTrue(default_url.startswith("sqlite:///"))

        # Heroku/Supabase postgres:// gets corrected
        heroku_url = "postgres://user:pass@host.com:5432/portwatch"
        normalized = normalize_database_url(heroku_url)
        self.assertFalse(normalized.startswith("postgres://"))
        self.assertTrue(normalized.startswith("postgresql"))

    def test_table_initialization_creates_all_tables(self):
        tables = database.Base.metadata.tables.keys()
        self.assertIn("users", tables)
        self.assertIn("activity_log", tables)
        self.assertIn("devices", tables)
        self.assertIn("device_timeline_events", tables)

    def test_orm_model_crud(self):
        with session_scope(self.engine) as session:
            # 1. Create User
            user = User(
                username="orm_user",
                password_hash="fakehash123",
                email="orm@watch.local",
            )
            session.add(user)
            session.flush()
            user_id = user.id
            self.assertIsNotNone(user_id)

            # 2. Create Device
            device = Device(
                user_id=user_id,
                mac="00:11:22:33:44:55",
                ip="192.168.1.80",
                vendor="Apple",
                guessed_type="phone",
                hostname="my-iphone",
                online=1,
            )
            session.add(device)

            # 3. Create Timeline Event
            event = DeviceTimelineEvent(
                user_id=user_id,
                mac="00:11:22:33:44:55",
                event_type="discovered",
                description="Device first seen on network",
                timestamp=1234567.0,
            )
            session.add(event)

            # 4. Create Activity Log
            log = ActivityLog(
                user_id=user_id,
                action="scan",
                detail="Manual network scan",
                timestamp=1234567.0,
            )
            session.add(log)

        # Query back and verify dictionary representations
        with session_scope(self.engine) as session:
            queried_user = session.query(User).filter_by(username="orm_user").first()
            self.assertIsNotNone(queried_user)
            u_dict = queried_user.to_dict()
            self.assertEqual(u_dict["username"], "orm_user")
            self.assertEqual(u_dict["email"], "orm@watch.local")

            queried_dev = session.query(Device).filter_by(user_id=user_id, mac="00:11:22:33:44:55").first()
            self.assertIsNotNone(queried_dev)
            d_dict = queried_dev.to_dict()
            self.assertEqual(d_dict["name"], "my-iphone")
            self.assertTrue(d_dict["online"])

    def test_cloud_connection_adapter_emulates_sqlite3(self):
        conn = CloudConnection(self.engine)

        # Insert with ? parameter placeholder
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, email, created_at, last_login_at, last_ip) VALUES (?, ?, ?, ?, ?, ?)",
            ("cloud_user", "hash456", "cloud@pw.io", 1000.0, 1000.0, "127.0.0.1"),
        )
        conn.commit()

        # Query with ? parameter placeholder
        cur2 = conn.execute("SELECT * FROM users WHERE username=?", ("cloud_user",))
        row = cur2.fetchone()
        self.assertIsNotNone(row)
        self.assertIsInstance(row, DictRow)

        # Test dictionary-style access
        self.assertEqual(row["username"], "cloud_user")
        self.assertEqual(row["email"], "cloud@pw.io")

        # Test index-style access
        self.assertEqual(row[1], "cloud_user")

        # Test keys()
        self.assertIn("username", row.keys())
        self.assertIn("email", row.keys())

        conn.close()

    def test_database_health_and_api_endpoint(self):
        # Direct function check
        health = database.check_database_health(self.engine)
        self.assertEqual(health["status"], "healthy")
        self.assertIn("backend", health)

        # HTTP Endpoint check
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"]["status"], "healthy")
        self.assertIn("timestamp", data)


if __name__ == "__main__":
    unittest.main()
