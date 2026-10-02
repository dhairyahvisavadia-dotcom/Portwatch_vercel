"""
tests/test_auth_and_landing.py
Automated tests for PortWatch's multi-user authentication, 3-day activity retention,
landing page, and session timeout functionality.
"""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auth_db
import db
import app as flask_app


class TestAuthDB(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_auth.db")
        self._orig_db_file = auth_db.DB_FILE
        auth_db.DB_FILE = self.db_path
        auth_db.init_auth_db()

    def tearDown(self):
        auth_db.DB_FILE = self._orig_db_file
        self.temp_dir.cleanup()

    def test_create_user_and_get_details(self):
        user = auth_db.create_user("testuser", "securepass123", email="test@example.com", ip="127.0.0.1")
        self.assertEqual(user["username"], "testuser")
        self.assertEqual(user["email"], "test@example.com")
        self.assertEqual(user["last_ip"], "127.0.0.1")

        fetched = auth_db.get_user_by_id(user["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["username"], "testuser")
        self.assertEqual(fetched["email"], "test@example.com")
        self.assertEqual(fetched["last_ip"], "127.0.0.1")

    def test_duplicate_username_rejected(self):
        auth_db.create_user("alice", "password123")
        with self.assertRaises(auth_db.UsernameTaken):
            auth_db.create_user("alice", "anotherpass123")

    def test_weak_password_rejected(self):
        with self.assertRaises(auth_db.WeakPassword):
            auth_db.create_user("bob", "123")  # less than 6 chars

    def test_verify_login(self):
        auth_db.create_user("charlie", "mypassword123", email="c@test.com", ip="10.0.0.1")
        verified = auth_db.verify_login("charlie", "mypassword123", ip="10.0.0.2")
        self.assertIsNotNone(verified)
        self.assertEqual(verified["username"], "charlie")
        self.assertEqual(verified["last_ip"], "10.0.0.2")

        # Wrong password
        self.assertIsNone(auth_db.verify_login("charlie", "wrongpass"))
        # Nonexistent user
        self.assertIsNone(auth_db.verify_login("ghost", "mypassword123"))

    def test_activity_logging_and_3day_retention(self):
        user = auth_db.create_user("worker", "pass12345")
        u_id = user["id"]

        auth_db.log_activity(u_id, "signup", "Account created")
        auth_db.log_activity(u_id, "login", "Logged in from localhost")
        auth_db.log_activity(u_id, "view_map3d", "Viewed 3D Live Map")

        activities = auth_db.get_recent_activity(u_id, days=3)
        self.assertEqual(len(activities), 3)
        actions = [a["action"] for a in activities]
        self.assertIn("signup", actions)
        self.assertIn("login", actions)
        self.assertIn("view_map3d", actions)

        # Inject an old event older than 3 days
        old_time = time.time() - (4 * 24 * 60 * 60)
        with auth_db._lock:
            conn = auth_db._connect()
            conn.execute(
                "INSERT INTO activity_log (user_id, action, detail, timestamp) VALUES (?, ?, ?, ?)",
                (u_id, "old_action", "ancient detail", old_time),
            )
            conn.commit()
            conn.close()

        # get_recent_activity with days=3 should filter out anything > 3 days
        recent = auth_db.get_recent_activity(u_id, days=3)
        self.assertEqual(len(recent), 3)

        # log_activity prunes events older than 3 days
        auth_db.log_activity(u_id, "rescan", "Manual scan")
        with auth_db._lock:
            conn = auth_db._connect()
            pruned_count = conn.execute(
                "SELECT COUNT(*) FROM activity_log WHERE action='old_action'"
            ).fetchone()[0]
            conn.close()
        self.assertEqual(pruned_count, 0)


class TestFlaskRoutesAndLanding(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_app_auth.db")
        self._orig_db_file = auth_db.DB_FILE
        auth_db.DB_FILE = self.db_path
        auth_db.init_auth_db()

        self._orig_device_db = db.DB_FILE
        self.device_db_path = os.path.join(self.temp_dir.name, "test_app_devices.db")
        db.DB_FILE = self.device_db_path
        db.init_db()

        flask_app.app.config["TESTING"] = True
        flask_app.app.config["SECRET_KEY"] = "test-secret"
        self.client = flask_app.app.test_client()

    def tearDown(self):
        auth_db.DB_FILE = self._orig_db_file
        db.DB_FILE = self._orig_device_db
        self.temp_dir.cleanup()

    def test_landing_page_accessible_to_all(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        content = res.data.decode("utf-8")
        self.assertIn("PortWatch", content)
        self.assertIn("See exactly who's on your hotspot", content)
        self.assertIn("Live Dashboard", content)
        self.assertIn("3D Live Map", content)
        self.assertIn("Connection Map", content)
        self.assertIn("Nearby Networks", content)
        self.assertIn("Log in", content)
        self.assertIn("Sign up", content)

    def test_unauthenticated_feature_access_redirects_to_login(self):
        for path in ("/dashboard", "/map3d", "/connections", "/nearby", "/about"):
            res = self.client.get(path)
            self.assertEqual(res.status_code, 302)
            self.assertIn("/login", res.headers["Location"])

    def test_signup_login_and_user_profile(self):
        # Sign up
        res = self.client.post("/signup", data={
            "username": "superhero",
            "email": "hero@watch.local",
            "password": "secretpass123",
            "confirm_password": "secretpass123",
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Check /api/user/me
        res_me = self.client.get("/api/user/me")
        self.assertEqual(res_me.status_code, 200)
        data = res_me.get_json()
        self.assertEqual(data["user"]["username"], "superhero")
        self.assertEqual(data["user"]["email"], "hero@watch.local")
        self.assertEqual(data["session_timeout_minutes"], 2)

        # Visit 3D map and dashboard
        self.client.get("/map3d")
        self.client.get("/connections")

        # Check activity has been recorded
        res_act = self.client.get("/api/activity")
        self.assertEqual(res_act.status_code, 200)
        act_data = res_act.get_json()
        actions = [a["action"] for a in act_data]
        self.assertIn("signup", actions)
        self.assertIn("view_map3d", actions)
        self.assertIn("view_connections", actions)

    def test_inactivity_logout(self):
        # Create and login user
        self.client.post("/signup", data={
            "username": "sessionuser",
            "password": "sessionpass123",
            "confirm_password": "sessionpass123",
        })
        # Trigger timeout logout
        res = self.client.get("/logout?timeout=1")
        self.assertEqual(res.status_code, 302)
        self.assertIn("timeout=1", res.headers["Location"])

        # Subsequent protected access should fail
        res2 = self.client.get("/dashboard")
        self.assertEqual(res2.status_code, 302)
        self.assertIn("/login", res2.headers["Location"])

    def test_device_isolation_between_different_users(self):
        import db
        # 1. Sign up user SIDDHA
        self.client.post("/signup", data={
            "username": "siddha_test",
            "password": "password123",
            "confirm_password": "password123",
        })
        u1_res = self.client.get("/api/user/me").get_json()
        u1_id = u1_res["user"]["id"]

        # Insert a past device for SIDDHA
        db.upsert_scan("11:22:33:44:55:01", "192.168.43.101", "Apple", "phone", "Siddhas-iPhone", user_id=u1_id)
        db.mark_offline_except([], user_id=u1_id)

        # SIDDHA sees their device in /api/devices
        res1 = self.client.get("/api/devices").get_json()
        macs1 = [d["mac"] for d in res1]
        self.assertIn("11:22:33:44:55:01", macs1)

        # 2. Log out SIDDHA
        self.client.get("/logout")

        # 3. Sign up user SMITH
        self.client.post("/signup", data={
            "username": "smith_test",
            "password": "password456",
            "confirm_password": "password456",
        })
        u2_res = self.client.get("/api/user/me").get_json()
        u2_id = u2_res["user"]["id"]

        # SMITH must NOT see SIDDHA's past connected device!
        res2 = self.client.get("/api/devices").get_json()
        macs2 = [d["mac"] for d in res2]
        self.assertNotIn("11:22:33:44:55:01", macs2)

        # Insert a device for SMITH
        db.upsert_scan("99:88:77:66:55:02", "192.168.43.202", "Sony", "speaker", "Smiths-Speaker", user_id=u2_id)
        res2_after = self.client.get("/api/devices").get_json()
        macs2_after = [d["mac"] for d in res2_after]
        self.assertIn("99:88:77:66:55:02", macs2_after)
        self.assertNotIn("11:22:33:44:55:01", macs2_after)

        # 4. Log out SMITH
        self.client.get("/logout")

        # 5. Log back in as SIDDHA
        self.client.post("/login", data={
            "username": "siddha_test",
            "password": "password123",
        })

        # SIDDHA sees their past device restored and does NOT see SMITH's device!
        res1_restored = self.client.get("/api/devices").get_json()
        macs1_restored = [d["mac"] for d in res1_restored]
        self.assertIn("11:22:33:44:55:01", macs1_restored)
        self.assertNotIn("99:88:77:66:55:02", macs1_restored)

    def test_deep_scan_api_response_and_terminal_payload(self):
        # Log in
        self.client.post("/signup", data={
            "username": "terminal_user",
            "password": "password123",
            "confirm_password": "password123",
        })
        u_res = self.client.get("/api/user/me").get_json()
        uid = u_res["user"]["id"]

        # Insert target device
        db.upsert_scan("00:11:22:33:44:55", "127.0.0.1", "Raspberry Pi", "unknown", "pi-node", user_id=uid)

        # Trigger deep-scan
        resp = self.client.post("/api/devices/00:11:22:33:44:55/deep-scan")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertIn("fingerprint", data)
        fp = data["fingerprint"]
        self.assertEqual(fp["target_ip"], "127.0.0.1")
        self.assertEqual(fp["target_mac"], "00:11:22:33:44:55")
        self.assertIn("open_ports", fp)

        # Test index, connections, map3d, nearby template renders
        dash = self.client.get("/dashboard")
        self.assertIn("nmapTerminalDrawer", dash.get_data(as_text=True))
        self.assertIn("Deep Search", dash.get_data(as_text=True))
        self.assertIn("deviceFinderSection", dash.get_data(as_text=True))
        self.assertIn("finderInput", dash.get_data(as_text=True))

        conn = self.client.get("/connections")
        self.assertEqual(conn.status_code, 200)

        map3d = self.client.get("/map3d")
        self.assertEqual(map3d.status_code, 200)

        nearby = self.client.get("/nearby")
        self.assertEqual(nearby.status_code, 200)

    def test_device_lookup_and_location_finder(self):
        self.client.post("/signup", data={
            "username": "finder_user",
            "password": "password123",
            "confirm_password": "password123",
        })
        u_res = self.client.get("/api/user/me").get_json()
        uid = u_res["user"]["id"]

        # Insert an online device with RTT distance
        db.upsert_scan(
            "AA:BB:CC:DD:EE:01", "192.168.1.101", "Samsung", "phone", "galaxy-s21",
            rtt_ms=3.5, rtt_distance_m=1.8, distance_band="Immediate Proximity (< 2m)",
            bandwidth_mbps=450, bandwidth_grade="A (Ultra Fast)", user_id=uid
        )

        # Insert an offline device in orbit
        db.upsert_scan(
            "AA:BB:CC:DD:EE:02", "192.168.1.102", "Sony", "speaker", "bravia-spk",
            rtt_ms=None, rtt_distance_m=None, distance_band="Out of Range",
            user_id=uid
        )
        # Mark second device offline
        db.mark_offline_except(["AA:BB:CC:DD:EE:01"], user_id=uid)

        # 1. Test missing query
        res = self.client.post("/api/devices/lookup", json={"query": ""})
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()["ok"])

        # 2. Test exact MAC lookup of online device
        res = self.client.post("/api/devices/lookup", json={"query": "AA:BB:CC:DD:EE:01"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["found"])
        self.assertEqual(data["device"]["mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(data["device"]["ip"], "192.168.1.101")
        self.assertTrue(data["location"]["is_online"])
        self.assertEqual(data["location"]["distance_m"], 1.8)
        self.assertIn("1.8m", data["location"]["distance_formatted"])
        self.assertIn("/map3d?mac=AA:BB:CC:DD:EE:01", data["location"]["map3d_url"])
        self.assertIn("/connections?mac=AA:BB:CC:DD:EE:01", data["location"]["connections_url"])

        # 3. Test exact MAC lookup of offline device (in orbit)
        res = self.client.get("/api/devices/lookup?q=AA:BB:CC:DD:EE:02")
        self.assertEqual(res.status_code, 200)
        data_off = res.get_json()
        self.assertTrue(data_off["ok"])
        self.assertEqual(data_off["device"]["mac"], "AA:BB:CC:DD:EE:02")
        self.assertFalse(data_off["location"]["is_online"])
        self.assertIn("Offline", data_off["location"]["status_label"])
        self.assertIn("Orbital", data_off["location"]["topology_zone"])

        # 4. Test IP lookup
        res_ip = self.client.post("/api/devices/lookup", json={"query": "192.168.1.101"})
        self.assertEqual(res_ip.status_code, 200)
        self.assertEqual(res_ip.get_json()["device"]["mac"], "AA:BB:CC:DD:EE:01")

        # 5. Test lookup of brand new MAC (resolves vendor from IEEE database & auto-registers)
        # 00:17:F2 is an Apple OUI
        res_new = self.client.post("/api/devices/lookup", json={"query": "00:17:F2:33:44:55"})
        self.assertEqual(res_new.status_code, 200)
        data_new = res_new.get_json()
        self.assertTrue(data_new["ok"])
        self.assertTrue(data_new["is_new"])
        self.assertEqual(data_new["device"]["mac"], "00:17:F2:33:44:55")
        self.assertIn("Apple", data_new["device"]["vendor"])

    def test_account_page_and_navbar_cleanliness(self):
        # 1. Sign up and access dashboard
        self.client.post("/signup", data={
            "username": "navuser",
            "password": "password123",
            "confirm_password": "password123",
            "email": "nav@pw.io"
        }, follow_redirects=True)
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        dash_html = dash_res.get_data(as_text=True)

        # Ensure "About" is present and NOT "About / Methodology" in nav
        self.assertIn('>About</a>', dash_html)
        self.assertNotIn('>About / Methodology</a>', dash_html)

        # Ensure no standalone Password or Log out buttons in navrow
        self.assertIn('/account', dash_html)
        self.assertIn('navuser', dash_html)
        self.assertNotIn('>Password</a>', dash_html)
        self.assertNotIn('>Log out</a>', dash_html)

        # 2. View Account details page
        acc_res = self.client.get("/account")
        self.assertEqual(acc_res.status_code, 200)
        acc_html = acc_res.get_data(as_text=True)
        self.assertIn("Account & Profile", acc_html)
        self.assertIn("navuser", acc_html)
        self.assertIn("nav@pw.io", acc_html)
        self.assertIn("Change Password", acc_html)
        self.assertIn("Log Out", acc_html)

        # 3. Change password via account page
        # Mismatched passwords
        pw_fail = self.client.post("/account", data={
            "current_password": "password123",
            "new_password": "newpassword123",
            "confirm_password": "differentpass"
        })
        self.assertIn("New passwords", pw_fail.get_data(as_text=True))

        # Successful change
        pw_ok = self.client.post("/account", data={
            "current_password": "password123",
            "new_password": "newpassword123",
            "confirm_password": "newpassword123"
        })
        self.assertIn("Password updated successfully", pw_ok.get_data(as_text=True))

        # Logout works from account page
        logout_res = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_res.status_code, 200)


if __name__ == "__main__":
    unittest.main()


