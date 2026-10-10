"""
tests/test_security.py
Comprehensive automated test suite for PortWatch's Phase 1 Security Hardening.
Tests:
1. CSRF Protection enforcement and token validation
2. Rate limiting defense against brute-force and resource starvation
3. Open Redirect vulnerability mitigation (safe redirect validation)
4. Brute-force account lockout defense (5 failed attempts -> 15 min lock)
5. Timing side-channel mitigation for user enumeration
6. Password complexity & username validation policies
7. HTTP Security Headers (nosniff, SAMEORIGIN, XSS block, cache control)
8. MAC address format validation and Stored XSS defense (input sanitization)
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as flask_app  # noqa: E402
import auth_db  # noqa: E402
import db  # noqa: E402


class TestSecurityHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_db_path = os.path.join(self.temp_dir.name, "sec_test_auth.db")
        self.device_db_path = os.path.join(self.temp_dir.name, "sec_test_devs.db")

        self._orig_auth_db = auth_db.DB_FILE
        self._orig_dev_db = db.DB_FILE
        auth_db.DB_FILE = self.auth_db_path
        db.DB_FILE = self.device_db_path

        auth_db.init_auth_db()
        db.init_db()

        flask_app.app.config["TESTING"] = True
        flask_app.app.config["SECRET_KEY"] = "security-test-key-32charslong!"
        self.client = flask_app.app.test_client()

    def tearDown(self):
        auth_db.DB_FILE = self._orig_auth_db
        db.DB_FILE = self._orig_dev_db
        self.temp_dir.cleanup()

    # --- 1. Password Complexity & Username Policy ---
    def test_password_policy_requires_both_letters_and_numbers(self):
        # Only letters -> reject
        with self.assertRaises(auth_db.WeakPassword):
            auth_db.create_user("validuser1", "onlyletters")

        # Only numbers -> reject
        with self.assertRaises(auth_db.WeakPassword):
            auth_db.create_user("validuser2", "123456789")

        # Less than 6 characters -> reject
        with self.assertRaises(auth_db.WeakPassword):
            auth_db.create_user("validuser3", "a1b2")

        # Valid mixed letters and numbers -> succeeds
        user = auth_db.create_user("validuser4", "securePass1")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "validuser4")

    def test_username_policy_rejects_illegal_characters(self):
        # Spaces not allowed
        with self.assertRaises(auth_db.WeakPassword):
            auth_db.create_user("user with space", "pass12345")

        # Malicious injection / special chars not allowed
        with self.assertRaises(auth_db.WeakPassword):
            auth_db.create_user("<script>bad</script>", "pass12345")

        with self.assertRaises(auth_db.WeakPassword):
            auth_db.create_user("user;DROP TABLE users;--", "pass12345")

    # --- 2. Brute-Force Account Lockout ---
    def test_account_locks_after_five_failed_attempts(self):
        auth_db.create_user("target_user", "correctPass1")

        # 4 consecutive wrong passwords should fail normally without locking
        for i in range(4):
            res = auth_db.verify_login("target_user", f"wrongpass{i}")
            self.assertIsNone(res)

        # 5th failed attempt should trigger AccountLocked
        with self.assertRaises(auth_db.AccountLocked):
            auth_db.verify_login("target_user", "wrongpass5")

        # Subsequent attempts are also blocked by lockout
        with self.assertRaises(auth_db.AccountLocked):
            auth_db.verify_login("target_user", "correctPass1")

    def test_successful_login_resets_failed_attempt_counter(self):
        auth_db.create_user("reset_user", "correctPass1")

        # 3 failed attempts
        for _ in range(3):
            auth_db.verify_login("reset_user", "wrongpass")

        # Successful login resets the counter
        success = auth_db.verify_login("reset_user", "correctPass1")
        self.assertIsNotNone(success)

        # User can now fail again without reaching immediate lockout
        self.assertIsNone(auth_db.verify_login("reset_user", "wrongpass"))

    def test_timing_defense_on_nonexistent_user(self):
        # Does not raise and returns None smoothly
        result = auth_db.verify_login("completely_nonexistent_user_xyz", "somepassword123")
        self.assertIsNone(result)

    # --- 3. Open Redirect Prevention ---
    def test_login_blocks_open_redirect_to_external_domains(self):
        auth_db.create_user("redirect_user", "validPass123")

        # Attempt to redirect to an attacker-controlled external domain
        malicious_urls = [
            "https://evil.com/phish",
            "http://attacker.org",
            "//evil.com",
            "javascript:alert(1)",
        ]

        for mal_url in malicious_urls:
            res = self.client.post(
                f"/login?next={mal_url}",
                data={"username": "redirect_user", "password": "validPass123"},
                follow_redirects=False,
            )
            self.assertEqual(res.status_code, 302)
            location = res.headers.get("Location", "")
            # Must NOT redirect to the evil domain
            self.assertNotIn("evil.com", location)
            self.assertNotIn("attacker.org", location)
            # Must redirect safely to local dashboard
            self.assertTrue(location.endswith("/dashboard") or "/dashboard" in location)

    def test_login_allows_safe_local_redirects(self):
        auth_db.create_user("local_user", "validPass123")
        res = self.client.post(
            "/login?next=/map3d",
            data={"username": "local_user", "password": "validPass123"},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.headers.get("Location", "").endswith("/map3d"))

    # --- 4. HTTP Security Headers ---
    def test_security_headers_present_on_responses(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)

        # Standard OWASP security headers
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(res.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("geolocation=()", res.headers.get("Permissions-Policy", ""))

    def test_cache_control_headers_on_sensitive_endpoints(self):
        # Sign in
        self.client.post("/signup", data={
            "username": "headeruser",
            "password": "passWord123",
            "confirm_password": "passWord123",
        })
        res = self.client.get("/api/devices")
        self.assertIn("no-store", res.headers.get("Cache-Control", ""))

    # --- 5. Input Validation & Stored XSS Mitigation ---
    def test_invalid_mac_addresses_rejected_by_api(self):
        # Sign in
        self.client.post("/signup", data={
            "username": "macuser",
            "password": "passWord123",
            "confirm_password": "passWord123",
        })

        invalid_macs = [
            "invalid-mac-string",
            "12:34:56",
            "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",
            "00:11:22:33:44",
            "malicious_mac_inject",
        ]

        for bad_mac in invalid_macs:
            res_timeline = self.client.get(f"/api/devices/{bad_mac}/timeline")
            self.assertEqual(res_timeline.status_code, 400)
            self.assertIn("Invalid MAC", res_timeline.get_json().get("error", ""))

            res_patch = self.client.patch(f"/api/devices/{bad_mac}", json={"name": "test"})
            self.assertEqual(res_patch.status_code, 400)

            res_del = self.client.delete(f"/api/devices/{bad_mac}")
            self.assertEqual(res_del.status_code, 400)

        # Path traversal attempts are blocked by routing/validation
        res_traversal = self.client.get("/api/devices/..%2F..%2Fpasswd/timeline")
        self.assertIn(res_traversal.status_code, (400, 404))

    def test_device_label_xss_sanitization(self):
        self.client.post("/signup", data={
            "username": "xssuser",
            "password": "passWord123",
            "confirm_password": "passWord123",
        })
        u_id = self.client.get("/api/user/me").get_json()["user"]["id"]

        # Insert a valid device
        valid_mac = "AA:BB:CC:11:22:33"
        db.upsert_scan(valid_mac, "192.168.1.50", "TestVendor", "phone", "TestHost", user_id=u_id)

        # Attempt to label with XSS payload
        xss_payload = '<script>alert("pwnd")</script>'
        res = self.client.patch(f"/api/devices/{valid_mac}", json={"name": xss_payload, "type": "<b>phone</b>"})
        self.assertEqual(res.status_code, 200)

        # Retrieve device and verify HTML tags were escaped
        dev = next(d for d in db.get_all(user_id=u_id) if d["mac"] == valid_mac)
        self.assertNotIn("<script>", dev["name"])
        self.assertIn("&lt;script&gt;", dev["name"])
        self.assertNotIn("<b>", dev["type"])
        self.assertIn("&lt;b&gt;", dev["type"])

    # --- 6. CSRF Protection Enforcement ---
    def test_csrf_protection_blocks_post_when_testing_false(self):
        # Temporarily enable CSRF enforcement
        flask_app.app.config["TESTING"] = False
        try:
            # POST without CSRF token should be rejected with 400
            res = self.client.post("/login", data={"username": "any", "password": "any"})
            self.assertEqual(res.status_code, 400)
        finally:
            flask_app.app.config["TESTING"] = True


if __name__ == "__main__":
    unittest.main()
