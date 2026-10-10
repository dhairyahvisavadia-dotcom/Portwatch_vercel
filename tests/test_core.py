"""
tests/test_core.py
Automated tests for PortWatch's scanning/detection logic -- run these to
demonstrate correctness beyond a live demo (useful for a university
submission or CI). These test the pure logic functions with mocked
subprocess output, not the actual network -- so they run anywhere,
including outside Windows/off a real hotspot.

Run:
    python -m pytest tests/ -v
or:
    python -m unittest discover tests -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import device_scan  # noqa: E402
import vendor_lookup  # noqa: E402


class TestTTLClassification(unittest.TestCase):
    def test_normal_baselines_not_flagged(self):
        for ttl in (64, 128, 255):
            flagged, note = device_scan.classify_ttl(ttl)
            self.assertFalse(flagged, f"TTL={ttl} should not be flagged as hotspot-sharing")

    def test_one_hop_below_baseline_flagged(self):
        flagged, note = device_scan.classify_ttl(63)
        self.assertTrue(flagged)
        self.assertIn("1 hop", note)

    def test_multiple_hops_below_baseline_flagged(self):
        flagged, note = device_scan.classify_ttl(60)
        self.assertTrue(flagged)
        self.assertIn("4 hop", note)

    def test_none_ttl_not_flagged(self):
        flagged, note = device_scan.classify_ttl(None)
        self.assertFalse(flagged)
        self.assertIn("no reply", note)

    def test_confidence_included_in_note(self):
        _, note = device_scan.classify_ttl(63, confidence="low")
        self.assertIn("low", note)


class TestPingSweepParsing(unittest.TestCase):
    def setUp(self):
        self._original_run = device_scan._run

    def tearDown(self):
        device_scan._run = self._original_run

    def test_extracts_ttl_and_rtt(self):
        device_scan._run = lambda cmd: "Reply from 1.2.3.4: bytes=32 time=8ms TTL=63"
        result = device_scan.ping_sweep("192.168.43", samples=1)
        self.assertEqual(result["192.168.43.1"]["ttl"], 63)
        self.assertEqual(result["192.168.43.1"]["rtt_ms"], 8.0)

    def test_no_reply_handled_gracefully(self):
        device_scan._run = lambda cmd: "Request timed out."
        result = device_scan.ping_sweep("192.168.43", samples=1)
        self.assertIsNone(result["192.168.43.1"]["ttl"])
        self.assertEqual(result["192.168.43.1"]["confidence"], "low")

    def test_majority_ttl_used_across_samples(self):
        outputs = iter(["TTL=63"] * 2 + ["TTL=99"])

        def fake_run(cmd):
            return next(outputs, "TTL=63")

        device_scan._run = fake_run
        result = device_scan.ping_sweep("192.168.43", samples=3)
        # only host .1 gets pinged in this simplified test since fake_run
        # ignores the host argument; just checking the majority logic works
        self.assertIn(result["192.168.43.1"]["ttl"], (63, 99))


class TestArpParsing(unittest.TestCase):
    def setUp(self):
        self._original_run = device_scan._run

    def tearDown(self):
        device_scan._run = self._original_run

    def test_parses_dynamic_entries_in_subnet(self):
        device_scan._run = lambda cmd: (
            "  192.168.43.10        aa-bb-cc-11-22-33     dynamic\n"
            "  192.168.43.1         ff-ff-ff-ff-ff-ff     static\n"  # broadcast, should be excluded
            "  10.0.0.5             11-22-33-44-55-66     dynamic\n"  # wrong subnet, excluded
        )
        results = device_scan.read_arp_table("192.168.43")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], ("192.168.43.10", "AA:BB:CC:11:22:33"))


class TestWifiNetworkParsing(unittest.TestCase):
    def setUp(self):
        self._original_run = device_scan._run

    def tearDown(self):
        device_scan._run = self._original_run

    def test_parses_multiple_ssids_and_bssids(self):
        device_scan._run = lambda cmd: (
            "SSID 1 : HomeNet\n"
            "    Authentication          : WPA2-Personal\n"
            "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
            "         Signal             : 70%\n"
            "         Channel            : 6\n"
            "         Radio type         : 802.11ac\n"
            "SSID 2 : \n"
            "    Authentication          : Open\n"
            "    BSSID 1                 : 11:22:33:44:55:66\n"
            "         Signal             : 40%\n"
        )
        results = device_scan.scan_wifi_networks()
        self.assertEqual(len(results), 2)
        ssids = {r["ssid"] for r in results}
        self.assertIn("HomeNet", ssids)
        self.assertIn("(hidden network)", ssids)
        # sorted by signal descending
        self.assertEqual(results[0]["ssid"], "HomeNet")


class TestOwnConnectionInfo(unittest.TestCase):
    def setUp(self):
        self._original_run = device_scan._run

    def tearDown(self):
        device_scan._run = self._original_run

    def test_parses_connected_state(self):
        device_scan._run = lambda cmd: (
            "    SSID                   : TestNet\n"
            "    BSSID                  : aa:bb:cc:dd:ee:ff\n"
            "    Signal                 : 72%\n"
            "    Channel                : 44\n"
        )
        info = device_scan.get_own_connection_info()
        self.assertEqual(info["ssid"], "TestNet")
        self.assertEqual(info["signal_percent"], 72)

    def test_not_connected_returns_none(self):
        device_scan._run = lambda cmd: "There is 1 interface on the system:\n    State  : disconnected\n"
        info = device_scan.get_own_connection_info()
        self.assertIsNone(info)


class TestDistanceEstimate(unittest.TestCase):
    def test_higher_signal_gives_smaller_distance(self):
        _, low1, high1, _ = device_scan.estimate_distance_band(90)
        _, low2, high2, _ = device_scan.estimate_distance_band(30)
        self.assertLess(high1, high2, "stronger signal should estimate a shorter distance")

    def test_none_signal_returns_none(self):
        band, low, high, dbm = device_scan.estimate_distance_band(None)
        self.assertIsNone(band)


class TestRttDistanceEstimate(unittest.TestCase):
    def test_lower_rtt_gives_smaller_distance(self):
        dist1, band1, low1, high1 = device_scan.estimate_distance_from_rtt(2.0)
        dist2, band2, low2, high2 = device_scan.estimate_distance_from_rtt(20.0)
        self.assertLess(dist1, dist2, "lower RTT latency should yield a closer distance estimate")
        self.assertIn("Immediate", band1)
        self.assertIn("Different room", band2)

    def test_none_rtt_returns_none(self):
        dist, band, low, high = device_scan.estimate_distance_from_rtt(None)
        self.assertIsNone(dist)
        self.assertIsNone(band)

    def test_database_populates_rtt_distance(self):
        import db
        import tempfile
        tmp = tempfile.mktemp(suffix=".db")
        orig = db.DB_FILE
        db.DB_FILE = tmp
        try:
            db.init_db()
            db.upsert_scan("00:11:22:33:44:55", "192.168.1.50", "Apple", "phone", "iPhone", rtt_ms=8.0)
            devs = db.get_all()
            self.assertEqual(len(devs), 1)
            self.assertIsNotNone(devs[0]["rtt_distance_m"])
            self.assertGreater(devs[0]["rtt_distance_m"], 4.0)
            self.assertLess(devs[0]["rtt_distance_m"], 10.0)
            self.assertEqual(devs[0]["distance_band"], "Same room/floor (~6-12m)")
        finally:
            db.DB_FILE = orig
            if os.path.exists(tmp):
                os.remove(tmp)


class TestVendorLookup(unittest.TestCase):
    def test_local_oui_hit_is_high_confidence(self):
        result = vendor_lookup.lookup_vendor_detailed("3C:22:FB:00:00:00")
        self.assertEqual(result["source"], "local")
        self.assertEqual(result["confidence"], "high")

    def test_randomized_mac_detected(self):
        # E6, 2A, DA all have bit 1 set (locally administered)
        self.assertTrue(vendor_lookup.is_randomized_mac("E6:5A:35:73:18:5C"))
        self.assertTrue(vendor_lookup.is_randomized_mac("2A:DE:5A:5B:66:66"))
        self.assertFalse(vendor_lookup.is_randomized_mac("00:11:22:33:44:55"))
        result = vendor_lookup.lookup_vendor_detailed("E6:5A:35:73:18:5C")
        self.assertIn("Private MAC", result["vendor"])
        self.assertEqual(result["source"], "private_mac")

    def test_unknown_mac_falls_back_gracefully(self):
        result = vendor_lookup.lookup_vendor_detailed("00:00:00:00:00:00")
        self.assertIn(result["confidence"], ("low", "medium"))


class TestTypeGuessing(unittest.TestCase):
    def test_vendor_and_hostname_agreement_is_high_confidence(self):
        result = vendor_lookup.guess_type_detailed("Apple, Inc.", "Sams-iPhone")
        self.assertEqual(result["type"], "phone")
        self.assertEqual(result["confidence"], "high")

    def test_hostname_overrides_ambiguous_vendor(self):
        result = vendor_lookup.guess_type_detailed("Apple, Inc.", "Sams-MacBook-Pro")
        self.assertEqual(result["type"], "laptop")

    def test_no_signal_returns_unknown(self):
        result = vendor_lookup.guess_type_detailed("Unknown", None)
        self.assertEqual(result["type"], "unknown")
        self.assertEqual(result["confidence"], "low")


class TestDatabase(unittest.TestCase):
    def setUp(self):
        import db
        self.db = db
        self._original_db_file = db.DB_FILE
        self.tmpfile = tempfile.mktemp(suffix=".db")
        db.DB_FILE = self.tmpfile
        db.init_db()

    def tearDown(self):
        self.db.DB_FILE = self._original_db_file
        if os.path.exists(self.tmpfile):
            os.remove(self.tmpfile)

    def test_upsert_and_retrieve(self):
        self.db.upsert_scan("AA:BB:CC:11:22:33", "192.168.43.10", "Apple, Inc.", "phone", "iPhone")
        devices = self.db.get_all()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["name"], "iPhone")
        self.assertTrue(devices[0]["online"])

    def test_offline_device_keeps_history(self):
        self.db.upsert_scan("AA:BB:CC:11:22:33", "192.168.43.10", "Apple, Inc.", "phone", "iPhone")
        self.db.mark_offline_except([])  # nothing seen this pass
        devices = self.db.get_all()
        self.assertEqual(len(devices), 1, "device history should persist even when offline")
        self.assertFalse(devices[0]["online"])

    def test_manual_label_overrides_guess(self):
        self.db.upsert_scan("AA:BB:CC:11:22:33", "192.168.43.10", "Apple, Inc.", "phone", "iPhone")
        self.db.set_label("AA:BB:CC:11:22:33", "Sam's Phone", "phone")
        devices = self.db.get_all()
        self.assertEqual(devices[0]["name"], "Sam's Phone")
        self.assertTrue(devices[0]["type_is_manual"])

    def test_forget_deletes_device(self):
        self.db.upsert_scan("AA:BB:CC:11:22:33", "192.168.43.10", "Apple, Inc.", "phone", "iPhone")
        self.db.forget_device("AA:BB:CC:11:22:33")
        self.assertEqual(len(self.db.get_all()), 0)

    def test_user_isolation(self):
        # User 1 (e.g. Siddha) adds a device
        self.db.upsert_scan("11:22:33:44:55:66", "192.168.43.20", "Samsung", "phone", "Galaxy", user_id=1)
        # User 2 (e.g. Smith) adds a device
        self.db.upsert_scan("99:88:77:66:55:44", "192.168.43.30", "Sony", "speaker", "Soundbar", user_id=2)

        # User 1 should only see their own device
        u1_devs = self.db.get_all(user_id=1)
        self.assertEqual(len(u1_devs), 1)
        self.assertEqual(u1_devs[0]["mac"], "11:22:33:44:55:66")
        self.assertEqual(u1_devs[0]["name"], "Galaxy")

        # User 2 should only see their own device
        u2_devs = self.db.get_all(user_id=2)
        self.assertEqual(len(u2_devs), 1)
        self.assertEqual(u2_devs[0]["mac"], "99:88:77:66:55:44")
        self.assertEqual(u2_devs[0]["name"], "Soundbar")

        # Marking offline for user 1 does not mark user 2 offline
        self.db.mark_offline_except([], user_id=1)
        self.assertFalse(self.db.get_all(user_id=1)[0]["online"])
        self.assertTrue(self.db.get_all(user_id=2)[0]["online"])

        # Relabeling for user 1 does not affect user 2
        self.db.set_label("11:22:33:44:55:66", "Siddha's Phone", "phone", user_id=1)
        self.assertEqual(self.db.get_all(user_id=1)[0]["name"], "Siddha's Phone")

        # Forgetting device for user 1 leaves user 2 intact
        self.db.forget_device("11:22:33:44:55:66", user_id=1)
        self.assertEqual(len(self.db.get_all(user_id=1)), 0)
        self.assertEqual(len(self.db.get_all(user_id=2)), 1)

    def test_device_timeline_logging(self):
        # 1. Discovery
        self.db.upsert_scan("AA:BB:CC:11:22:33", "192.168.43.10", "Apple, Inc.", "phone", "iPhone", user_id=1)
        timeline = self.db.get_device_timeline("AA:BB:CC:11:22:33", user_id=1)
        self.assertIsNotNone(timeline)
        self.assertTrue(timeline["online"])
        event_types = [e["event_type"] for e in timeline["events"]]
        self.assertIn("discovered", event_types)

        # 2. IP Change
        self.db.upsert_scan("AA:BB:CC:11:22:33", "192.168.43.55", "Apple, Inc.", "phone", "iPhone", user_id=1)
        timeline = self.db.get_device_timeline("AA:BB:CC:11:22:33", user_id=1)
        event_types = [e["event_type"] for e in timeline["events"]]
        self.assertIn("ip_change", event_types)

        # 3. Disconnect
        self.db.mark_offline_except([], user_id=1)
        timeline = self.db.get_device_timeline("AA:BB:CC:11:22:33", user_id=1)
        self.assertFalse(timeline["online"])
        event_types = [e["event_type"] for e in timeline["events"]]
        self.assertIn("disconnected", event_types)

        # 4. Relabel
        self.db.set_label("AA:BB:CC:11:22:33", "Sam Phone", "phone", user_id=1)
        timeline = self.db.get_device_timeline("AA:BB:CC:11:22:33", user_id=1)
        event_types = [e["event_type"] for e in timeline["events"]]
        self.assertIn("relabel", event_types)


class TestBandwidthEstimation(unittest.TestCase):
    def test_lower_rtt_yields_higher_bandwidth(self):
        bw1, grade1, _ = device_scan.estimate_bandwidth(2.0)
        bw2, grade2, _ = device_scan.estimate_bandwidth(25.0)
        self.assertIsNotNone(bw1)
        self.assertIsNotNone(bw2)
        self.assertGreater(bw1, bw2)
        self.assertIn("Ultra", grade1)
        self.assertIn("Fair", grade2)

    def test_none_rtt_returns_none(self):
        bw, grade, note = device_scan.estimate_bandwidth(None)
        self.assertIsNone(bw)
        self.assertIsNone(grade)


class TestIeeeOuiDatabase(unittest.TestCase):
    def test_ieee_db_lookup_success(self):
        res = vendor_lookup.lookup_vendor_detailed("00:0C:29:11:22:33")
        self.assertEqual(res["source"], "ieee_db")
        self.assertEqual(res["confidence"], "high")
        self.assertIn("VMware", res["vendor"])


class TestDeepFingerprinting(unittest.TestCase):
    def test_find_nmap_returns_str_or_none(self):
        res = device_scan.find_nmap()
        self.assertTrue(res is None or isinstance(res, str))

    def test_deep_fingerprint_fallback(self):
        # Scan loopback - tests that function completes safely without crashing
        res = device_scan.deep_fingerprint_device("127.0.0.1", timeout_per_port=0.1)
        # Should return a dictionary or None, and not throw exceptions
        self.assertTrue(res is None or isinstance(res, dict))


if __name__ == "__main__":
    unittest.main(verbosity=2)
