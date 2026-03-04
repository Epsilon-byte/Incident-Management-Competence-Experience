#!/usr/bin/env python3
"""
Catnip Games SOC Platform — Integration Test Suite
Owner: Platform Reliability
Purpose: Automated tests to verify all platform components are
         working correctly before a live demonstration or after changes.

Usage:
    python3 tests/test_platform_integration.py
    python3 tests/test_platform_integration.py -v    # verbose output
"""

import json
import os
import sys
import unittest

import requests
import urllib3

# Suppress SSL warnings for local MISP instance
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ─────────────────────────────────────────────
THEHIVE_URL     = os.getenv("THEHIVE_URL",     "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
CORTEX_URL      = os.getenv("CORTEX_URL",      "http://localhost:9001")
CORTEX_API_KEY  = os.getenv("CORTEX_API_KEY",  "")
MISP_URL        = os.getenv("MISP_URL",        "https://localhost")
MISP_API_KEY    = os.getenv("MISP_API_KEY",    "")
ES_URL          = os.getenv("ES_URL",          "http://localhost:9200")

THEHIVE_HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
}
CORTEX_HEADERS = {
    "Authorization": f"Bearer {CORTEX_API_KEY}",
    "Content-Type": "application/json",
}
MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
}


# ═══════════════════════════════════════════════════════════════
# TEST CLASS 1: Service Availability
# ═══════════════════════════════════════════════════════════════
class TestServiceAvailability(unittest.TestCase):
    """Verify all SOC platform services are reachable."""

    def test_thehive_is_reachable(self):
        """TheHive UI should respond on port 9000."""
        try:
            resp = requests.get(THEHIVE_URL, timeout=5)
            self.assertIn(resp.status_code, [200, 302, 401],
                          "TheHive returned an unexpected status code")
        except requests.ConnectionError:
            self.fail("TheHive is not reachable at " + THEHIVE_URL)

    def test_cortex_is_reachable(self):
        """Cortex should respond on port 9001."""
        try:
            resp = requests.get(CORTEX_URL, timeout=5)
            self.assertIn(resp.status_code, [200, 302, 401],
                          "Cortex returned an unexpected status code")
        except requests.ConnectionError:
            self.fail("Cortex is not reachable at " + CORTEX_URL)

    def test_elasticsearch_is_reachable(self):
        """Elasticsearch should respond on port 9200."""
        try:
            resp = requests.get(ES_URL, timeout=5)
            self.assertEqual(resp.status_code, 200,
                             "Elasticsearch did not return HTTP 200")
        except requests.ConnectionError:
            self.fail("Elasticsearch is not reachable at " + ES_URL)

    def test_misp_is_reachable(self):
        """MISP should respond on port 443."""
        try:
            resp = requests.get(MISP_URL, timeout=5, verify=False)
            self.assertIn(resp.status_code, [200, 302],
                          "MISP returned an unexpected status code")
        except requests.ConnectionError:
            self.fail("MISP is not reachable at " + MISP_URL)


# ═══════════════════════════════════════════════════════════════
# TEST CLASS 2: TheHive API
# ═══════════════════════════════════════════════════════════════
class TestTheHiveAPI(unittest.TestCase):
    """Verify TheHive API authentication and core operations."""

    def setUp(self):
        if not THEHIVE_API_KEY:
            self.skipTest("THEHIVE_API_KEY not set")

    def test_thehive_api_authentication(self):
        """API key should authenticate successfully."""
        resp = requests.get(f"{THEHIVE_URL}/api/v1/user/current",
                            headers=THEHIVE_HEADERS, timeout=5)
        self.assertEqual(resp.status_code, 200,
                         "TheHive API authentication failed")

    def test_thehive_can_list_cases(self):
        """API should return a list of cases (may be empty)."""
        payload = {"query": [{"_name": "all"}], "range": "0-10"}
        resp = requests.post(f"{THEHIVE_URL}/api/v1/case/_search",
                             headers=THEHIVE_HEADERS, json=payload, timeout=5)
        self.assertEqual(resp.status_code, 200, "Could not list cases")
        self.assertIsInstance(resp.json(), list, "Cases response should be a list")

    def test_thehive_can_list_alerts(self):
        """API should return a list of alerts (may be empty)."""
        payload = {"query": [{"_name": "all"}], "range": "0-10"}
        resp = requests.post(f"{THEHIVE_URL}/api/v1/alert/_search",
                             headers=THEHIVE_HEADERS, json=payload, timeout=5)
        self.assertEqual(resp.status_code, 200, "Could not list alerts")
        self.assertIsInstance(resp.json(), list, "Alerts response should be a list")

    def test_thehive_create_and_delete_test_case(self):
        """Should be able to create a test case and then delete it."""
        # Create
        payload = {
            "title": "[AUTOMATED TEST] Integration test case — safe to delete",
            "description": "Created by test_platform_integration.py. Delete after test.",
            "severity": 1,
            "tags": ["automated-test"],
            "flag": False,
        }
        create_resp = requests.post(f"{THEHIVE_URL}/api/v1/case",
                                    headers=THEHIVE_HEADERS, json=payload, timeout=5)
        self.assertEqual(create_resp.status_code, 201, "Could not create test case")
        case_id = create_resp.json().get("_id")
        self.assertIsNotNone(case_id, "Created case has no _id")

        # Delete
        del_resp = requests.delete(f"{THEHIVE_URL}/api/v1/case/{case_id}",
                                   headers=THEHIVE_HEADERS, timeout=5)
        self.assertIn(del_resp.status_code, [200, 204],
                      "Could not delete test case")


# ═══════════════════════════════════════════════════════════════
# TEST CLASS 3: Elasticsearch
# ═══════════════════════════════════════════════════════════════
class TestElasticsearch(unittest.TestCase):
    """Verify Elasticsearch cluster health and index availability."""

    def test_cluster_health(self):
        """Cluster health should be green or yellow (yellow OK for single-node)."""
        resp = requests.get(f"{ES_URL}/_cluster/health", timeout=5)
        self.assertEqual(resp.status_code, 200)
        status = resp.json().get("status")
        self.assertIn(status, ["green", "yellow"],
                      f"Elasticsearch cluster status is '{status}' — expected green or yellow")

    def test_can_list_indices(self):
        """Should be able to list Elasticsearch indices."""
        resp = requests.get(f"{ES_URL}/_cat/indices?format=json", timeout=5)
        self.assertEqual(resp.status_code, 200, "Could not list indices")
        self.assertIsInstance(resp.json(), list)

    def test_index_write_and_read(self):
        """Should be able to write and read a test document."""
        doc = {"test": True, "message": "SOC platform integration test", "source": "test_suite"}
        # Write
        write_resp = requests.post(f"{ES_URL}/soc-test-index/_doc",
                                   json=doc, timeout=5)
        self.assertIn(write_resp.status_code, [200, 201], "Could not write test document")
        doc_id = write_resp.json().get("_id")

        # Read back
        read_resp = requests.get(f"{ES_URL}/soc-test-index/_doc/{doc_id}", timeout=5)
        self.assertEqual(read_resp.status_code, 200, "Could not read test document back")

        # Cleanup
        requests.delete(f"{ES_URL}/soc-test-index/_doc/{doc_id}", timeout=5)


# ═══════════════════════════════════════════════════════════════
# TEST CLASS 4: Cortex API
# ═══════════════════════════════════════════════════════════════
class TestCortexAPI(unittest.TestCase):
    """Verify Cortex API and analyser availability."""

    def setUp(self):
        if not CORTEX_API_KEY:
            self.skipTest("CORTEX_API_KEY not set")

    def test_cortex_api_authentication(self):
        """Cortex API key should authenticate successfully."""
        resp = requests.get(f"{CORTEX_URL}/api/user/current",
                            headers=CORTEX_HEADERS, timeout=5)
        self.assertEqual(resp.status_code, 200, "Cortex API authentication failed")

    def test_cortex_has_analysers(self):
        """Cortex should have at least one analyser configured."""
        resp = requests.get(f"{CORTEX_URL}/api/analyzer",
                            headers=CORTEX_HEADERS, timeout=5)
        self.assertEqual(resp.status_code, 200, "Could not list Cortex analysers")
        analysers = resp.json()
        self.assertGreater(len(analysers), 0,
                           "No analysers found in Cortex — at least one should be configured")


# ═══════════════════════════════════════════════════════════════
# TEST CLASS 5: Backup Verification
# ═══════════════════════════════════════════════════════════════
class TestBackupSystem(unittest.TestCase):
    """Verify the backup system is configured and recent."""

    BACKUP_DIR = "/opt/backups"

    def test_backup_directory_exists(self):
        """Backup directory should exist on the host."""
        import os
        self.assertTrue(os.path.isdir(self.BACKUP_DIR),
                        f"Backup directory {self.BACKUP_DIR} does not exist")

    def test_recent_backup_exists(self):
        """A backup file should exist from the last 48 hours."""
        import os
        import time
        cutoff = time.time() - (48 * 3600)
        recent_files = []
        for root, _, files in os.walk(self.BACKUP_DIR):
            for f in files:
                path = os.path.join(root, f)
                if os.path.getmtime(path) > cutoff:
                    recent_files.append(path)
        self.assertGreater(len(recent_files), 0,
                           "No backup files found from the last 48 hours")


# ── Entry Point ───────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Catnip Games SOC — Integration Test Suite")
    print(f"  {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")
    unittest.main(verbosity=2)
