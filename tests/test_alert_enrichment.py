#!/usr/bin/env python3
"""
Catnip Games SOC Platform — Unit Tests for Alert Enrichment Script
Owner: Platform Reliability
Purpose: Tests the classification and enrichment logic in alert_enrichment.py
         without requiring a live TheHive connection.

Usage:
    python3 tests/test_alert_enrichment.py
    python3 tests/test_alert_enrichment.py -v
"""

import sys
import os
import unittest

# Add automation path so we can import the script
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'automation', 'alert-enrichment'))

from alert_enrichment import build_enrichment, classify_alert_source, is_internal_ip


class TestAlertClassification(unittest.TestCase):
    """Test that alerts are classified into the correct categories."""

    def _make_alert(self, title, source="", severity=2):
        return {"title": title, "source": source, "severity": severity}

    def test_account_compromise_keywords(self):
        """Alerts with login/auth keywords should map to Account Security."""
        for keyword in ["Failed login attempt", "Auth token expired", "Password reset flood"]:
            alert = self._make_alert(keyword)
            result = build_enrichment(alert)
            self.assertEqual(
                result["alert-category"]["string"],
                "Account Security",
                f"'{keyword}' should classify as Account Security"
            )

    def test_bot_attack_keywords(self):
        """Alerts with bot/exploit keywords should map to Game Integrity."""
        for keyword in ["Bot detected in matchmaking", "Exploit attempt on loot system", "Cheat engine signature"]:
            alert = self._make_alert(keyword)
            result = build_enrichment(alert)
            self.assertEqual(
                result["alert-category"]["string"],
                "Game Integrity",
                f"'{keyword}' should classify as Game Integrity"
            )

    def test_social_engineering_keywords(self):
        """Alerts with phishing/social keywords should map to Social Engineering."""
        for keyword in ["Phishing link in player chat", "Social engineering attempt", "Staff impersonation reported"]:
            alert = self._make_alert(keyword)
            result = build_enrichment(alert)
            self.assertEqual(
                result["alert-category"]["string"],
                "Social Engineering",
                f"'{keyword}' should classify as Social Engineering"
            )

    def test_unknown_alert_falls_back_to_uncategorised(self):
        """Alerts with no matching keywords should be Uncategorised."""
        alert = self._make_alert("Unusual network packet size detected")
        result = build_enrichment(alert)
        self.assertEqual(result["alert-category"]["string"], "Uncategorised")

    def test_high_severity_sets_escalation_flag(self):
        """Severity 3 (High) or above should set escalation-flag to True."""
        for severity in [3, 4]:
            alert = self._make_alert("Generic alert", severity=severity)
            result = build_enrichment(alert)
            self.assertTrue(result["escalation-flag"]["boolean"],
                            f"Severity {severity} should set escalation flag")

    def test_low_medium_severity_does_not_escalate(self):
        """Severity 1-2 should not set escalation flag."""
        for severity in [1, 2]:
            alert = self._make_alert("Generic alert", severity=severity)
            result = build_enrichment(alert)
            self.assertFalse(result["escalation-flag"]["boolean"],
                             f"Severity {severity} should not set escalation flag")

    def test_enrichment_always_includes_timestamp(self):
        """Every enrichment result must include an enrichment timestamp."""
        alert = self._make_alert("Any alert")
        result = build_enrichment(alert)
        self.assertIn("enrichment-timestamp", result)
        self.assertIsInstance(result["enrichment-timestamp"]["date"], int)

    def test_playbook_recommended_for_account_alerts(self):
        """Account security alerts should recommend the account-compromise playbook."""
        alert = self._make_alert("Suspicious login from new country")
        result = build_enrichment(alert)
        self.assertEqual(result["recommended-playbook"]["string"],
                         "account-compromise-playbook")


class TestSourceClassification(unittest.TestCase):
    """Test the alert source description lookup."""

    def test_known_sources_return_description(self):
        known = {
            "auth-service":  "Player authentication service",
            "matchmaking":   "Matchmaking server",
            "game-host":     "Game hosting server",
            "api-gateway":   "API gateway",
            "elasticsearch": "Elasticsearch watcher rule",
        }
        for source, expected in known.items():
            result = classify_alert_source(source)
            self.assertEqual(result, expected, f"Source '{source}' returned wrong description")

    def test_unknown_source_returns_fallback(self):
        result = classify_alert_source("unknown-service-xyz")
        self.assertIn("Unknown source", result)

    def test_source_matching_is_case_insensitive(self):
        self.assertEqual(
            classify_alert_source("AUTH-SERVICE"),
            classify_alert_source("auth-service"),
        )


class TestIPClassification(unittest.TestCase):
    """Test internal vs external IP detection."""

    def test_internal_ips_are_recognised(self):
        internal_ips = ["10.0.0.1", "192.168.1.50", "172.16.0.1"]
        for ip in internal_ips:
            self.assertTrue(is_internal_ip(ip), f"{ip} should be internal")

    def test_external_ips_are_not_internal(self):
        external_ips = ["8.8.8.8", "185.220.101.45", "45.155.205.233"]
        for ip in external_ips:
            self.assertFalse(is_internal_ip(ip), f"{ip} should be external")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Alert Enrichment — Unit Tests")
    print("=" * 60 + "\n")
    unittest.main(verbosity=2)
