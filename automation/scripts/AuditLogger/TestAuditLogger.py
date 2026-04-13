#!/usr/bin/env python3
"""
Catnip Games SOC Platform — Unit Tests for Audit Logger
Owner: Platform Reliability

PURPOSE
-------
This file verifies that every calculation and decision in audit_logger.py
produces the correct result. All tests run entirely offline — no live
TheHive connection is needed — by feeding synthetic "fake" data that mimics
the structure of a real TheHive API response.

WHY UNIT TESTS?
---------------
The audit logger is used to produce evidence submitted to assessors and auditors.
If the SLA calculations or NFR checks contain bugs, the evidence would be wrong.
Unit tests give a repeatable, automated way to confirm correctness after any change.

STRUCTURE
---------
Each test class focuses on one area of the code:

    TestHelpers              — low-level utility functions (timestamp conversion etc.)
    TestIsAutomated          — actor classification (human vs script)
    TestCaseAuditRecord      — build_case_audit_record() output fields and logic
    TestAlertAuditRecord     — build_alert_audit_record() output fields and logic
    TestComplianceSummary    — build_compliance_summary() aggregation and NFR checks

USAGE
-----
    python3 tests/test_audit_logger.py          # run all tests
    python3 tests/test_audit_logger.py -v       # verbose mode (shows each test name)
"""

import sys
import os
import unittest
from datetime import datetime, timezone

# Add the automation/scripts directory to Python's module search path so we can
# import audit_logger without installing it as a package. This allows the tests
# to live in a separate tests/ directory while still importing from automation/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "automation", "scripts"))

from Audit_logger import (
    build_case_audit_record,
    build_alert_audit_record,
    build_compliance_summary,
    is_automated,
    ms_to_minutes,
    ts_to_dt,
    dt_to_str,
)


# ── Test fixtures ──────────────────────────────────────────────────────────────
#
# Fixtures are factory functions that produce synthetic TheHive API response dicts.
# Using factory functions (rather than constants) lets each test customise only the
# fields it cares about while getting sensible defaults for everything else.
#
# The field names (_id, _createdAt, endDate, etc.) match the actual TheHive v1 API
# field names so the fixtures are realistic.

def make_case(
    case_id="case-001",
    number=1,
    title="Test case",
    status="Resolved",
    severity=3,             # 3 = High
    created_at_ms=1_000_000,
    end_ms=1_900_000,       # 900,000 ms after creation = exactly 15 minutes
    assignee="analyst1@catnip.soc",
    created_by="analyst1@catnip.soc",
    source="",
    tags=None,
    custom_fields=None,
):
    """
    Return a dict that looks like a TheHive case API response.

    Defaults represent a typical resolved case: created by a human analyst,
    closed exactly at the SLA target (15 min), High severity, no enrichment.
    Individual tests override only the fields they need to exercise.
    """
    return {
        "_id":          case_id,
        "number":       number,
        "title":        title,
        "status":       status,
        "severity":     severity,
        "_createdAt":   created_at_ms,      # epoch ms: when case was opened
        "_updatedAt":   created_at_ms + 60_000,  # 1 minute after creation
        "endDate":      end_ms,             # epoch ms: when case was closed (None = open)
        "assignee":     assignee,
        "_createdBy":   created_by,
        "source":       source,
        "tags":         tags or [],
        "customFields": custom_fields or {},
    }


def make_alert(
    alert_id="alert-001",
    title="Test alert",
    status="Imported",      # Imported = an analyst promoted it to a case
    severity=2,             # 2 = Medium
    created_at_ms=1_000_000,
    updated_ms=1_900_000,   # 900,000 ms after creation = 15 minutes
    created_by="alert_enrichment",  # automated source by default
    source="alert_enrichment",
    tags=None,
    custom_fields=None,
):
    """
    Return a dict that looks like a TheHive alert API response.

    Defaults represent a typical alert created by the alert_enrichment.py script
    and imported by an analyst within 15 minutes.
    """
    return {
        "_id":          alert_id,
        "title":        title,
        "status":       status,
        "severity":     severity,
        "_createdAt":   created_at_ms,
        "_updatedAt":   updated_ms,         # epoch ms: when the alert status last changed
        "_createdBy":   created_by,
        "source":       source,
        "tags":         tags or [],
        "customFields": custom_fields or {},
    }


# ── Test class 1: Helper functions ─────────────────────────────────────────────

class TestHelpers(unittest.TestCase):
    """
    Tests for the low-level utility functions in audit_logger.py.
    These are the building blocks used by every other function,
    so correctness here is foundational.
    """

    def test_ms_to_minutes(self):
        """
        Verify millisecond-to-minute conversion at common values.
        60,000 ms = 60 seconds = 1 minute.
        900,000 ms = 900 seconds = 15 minutes (the SLA target).
        """
        self.assertEqual(ms_to_minutes(60_000),   1.0)
        self.assertEqual(ms_to_minutes(900_000),  15.0)
        self.assertEqual(ms_to_minutes(1_800_000), 30.0)

    def test_ts_to_dt_returns_utc(self):
        """
        ts_to_dt must always return a timezone-aware UTC datetime.
        Without timezone info, comparing timestamps from different sources
        can silently produce wrong results.
        """
        dt = ts_to_dt(0)   # Unix epoch: 1970-01-01 00:00:00 UTC
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_ts_to_dt_none_returns_none(self):
        """
        A None input (e.g. a case with no endDate) must produce None,
        not raise an exception or return epoch zero.
        """
        self.assertIsNone(ts_to_dt(None))

    def test_dt_to_str_format(self):
        """
        dt_to_str must produce the exact format "YYYY-MM-DD HH:MM:SS UTC"
        so audit log entries are consistently formatted across all records.
        """
        dt = datetime(2026, 4, 8, 12, 30, 0, tzinfo=timezone.utc)
        self.assertEqual(dt_to_str(dt), "2026-04-08 12:30:00 UTC")

    def test_dt_to_str_none(self):
        """
        dt_to_str(None) must return an empty string, not "None".
        Empty strings produce blank CSV cells; "None" would be confusing.
        """
        self.assertEqual(dt_to_str(None), "")


# ── Test class 2: Actor classification ────────────────────────────────────────

class TestIsAutomated(unittest.TestCase):
    """
    Tests for is_automated(), which distinguishes human analysts from
    automated scripts. This classification affects the analyst_activity
    summary and the automated_enrichment NFR check.
    """

    def test_known_service_accounts_are_automated(self):
        """
        The Cortex and MISP service accounts (defined in profiles.json)
        must always be classified as automated.
        """
        self.assertTrue(is_automated("cortex-svc@catnip.soc"))
        self.assertTrue(is_automated("misp-svc@catnip.soc"))

    def test_enrichment_script_source_is_automated(self):
        """
        alert_enrichment.py and ioc_watchlist_check.py identify themselves
        via the 'source' field rather than _createdBy.
        Both must be detected.
        """
        self.assertTrue(is_automated(None, source="alert_enrichment"))
        self.assertTrue(is_automated(None, source="ioc-watchlist-checker"))

    def test_human_analyst_is_not_automated(self):
        """
        Human analyst email addresses must not be classified as automated,
        regardless of their role.
        """
        self.assertFalse(is_automated("analyst1@catnip.soc"))
        self.assertFalse(is_automated("senior1@catnip.soc"))

    def test_none_actor_is_not_automated(self):
        """
        None actor with no source must return False, not raise an exception.
        This guards against missing API fields in edge cases.
        """
        self.assertFalse(is_automated(None))
        self.assertFalse(is_automated(None, source=None))


# ── Test class 3: Case audit record building ───────────────────────────────────

class TestCaseAuditRecord(unittest.TestCase):
    """
    Tests for build_case_audit_record(), which transforms a raw TheHive
    case dict into a flat audit record.

    Each test exercises one specific field or calculation to keep failures
    easy to diagnose — if a test fails, you know exactly which field broke.
    """

    def test_basic_fields_are_populated(self):
        """
        The most important fields (record_type, case_id, status, severity)
        must always be present and correctly mapped.
        """
        case   = make_case()
        record = build_case_audit_record(case)
        self.assertEqual(record["record_type"], "case")
        self.assertEqual(record["case_id"],     "case-001")
        self.assertEqual(record["status"],      "Resolved")
        self.assertEqual(record["severity"],    "High")   # severity=3 → "High"

    def test_response_minutes_calculated_correctly(self):
        """
        response_minutes must equal (endDate - _createdAt) in minutes.
        900,000 ms difference = 15.0 minutes.
        """
        case   = make_case(created_at_ms=0, end_ms=900_000)
        record = build_case_audit_record(case)
        self.assertEqual(record["response_minutes"], 15.0)

    def test_sla_met_exactly_at_target(self):
        """
        A case closed exactly at the SLA boundary (15 minutes) must be
        classified as MET, not BREACHED. The boundary is inclusive.
        """
        case   = make_case(created_at_ms=0, end_ms=900_000)   # exactly 15 min
        record = build_case_audit_record(case)
        self.assertEqual(record["sla_status"], "MET")

    def test_sla_breached_when_over_target(self):
        """
        A case closed one minute over the target (16 minutes) must be BREACHED.
        This confirms the boundary check works in both directions.
        """
        case   = make_case(created_at_ms=0, end_ms=960_000)   # 16 minutes
        record = build_case_audit_record(case)
        self.assertEqual(record["sla_status"], "BREACHED")

    def test_sla_na_when_case_still_open(self):
        """
        An open case (no endDate) must have response_minutes=None and
        sla_status="N/A". Computing a response time for an open case would
        be meaningless and would unfairly inflate breach counts.
        """
        case   = make_case(status="Open", end_ms=None)
        record = build_case_audit_record(case)
        self.assertIsNone(record["response_minutes"])
        self.assertEqual(record["sla_status"], "N/A")

    def test_human_analyst_actor_type(self):
        """
        A case created by a human analyst email must produce actor_type="human".
        """
        case   = make_case(created_by="analyst1@catnip.soc")
        record = build_case_audit_record(case)
        self.assertEqual(record["actor_type"], "human")

    def test_automated_actor_type_for_service_account(self):
        """
        A case where both _createdBy and source match a known service account
        must produce actor_type="automated".
        """
        case   = make_case(created_by="cortex-svc@catnip.soc",
                           source="cortex-svc@catnip.soc")
        record = build_case_audit_record(case)
        self.assertEqual(record["actor_type"], "automated")

    def test_enrichment_detected_from_custom_fields(self):
        """
        When alert_enrichment.py processes a case it writes three custom fields:
        enrichment-timestamp, alert-category, and recommended-playbook.
        All three must be correctly extracted from the customFields dict.
        """
        custom = {
            "enrichment-timestamp":  {"date": 12345},
            "alert-category":        {"string": "Account Security"},
            "recommended-playbook":  {"string": "account-compromise-playbook"},
        }
        case   = make_case(custom_fields=custom)
        record = build_case_audit_record(case)
        self.assertTrue(record["was_auto_enriched"])
        self.assertEqual(record["alert_category"],      "Account Security")
        self.assertEqual(record["recommended_playbook"], "account-compromise-playbook")

    def test_no_enrichment_when_custom_fields_empty(self):
        """
        A case with no custom fields must have was_auto_enriched=False.
        This is the baseline state before the enrichment pipeline runs.
        """
        case   = make_case(custom_fields={})
        record = build_case_audit_record(case)
        self.assertFalse(record["was_auto_enriched"])

    def test_escalation_flag_captured(self):
        """
        The escalation-flag custom field is set to True for High/Critical cases
        by alert_enrichment.py. The audit record must faithfully capture this.
        """
        custom = {"escalation-flag": {"boolean": True}}
        case   = make_case(custom_fields=custom)
        record = build_case_audit_record(case)
        self.assertTrue(record["escalation_flagged"])

    def test_severity_mapping(self):
        """
        TheHive stores severity as an integer (1–4). The audit record must
        convert each value to the correct human-readable label.
        """
        expected = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        for sev_int, sev_str in expected.items():
            case   = make_case(severity=sev_int)
            record = build_case_audit_record(case)
            self.assertEqual(record["severity"], sev_str,
                             f"severity={sev_int} should produce '{sev_str}'")


# ── Test class 4: Alert audit record building ──────────────────────────────────

class TestAlertAuditRecord(unittest.TestCase):
    """
    Tests for build_alert_audit_record(), which transforms a raw TheHive
    alert dict into a flat audit record.

    Alerts are simpler than cases (no assignee, no endDate) but introduce
    the time_to_action field that has its own edge cases.
    """

    def test_basic_fields_are_populated(self):
        """
        The essential fields must be present and correctly set for all alerts.
        """
        alert  = make_alert()
        record = build_alert_audit_record(alert)
        self.assertEqual(record["record_type"], "alert")
        self.assertEqual(record["alert_id"],    "alert-001")
        self.assertEqual(record["status"],      "Imported")

    def test_automated_actor_for_enrichment_script(self):
        """
        Alerts created by alert_enrichment.py must be classified as automated.
        The source field "alert_enrichment" is the identifier the script uses.
        """
        alert  = make_alert(created_by="alert_enrichment", source="alert_enrichment")
        record = build_alert_audit_record(alert)
        self.assertEqual(record["actor_type"], "automated")

    def test_time_to_action_calculated(self):
        """
        time_to_action_minutes is the gap between when the alert arrived (created_at)
        and when it was first acted on (updated_at, when status changed from New).
        900,000 ms = 15.0 minutes.
        """
        alert  = make_alert(created_at_ms=0, updated_ms=900_000, status="Imported")
        record = build_alert_audit_record(alert)
        self.assertEqual(record["time_to_action_minutes"], 15.0)

    def test_time_to_action_none_when_still_new(self):
        """
        If an alert is still "New" (status unchanged), no action has been taken
        yet so time_to_action_minutes must be None and sla_status must be "N/A".
        Measuring time for an untriaged alert would give a misleading result.
        """
        alert  = make_alert(status="New", created_at_ms=0, updated_ms=60_000)
        record = build_alert_audit_record(alert)
        self.assertIsNone(record["time_to_action_minutes"])
        self.assertEqual(record["sla_status"], "N/A")

    def test_sla_breach_when_over_target(self):
        """
        An alert that took 16 minutes to action must be classified as BREACHED.
        960,000 ms = 16 minutes; 15 minutes is the SLA target.
        """
        alert  = make_alert(status="Imported", created_at_ms=0, updated_ms=960_000)
        record = build_alert_audit_record(alert)
        self.assertEqual(record["sla_status"], "BREACHED")


# ── Test class 5: Compliance summary aggregation ───────────────────────────────

class TestComplianceSummary(unittest.TestCase):
    """
    Tests for build_compliance_summary(), which aggregates all individual
    audit records into platform-level totals and NFR compliance results.

    This class uses helper methods to construct small sets of pre-built
    records so each test can focus on one specific aggregation result.
    """

    def _make_case_records(self):
        """
        Build a small set of case records for use across multiple tests:
          - c1: resolved, SLA met    (15 minutes, High severity, analyst1)
          - c2: resolved, SLA breach (40 minutes, Medium severity, analyst1)
          - c3: open (no closure time, unassigned → handled by analyst2 in fixture)
        This mix lets us test totals, SLA percentages, and severity breakdowns.
        """
        case_met = build_case_audit_record(
            make_case(case_id="c1", status="Resolved",
                      created_at_ms=0, end_ms=900_000,    # 15 min — SLA met
                      assignee="analyst1@catnip.soc", severity=3))
        case_breached = build_case_audit_record(
            make_case(case_id="c2", status="Resolved",
                      created_at_ms=0, end_ms=2_400_000,  # 40 min — SLA breached
                      assignee="analyst1@catnip.soc", severity=2))
        case_open = build_case_audit_record(
            make_case(case_id="c3", status="Open",
                      end_ms=None, assignee="analyst2@catnip.soc"))
        return [case_met, case_breached, case_open]

    def _make_alert_records(self):
        """
        Build two alert records, both acted on within 10 minutes.
        Used to test alert metric aggregation.
        """
        a1 = build_alert_audit_record(
            make_alert(alert_id="a1", status="Imported",
                       created_at_ms=0, updated_ms=600_000))  # 10 min
        a2 = build_alert_audit_record(
            make_alert(alert_id="a2", status="Imported",
                       created_at_ms=0, updated_ms=600_000))
        return [a1, a2]

    def test_case_totals_correct(self):
        """
        The summary must correctly count total, open, and resolved cases.
        With 3 cases (1 met, 1 breached, 1 open): total=3, open=1, resolved=2.
        """
        summary = build_compliance_summary(
            self._make_case_records(), [], None,
            datetime.now(tz=timezone.utc))
        self.assertEqual(summary["cases"]["total"],    3)
        self.assertEqual(summary["cases"]["open"],     1)
        self.assertEqual(summary["cases"]["resolved"], 2)

    def test_sla_percentage_calculated(self):
        """
        SLA percentage = (cases meeting SLA / total closed cases) × 100.
        1 met out of 2 closed = 50.0%.
        Note: the open case (c3) is excluded because it has no response time.
        """
        summary = build_compliance_summary(
            self._make_case_records(), [], None,
            datetime.now(tz=timezone.utc))
        self.assertEqual(summary["cases"]["sla_pct"], 50.0)

    def test_alert_totals_correct(self):
        """
        The summary must correctly count all alerts in the records list.
        """
        summary = build_compliance_summary(
            [], self._make_alert_records(), None,
            datetime.now(tz=timezone.utc))
        self.assertEqual(summary["alerts"]["total"], 2)

    def test_nfr_concurrent_incidents_pass(self):
        """
        With only 1 open case the platform is well under the 100-incident limit.
        The NFR check must return PASS.
        """
        summary = build_compliance_summary(
            self._make_case_records(), [], None,
            datetime.now(tz=timezone.utc))
        nfr = summary["nfr_compliance"]["concurrent_incidents_100"]
        self.assertEqual(nfr["status"], "PASS")

    def test_nfr_concurrent_incidents_fail(self):
        """
        When 101 cases are open simultaneously the limit is exceeded.
        The NFR check must return FAIL to alert the SOC manager.
        We generate 101 open cases programmatically to simulate this.
        """
        open_cases = [
            build_case_audit_record(
                make_case(case_id=f"c{i}", status="Open", end_ms=None))
            for i in range(101)
        ]
        summary = build_compliance_summary(
            open_cases, [], None, datetime.now(tz=timezone.utc))
        nfr = summary["nfr_compliance"]["concurrent_incidents_100"]
        self.assertEqual(nfr["status"], "FAIL")

    def test_nfr_sla_pass_when_90_percent_met(self):
        """
        The triage SLA NFR requires ≥ 90% of cases to be closed within 15 minutes.
        With 9 met and 1 breached = 90% exactly, the status must be PASS.
        """
        # 9 cases closed in 15 min
        met_cases = [
            build_case_audit_record(
                make_case(case_id=f"c{i}", status="Resolved",
                          created_at_ms=0, end_ms=900_000))  # 15 min each
            for i in range(9)
        ]
        # 1 case closed in 40 min (breach)
        breached = build_case_audit_record(
            make_case(case_id="c9", status="Resolved",
                      created_at_ms=0, end_ms=2_400_000))
        summary = build_compliance_summary(
            met_cases + [breached], [], None,
            datetime.now(tz=timezone.utc))
        nfr = summary["nfr_compliance"]["triage_sla_15min"]
        self.assertEqual(nfr["status"], "PASS")

    def test_nfr_sla_fail_when_below_90_percent(self):
        """
        With only 50% SLA compliance (1 met, 1 breached), the NFR must FAIL.
        This validates the 90% threshold in the NFR check logic.
        """
        summary = build_compliance_summary(
            self._make_case_records(), [], None,
            datetime.now(tz=timezone.utc))
        nfr = summary["nfr_compliance"]["triage_sla_15min"]
        self.assertEqual(nfr["status"], "FAIL")

    def test_analyst_activity_excludes_service_accounts(self):
        """
        The analyst activity table should show only human analysts.
        Service account actors must be silently excluded so the table
        does not misleadingly show bots as "analysts" with performance metrics.
        """
        automated_case = build_case_audit_record(
            make_case(case_id="auto", assignee="cortex-svc@catnip.soc",
                      created_by="cortex-svc@catnip.soc"))
        human_case = build_case_audit_record(
            make_case(case_id="human", assignee="analyst1@catnip.soc",
                      created_by="analyst1@catnip.soc"))
        summary = build_compliance_summary(
            [automated_case, human_case], [], None,
            datetime.now(tz=timezone.utc))
        analysts = summary["analyst_activity"]
        # Human analyst appears in the table
        self.assertIn("analyst1@catnip.soc", analysts)
        # Cortex service account does NOT appear
        self.assertNotIn("cortex-svc@catnip.soc", analysts)

    def test_empty_data_does_not_crash(self):
        """
        The logger must handle a completely empty platform gracefully.
        This guards against division-by-zero errors and KeyErrors when
        there are no cases or alerts (e.g. on a freshly deployed stack).
        """
        summary = build_compliance_summary(
            [], [], None, datetime.now(tz=timezone.utc))
        self.assertEqual(summary["cases"]["total"],  0)
        self.assertEqual(summary["alerts"]["total"], 0)
        # sla_pct is None when there are no closed cases — not zero
        self.assertIsNone(summary["cases"]["sla_pct"])

    def test_severity_breakdown_counts_correctly(self):
        """
        The severity breakdown dict must contain an accurate count for each level.
        Two Critical + one High = Critical:2, High:1, Medium:0, Low:0.
        """
        cases = [
            build_case_audit_record(make_case(case_id="a", severity=4)),  # Critical
            build_case_audit_record(make_case(case_id="b", severity=4)),  # Critical
            build_case_audit_record(make_case(case_id="c", severity=3)),  # High
        ]
        summary = build_compliance_summary(
            cases, [], None, datetime.now(tz=timezone.utc))
        self.assertEqual(summary["cases"]["severity"]["Critical"], 2)
        self.assertEqual(summary["cases"]["severity"]["High"],     1)
        self.assertEqual(summary["cases"]["severity"]["Medium"],   0)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Catnip Games SOC — Audit Logger Unit Tests")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")
    unittest.main(verbosity=2)