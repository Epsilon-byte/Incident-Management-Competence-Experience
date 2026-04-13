#!/usr/bin/env python3
import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import requests

# ── Configuration ──────────────────────────────────────────────────────────────
# All settings are read from environment variables so that credentials are never
# hardcoded into source files. Defaults match the testing docker-compose setup.
THEHIVE_URL        = os.getenv("THEHIVE_URL",        "http://localhost:9000")
THEHIVE_API_KEY    = os.getenv("THEHIVE_API_KEY",    "")
SLA_TARGET_MINUTES = int(os.getenv("SLA_TARGET_MINUTES", "15"))   # platform NFR
ALERT_DAILY_TARGET = int(os.getenv("ALERT_DAILY_TARGET", "1000")) # platform NFR

# HTTP headers sent with every TheHive API request.
# Bearer token authentication is the standard TheHive v1 auth method.
HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
}

# TheHive stores severity as an integer (1–4). This maps it to a readable label.
SEVERITY_MAP = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# The set of actor names that belong to automated scripts rather than humans.
# These are the service account usernames defined in thehive/user-roles/profiles.json
# plus the source identifiers used by our own automation scripts.
# Any case or alert created/touched by one of these is flagged as actor_type="automated"
# so auditors can separate human decisions from scripted actions.
AUTOMATED_ACTORS = {
    "cortex-svc@catnip.soc",    # Cortex service account (defined in profiles.json)
    "misp-svc@catnip.soc",      # MISP sync service account (defined in profiles.json)
    "alert_enrichment",          # Source identifier set by alert_enrichment.py
    "ioc-watchlist-checker",     # Source identifier set by ioc_watchlist_check.py
}


# ── Helper functions ───────────────────────────────────────────────────────────

def log(msg: str) -> None:
    """
    Print a timestamped progress message to stderr.
    Using stderr keeps diagnostic output separate from any JSON/CSV written to stdout,
    which matters when the caller pipes output to another tool.
    """
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr)


def ts_to_dt(ms: Optional[int]) -> Optional[datetime]:
    """
    Convert a TheHive millisecond epoch timestamp to a timezone-aware UTC datetime.

    TheHive stores all timestamps as milliseconds since the Unix epoch (1 Jan 1970).
    Python's datetime.fromtimestamp() expects seconds, so we divide by 1000.
    We always attach UTC timezone info so comparisons between records are safe.

    Returns None only if the input is None (e.g. a case that has no endDate yet).
    A value of 0 is a valid timestamp (Unix epoch) and is converted normally.
    """
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


def dt_to_str(dt: Optional[datetime]) -> str:
    """
    Format a UTC datetime as a human-readable string for display in the CSV/report.
    Returns an empty string for None so CSV cells are blank rather than "None".
    """
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def ms_to_minutes(ms: int) -> float:
    """
    Convert a millisecond duration to minutes, rounded to one decimal place.
    Used to express response times in a human-readable way (e.g. "12.4 min").
    """
    return round(ms / 1000 / 60, 1)


def is_automated(actor: Optional[str], source: Optional[str] = None) -> bool:
    """
    Return True if an action was performed by an automated script rather than
    a human analyst.

    Checks both the actor (who performed the action) and the source (which system
    originated the data), because different automation scripts use different fields
    to identify themselves in TheHive's API responses.

    Examples:
        is_automated("cortex-svc@catnip.soc")          → True  (service account)
        is_automated(None, source="alert_enrichment")   → True  (enrichment script)
        is_automated("analyst1@catnip.soc")             → False (human analyst)
    """
    if actor and actor in AUTOMATED_ACTORS:
        return True
    if source and source in AUTOMATED_ACTORS:
        return True
    return False


# ── TheHive API functions ──────────────────────────────────────────────────────

def _post(endpoint: str, payload: Dict) -> Any:
    """
    Send a POST request to the TheHive v1 API and return the parsed JSON response.

    TheHive uses POST for search/query operations (not just writes), which is why
    this helper is used for both fetching cases and fetching alerts.

    Exits immediately with an error message if:
    - The connection is refused (TheHive not running / wrong URL)
    - TheHive returns an HTTP error (wrong API key, missing endpoint, etc.)

    This hard exit is intentional: an audit log produced from partial data would be
    misleading, so we prefer to fail loudly and let the user fix the issue.
    """
    url = f"{THEHIVE_URL}{endpoint}"
    try:
        r = requests.post(url, headers=HEADERS, json=payload, timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        log(f"ERROR: Cannot connect to TheHive at {THEHIVE_URL}")
        log("       Is the stack running? Try: python3 soc_launcher.py status")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        log(f"ERROR: TheHive returned HTTP {e.response.status_code} for {endpoint}")
        log("       Check that THEHIVE_API_KEY is correct.")
        sys.exit(1)


def fetch_cases(since_ms: Optional[int] = None) -> List[Dict]:
    """
    Retrieve all cases from TheHive, optionally filtered to a time window.

    The TheHive v1 search API accepts a list of filter objects. When since_ms is
    provided we add a _createdAt >= filter so the audit covers only the requested
    date range. Without it, all cases ever created are returned (up to 1000).

    Returns a list of raw TheHive case dicts.
    """
    filters = [{"_name": "all"}]
    if since_ms:
        # Filter to cases created at or after the given epoch millisecond timestamp
        filters = [{"_name": "filter", "_field": "_createdAt",
                    "_value": {"_gte": since_ms}}]
    result = _post("/api/v1/case/_search",
                   {"query": filters, "range": "0-1000"})
    return result if isinstance(result, list) else []


def fetch_alerts(since_ms: Optional[int] = None) -> List[Dict]:
    """
    Retrieve all alerts from TheHive, optionally filtered to a time window.

    Alerts in TheHive represent incoming security events before they are promoted
    to full cases. Their status progresses: New → Imported (promoted to case)
    or New → Ignored (dismissed). Both are audited here.

    Returns a list of raw TheHive alert dicts.
    """
    filters = [{"_name": "all"}]
    if since_ms:
        filters = [{"_name": "filter", "_field": "_createdAt",
                    "_value": {"_gte": since_ms}}]
    result = _post("/api/v1/alert/_search",
                   {"query": filters, "range": "0-1000"})
    return result if isinstance(result, list) else []


def fetch_case_tasks(case_id: str) -> List[Dict]:
    """
    Retrieve the task list for a specific case.

    Tasks represent individual steps within a case (e.g. "Enrich IOCs",
    "Notify affected player"). This function is available for future use —
    a more detailed audit could check whether required playbook steps were
    completed for each case.

    Returns a list of task dicts for the given case.
    """
    result = _post(f"/api/v1/case/{case_id}/task/_search",
                   {"query": [{"_name": "all"}], "range": "0-100"})
    return result if isinstance(result, list) else []


# ── Audit record builders ──────────────────────────────────────────────────────

def build_case_audit_record(case: Dict) -> Dict:
    """
    Transform a raw TheHive case dict into a flat, auditable record.

    This function extracts, computes, and normalises the fields that matter for
    an audit, discarding low-level API noise. Key calculations:

    Response time:
        Measured from _createdAt to endDate (the closure timestamp).
        If the case is still open (no endDate), response_minutes is None
        and sla_status is "N/A". This avoids misleadingly classifying open
        cases as SLA breaches.

    SLA status:
        MET      — case closed within SLA_TARGET_MINUTES
        BREACHED — case closed but took longer than the target
        N/A      — case not yet closed; cannot assess

    Actor type:
        Determined by checking _createdBy and source against AUTOMATED_ACTORS.
        "automated" means a script created this case; "human" means an analyst did.

    Enrichment detection:
        The alert_enrichment.py script writes a custom field called
        "enrichment-timestamp" to every case it processes. Checking for this
        field tells us whether the automated enrichment pipeline ran before
        the analyst triaged the case.
    """
    # --- Extract raw fields from the TheHive API response ---
    case_id    = case.get("_id", "unknown")
    created_ms = case.get("_createdAt", 0)     # millisecond epoch: when case was opened
    updated_ms = case.get("_updatedAt", 0)     # millisecond epoch: last change
    end_ms     = case.get("endDate")           # millisecond epoch: when case was closed (None if open)
    created_by = case.get("_createdBy", "unknown")
    assignee   = case.get("assignee", "Unassigned")
    status     = case.get("status", "Unknown") # Open / InProgress / Resolved
    severity   = SEVERITY_MAP.get(case.get("severity", 2), "Medium")

    # Convert millisecond timestamps to readable datetime objects
    created_dt = ts_to_dt(created_ms)
    updated_dt = ts_to_dt(updated_ms)
    closed_dt  = ts_to_dt(end_ms)

    # --- Compute response time and SLA compliance ---
    # Only calculate when the case is actually closed (end_ms is not None).
    # We also guard end_ms > created_ms to avoid negative durations from data issues.
    response_minutes: Optional[float] = None
    if created_ms is not None and end_ms is not None and end_ms > created_ms:
        response_minutes = ms_to_minutes(end_ms - created_ms)

    # Assess SLA: closed cases are MET or BREACHED; open cases get N/A
    sla_status = "N/A"
    if response_minutes is not None:
        sla_status = "MET" if response_minutes <= SLA_TARGET_MINUTES else "BREACHED"

    # --- Determine whether the action was human or automated ---
    source     = case.get("source", "")
    actor_type = "automated" if is_automated(created_by, source) else "human"

    # --- Check for automated enrichment via custom fields ---
    # alert_enrichment.py writes these fields when it processes an alert/case.
    # Their presence proves the enrichment pipeline ran before analyst triage.
    custom_fields  = case.get("customFields", {})
    was_enriched   = "enrichment-timestamp" in custom_fields
    alert_category = custom_fields.get("alert-category", {}).get("string", "")
    rec_playbook   = custom_fields.get("recommended-playbook", {}).get("string", "")
    # escalation-flag is set to True when severity is High or Critical
    escalated      = custom_fields.get("escalation-flag", {}).get("boolean", False)

    # --- Return a flat dict with all audit-relevant fields ---
    return {
        "record_type":          "case",
        "case_id":              case_id,
        "case_number":          case.get("number", ""),      # human-friendly case ref
        "title":                case.get("title", ""),
        "status":               status,
        "severity":             severity,
        "created_at":           dt_to_str(created_dt),
        "created_at_epoch_ms":  created_ms,                  # raw ms for sorting/filtering
        "last_updated_at":      dt_to_str(updated_dt),
        "closed_at":            dt_to_str(closed_dt),        # blank if still open
        "created_by":           created_by,
        "assignee":             assignee,
        "actor_type":           actor_type,                  # "human" or "automated"
        "response_minutes":     response_minutes,            # None if still open
        "sla_target_minutes":   SLA_TARGET_MINUTES,          # stored so the CSV is self-documenting
        "sla_status":           sla_status,                  # MET / BREACHED / N/A
        "was_auto_enriched":    was_enriched,                # True if enrichment pipeline ran
        "alert_category":       alert_category,              # e.g. "Account Security"
        "recommended_playbook": rec_playbook,                # e.g. "account-compromise-playbook"
        "escalation_flagged":   escalated,                   # True for High/Critical cases
        "tags":                 case.get("tags", []),
        "source":               source,
    }


def build_alert_audit_record(alert: Dict) -> Dict:
    """
    Transform a raw TheHive alert dict into a flat, auditable record.

    Alerts differ from cases in one key way: they have a simpler lifecycle
    (New → Imported or New → Ignored) and we measure time_to_action rather
    than response time. Time to action is how long the alert sat untouched
    as "New" before something (a human or script) acted on it.

    Note: If status is still "New", time_to_action_minutes is None because
    no action has been taken yet — computing a duration would be meaningless.
    """
    # --- Extract raw fields ---
    alert_id   = alert.get("_id", "unknown")
    created_ms = alert.get("_createdAt", 0)
    updated_ms = alert.get("_updatedAt", 0)   # when the alert was last changed (e.g. status update)
    created_by = alert.get("_createdBy", "unknown")
    status     = alert.get("status", "Unknown")  # New / Imported / Ignored
    source     = alert.get("source", "")
    severity   = SEVERITY_MAP.get(alert.get("severity", 2), "Medium")

    # Classify the actor that created the alert
    actor_type = "automated" if is_automated(created_by, source) else "human"

    # --- Compute time to action ---
    # This measures how long the alert waited before being triaged.
    # We only calculate if:
    #   1. Both timestamps are available
    #   2. The update happened after creation (guards against data anomalies)
    #   3. The alert is no longer "New" (if still New, no action has occurred yet)
    time_to_action_minutes: Optional[float] = None
    if (created_ms is not None and updated_ms is not None
            and updated_ms > created_ms and status != "New"):
        time_to_action_minutes = ms_to_minutes(updated_ms - created_ms)

    # Assess SLA for this alert (same target as cases: 15 minutes)
    sla_status = "N/A"
    if time_to_action_minutes is not None:
        sla_status = "MET" if time_to_action_minutes <= SLA_TARGET_MINUTES else "BREACHED"

    # --- Check for enrichment custom fields ---
    # Same logic as cases: presence of enrichment-timestamp proves the
    # alert_enrichment.py pipeline ran before a human triaged this alert.
    custom_fields  = alert.get("customFields", {})
    was_enriched   = "enrichment-timestamp" in custom_fields
    alert_category = custom_fields.get("alert-category", {}).get("string", "")
    rec_playbook   = custom_fields.get("recommended-playbook", {}).get("string", "")

    return {
        "record_type":            "alert",
        "alert_id":               alert_id,
        "title":                  alert.get("title", ""),
        "status":                 status,
        "severity":               severity,
        "source":                 source,
        "created_at":             dt_to_str(ts_to_dt(created_ms)),
        "created_at_epoch_ms":    created_ms,
        "last_updated_at":        dt_to_str(ts_to_dt(updated_ms)),
        "created_by":             created_by,
        "actor_type":             actor_type,
        "time_to_action_minutes": time_to_action_minutes,  # None if still New
        "sla_target_minutes":     SLA_TARGET_MINUTES,
        "sla_status":             sla_status,
        "was_auto_enriched":      was_enriched,
        "alert_category":         alert_category,
        "recommended_playbook":   rec_playbook,
        "tags":                   alert.get("tags", []),
    }


# ── Compliance summary ─────────────────────────────────────────────────────────

def build_compliance_summary(case_records: List[Dict],
                              alert_records: List[Dict],
                              since_dt: Optional[datetime],
                              generated_at: datetime) -> Dict:
    """
    Aggregate all audit records into a platform compliance summary.

    This function has four responsibilities:

    1. Case metrics — totals, open/resolved counts, severity breakdown,
       average response time, and SLA compliance percentage.

    2. Alert metrics — totals, pending count, how many were auto-created
       vs human-submitted, and how many passed their triage SLA.

    3. Analyst activity — a per-analyst breakdown showing how many cases
       each human analyst handled, their resolution rate, average response
       time, and individual SLA compliance. Service accounts are excluded
       here because they are not human analysts.

    4. NFR compliance — pass/fail checks against the four platform
       non-functional requirements defined in the project specification.
       These give a marker or auditor an at-a-glance view of platform health.
    """

    # ── 1. Case metrics ───────────────────────────────────────────────────────

    total_cases    = len(case_records)
    open_cases     = sum(1 for r in case_records if r["status"] in ("Open", "InProgress"))
    resolved_cases = sum(1 for r in case_records if r["status"] == "Resolved")

    # Filter to only closed cases for SLA and response time calculations.
    # Open cases have response_minutes=None and must be excluded to avoid
    # distorting the average or the compliance percentage.
    closed_with_time = [r for r in case_records if r["response_minutes"] is not None]
    sla_met   = sum(1 for r in closed_with_time if r["sla_status"] == "MET")
    sla_total = len(closed_with_time)
    # sla_pct is None when no cases are closed yet (avoids division by zero)
    sla_pct   = round(sla_met / sla_total * 100, 1) if sla_total else None

    avg_response = (
        round(sum(r["response_minutes"] for r in closed_with_time) / sla_total, 1)
        if sla_total else None
    )

    # ── 2. Alert metrics ──────────────────────────────────────────────────────

    total_alerts  = len(alert_records)
    new_alerts    = sum(1 for r in alert_records if r["status"] == "New")
    auto_enriched = sum(1 for r in alert_records if r["was_auto_enriched"])
    auto_created  = sum(1 for r in alert_records if r["actor_type"] == "automated")

    # Only alerts that have been acted on (not still "New") have a measurable
    # time_to_action, so filter before computing SLA percentages
    alert_sla_records = [r for r in alert_records if r["time_to_action_minutes"] is not None]
    alert_sla_met   = sum(1 for r in alert_sla_records if r["sla_status"] == "MET")
    alert_sla_total = len(alert_sla_records)
    alert_sla_pct   = (round(alert_sla_met / alert_sla_total * 100, 1)
                       if alert_sla_total else None)

    # ── 3. Severity breakdown ─────────────────────────────────────────────────

    # Count how many cases fall into each severity level.
    # Initialising with zeros ensures all four levels always appear in the output
    # even if no cases of a given severity exist.
    severity_breakdown: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in case_records:
        sev = r.get("severity", "Medium")
        if sev in severity_breakdown:
            severity_breakdown[sev] += 1

    # ── 4. Analyst activity ───────────────────────────────────────────────────

    # Build a per-analyst summary by iterating over all cases.
    # We use assignee (the person responsible for the case) as the primary key,
    # falling back to created_by if there is no assignee.
    # Service accounts and unassigned cases are skipped so the table shows
    # only human analysts.
    analyst_activity: Dict[str, Dict] = {}
    for r in case_records:
        actor = r.get("assignee") or r.get("created_by", "unknown")

        # Skip unassigned cases and service account actors
        if actor == "Unassigned" or is_automated(actor):
            continue

        # Initialise a fresh record the first time we see this analyst
        if actor not in analyst_activity:
            analyst_activity[actor] = {
                "cases_handled":  0,
                "cases_resolved": 0,
                "sla_met":        0,
                "sla_total":      0,
                "response_times": [],  # temporary list; removed after averaging
            }

        analyst_activity[actor]["cases_handled"] += 1
        if r["status"] == "Resolved":
            analyst_activity[actor]["cases_resolved"] += 1
        if r["sla_status"] == "MET":
            analyst_activity[actor]["sla_met"] += 1
        # Only count towards SLA total if we actually have a measured response time
        if r["sla_status"] in ("MET", "BREACHED"):
            analyst_activity[actor]["sla_total"] += 1
        if r["response_minutes"] is not None:
            analyst_activity[actor]["response_times"].append(r["response_minutes"])

    # Convert response_times list to a single average, then remove the raw list
    # so the output dict only contains serialisable scalar values
    analyst_summary = {}
    for actor, data in analyst_activity.items():
        times = data.pop("response_times")  # pop removes the key from the dict
        data["avg_response_minutes"] = (
            round(sum(times) / len(times), 1) if times else None
        )
        data["sla_compliance_pct"] = (
            round(data["sla_met"] / data["sla_total"] * 100, 1)
            if data["sla_total"] else None
        )
        analyst_summary[actor] = data

    # ── 5. NFR compliance ─────────────────────────────────────────────────────

    # Each check produces a target (what the platform should achieve),
    # an actual (what the data shows), and a status (PASS / FAIL / PARTIAL).
    # These map directly to the non-functional requirements in the project README.
    nfr_compliance = {

        # NFR: Alert triage SLA ≤ 15 minutes (≥ 90% compliance)
        "triage_sla_15min": {
            "target": f"≥ 90% of cases closed within {SLA_TARGET_MINUTES} min",
            "actual": f"{sla_pct}%" if sla_pct is not None else "N/A",
            "status": (
                "PASS"             if sla_pct and sla_pct >= 90 else
                "FAIL"             if sla_pct is not None else
                "INSUFFICIENT_DATA"   # no closed cases yet — cannot assess
            ),
        },

        # NFR: Platform must handle 1,000 alerts per day
        "alert_throughput_1000_per_day": {
            "target": f"≤ {ALERT_DAILY_TARGET} alerts/day capacity",
            "actual": f"{total_alerts} in audit window",
            "status": "PASS" if total_alerts <= ALERT_DAILY_TARGET else "FAIL",
        },

        # NFR: Support up to 100 concurrent incidents
        "concurrent_incidents_100": {
            "target": "≤ 100 concurrent open cases",
            "actual": f"{open_cases} currently open",
            "status": "PASS" if open_cases <= 100 else "FAIL",
        },

        # NFR: All alerts must be enriched before analyst triage
        # PARTIAL means the enrichment script ran on some but not all alerts —
        # this may indicate the script is not running on its cron schedule.
        "automated_enrichment": {
            "target": "All alerts enriched before analyst triage",
            "actual": f"{auto_enriched}/{total_alerts} alerts enriched",
            "status": (
                "PASS"    if total_alerts == 0 or auto_enriched == total_alerts else
                "PARTIAL" if auto_enriched > 0 else
                "FAIL"
            ),
        },
    }

    return {
        "generated_at":        generated_at.isoformat(),
        "audit_window_start":  since_dt.isoformat() if since_dt else "all time",
        "audit_window_end":    generated_at.isoformat(),
        "cases": {
            "total":                total_cases,
            "open":                 open_cases,
            "resolved":             resolved_cases,
            "severity":             severity_breakdown,
            "sla_met":              sla_met,
            "sla_total":            sla_total,
            "sla_pct":              sla_pct,
            "avg_response_minutes": avg_response,
        },
        "alerts": {
            "total":         total_alerts,
            "pending_new":   new_alerts,
            "auto_created":  auto_created,
            "auto_enriched": auto_enriched,
            "sla_met":       alert_sla_met,
            "sla_total":     alert_sla_total,
            "sla_pct":       alert_sla_pct,
        },
        "analyst_activity": analyst_summary,
        "nfr_compliance":   nfr_compliance,
    }


# ── Output writers ─────────────────────────────────────────────────────────────

def write_json(audit_log: Dict, path: str) -> None:
    """
    Serialise the complete audit log to a pretty-printed JSON file.

    The JSON file contains everything: the compliance summary, every individual
    case record, and every alert record. It is suitable for archiving or for
    piping into tools like jq for further analysis.

    Example query with jq:
        cat audit_log.json | jq '.compliance_summary.nfr_compliance'
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(audit_log, f, indent=2)
    log(f"JSON audit log written → {path}")


def write_csv(case_records: List[Dict], alert_records: List[Dict], path: str) -> None:
    """
    Write a flat CSV file containing one row per case and one row per alert.

    Both record types are written to the same file. The column set is the union
    of all case fields and all alert fields, so some cells will be blank for the
    record type that does not have that field (e.g. alerts have no 'case_number').

    List fields (like 'tags') are flattened to semicolon-separated strings because
    CSV cells cannot contain JSON arrays. For example: ["bot","automated"] → "bot;automated"

    The extrasaction="ignore" argument on DictWriter tells it to silently skip any
    keys in a record dict that are not in the defined column list, preventing crashes
    from unexpected API fields.
    """
    # Define the columns that appear in the CSV, in display order.
    # Case-specific columns come first, then alert-specific ones.
    case_fields = [
        "record_type", "case_number", "title", "status", "severity",
        "created_at", "closed_at", "created_by", "assignee", "actor_type",
        "response_minutes", "sla_target_minutes", "sla_status",
        "was_auto_enriched", "alert_category", "recommended_playbook",
        "escalation_flagged", "source",
    ]
    alert_fields = [
        "record_type", "alert_id", "title", "status", "severity",
        "source", "created_at", "last_updated_at", "created_by", "actor_type",
        "time_to_action_minutes", "sla_target_minutes", "sla_status",
        "was_auto_enriched", "alert_category", "recommended_playbook",
    ]

    # dict.fromkeys preserves insertion order and deduplicates: the result is
    # a combined column list with no repeats (dict.fromkeys values are all None,
    # but we only care about the keys here).
    all_fields = list(dict.fromkeys(case_fields + alert_fields))

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_fields, extrasaction="ignore")
        writer.writeheader()
        for record in case_records + alert_records:
            # Flatten any list values to semicolon-separated strings
            flat = {k: (";".join(str(i) for i in v) if isinstance(v, list) else v)
                    for k, v in record.items()}
            writer.writerow(flat)

    log(f"CSV evidence file written → {path}")


def print_summary(summary: Dict) -> None:
    """
    Print a human-readable compliance summary to stdout.

    Sections:
        CASES           — totals, response time, SLA, severity bar chart
        ALERTS          — totals, pending, automation coverage
        ANALYST ACTIVITY — per-analyst performance table
        NFR COMPLIANCE  — pass/fail results for each platform NFR
    """
    sep  = "=" * 60
    dash = "-" * 60

    print(f"\n{sep}")
    print("  Catnip Games SOC — Audit & Compliance Report")
    print(f"  Generated : {summary['generated_at']}")
    print(f"  Window    : {summary['audit_window_start']}")
    print(f"             → {summary['audit_window_end']}")
    print(sep)

    # ── Cases section ──────────────────────────────────────────────────────────
    c = summary["cases"]
    sla_str = (f"{c['sla_pct']}%  ({c['sla_met']}/{c['sla_total']} cases)"
               if c["sla_pct"] is not None else "N/A")
    avg_str = f"{c['avg_response_minutes']} min" if c["avg_response_minutes"] else "N/A"
    print(f"\n  CASES")
    print(dash)
    print(f"  {'Total':<30} {c['total']}")
    print(f"  {'Open':<30} {c['open']}")
    print(f"  {'Resolved':<30} {c['resolved']}")
    print(f"  {'Avg Response Time':<30} {avg_str}")
    print(f"  {'SLA Compliance (≤15 min)':<30} {sla_str}")
    print(f"\n  Severity Breakdown:")
    for sev, count in c["severity"].items():
        # Simple ASCII bar chart: one block per case, capped at 40 to fit the terminal
        bar = "█" * count if count <= 40 else "█" * 40 + f" (+{count - 40})"
        print(f"    {sev:<12} {count:>3}  {bar}")

    # ── Alerts section ─────────────────────────────────────────────────────────
    a = summary["alerts"]
    al_sla_str = (f"{a['sla_pct']}%  ({a['sla_met']}/{a['sla_total']} alerts)"
                  if a["sla_pct"] is not None else "N/A")
    print(f"\n  ALERTS")
    print(dash)
    print(f"  {'Total':<30} {a['total']}")
    print(f"  {'Pending (New)':<30} {a['pending_new']}")
    print(f"  {'Auto-created':<30} {a['auto_created']}")
    print(f"  {'Auto-enriched':<30} {a['auto_enriched']}")
    print(f"  {'Triage SLA Compliance':<30} {al_sla_str}")

    # ── Analyst activity section ───────────────────────────────────────────────
    analysts = summary.get("analyst_activity", {})
    if analysts:
        print(f"\n  ANALYST ACTIVITY")
        print(dash)
        print(f"  {'Analyst':<30} {'Cases':>6}  {'Resolved':>8}  "
              f"{'Avg Resp':>10}  {'SLA%':>6}")
        for actor, data in sorted(analysts.items()):
            avg = (f"{data['avg_response_minutes']}m"
                   if data["avg_response_minutes"] is not None else "N/A")
            sla = (f"{data['sla_compliance_pct']}%"
                   if data["sla_compliance_pct"] is not None else "N/A")
            print(f"  {actor:<30} {data['cases_handled']:>6}  "
                  f"{data['cases_resolved']:>8}  {avg:>10}  {sla:>6}")

    # ── NFR compliance section ─────────────────────────────────────────────────
    print(f"\n  PLATFORM NFR COMPLIANCE")
    print(dash)
    for nfr_id, nfr in summary["nfr_compliance"].items():
        # Choose a symbol based on status: ✓ pass, ~ partial/unknown, ✗ fail
        icon = ("✓" if nfr["status"] == "PASS"
                else "~" if nfr["status"] in ("PARTIAL", "INSUFFICIENT_DATA")
                else "✗")
        print(f"  [{icon}] {nfr_id}")
        print(f"       Target : {nfr['target']}")
        print(f"       Actual : {nfr['actual']}  [{nfr['status']}]")

    print(f"\n{sep}\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Parse command-line arguments, fetch data, build audit records, and write outputs.

    Flow:
        1. Validate that THEHIVE_API_KEY is set (fail early if not)
        2. Determine the audit window (--days or all time)
        3. Fetch cases and alerts from TheHive
        4. Transform each raw API response into a flat audit record
        5. Aggregate records into a compliance summary
        6. Print the summary and/or write JSON + CSV files
    """
    parser = argparse.ArgumentParser(
        description="Catnip Games SOC — Audit Logger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 audit_logger.py                        # full audit, files + summary
  python3 audit_logger.py --days 7               # last 7 days only
  python3 audit_logger.py --out /var/log/soc     # custom output directory
  python3 audit_logger.py --no-files             # summary to stdout only
  python3 audit_logger.py --format json          # JSON summary to stdout
        """,
    )
    parser.add_argument(
        "--days", type=int, default=None,
        help="Only audit records from the last N days (default: all time)"
    )
    parser.add_argument(
        "--out", type=str, default=".",
        help="Directory to write output files into (default: current directory)"
    )
    parser.add_argument(
        "--no-files", action="store_true",
        help="Print summary to stdout only — do not write JSON or CSV files"
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format: 'text' prints the human-readable summary; "
             "'json' prints the full machine-readable log to stdout"
    )
    args = parser.parse_args()

    # Fail fast if the API key is missing — better than a confusing 401 error later
    if not THEHIVE_API_KEY:
        print("ERROR: THEHIVE_API_KEY environment variable is not set.", file=sys.stderr)
        print("       Export it with:  export THEHIVE_API_KEY=your_key_here",
              file=sys.stderr)
        sys.exit(1)

    # ── Determine audit window ─────────────────────────────────────────────────
    # All timestamps in the audit are UTC. generated_at becomes the window end.
    generated_at = datetime.now(tz=timezone.utc)
    since_dt: Optional[datetime] = None
    since_ms: Optional[int]      = None
    if args.days:
        since_dt = generated_at - timedelta(days=args.days)
        # TheHive API filters expect millisecond epoch timestamps
        since_ms = int(since_dt.timestamp() * 1000)
        log(f"Audit window: last {args.days} day(s) "
            f"(since {since_dt.strftime('%Y-%m-%d %H:%M UTC')})")
    else:
        log("Audit window: all time")

    # ── Fetch data from TheHive ────────────────────────────────────────────────
    log(f"Connecting to TheHive at {THEHIVE_URL} ...")
    log("Fetching cases ...")
    cases = fetch_cases(since_ms)
    log(f"  {len(cases)} case(s) found")

    log("Fetching alerts ...")
    alerts = fetch_alerts(since_ms)
    log(f"  {len(alerts)} alert(s) found")

    # ── Build structured audit records ────────────────────────────────────────
    # List comprehensions apply the builder function to every raw API dict.
    log("Building audit records ...")
    case_records  = [build_case_audit_record(c)  for c in cases]
    alert_records = [build_alert_audit_record(a) for a in alerts]

    # ── Aggregate into compliance summary ────────────────────────────────────
    summary = build_compliance_summary(case_records, alert_records, since_dt, generated_at)

    # Bundle everything into one top-level dict for the JSON output.
    # The meta section records audit provenance so anyone reading the file knows
    # exactly when it was generated and what settings were in use.
    full_log = {
        "meta": {
            "generated_at":       generated_at.isoformat(),
            "generated_by":       "audit_logger.py",
            "audit_window_days":  args.days,       # None means "all time"
            "thehive_url":        THEHIVE_URL,
            "sla_target_minutes": SLA_TARGET_MINUTES,
            "alert_daily_target": ALERT_DAILY_TARGET,
        },
        "compliance_summary": summary,
        "case_audit_records":  case_records,
        "alert_audit_records": alert_records,
    }

    # ── Write outputs ─────────────────────────────────────────────────────────
    if args.format == "json":
        # Full machine-readable output — good for piping to jq or a SIEM
        print(json.dumps(full_log, indent=2))
    else:
        # Human-readable summary — the default
        print_summary(summary)

    if not args.no_files:
        os.makedirs(args.out, exist_ok=True)
        # Timestamp in filename ensures each run produces a unique file
        stamp     = generated_at.strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(args.out, f"audit_log_{stamp}.json")
        csv_path  = os.path.join(args.out, f"audit_log_{stamp}.csv")
        write_json(full_log, json_path)
        write_csv(case_records, alert_records, csv_path)

    # Final summary line so the user knows the run completed cleanly
    total_nfr   = len(summary["nfr_compliance"])
    passing_nfr = sum(1 for n in summary["nfr_compliance"].values()
                      if n["status"] == "PASS")
    log(f"Audit complete. NFR compliance: {passing_nfr}/{total_nfr} checks passing.")


if __name__ == "__main__":
    main()