#!/usr/bin/env python3
"""
Catnip Games SOC Platform — Stale Case Detector
Owner: Platform Reliability
Purpose: Identifies TheHive cases that have had no activity for over 48 hours
         and flags them for analyst review. Prevents cases falling through the cracks.

Usage:
    python3 stale_case_detector.py
    python3 stale_case_detector.py --threshold-hours 24
    python3 stale_case_detector.py --dry-run
"""

import argparse
import os
import sys
from datetime import datetime, timezone, timedelta

import requests

# ── Configuration ─────────────────────────────────────────────
THEHIVE_URL     = os.getenv("THEHIVE_URL",     "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
}

SEVERITY_MAP = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


# ── Helpers ───────────────────────────────────────────────────
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def ms_to_datetime(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


# ── TheHive Queries ───────────────────────────────────────────
def fetch_open_cases() -> list:
    url = f"{THEHIVE_URL}/api/v1/case/_search"
    query = {
        "query": [
            {"_name": "filter", "_field": "status", "_value": "Open"}
        ],
        "range": "0-500"
    }
    try:
        resp = requests.post(url, headers=HEADERS, json=query, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        log(f"ERROR: Could not fetch cases — {e}")
        sys.exit(1)


def add_case_tag(case_id: str, tag: str, dry_run: bool):
    """Add a tag to a TheHive case."""
    # First get existing tags
    url = f"{THEHIVE_URL}/api/v1/case/{case_id}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        existing_tags = resp.json().get("tags", [])
    except requests.RequestException:
        existing_tags = []

    if tag in existing_tags:
        return  # Already tagged

    new_tags = existing_tags + [tag]
    payload = {"tags": new_tags}

    if dry_run:
        log(f"  [DRY RUN] Would add tag '{tag}' to case {case_id}")
        return

    try:
        resp = requests.patch(url, headers=HEADERS, json=payload, timeout=10)
        resp.raise_for_status()
        log(f"  [OK] Tagged case {case_id} as '{tag}'")
    except requests.RequestException as e:
        log(f"  [WARN] Could not tag case {case_id} — {e}")


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Stale Case Detector")
    parser.add_argument("--threshold-hours", type=int, default=48,
                        help="Hours of inactivity before a case is stale (default: 48)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing to TheHive")
    args = parser.parse_args()

    if not THEHIVE_API_KEY:
        log("ERROR: THEHIVE_API_KEY not set.")
        sys.exit(1)

    threshold = timedelta(hours=args.threshold_hours)
    now       = datetime.now(tz=timezone.utc)
    mode      = "DRY RUN" if args.dry_run else "LIVE"

    log(f"Stale Case Detector [{mode}] — threshold: {args.threshold_hours}h")
    log("Fetching open cases from TheHive...")

    cases = fetch_open_cases()
    log(f"Found {len(cases)} open case(s)")

    stale_cases = []
    for case in cases:
        updated_at = case.get("_updatedAt") or case.get("_createdAt", 0)
        last_update = ms_to_datetime(updated_at)
        age = now - last_update

        if age > threshold:
            stale_cases.append({
                "id":       case.get("_id"),
                "number":   case.get("number"),
                "title":    case.get("title", "No title"),
                "severity": SEVERITY_MAP.get(case.get("severity", 2), "Medium"),
                "age_hours": round(age.total_seconds() / 3600, 1),
                "assignee": case.get("assignee", "Unassigned"),
            })

    if not stale_cases:
        log(f"No stale cases found. All open cases updated within {args.threshold_hours}h.")
        return

    log(f"\n{'='*55}")
    log(f"  STALE CASES — {len(stale_cases)} case(s) need attention")
    log(f"{'='*55}")
    for c in stale_cases:
        log(f"  Case #{c['number']} [{c['severity']}] — {c['title']}")
        log(f"    Assignee: {c['assignee']} | Last updated: {c['age_hours']}h ago")
        add_case_tag(c["id"], "stale-needs-review", dry_run=args.dry_run)
    log(f"{'='*55}\n")

    log(f"Done. {len(stale_cases)} case(s) flagged as stale.")


if __name__ == "__main__":
    main()
