#!/usr/bin/env python3
"""
Catnip Games SOC Platform — IOC Watchlist Checker
Owner: Platform Reliability
Purpose: Checks a list of suspicious IPs/domains against MISP and flags
         any matches by creating a TheHive alert automatically.

Usage:
    python3 ioc_watchlist_check.py
    python3 ioc_watchlist_check.py --dry-run
"""

import argparse
import json
import os
import sys
from datetime import datetime

import requests

# ── Configuration ─────────────────────────────────────────────
THEHIVE_URL     = os.getenv("THEHIVE_URL",     "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
MISP_URL        = os.getenv("MISP_URL",        "https://localhost")
MISP_API_KEY    = os.getenv("MISP_API_KEY",    "")

THEHIVE_HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
}
MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# ── Simulated watchlist (in production, load from file or feed) ─
WATCHLIST = [
    {"type": "ip",     "value": "185.220.101.45", "note": "Known Tor exit node"},
    {"type": "ip",     "value": "45.155.205.233", "note": "Reported botnet C2"},
    {"type": "domain", "value": "malicious-auth-reset.com", "note": "Phishing domain"},
    {"type": "domain", "value": "catnip-account-verify.net", "note": "Brand impersonation"},
    {"type": "ip",     "value": "91.108.4.0",     "note": "Suspicious login attempts"},
]


# ── Helpers ───────────────────────────────────────────────────
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def check_ioc_in_misp(ioc: dict) -> bool:
    """Return True if the IOC is found in MISP."""
    url = f"{MISP_URL}/attributes/restSearch"
    payload = {"value": ioc["value"], "type": ioc["type"], "limit": 1}
    try:
        resp = requests.post(url, headers=MISP_HEADERS, json=payload,
                             timeout=10, verify=False)
        data = resp.json()
        attributes = data.get("response", {}).get("Attribute", [])
        return len(attributes) > 0
    except requests.RequestException:
        # MISP unreachable — treat as no match but log it
        log(f"  [WARN] Could not reach MISP for {ioc['value']}")
        return False


def create_thehive_alert(ioc: dict, misp_match: bool, dry_run: bool):
    """Create a TheHive alert for a watchlisted IOC."""
    title = f"Watchlist Hit: {ioc['type'].upper()} {ioc['value']}"
    description = (
        f"**IOC:** `{ioc['value']}`\n"
        f"**Type:** {ioc['type']}\n"
        f"**Note:** {ioc['note']}\n"
        f"**MISP Match:** {'Yes — confirmed in threat intelligence' if misp_match else 'No match in MISP'}\n\n"
        f"This IOC was found on the Catnip Games SOC watchlist. "
        f"Please triage and correlate with recent game server logs."
    )
    payload = {
        "title": title,
        "description": description,
        "type": "external",
        "source": "ioc-watchlist-checker",
        "sourceRef": f"watchlist-{ioc['value'].replace('.', '-')}",
        "severity": 3 if misp_match else 2,
        "tags": ["watchlist", ioc["type"], "automated"],
        "observables": [
            {"dataType": ioc["type"], "data": ioc["value"], "message": ioc["note"]}
        ],
    }

    if dry_run:
        log(f"  [DRY RUN] Would create alert: {title}")
        return

    try:
        resp = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            headers=THEHIVE_HEADERS,
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        alert_id = resp.json().get("_id", "unknown")
        log(f"  [OK] Created TheHive alert {alert_id}: {title}")
    except requests.RequestException as e:
        log(f"  [FAIL] Could not create alert for {ioc['value']} — {e}")


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="IOC Watchlist Checker")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing to TheHive")
    args = parser.parse_args()

    if not THEHIVE_API_KEY:
        log("ERROR: THEHIVE_API_KEY not set. Export it first.")
        sys.exit(1)

    mode = "DRY RUN" if args.dry_run else "LIVE"
    log(f"IOC Watchlist Check [{mode}] — {len(WATCHLIST)} IOCs to check")

    hits = 0
    for ioc in WATCHLIST:
        log(f"Checking {ioc['type']}: {ioc['value']}")
        misp_match = check_ioc_in_misp(ioc)
        status = "MISP MATCH" if misp_match else "no MISP match"
        log(f"  → {status}")
        create_thehive_alert(ioc, misp_match, dry_run=args.dry_run)
        if misp_match:
            hits += 1

    log(f"\nDone. {hits}/{len(WATCHLIST)} IOCs matched in MISP.")


if __name__ == "__main__":
    main()
