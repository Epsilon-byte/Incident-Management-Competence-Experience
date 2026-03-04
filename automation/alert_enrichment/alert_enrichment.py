#!/usr/bin/env python3
"""
Catnip Games SOC Platform — Alert Enrichment Script
Owner: Platform Reliability
Purpose: Pulls new TheHive alerts and enriches them with basic context
         before they are triaged by analysts.

Usage:
    python3 alert_enrichment.py
    python3 alert_enrichment.py --dry-run   # Preview without writing to TheHive
"""

import argparse
import json
import os
import sys
from datetime import datetime

import requests

# ── Configuration ────────────────────────────────────────────
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
}

# Alert severity labels (TheHive uses integers)
SEVERITY_MAP = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Catnip Games — known internal IP ranges (would be loaded from config in prod)
INTERNAL_RANGES = ["10.0.0.", "192.168.1.", "172.16."]


# ── Helpers ───────────────────────────────────────────────────
def log(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def is_internal_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in INTERNAL_RANGES)


def classify_alert_source(source: str) -> str:
    """Return a human-readable description of the alert source."""
    source_map = {
        "auth-service": "Player authentication service",
        "matchmaking": "Matchmaking server",
        "game-host": "Game hosting server",
        "api-gateway": "API gateway",
        "elasticsearch": "Elasticsearch watcher rule",
    }
    return source_map.get(source.lower(), f"Unknown source: {source}")


# ── TheHive API calls ─────────────────────────────────────────
def get_new_alerts() -> list:
    """Fetch all alerts with status 'New' from TheHive."""
    url = f"{THEHIVE_URL}/api/v1/alert/_search"
    query = {
        "query": [
            {"_name": "filter", "_field": "status", "_value": "New"}
        ],
        "range": "0-100"
    }
    try:
        response = requests.post(url, headers=HEADERS, json=query, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        log(f"ERROR: Could not fetch alerts from TheHive — {e}")
        sys.exit(1)


def enrich_alert(alert_id: str, enrichment: dict, dry_run: bool = False):
    """Add enrichment data as a custom field update on the alert."""
    url = f"{THEHIVE_URL}/api/v1/alert/{alert_id}"
    payload = {"customFields": enrichment}

    if dry_run:
        log(f"  [DRY RUN] Would update alert {alert_id} with: {json.dumps(enrichment)}")
        return

    try:
        response = requests.patch(url, headers=HEADERS, json=payload, timeout=10)
        response.raise_for_status()
        log(f"  [OK] Enriched alert {alert_id}")
    except requests.RequestException as e:
        log(f"  [WARN] Failed to enrich alert {alert_id} — {e}")


# ── Enrichment Logic ──────────────────────────────────────────
def build_enrichment(alert: dict) -> dict:
    """
    Analyse the alert and build enrichment fields.
    In a production setup this would call Cortex analysers,
    MISP lookups, and GeoIP. Here we add structured context
    that helps analysts triage faster.
    """
    enrichment = {}
    title = alert.get("title", "").lower()
    source = alert.get("source", "")
    severity = alert.get("severity", 2)

    # Classify the alert type based on title keywords
    if any(kw in title for kw in ["login", "auth", "password", "account"]):
        enrichment["alert-category"] = {"string": "Account Security"}
        enrichment["recommended-playbook"] = {"string": "account-compromise-playbook"}
    elif any(kw in title for kw in ["bot", "exploit", "cheat", "manipulation"]):
        enrichment["alert-category"] = {"string": "Game Integrity"}
        enrichment["recommended-playbook"] = {"string": "bot-attack-playbook"}
    elif any(kw in title for kw in ["social", "phish", "impersonat"]):
        enrichment["alert-category"] = {"string": "Social Engineering"}
        enrichment["recommended-playbook"] = {"string": "social-engineering-playbook"}
    else:
        enrichment["alert-category"] = {"string": "Uncategorised"}
        enrichment["recommended-playbook"] = {"string": "generic-triage-playbook"}

    # Add source description
    if source:
        enrichment["source-description"] = {"string": classify_alert_source(source)}

    # Flag critical/high alerts for immediate escalation
    if severity >= 3:
        enrichment["escalation-flag"] = {"boolean": True}
    else:
        enrichment["escalation-flag"] = {"boolean": False}

    # Timestamp when enrichment was applied
    enrichment["enrichment-timestamp"] = {
        "date": int(datetime.utcnow().timestamp() * 1000)
    }

    return enrichment


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="TheHive Alert Enrichment Script")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview enrichment without writing to TheHive")
    args = parser.parse_args()

    if not THEHIVE_API_KEY:
        log("ERROR: THEHIVE_API_KEY environment variable is not set.")
        log("       Export it with: export THEHIVE_API_KEY=your_key_here")
        sys.exit(1)

    mode = "DRY RUN" if args.dry_run else "LIVE"
    log(f"Starting alert enrichment [{mode}]")
    log(f"Connecting to TheHive at {THEHIVE_URL}")

    alerts = get_new_alerts()
    log(f"Found {len(alerts)} new alert(s) to process")

    if not alerts:
        log("Nothing to do. Exiting.")
        return

    for alert in alerts:
        alert_id = alert.get("_id", "unknown")
        title = alert.get("title", "No title")
        severity_label = SEVERITY_MAP.get(alert.get("severity", 2), "Unknown")

        log(f"Processing [{severity_label}] {alert_id} — {title}")
        enrichment = build_enrichment(alert)
        enrich_alert(alert_id, enrichment, dry_run=args.dry_run)

    log(f"Enrichment complete. Processed {len(alerts)} alert(s).")


if __name__ == "__main__":
    main()
