#!/usr/bin/env python3
"""
Catnip Games SOC Platform — Incident Metrics Reporter
Owner: Platform Reliability
Purpose: Queries TheHive for case data and prints a KPI summary report.
         Helps the Metrics & Reporting team member by providing structured data.

Usage:
    python3 metrics_report.py
    python3 metrics_report.py --output json
    python3 metrics_report.py --output csv
"""

import argparse
import csv
import io
import json
import os
import sys
from datetime import datetime, timezone

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
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr)


def ms_to_minutes(ms: int) -> float:
    return round(ms / 1000 / 60, 1)


# ── TheHive Queries ───────────────────────────────────────────
def fetch_cases() -> list:
    url = f"{THEHIVE_URL}/api/v1/case/_search"
    query = {"query": [{"_name": "all"}], "range": "0-500"}
    try:
        resp = requests.post(url, headers=HEADERS, json=query, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        log(f"ERROR fetching cases: {e}")
        sys.exit(1)


def fetch_alerts() -> list:
    url = f"{THEHIVE_URL}/api/v1/alert/_search"
    query = {"query": [{"_name": "all"}], "range": "0-1000"}
    try:
        resp = requests.post(url, headers=HEADERS, json=query, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        log(f"ERROR fetching alerts: {e}")
        return []


# ── Metric Calculations ───────────────────────────────────────
def calculate_metrics(cases: list, alerts: list) -> dict:
    total_cases    = len(cases)
    open_cases     = sum(1 for c in cases if c.get("status") in ("Open", "InProgress"))
    closed_cases   = sum(1 for c in cases if c.get("status") == "Resolved")
    total_alerts   = len(alerts)
    new_alerts     = sum(1 for a in alerts if a.get("status") == "New")

    # Response times (ms stored in TheHive)
    response_times = []
    for case in cases:
        created  = case.get("_createdAt", 0)
        end_date = case.get("endDate", 0)
        if created and end_date and end_date > created:
            response_times.append(end_date - created)

    avg_response_min = (
        ms_to_minutes(sum(response_times) // len(response_times))
        if response_times else None
    )
    meets_sla = (
        sum(1 for t in response_times if ms_to_minutes(t) <= 15)
        if response_times else 0
    )
    sla_percent = (
        round((meets_sla / len(response_times)) * 100, 1)
        if response_times else None
    )

    # Severity breakdown
    severity_breakdown = {label: 0 for label in SEVERITY_MAP.values()}
    for case in cases:
        label = SEVERITY_MAP.get(case.get("severity", 2), "Medium")
        severity_breakdown[label] += 1

    return {
        "generated_at":       datetime.now(timezone.utc).isoformat(),
        "total_cases":        total_cases,
        "open_cases":         open_cases,
        "closed_cases":       closed_cases,
        "total_alerts":       total_alerts,
        "new_alerts_pending": new_alerts,
        "avg_response_minutes":    avg_response_min,
        "sla_target_minutes":      15,
        "cases_meeting_sla":       meets_sla,
        "sla_compliance_percent":  sla_percent,
        "severity_breakdown":      severity_breakdown,
    }


# ── Output Formatters ─────────────────────────────────────────
def print_report(metrics: dict):
    sla = metrics["sla_compliance_percent"]
    sla_str = f"{sla}%" if sla is not None else "N/A (no closed cases)"
    avg = metrics["avg_response_minutes"]
    avg_str = f"{avg} min" if avg is not None else "N/A"

    print("\n" + "=" * 50)
    print("  Catnip Games SOC — KPI Report")
    print(f"  Generated: {metrics['generated_at']}")
    print("=" * 50)
    print(f"  Total Cases        : {metrics['total_cases']}")
    print(f"  Open Cases         : {metrics['open_cases']}")
    print(f"  Closed Cases       : {metrics['closed_cases']}")
    print(f"  Total Alerts       : {metrics['total_alerts']}")
    print(f"  Pending (New)      : {metrics['new_alerts_pending']}")
    print("-" * 50)
    print(f"  Avg Response Time  : {avg_str}")
    print(f"  SLA Target         : ≤ {metrics['sla_target_minutes']} min")
    print(f"  SLA Compliance     : {sla_str}")
    print("-" * 50)
    print("  Severity Breakdown:")
    for severity, count in metrics["severity_breakdown"].items():
        bar = "█" * count
        print(f"    {severity:<10}: {count:>3}  {bar}")
    print("=" * 50 + "\n")


def print_json(metrics: dict):
    print(json.dumps(metrics, indent=2))


def print_csv(metrics: dict):
    output = io.StringIO()
    flat = {k: v for k, v in metrics.items() if not isinstance(v, dict)}
    for k, v in metrics["severity_breakdown"].items():
        flat[f"severity_{k.lower()}"] = v
    writer = csv.DictWriter(output, fieldnames=flat.keys())
    writer.writeheader()
    writer.writerow(flat)
    print(output.getvalue())


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SOC Metrics Reporter")
    parser.add_argument("--output", choices=["text", "json", "csv"],
                        default="text", help="Output format (default: text)")
    args = parser.parse_args()

    if not THEHIVE_API_KEY:
        log("ERROR: THEHIVE_API_KEY not set.")
        sys.exit(1)

    log("Fetching cases from TheHive...")
    cases  = fetch_cases()
    log(f"  {len(cases)} cases found")
    alerts = fetch_alerts()
    log(f"  {len(alerts)} alerts found")

    metrics = calculate_metrics(cases, alerts)

    if args.output == "json":
        print_json(metrics)
    elif args.output == "csv":
        print_csv(metrics)
    else:
        print_report(metrics)


if __name__ == "__main__":
    main()
