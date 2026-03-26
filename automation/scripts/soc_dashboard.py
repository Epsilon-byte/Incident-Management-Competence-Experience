#!/usr/bin/env python3
"""
Catnip Games SOC Platform — Live Terminal Dashboard
Owner: Platform Reliability

Connects to TheHive and Elasticsearch to display a real-time
SOC status dashboard in the terminal. Refreshes every 30 seconds.

Usage:
    python3 soc_dashboard.py
    python3 soc_dashboard.py --once       # Print once and exit (great for CI/logging)
    python3 soc_dashboard.py --interval 60  # Refresh every 60 seconds

Environment variables:
    THEHIVE_URL         (default: http://localhost:9000)
    THEHIVE_API_KEY     (required for TheHive data)
    ES_URL              (default: http://localhost:9200)
    ES_USER             (default: elastic)
    ES_PASSWORD         (optional — enables ES auth)
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ─────────────────────────────────────────────
THEHIVE_URL     = os.getenv("THEHIVE_URL",     "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
ES_URL          = os.getenv("ES_URL",          "http://localhost:9200")
ES_USER         = os.getenv("ES_USER",         "elastic")
ES_PASSWORD     = os.getenv("ES_PASSWORD",     "")
CORTEX_URL      = os.getenv("CORTEX_URL",      "http://localhost:9001")
MISP_URL        = os.getenv("MISP_URL",        "https://localhost")

THEHIVE_HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
}

# ── ANSI colours ──────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"

    @staticmethod
    def severity(label: str) -> str:
        return {
            "Critical": C.RED + C.BOLD,
            "High":     C.RED,
            "Medium":   C.YELLOW,
            "Low":      C.GREEN,
        }.get(label, C.DIM)

SEVERITY_MAP = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


# ── Data fetchers ─────────────────────────────────────────────
def safe_get(url: str, headers: Dict, timeout: int = 5, **kwargs) -> Optional[Dict]:
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=False, **kwargs)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def safe_post(url: str, headers: Dict, payload: Dict, timeout: int = 5) -> Optional[Any]:
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=timeout, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def fetch_thehive_cases() -> List[Dict]:
    result = safe_post(
        f"{THEHIVE_URL}/api/v1/case/_search",
        THEHIVE_HEADERS,
        {"query": [{"_name": "all"}], "range": "0-500"},
    )
    return result if isinstance(result, list) else []


def fetch_thehive_alerts() -> List[Dict]:
    result = safe_post(
        f"{THEHIVE_URL}/api/v1/alert/_search",
        THEHIVE_HEADERS,
        {"query": [{"_name": "all"}], "range": "0-500"},
    )
    return result if isinstance(result, list) else []


def fetch_es_cluster_health() -> Optional[Dict]:
    auth = (ES_USER, ES_PASSWORD) if ES_PASSWORD else None
    return safe_get(f"{ES_URL}/_cluster/health", {}, auth=auth)


def fetch_es_index_count() -> int:
    auth = (ES_USER, ES_PASSWORD) if ES_PASSWORD else None
    result = safe_get(f"{ES_URL}/_cat/indices?format=json", {}, auth=auth)
    return len(result) if isinstance(result, list) else 0


def check_service(url: str, name: str) -> str:
    try:
        r = requests.get(url, timeout=3, verify=False)
        if r.status_code in (200, 302, 401, 403):
            return f"{C.GREEN}● UP{C.RESET}"
        return f"{C.YELLOW}● {r.status_code}{C.RESET}"
    except Exception:
        return f"{C.RED}● DOWN{C.RESET}"


# ── Metric calculations ───────────────────────────────────────
def ms_to_minutes(ms: int) -> float:
    return round(ms / 1000 / 60, 1)


def compute_case_metrics(cases: List[Dict]) -> Dict:
    total     = len(cases)
    open_c    = sum(1 for c in cases if c.get("status") in ("Open", "InProgress"))
    resolved  = sum(1 for c in cases if c.get("status") == "Resolved")
    severity  = {label: 0 for label in SEVERITY_MAP.values()}
    for c in cases:
        label = SEVERITY_MAP.get(c.get("severity", 2), "Medium")
        severity[label] += 1

    response_times = []
    for c in cases:
        created  = c.get("_createdAt", 0)
        end_date = c.get("endDate", 0)
        if created and end_date and end_date > created:
            response_times.append(end_date - created)

    avg_min = (
        ms_to_minutes(sum(response_times) // len(response_times))
        if response_times else None
    )
    sla_met = sum(1 for t in response_times if ms_to_minutes(t) <= 15)
    sla_pct = round(sla_met / len(response_times) * 100, 1) if response_times else None

    return {
        "total": total, "open": open_c, "resolved": resolved,
        "severity": severity, "avg_response_min": avg_min,
        "sla_pct": sla_pct, "sla_met": sla_met,
        "sla_total": len(response_times),
    }


def compute_alert_metrics(alerts: List[Dict]) -> Dict:
    total   = len(alerts)
    new_    = sum(1 for a in alerts if a.get("status") == "New")
    ignored = sum(1 for a in alerts if a.get("status") == "Ignored")
    imported = sum(1 for a in alerts if a.get("status") == "Imported")
    severity = {label: 0 for label in SEVERITY_MAP.values()}
    for a in alerts:
        label = SEVERITY_MAP.get(a.get("severity", 2), "Medium")
        severity[label] += 1
    return {
        "total": total, "new": new_, "ignored": ignored,
        "imported": imported, "severity": severity,
    }


# ── Rendering helpers ─────────────────────────────────────────
WIDTH = 70

def divider(char: str = "─") -> str:
    return C.DIM + char * WIDTH + C.RESET


def header(title: str) -> str:
    pad = WIDTH - len(title) - 4
    return (
        C.CYAN + C.BOLD + "┌" + "─" * 2 + " " + title + " " + "─" * pad + "┐" + C.RESET
    )


def row(label: str, value: str, width: int = WIDTH - 4) -> str:
    label_col = f"{C.DIM}{label:<24}{C.RESET}"
    return f"  {label_col}{value}"


def bar_chart(data: Dict[str, int], max_val: int = 20) -> List[str]:
    lines = []
    for label, count in data.items():
        bar_len = min(int(count / max(max_val, 1) * 20), 20)
        col = C.severity(label)
        bar = col + "█" * bar_len + C.DIM + "░" * (20 - bar_len) + C.RESET
        lines.append(f"  {C.DIM}{label:<10}{C.RESET} {bar} {col}{count:>3}{C.RESET}")
    return lines


def sla_badge(pct: Optional[float]) -> str:
    if pct is None:
        return f"{C.DIM}N/A{C.RESET}"
    if pct >= 90:
        return f"{C.GREEN}{C.BOLD}{pct}%{C.RESET} {C.GREEN}✓{C.RESET}"
    if pct >= 70:
        return f"{C.YELLOW}{pct}%{C.RESET} {C.YELLOW}!{C.RESET}"
    return f"{C.RED}{pct}%{C.RESET} {C.RED}✗{C.RESET}"


# ── Main render ───────────────────────────────────────────────
def render_dashboard(cases: List[Dict], alerts: List[Dict],
                     es_health: Optional[Dict], es_indices: int) -> None:

    cm = compute_case_metrics(cases)
    am = compute_alert_metrics(alerts)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Clear screen
    print("\033[2J\033[H", end="")

    # Title bar
    print()
    title = "CATNIP GAMES SOC — LIVE PLATFORM DASHBOARD"
    pad = (WIDTH - len(title)) // 2
    print(C.CYAN + C.BOLD + " " * pad + title + C.RESET)
    print(C.DIM + " " * pad + f"Last updated: {now}" + C.RESET)
    print()

    # ── Service Status ────────────────────────────────────────
    print(header("SERVICE STATUS"))
    print(row("TheHive",        check_service(THEHIVE_URL, "TheHive")))
    print(row("Cortex",         check_service(CORTEX_URL, "Cortex")))
    print(row("Elasticsearch",  check_service(ES_URL, "ES")))
    print(row("MISP",           check_service(MISP_URL, "MISP")))
    if es_health:
        es_status = es_health.get("status", "unknown")
        col = C.GREEN if es_status == "green" else C.YELLOW if es_status == "yellow" else C.RED
        num_nodes = es_health.get("number_of_nodes", "?")
        print(row("ES Cluster Health", f"{col}● {es_status}{C.RESET}  ({num_nodes} node(s), {es_indices} indices)"))
    print()

    # ── Case Overview ─────────────────────────────────────────
    print(header("CASES"))
    if not THEHIVE_API_KEY:
        print(f"  {C.YELLOW}Set THEHIVE_API_KEY to enable TheHive metrics{C.RESET}")
    else:
        print(row("Total Cases",     f"{C.WHITE}{C.BOLD}{cm['total']}{C.RESET}"))
        print(row("  Open / Active", f"{C.CYAN}{cm['open']}{C.RESET}"))
        print(row("  Resolved",      f"{C.GREEN}{cm['resolved']}{C.RESET}"))
        print(row("Avg Response",
            f"{C.WHITE}{cm['avg_response_min']} min{C.RESET}" if cm['avg_response_min'] else f"{C.DIM}N/A{C.RESET}"
        ))
        print(row("SLA ≤15 min",     sla_badge(cm['sla_pct'])))
        print()
        print(f"  {C.DIM}Severity breakdown:{C.RESET}")
        for line in bar_chart(cm["severity"], max_val=max(cm["severity"].values() or [1])):
            print(line)
    print()

    # ── Alert Overview ────────────────────────────────────────
    print(header("ALERTS"))
    if not THEHIVE_API_KEY:
        print(f"  {C.YELLOW}Set THEHIVE_API_KEY to enable alert metrics{C.RESET}")
    else:
        print(row("Total Alerts",    f"{C.WHITE}{C.BOLD}{am['total']}{C.RESET}"))
        print(row("  Pending (New)", f"{C.YELLOW}{am['new']}{C.RESET}"))
        print(row("  Imported",      f"{C.CYAN}{am['imported']}{C.RESET}"))
        print(row("  Ignored",       f"{C.DIM}{am['ignored']}{C.RESET}"))

        # Throughput note
        if am['total'] > 0:
            throughput_note = "within 1,000/day SLA" if am['total'] <= 1000 else "⚠ exceeds 1,000/day SLA"
            col = C.GREEN if am['total'] <= 1000 else C.RED
            print(row("Throughput",  f"{col}{throughput_note}{C.RESET}"))
        print()
        print(f"  {C.DIM}Severity breakdown:{C.RESET}")
        for line in bar_chart(am["severity"], max_val=max(am["severity"].values() or [1])):
            print(line)
    print()

    # ── Non-functional Requirements ───────────────────────────
    print(header("PLATFORM TARGETS"))
    sla_str = sla_badge(cm.get("sla_pct"))
    print(row("Triage SLA ≤15 min", sla_str))

    # Alert throughput
    daily_alerts = am.get("total", 0)
    throughput_ok = daily_alerts <= 1000
    print(row("1,000 alerts/day capacity",
        f"{C.GREEN}✓ ({daily_alerts} in backlog){C.RESET}" if throughput_ok
        else f"{C.RED}✗ ({daily_alerts} exceeds target){C.RESET}"
    ))

    print()
    print(divider("═"))
    print(f"  {C.DIM}Press Ctrl+C to stop.  Refreshes every 30 seconds.{C.RESET}")
    print(divider("═"))
    print()


# ── Entry point ───────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Catnip Games SOC Live Dashboard")
    parser.add_argument("--once",     action="store_true",  help="Print once and exit")
    parser.add_argument("--interval", type=int, default=30, help="Refresh interval in seconds (default 30)")
    args = parser.parse_args()

    while True:
        cases      = fetch_thehive_cases()
        alerts     = fetch_thehive_alerts()
        es_health  = fetch_es_cluster_health()
        es_indices = fetch_es_index_count()

        render_dashboard(cases, alerts, es_health, es_indices)

        if args.once:
            break

        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n{C.DIM}Dashboard stopped.{C.RESET}")
            sys.exit(0)


if __name__ == "__main__":
    main()
