#!/usr/bin/env python3
import argparse
import json
import os
from typing import Any, Dict, Tuple

from dotenv import load_dotenv

load_dotenv()

VT_MALICIOUS_HIGH = int(os.getenv("VT_MALICIOUS_HIGH", "5"))
ABUSE_HIGH = int(os.getenv("ABUSE_HIGH", "70"))
ABUSE_MEDIUM = int(os.getenv("ABUSE_MEDIUM", "30"))


def load_enrichment(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)


def categorise(enriched: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    """
    Returns: (severity, recommended_action, rationale_dict)
    """
    indicator = enriched.get("indicator")
    indicator_type = enriched.get("indicator_type")

    vt_mal = enriched.get("signals", {}).get("virustotal", {}).get("malicious")
    abuse = enriched.get("signals", {}).get("abuseipdb", {}).get("abuseConfidenceScore")

    rationale = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "thresholds": {
            "vt_malicious_high": VT_MALICIOUS_HIGH,
            "abuse_high": ABUSE_HIGH,
            "abuse_medium": ABUSE_MEDIUM,
        },
        "observed": {
            "vt_malicious": vt_mal,
            "abuse_confidence": abuse,
        },
    }

    # If we have AbuseIPDB (IP case), use both signals.
    if indicator_type == "ip":
        # HIGH
        if (isinstance(abuse, int) and abuse >= ABUSE_HIGH) or (isinstance(vt_mal, int) and vt_mal >= VT_MALICIOUS_HIGH):
            return (
                "HIGH",
                "Escalate incident. Consider blocking IP at edge/WAF, reset affected accounts, and hunt for related IOCs.",
                {**rationale, "decision": "High risk based on AbuseIPDB and/or VirusTotal thresholds."},
            )
        # MEDIUM
        if (isinstance(abuse, int) and abuse >= ABUSE_MEDIUM) or (isinstance(vt_mal, int) and vt_mal > 0):
            return (
                "MEDIUM",
                "Investigate further. Correlate with logs, check authentication events, and monitor for repeat activity.",
                {**rationale, "decision": "Medium risk based on moderate abuse score or some VT detections."},
            )
        # LOW
        return (
            "LOW",
            "No immediate containment. Document enrichment results and continue monitoring.",
            {**rationale, "decision": "Low risk (no detections / low abuse score)."},
        )

    # Domain/URL: typically only VT signal in this script
    if isinstance(vt_mal, int) and vt_mal >= VT_MALICIOUS_HIGH:
        return (
            "HIGH",
            "Escalate incident. Block domain/URL (DNS/Proxy), notify users, and search for related indicators.",
            {**rationale, "decision": "High risk based on VirusTotal detections threshold."},
        )
    if isinstance(vt_mal, int) and vt_mal > 0:
        return (
            "MEDIUM",
            "Investigate domain/URL in context. Validate source, check click telemetry, and monitor.",
            {**rationale, "decision": "Medium risk based on some VirusTotal detections."},
        )
    return (
        "LOW",
        "Document as likely benign. Continue monitoring.",
        {**rationale, "decision": "Low risk (no VirusTotal detections)."},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Categorise an incident based on enrichment JSON output.")
    parser.add_argument("--in", dest="infile", required=True, help="Input JSON produced by enrich_alert.py")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print output")
    args = parser.parse_args()

    enriched = load_enrichment(args.infile)
    severity, action, rationale = categorise(enriched)

    out = {
        "severity": severity,
        "recommended_action": action,
        "rationale": rationale,
    }
    print(json.dumps(out, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
