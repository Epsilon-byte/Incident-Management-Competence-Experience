#!/usr/bin/env python3
import argparse
import json
import os
from typing import Any, Dict, Tuple, Optional

from dotenv import load_dotenv

load_dotenv()

VT_MALICIOUS_HIGH = int(os.getenv("VT_MALICIOUS_HIGH", "5"))
ABUSE_HIGH = int(os.getenv("ABUSE_HIGH", "70"))
ABUSE_MEDIUM = int(os.getenv("ABUSE_MEDIUM", "30"))


def load_enrichment(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)


def _to_int_or_none(value: Any) -> Optional[int]:
    """Convert value to int if possible, else None."""
    try:
        if value is None:
            return None
        return int(value)
    except (ValueError, TypeError):
        return None


def categorise(enriched: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    """
    Returns: (severity, recommended_action, rationale_dict)

    Improvements:
    - Handles missing/failed VirusTotal gracefully (e.g., auth failure)
    - Adds explicit rationale when VT is unavailable
    """

    indicator = enriched.get("indicator")
    indicator_type = enriched.get("indicator_type")

    vt_section = enriched.get("signals", {}).get("virustotal", {})
    abuse_section = enriched.get("signals", {}).get("abuseipdb", {})

    vt_mal = _to_int_or_none(vt_section.get("malicious"))
    vt_err = vt_section.get("error")  # may exist if enrichment captured VT failures

    abuse = _to_int_or_none(abuse_section.get("abuseConfidenceScore"))

    rationale: Dict[str, Any] = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "thresholds": {
            "vt_malicious_high": VT_MALICIOUS_HIGH,
            "abuse_high": ABUSE_HIGH,
            "abuse_medium": ABUSE_MEDIUM,
        },
        "observed": {
            "vt_malicious": vt_mal,
            "vt_error": vt_err,
            "abuse_confidence": abuse,
        },
        "data_quality": {
            "virustotal_available": vt_mal is not None and not vt_err,
            "abuseipdb_available": abuse is not None,
        },
    }

    # IP: use AbuseIPDB primarily; use VT if available
    if indicator_type == "ip":
        # HIGH (AbuseIPDB drives high confidence; VT supports if present)
        if (abuse is not None and abuse >= ABUSE_HIGH) or (vt_mal is not None and vt_mal >= VT_MALICIOUS_HIGH):
            return (
                "HIGH",
                "Escalate incident. Consider blocking IP at edge/WAF, reset affected accounts, and hunt for related IOCs.",
                {**rationale, "decision": "High risk based on AbuseIPDB and/or VirusTotal thresholds."},
            )

        # MEDIUM
        if (abuse is not None and abuse >= ABUSE_MEDIUM) or (vt_mal is not None and vt_mal > 0):
            return (
                "MEDIUM",
                "Investigate further. Correlate with logs, check authentication events, and monitor for repeat activity.",
                {**rationale, "decision": "Medium risk based on moderate abuse score or some VirusTotal detections."},
            )

        # LOW (if AbuseIPDB is low/none and VT is unavailable, still label LOW but add note)
        if abuse is None and (vt_mal is None or vt_err):
            return (
                "LOW",
                "No immediate containment. Document limited intelligence due to unavailable VT/Abuse signals and continue monitoring.",
                {**rationale, "decision": "Low risk by default due to missing enrichment signals (data quality limitation)."},
            )

        return (
            "LOW",
            "No immediate containment. Document enrichment results and continue monitoring.",
            {**rationale, "decision": "Low risk (no detections / low abuse score)."},
        )

    # Domain/URL: typically VT-driven. If VT unavailable, categorise as MEDIUM (unknown) not LOW.
    if indicator_type in ("domain", "url"):
        if vt_err or vt_mal is None:
            return (
                "MEDIUM",
                "VirusTotal signal unavailable. Investigate context (source, logs, user action) and consider additional enrichment sources.",
                {**rationale, "decision": "Medium risk due to missing VirusTotal intelligence (unknown risk)."},
            )

        if vt_mal >= VT_MALICIOUS_HIGH:
            return (
                "HIGH",
                "Escalate incident. Block domain/URL (DNS/Proxy), notify users, and search for related indicators.",
                {**rationale, "decision": "High risk based on VirusTotal detections threshold."},
            )

        if vt_mal > 0:
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

    # Unknown type fallback
    return (
        "MEDIUM",
        "Unsupported indicator type for automated categorisation. Review manually.",
        {**rationale, "decision": "Medium risk by default due to unsupported indicator type."},
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
