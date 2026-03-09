#!/usr/bin/env python3
import argparse
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "").strip()

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
IPINFO_BASE = "https://ipinfo.io"


class EnrichmentError(Exception):
    pass


def is_ip(value: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value.strip()))


def is_url(value: str) -> bool:
    v = value.strip().lower()
    return v.startswith("http://") or v.startswith("https://")


def to_domain(value: str) -> str:
    v = value.strip()
    if is_url(v):
        return re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
    return v


def vt_headers() -> Dict[str, str]:
    if not VT_API_KEY:
        raise EnrichmentError("VT_API_KEY not set in .env")
    return {"x-apikey": VT_API_KEY}


def vt_extract_malicious_count(vt_obj: Dict[str, Any]) -> Optional[int]:
    # Analysis format: data.attributes.stats.malicious
    try:
        return int(vt_obj["data"]["attributes"]["stats"]["malicious"])
    except Exception:
        pass

    # IP/domain format: data.attributes.last_analysis_stats.malicious
    try:
        return int(vt_obj["data"]["attributes"]["last_analysis_stats"]["malicious"])
    except Exception:
        return None


def vt_get_ip(ip: str) -> Dict[str, Any]:
    r = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=vt_headers(), timeout=30)
    if r.status_code == 401:
        raise EnrichmentError("VirusTotal authentication failed (check VT_API_KEY).")
    r.raise_for_status()
    return r.json()


def vt_get_domain(domain: str) -> Dict[str, Any]:
    r = requests.get(f"{VT_BASE}/domains/{domain}", headers=vt_headers(), timeout=30)
    if r.status_code == 401:
        raise EnrichmentError("VirusTotal authentication failed (check VT_API_KEY).")
    r.raise_for_status()
    return r.json()


def vt_submit_url(url: str) -> str:
    r = requests.post(
        f"{VT_BASE}/urls",
        headers=vt_headers(),
        data={"url": url},
        timeout=30,
    )
    if r.status_code == 401:
        raise EnrichmentError("VirusTotal authentication failed (check VT_API_KEY).")
    r.raise_for_status()
    return r.json()["data"]["id"]


def vt_get_url_analysis(analysis_id: str) -> Dict[str, Any]:
    r = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=vt_headers(), timeout=30)
    if r.status_code == 401:
        raise EnrichmentError("VirusTotal authentication failed (check VT_API_KEY).")
    r.raise_for_status()
    return r.json()


def abuseipdb_check(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        raise EnrichmentError("ABUSEIPDB_API_KEY not set in .env")
    r = requests.get(
        f"{ABUSE_BASE}/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        timeout=30,
    )
    if r.status_code in (401, 403):
        raise EnrichmentError("AbuseIPDB authentication failed (check ABUSEIPDB_API_KEY).")
    r.raise_for_status()
    return r.json()


def ipinfo_lookup(ip: str) -> Dict[str, Any]:
    if not IPINFO_TOKEN:
        raise EnrichmentError("IPINFO_TOKEN not set in .env")
    r = requests.get(f"{IPINFO_BASE}/{ip}/json", params={"token": IPINFO_TOKEN}, timeout=30)
    if r.status_code in (401, 403):
        raise EnrichmentError("IPinfo authentication failed (check IPINFO_TOKEN).")
    r.raise_for_status()
    return r.json()


@dataclass
class EnrichmentResult:
    indicator: str
    indicator_type: str  # ip|domain|url

    vt_malicious: Optional[int]
    vt_error: Optional[str]
    vt_raw: Optional[Dict[str, Any]]

    abuse_confidence: Optional[int]
    abuse_error: Optional[str]
    abuse_raw: Optional[Dict[str, Any]]

    ipinfo_error: Optional[str]
    ipinfo_raw: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "signals": {
                "virustotal": {
                    "malicious": self.vt_malicious,
                    "error": self.vt_error,
                },
                "abuseipdb": {
                    "abuseConfidenceScore": self.abuse_confidence,
                    "error": self.abuse_error,
                },
                "ipinfo": {
                    "country": (self.ipinfo_raw or {}).get("country"),
                    "org": (self.ipinfo_raw or {}).get("org"),
                    "error": self.ipinfo_error,
                },
            },
            "raw": {
                "virustotal": self.vt_raw,
                "abuseipdb": self.abuse_raw,
                "ipinfo": self.ipinfo_raw,
            },
        }


def enrich_ip(ip: str) -> EnrichmentResult:
    # VT (best-effort)
    vt = None
    vt_mal = None
    vt_err = None
    try:
        vt = vt_get_ip(ip)
        vt_mal = vt_extract_malicious_count(vt)
    except Exception as e:
        vt_err = str(e)

    # AbuseIPDB (required for IP enrichment)
    abuse = None
    abuse_score = None
    abuse_err = None
    try:
        abuse = abuseipdb_check(ip)
        abuse_score = int(abuse["data"]["abuseConfidenceScore"])
    except Exception as e:
        abuse_err = str(e)

    # IPInfo (required for IP enrichment)
    ipinfo = None
    ipinfo_err = None
    try:
        ipinfo = ipinfo_lookup(ip)
    except Exception as e:
        ipinfo_err = str(e)

    return EnrichmentResult(
        indicator=ip,
        indicator_type="ip",
        vt_malicious=vt_mal,
        vt_error=vt_err,
        vt_raw=vt,
        abuse_confidence=abuse_score,
        abuse_error=abuse_err,
        abuse_raw=abuse,
        ipinfo_error=ipinfo_err,
        ipinfo_raw=ipinfo,
    )


def enrich_domain(domain: str) -> EnrichmentResult:
    vt = None
    vt_mal = None
    vt_err = None
    try:
        vt = vt_get_domain(domain)
        vt_mal = vt_extract_malicious_count(vt)
    except Exception as e:
        vt_err = str(e)

    return EnrichmentResult(
        indicator=domain,
        indicator_type="domain",
        vt_malicious=vt_mal,
        vt_error=vt_err,
        vt_raw=vt,
        abuse_confidence=None,
        abuse_error=None,
        abuse_raw=None,
        ipinfo_error=None,
        ipinfo_raw=None,
    )


def enrich_url(url: str) -> EnrichmentResult:
    vt = None
    vt_mal = None
    vt_err = None
    try:
        analysis_id = vt_submit_url(url)
        vt = vt_get_url_analysis(analysis_id)
        vt_mal = vt_extract_malicious_count(vt)
    except Exception as e:
        vt_err = str(e)

    return EnrichmentResult(
        indicator=url,
        indicator_type="url",
        vt_malicious=vt_mal,
        vt_error=vt_err,
        vt_raw=vt,
        abuse_confidence=None,
        abuse_error=None,
        abuse_raw=None,
        ipinfo_error=None,
        ipinfo_raw=None,
    )


def enrich(indicator: str) -> EnrichmentResult:
    indicator = indicator.strip()

    if is_ip(indicator):
        return enrich_ip(indicator)

    if is_url(indicator):
        return enrich_url(indicator)

    return enrich_domain(to_domain(indicator))


def main() -> None:
    parser = argparse.ArgumentParser(description="Alert enrichment using VirusTotal, AbuseIPDB, and IPinfo.")
    parser.add_argument("indicator", help="IP, domain, or URL to enrich (e.g., 8.8.8.8, google.com, https://example.com)")
    parser.add_argument("--out", default="", help="Optional output JSON file path")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    result = enrich(args.indicator)
    payload = result.to_dict()
    text = json.dumps(payload, indent=2 if args.pretty else None)

    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print(f"[OK] Wrote enrichment output to {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
