import os
import time
import json
import requests
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.environ["THEHIVE_API_KEY"]

# Which observable types to auto-enrich
WATCH_TYPES = set(os.environ.get("WATCH_TYPES", "ip").split(","))

# Analyzer names as they appear in TheHive UI
ANALYZERS = os.environ.get(
    "ANALYZERS",
    "VirusTotal_GetReport_3_1,AbuseIPDB_1_1,IPInfo_Details_1_0"
).split(",")

POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "30"))
STATE_FILE = os.environ.get("STATE_FILE", "state.json")

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
}

def utc_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)

def load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {
        "processed_observable_ids": [],
        "last_poll_ms": 0,
    }

def save_state(state: Dict[str, Any]) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def hive_request(method: str, path: str, *, json_body: Optional[dict] = None) -> Any:
    url = f"{THEHIVE_URL}{path}"
    r = requests.request(method, url, headers=HEADERS, json=json_body, timeout=30)
    r.raise_for_status()
    if not r.content:
        return None
    return r.json()

def search_observables_recent(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Uses TheHive query API to fetch recent observables.
    TheHive 5 uses a query endpoint; depending on deployment, it can be /api/v1/query or /api/query.
    We'll try both.
    """
    query = {
        "query": [
            {"_name": "listObservable"},
            {"_name": "sort", "_fields": [{"createdAt": "desc"}]},
            {"_name": "page", "from": 0, "to": limit, "extraData": ["case"]}
        ]
    }

    # Try common query endpoints
    for endpoint in ("/api/v1/query", "/api/query"):
        try:
            return hive_request("POST", endpoint, json_body=query)
        except requests.HTTPError:
            continue

    raise RuntimeError("Could not query observables (query endpoint not found/authorized).")

def run_analyzers(observable_id: str, analyzers: List[str]) -> None:
    """
    Run analyzers for an observable. Endpoint varies by TheHive build.
    We'll try common endpoints.
    """
    body = {"analyzers": analyzers}

    candidates = [
        f"/api/v1/observable/{observable_id}/analyze",
        f"/api/observable/{observable_id}/analyze",
        f"/api/v1/observable/{observable_id}/analyzer",
        f"/api/observable/{observable_id}/analyzer",
    ]

    last_err = None
    for path in candidates:
        try:
            hive_request("POST", path, json_body=body)
            return
        except Exception as e:
            last_err = e

    raise RuntimeError(f"Could not start analyzers for observable {observable_id}: {last_err}")

def add_case_note(case_id: str, message: str) -> None:
    """
    Add an observable/case note so the demo shows automation clearly.
    Endpoint varies; try common paths.
    """
    body = {"message": message}

    candidates = [
        f"/api/v1/case/{case_id}/comment",
        f"/api/case/{case_id}/comment",
        f"/api/v1/case/{case_id}/note",
        f"/api/case/{case_id}/note",
    ]

    for path in candidates:
        try:
            hive_request("POST", path, json_body=body)
            return
        except Exception:
            continue

    # Non-fatal: notes are nice-to-have
    print(f"[WARN] Could not add note to case {case_id} (endpoint may differ).")

def main() -> None:
    state = load_state()
    processed = set(state.get("processed_observable_ids", []))

    print(f"[INFO] Auto-enrichment starting. Watch types={WATCH_TYPES}, analyzers={ANALYZERS}, poll={POLL_SECONDS}s")

    while True:
        try:
            obs = search_observables_recent(limit=50)

            for o in obs:
                obs_id = o.get("_id") or o.get("id")
                if not obs_id or obs_id in processed:
                    continue

                data_type = o.get("dataType") or o.get("type")
                value = o.get("data") or o.get("value")

                # case info may be included in extraData; handle both
                case_obj = o.get("case") or o.get("_case") or {}
                case_id = case_obj.get("_id") or case_obj.get("id") or o.get("caseId")

                if data_type not in WATCH_TYPES:
                    continue

                if not case_id:
                    # still run analyzers even without note, but log
                    print(f"[WARN] Observable {obs_id} has no caseId in response; will run analyzers without case note.")

                print(f"[INFO] New observable: {data_type}={value} (obs={obs_id}, case={case_id})")
                run_analyzers(obs_id, ANALYZERS)

                if case_id:
                    add_case_note(
                        case_id,
                        f"[AUTO] Triggered analyzers {', '.join(ANALYZERS)} for observable {data_type}={value}."
                    )

                processed.add(obs_id)
                state["processed_observable_ids"] = list(processed)
                state["last_poll_ms"] = utc_ms()
                save_state(state)

        except Exception as e:
            print(f"[ERROR] {e}")

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
