# Cortex Automation (Tosin)

## What this does
- `scripts/enrich_alert.py`: Enriches IP/domain/URL using VirusTotal, AbuseIPDB and IPinfo.
- `scripts/categorise_incident.py`: Applies severity logic (LOW/MEDIUM/HIGH) with recommended actions.

## Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Secrets
Create a `.env` file in this folder (do not commit):
VT_API_KEY=
ABUSEIPDB_API_KEY=
IPINFO_TOKEN=

## Run
./scripts/enrich_alert.py 8.8.8.8 --pretty --out out.json
./scripts/categorise_incident.py --in out.json --pretty

## Samples
`samples/` contains JSON fixtures to demonstrate HIGH and MEDIUM severity outputs.
