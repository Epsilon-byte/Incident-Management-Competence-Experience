# Automation Scripts
**Owner:** Platform Reliability

This folder contains all automation scripts for the Catnip Games SOC platform. Each script is independently runnable and supports a `--dry-run` flag where relevant.

---

## Scripts Overview

| Script | Purpose | DCWF Task |
|--------|---------|-----------|
| `scripts/health_check.sh` | Check all SOC services are running | [705] Security Monitoring |
| `scripts/backup.sh` | Automated nightly backup of all components | NFR: Reliability |
| `scripts/ioc_watchlist_check.py` | Check IOCs against MISP, raise TheHive alerts | [707] Threat Analysis |
| `scripts/metrics_report.py` | Generate KPI report from TheHive case data | [705] Security Monitoring |
| `scripts/stale_case_detector.py` | Flag open cases with no recent activity | [852] Incident Supervision |
| `alert-enrichment/alert_enrichment.py` | Enrich new alerts with category and playbook | [705] Security Monitoring |

---

## Environment Variables

All scripts read credentials from environment variables — **never hardcode API keys**.

```bash
export THEHIVE_URL="http://localhost:9000"
export THEHIVE_API_KEY="your_thehive_key_here"
export CORTEX_URL="http://localhost:9001"
export CORTEX_API_KEY="your_cortex_key_here"
export MISP_URL="https://localhost"
export MISP_API_KEY="your_misp_key_here"
export ES_URL="http://localhost:9200"
```

Tip: Save these to a file called `.env.local` (already in `.gitignore`) and load with:
```bash
source .env.local
```

---

## Quick Reference

### Run health check
```bash
bash automation/scripts/health_check.sh
```

### Run manual backup
```bash
sudo bash automation/scripts/backup.sh
```

### Enrich new alerts (dry run first)
```bash
python3 automation/alert-enrichment/alert_enrichment.py --dry-run
python3 automation/alert-enrichment/alert_enrichment.py
```

### Check IOC watchlist
```bash
python3 automation/scripts/ioc_watchlist_check.py --dry-run
python3 automation/scripts/ioc_watchlist_check.py
```

### Generate metrics report
```bash
python3 automation/scripts/metrics_report.py
python3 automation/scripts/metrics_report.py --output json
python3 automation/scripts/metrics_report.py --output csv
```

### Find stale cases
```bash
python3 automation/scripts/stale_case_detector.py --threshold-hours 48 --dry-run
python3 automation/scripts/stale_case_detector.py --threshold-hours 48
```

---

## Running Tests

```bash
# Unit tests (no live services needed)
python3 tests/test_alert_enrichment.py -v

# Integration tests (requires running platform)
python3 tests/test_platform_integration.py -v
```

---

## Cron Schedule (Production)

```cron
# Nightly backup at 02:00
0 2 * * * /opt/catnip-soc/automation/scripts/backup.sh >> /var/log/soc-backup.log 2>&1

# Alert enrichment every 5 minutes
*/5 * * * * python3 /opt/catnip-soc/automation/alert-enrichment/alert_enrichment.py >> /var/log/soc-enrichment.log 2>&1

# IOC watchlist check every 15 minutes
*/15 * * * * python3 /opt/catnip-soc/automation/scripts/ioc_watchlist_check.py >> /var/log/soc-ioc.log 2>&1

# Stale case check every hour
0 * * * * python3 /opt/catnip-soc/automation/scripts/stale_case_detector.py >> /var/log/soc-stale.log 2>&1
```
