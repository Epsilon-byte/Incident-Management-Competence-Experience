# Tests
**Owner:** Platform Reliability

This folder contains automated tests for the Catnip Games SOC platform. Tests are split into two categories:

---

## Unit Tests (no live platform needed)

These test the logic of automation scripts in isolation. Safe to run anywhere.

| File | Tests |
|------|-------|
| `test_alert_enrichment.py` | Alert classification, source lookup, IP detection, escalation logic |

Run with:
```bash
python3 tests/test_alert_enrichment.py -v
```

---

## Integration Tests (requires running platform)

These connect to live services and verify end-to-end functionality. Run on the VM with all services up.

| File | Tests |
|------|-------|
| `test_platform_integration.py` | Service availability, TheHive API, Elasticsearch read/write, Cortex analysers, backup system |

Run with:
```bash
# Set environment variables first
source .env.local

python3 tests/test_platform_integration.py -v
```

---

## Pre-Demo Checklist

Run both test suites before every demonstration:

```bash
# 1. Unit tests
python3 tests/test_alert_enrichment.py

# 2. Integration tests
python3 tests/test_platform_integration.py

# 3. Health check
bash automation/scripts/health_check.sh
```

All three should pass with no failures before going live.

---

## Test Results Log

Record test results before each major milestone:

| Date | Unit Tests | Integration Tests | Notes |
|------|-----------|-------------------|-------|
| 2026-04 | — | — | Initial setup |
| | | | |
