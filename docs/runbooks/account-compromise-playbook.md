# Playbook: Account Compromise
**ID:** PB-001  
**Owner:** Incident Response Lead  
**Linked alert category:** `Account Security`  
**Triggered by:** `alert_enrichment.py` when title contains: `login`, `auth`, `password`, `account`  
**Last Updated:** 2026-04  
**Review Cycle:** Quarterly

---

## Overview

This playbook covers suspected or confirmed compromise of a Catnip Games player or staff account. Triggers include credential stuffing, brute-force login attempts, suspicious session activity, and account takeover reports.

**SLA target:** Triage within 15 minutes of alert creation.

---

## Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Staff/admin account compromised, or >500 accounts affected |
| **High** | AbuseIPDB score ≥ 70 OR VirusTotal detections ≥ 5 on source IP |
| **Medium** | AbuseIPDB score 30–69 OR some VT detections, single player account |
| **Low** | Failed login attempts below threshold, no successful access |

Use `enrich_alert.py` + `categorise_incident.py` to auto-score the source IP before triaging.

---

## Phase 1 — Detection & Triage (0–15 min)

**Analyst: L1**

- [ ] Acknowledge alert in TheHive; set status to **In Progress**
- [ ] Run enrichment on source IP:
  ```bash
  python3 cortex-automation/tosin/scripts/enrich_alert.py <source_ip> --pretty --out /tmp/enrich.json
  python3 cortex-automation/tosin/scripts/categorise_incident.py --in /tmp/enrich.json --pretty
  ```
- [ ] Record enrichment result as a TheHive observable (`ip` data type)
- [ ] Check Elasticsearch for login events from the same IP in the last 24 hours:
  ```
  GET /game-logs-*/_search
  { "query": { "term": { "source_ip": "<source_ip>" } } }
  ```
- [ ] Determine: was login successful? Which account(s)?
- [ ] **If no successful login and low enrichment score → monitor and close as Low, document findings**
- [ ] **If successful login or High/Critical → escalate to L2, continue Phase 2**

---

## Phase 2 — Containment (15–45 min)

**Analyst: L2 / Incident Lead**

- [ ] **Disable affected account(s)** in the game platform admin panel
- [ ] **Invalidate all active sessions** for the affected account(s)
- [ ] If source IP is HIGH/CRITICAL: add to edge/WAF block list
  - Document the block with the TheHive case number as the reason
- [ ] Check for lateral movement: search Elasticsearch for other accounts accessed from same IP
- [ ] Check MISP for the source IP — is it a known threat actor?
  ```bash
  python3 automation/scripts/ioc_watchlist_check.py --dry-run
  ```
- [ ] Notify the affected player via the in-game support system (template: `ACC-COMPROMISE-NOTICE`)
- [ ] If a **staff account** is involved: immediately notify the SOC Manager and suspend the account

---

## Phase 3 — Investigation (45 min – 4 hrs)

**Analyst: L2**

- [ ] Pull full login history for the affected account from Elasticsearch
- [ ] Identify the compromise vector:
  - Credential stuffing (many accounts, same IP range)?
  - Phishing (look for social engineering alerts in same timeframe)?
  - Malware / session hijack (unusual geolocation change)?
- [ ] Search MISP for any related IOCs (email domain, IP range, user agent string)
- [ ] Document timeline of events in TheHive case description
- [ ] Add all IOCs as TheHive observables and push to MISP if novel

---

## Phase 4 — Recovery & Communication (4–24 hrs)

**Analyst: L2 / SOC Manager**

- [ ] Re-enable account only after password reset is confirmed by the player
- [ ] Restore any in-game items/currency lost due to malicious activity (coordinate with game ops team)
- [ ] Remove IP block if determined to be a shared/residential IP with low ongoing risk
- [ ] Update MISP with any new threat intelligence gathered

---

## Phase 5 — Post-Incident (within 5 days)

**Owner: SOC Manager**

- [ ] Complete post-incident review in TheHive (`Close` the case with resolution notes)
- [ ] If 10+ accounts were affected: file incident report to management
- [ ] Update this playbook if new attack patterns were observed
- [ ] Run `metrics_report.py` to confirm the SLA was met and log the result

---

## Escalation Matrix

| Condition | Escalate to | Method |
|-----------|-------------|--------|
| Staff account compromised | SOC Manager + IT Director | Phone + Slack |
| > 100 accounts in one incident | SOC Manager | Slack |
| Active data exfiltration suspected | SOC Manager + Legal | Phone |
| Unable to contain within 1 hour | L2 on-call | Slack |

---

## Key IOC Types to Collect

- Source IP address(es)
- User agent string
- Affected account username(s)
- Timestamps of suspicious login events
- Geolocation of anomalous sessions

---

## Related Playbooks

- [PB-002 Bot Attack / Game Integrity](bot-attack-playbook.md)
- [PB-003 Social Engineering](social-engineering-playbook.md)

---

## Revision History

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-04 | Initial version |
