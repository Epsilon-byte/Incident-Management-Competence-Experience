# Playbook: Generic Alert Triage
**ID:** PB-000  
**Owner:** Incident Response Lead  
**Linked alert category:** `Uncategorised`  
**Triggered by:** `alert_enrichment.py` as fallback when no specific category matches  
**Last Updated:** 2026-04  
**Review Cycle:** Quarterly

---

## Overview

This playbook is the fallback triage procedure for alerts that do not match a specific category. It provides a structured approach to ensure no alert is left unexamined, and guides analysts toward the correct specialist playbook.

**SLA target:** Triage within 15 minutes of alert creation.

---

## Phase 1 — Initial Triage (0–15 min)

**Analyst: L1**

- [ ] Acknowledge the alert in TheHive and set status to **In Progress**
- [ ] Read the alert title and description carefully — identify the primary indicator(s)
- [ ] Enrich any IP addresses, domains, or URLs present:
  ```bash
  python3 cortex-automation/tosin/scripts/enrich_alert.py <indicator> --pretty --out /tmp/enrich.json
  python3 cortex-automation/tosin/scripts/categorise_incident.py --in /tmp/enrich.json --pretty
  ```
- [ ] Search Elasticsearch for related events in the last 24 hours:
  ```
  GET /game-logs-*/_search
  { "query": { "match": { "source_ip": "<indicator>" } } }
  ```
- [ ] Determine whether this alert matches a known category:
  - Login/auth/password/account → **use PB-001 (Account Compromise)**
  - Bot/exploit/cheat → **use PB-002 (Bot Attack)**
  - Phishing/social/impersonation → **use PB-003 (Social Engineering)**
  - Unknown → continue below

---

## Phase 2 — Classification

**Analyst: L1**

Assess the alert against the following questions and assign a severity:

| Question | If YES |
|----------|--------|
| Is there evidence of successful unauthorised access? | Severity ≥ High |
| Is sensitive data (player PII, payment info) involved? | Severity = Critical, notify SOC Manager |
| Is a production game service affected? | Severity ≥ High |
| Is this a known false positive source? | Close as False Positive, document reason |
| Are there < 3 matching events with no impact? | Severity = Low, monitor and close |

- [ ] Set the alert severity in TheHive based on the above
- [ ] Add a comment in TheHive explaining the classification rationale

---

## Phase 3 — Response

**Analyst: L1 / L2**

- [ ] If severity is **High or Critical**: escalate to L2 immediately and follow the appropriate specialist playbook
- [ ] If severity is **Medium**: investigate further — pull 48 hours of related logs from Elasticsearch, enrich all IOCs, document in TheHive
- [ ] If severity is **Low**: document findings, add IOCs as observables, close the case with notes
- [ ] If the alert is a **confirmed false positive**: close the case, note the false positive source, and consider whether the detection rule needs tuning

---

## Phase 4 — Close & Document

- [ ] Write a case summary in TheHive covering: what was detected, what was investigated, and what action was taken
- [ ] Tag the case with: the category determined, the analyst username, and `generic-triage`
- [ ] If a new attack type was identified that has no playbook: flag to the Incident Response Lead to create one

---

## Related Playbooks

- [PB-001 Account Compromise](account-compromise-playbook.md)
- [PB-002 Bot Attack / Game Integrity](bot-attack-playbook.md)
- [PB-003 Social Engineering](social-engineering-playbook.md)

---

## Revision History

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-04 | Initial version |
