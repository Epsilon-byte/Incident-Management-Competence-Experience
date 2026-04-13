# Playbook: Bot Attack / Game Integrity
**ID:** PB-002  
**Owner:** Incident Response Lead  
**Linked alert category:** `Game Integrity`  
**Triggered by:** `alert_enrichment.py` when title contains: `bot`, `exploit`, `cheat`, `manipulation`  
**Last Updated:** 2026-04  
**Review Cycle:** Quarterly

---

## Overview

This playbook covers automated bot activity, exploit abuse, cheat engine usage, and any attempt to manipulate Catnip Games' game economy or matchmaking systems. These incidents are unique to game platforms and may not trigger traditional security tools.

**SLA target:** Triage within 15 minutes of alert creation.

---

## Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Economy-wide exploit actively being abused; game server integrity at risk |
| **High** | Coordinated botnet (>50 accounts), matchmaking manipulation at scale |
| **Medium** | Single or small cluster of bot accounts, in-game item duplication exploit |
| **Low** | Single player using minor cheat, no economy impact, first offence |

---

## Phase 1 — Detection & Triage (0–15 min)

**Analyst: L1**

- [ ] Acknowledge alert in TheHive; set status to **In Progress**
- [ ] Identify the alert source (which game service triggered it):
  - `matchmaking` → likely bot in ranked queues
  - `game-host` → likely exploit or cheat engine on a game server
  - `api-gateway` → likely scripted API abuse / account farming
- [ ] Check Elasticsearch for abnormal activity patterns from the flagged account(s):
  ```
  GET /game-logs-*/_search
  { "query": { "match": { "account_id": "<account_id>" } }, "size": 100 }
  ```
  Look for: superhuman action timing, repeated identical inputs, impossible win rates
- [ ] Enrich any associated IP addresses:
  ```bash
  python3 cortex-automation/tosin/scripts/enrich_alert.py <ip> --pretty --out /tmp/enrich.json
  python3 cortex-automation/tosin/scripts/categorise_incident.py --in /tmp/enrich.json --pretty
  ```
- [ ] **If single account, no economy impact, Low score → warn account, document, close**
- [ ] **If coordinated / High score → escalate to L2, continue Phase 2**

---

## Phase 2 — Containment (15–60 min)

**Analyst: L2 / Incident Lead**

- [ ] **Suspend all confirmed bot/cheat accounts** (do not permanently ban yet — preserve for investigation)
- [ ] If matchmaking is actively affected: notify game ops to temporarily pause ranked queues
- [ ] If an exploit is being actively abused:
  - [ ] Identify the vulnerable endpoint from Elasticsearch logs
  - [ ] Coordinate with the game dev team to disable or rate-limit the endpoint immediately
  - [ ] Do NOT patch in production without dev sign-off — document the vulnerability in TheHive
- [ ] Freeze affected accounts' in-game economies (prevent withdrawal of exploited resources)
- [ ] Search for related accounts by shared IP, device fingerprint, or referral chain

---

## Phase 3 — Investigation (1–8 hrs)

**Analyst: L2**

- [ ] Determine the scope:
  - How many accounts are involved?
  - How long has the activity been occurring?
  - What is the estimated economy impact (items/currency gained)?
- [ ] Pull full action logs for all confirmed bot accounts from Elasticsearch
- [ ] Identify the botnet C2 or automation tool if possible:
  - Check user agent strings for known bot frameworks
  - Check IP ranges against MISP and AbuseIPDB via `enrich_alert.py`
- [ ] Check if the exploit/cheat has been shared publicly (game forums, Discord, cheat sites)
  - If yes: elevate severity — assume widespread exploitation
- [ ] Document all findings and IOCs in the TheHive case
- [ ] Add IP addresses and account identifiers to MISP as observables if novel

---

## Phase 4 — Eradication & Recovery (8–48 hrs)

**Analyst: L2 + Game Ops + Dev Team**

- [ ] **Permanently ban** confirmed bot/cheat accounts after investigation is complete
- [ ] Roll back economy changes caused by the exploit (coordinate with game ops team)
- [ ] Deploy a patch or mitigation for any exploited vulnerability (dev team leads)
- [ ] Re-enable ranked queues or affected game modes once containment is confirmed
- [ ] Review and tighten rate limits on the affected API endpoint
- [ ] Update the IOC watchlist (`automation/scripts/ioc_watchlist_check.py`) with new bot IP ranges

---

## Phase 5 — Post-Incident (within 5 days)

**Owner: SOC Manager + Game Integrity Team**

- [ ] Complete post-incident review in TheHive
- [ ] Quantify the economy impact for management reporting
- [ ] If a new cheat signature was identified: add detection rule to the game anti-cheat system
- [ ] Review matchmaking anomaly detection thresholds — do they need adjusting?
- [ ] Update this playbook with new attack patterns observed

---

## Escalation Matrix

| Condition | Escalate to | Method |
|-----------|-------------|--------|
| Active exploit causing economy damage | SOC Manager + Game Dev Lead | Phone |
| > 1,000 accounts suspected | SOC Manager | Slack |
| Coordinated attack with external C2 | SOC Manager + Legal | Phone |
| Game server stability affected | Infrastructure Lead | Phone |

---

## Game-Specific Indicators of Bot Activity

| Indicator | What to look for in logs |
|-----------|--------------------------|
| Superhuman timing | Action intervals < 50ms consistently |
| Pattern repetition | Identical input sequences repeated > 100× |
| Impossible win rates | Win rate > 95% over 500+ games |
| Economy farming | Resource gain rate 10× the 99th percentile |
| Session anomalies | 20+ hour unbroken sessions |
| Geographic impossibility | Location change > 500 miles within 10 minutes |

---

## Key IOC Types to Collect

- Bot account IDs and usernames
- Source IP addresses and ASN
- User agent strings of automation tools
- Exploited API endpoints
- Timestamps of abnormal activity bursts

---

## Related Playbooks

- [PB-001 Account Compromise](account-compromise-playbook.md)
- [PB-003 Social Engineering](social-engineering-playbook.md)

---

## Revision History

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-04 | Initial version |
