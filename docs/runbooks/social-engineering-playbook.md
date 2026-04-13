# Playbook: Social Engineering
**ID:** PB-003  
**Owner:** Incident Response Lead  
**Linked alert category:** `Social Engineering`  
**Triggered by:** `alert_enrichment.py` when title contains: `social`, `phish`, `impersonat`  
**Last Updated:** 2026-04  
**Review Cycle:** Quarterly

---

## Overview

This playbook covers phishing attacks targeting Catnip Games players or staff, brand impersonation (fake Catnip Games support accounts), and in-game social engineering (players manipulating other players into sharing credentials or items). These incidents often precede account compromises and should be treated as high-priority even when no account breach has yet occurred.

**SLA target:** Triage within 15 minutes of alert creation.

---

## Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Staff credentials targeted; active phishing site harvesting player logins at scale |
| **High** | Confirmed phishing domain with active traffic; brand impersonation with wide reach |
| **Medium** | Phishing link reported by single player; impersonation account with limited followers |
| **Low** | Suspicious message reported but no malicious link confirmed |

Use `enrich_alert.py` to check any domain/URL against VirusTotal before classifying.

---

## Phase 1 — Detection & Triage (0–15 min)

**Analyst: L1**

- [ ] Acknowledge alert in TheHive; set status to **In Progress**
- [ ] Identify the attack vector:
  - **In-game chat** → player reported a suspicious link or message
  - **Email** → phishing email targeting player or staff
  - **External platform** → fake social media / Discord / forum account impersonating Catnip Games
- [ ] Enrich any URLs or domains reported:
  ```bash
  python3 cortex-automation/tosin/scripts/enrich_alert.py "https://suspicious-site.com" --pretty --out /tmp/enrich.json
  python3 cortex-automation/tosin/scripts/categorise_incident.py --in /tmp/enrich.json --pretty
  ```
- [ ] Check the domain/URL in MISP for prior intelligence
- [ ] **If no malicious indicators → document, monitor, close as Low**
- [ ] **If domain is confirmed malicious or impersonating Catnip → continue Phase 2**

---

## Phase 2 — Containment (15–45 min)

**Analyst: L2 / Incident Lead**

**For phishing domains/URLs:**
- [ ] Submit the domain for takedown via domain registrar abuse contact
  - Use WHOIS to identify registrar: `whois <domain>`
  - Most registrars have an abuse form at `abuse.<registrar>.com`
- [ ] Block the domain at the DNS/proxy level for all Catnip internal systems
- [ ] If the phishing site is cloning the Catnip Games login page: alert the player communications team to issue an in-game warning
- [ ] Submit domain to Google Safe Browsing and Microsoft SmartScreen via their reporting portals

**For in-game social engineering:**
- [ ] Identify the offending player account(s) from the report
- [ ] Review the chat logs in Elasticsearch for the reported conversation
- [ ] Suspend the offending account pending investigation

**For brand impersonation on external platforms:**
- [ ] Report the impersonating account via the platform's abuse process
  - Discord: Trust & Safety form
  - Reddit: report + message r/[subreddit] moderators
  - Twitter/X: impersonation report
- [ ] Document the impersonating account URL as a TheHive observable

---

## Phase 3 — Investigation (45 min – 4 hrs)

**Analyst: L2**

- [ ] Determine whether any player credentials were actually submitted to the phishing site
  - Check for account compromise alerts in the same timeframe (cross-reference PB-001)
  - Search Elasticsearch for unusual login activity from affected players
- [ ] Investigate the infrastructure behind the phishing domain:
  - WHOIS registration date (very recently registered = high suspicion)
  - Hosting provider / ASN — is it a known bulletproof hoster?
  - Are other phishing domains registered to the same registrant email?
- [ ] Add all phishing infrastructure to MISP:
  - Domain, IP, registrant email, hosting provider
- [ ] Check if staff email addresses were targeted (spear phishing):
  - If yes: immediately notify the SOC Manager and review email gateway logs
- [ ] Identify how the phishing link was distributed (in-game, email, Discord, etc.)

---

## Phase 4 — Eradication & Recovery (4–24 hrs)

**Analyst: L2 + Player Comms Team**

- [ ] Confirm the phishing domain has been taken down or is blocked
- [ ] If players submitted credentials: initiate account recovery for affected accounts (follow PB-001)
- [ ] Draft a player advisory if the phishing campaign was widespread:
  - Publish in-game notification: "We have identified a phishing campaign..."
  - Remind players: Catnip Games will never ask for passwords via chat, email, or Discord
- [ ] If a staff account was targeted: require password reset and MFA re-enrolment
- [ ] Push phishing IOCs to MISP for sharing with other game studios or threat intel partners

---

## Phase 5 — Post-Incident (within 5 days)

**Owner: SOC Manager**

- [ ] Close the TheHive case with full resolution notes
- [ ] Conduct a brief security awareness reminder for the game team if staff were targeted
- [ ] Review the phishing detection keyword list in `alert_enrichment.py` — add any new patterns observed
- [ ] Update MISP feed subscriptions if a new phishing kit or actor was identified

---

## Escalation Matrix

| Condition | Escalate to | Method |
|-----------|-------------|--------|
| Staff credentials harvested | SOC Manager + IT Director | Phone |
| > 50 players affected | SOC Manager + Player Comms | Slack |
| Active phishing site with live traffic | SOC Manager | Slack |
| Regulatory notification may be required | SOC Manager + Legal | Phone |

---

## Quick Reference: Takedown Contacts

| Registrar | Abuse Contact |
|-----------|--------------|
| Namecheap | abuse@namecheap.com |
| GoDaddy | abuse@godaddy.com |
| Cloudflare | abuse@cloudflare.com |
| Generic | abuse@[registrar domain] |

**Safe Browsing Reporting:**
- Google: https://safebrowsing.google.com/safebrowsing/report_phish/
- Microsoft: https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site

---

## Key IOC Types to Collect

- Phishing domain(s) and full URLs
- Hosting IP address(es)
- WHOIS registrant details
- Phishing email headers (if applicable)
- Impersonating account URLs
- Player accounts that reported or were targeted

---

## Related Playbooks

- [PB-001 Account Compromise](account-compromise-playbook.md) — often follows a successful phishing attack
- [PB-002 Bot Attack / Game Integrity](bot-attack-playbook.md)

---

## Revision History

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-04 | Initial version |
