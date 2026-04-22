# 🔐 MISP–TheHive–Cortex Integration & Incident Workflow
### SOC Prototype | Catnip Games International | April 2026

> **Role:** Integration Testing, Incident Handling & Workflow Validation  
> **Platform:** TheHive 5.6 · MISP 2.5.32 · Cortex  
> **Status:** ✅ Successfully Validated End-to-End

---

## 📋 Table of Contents

- [Objective](#objective)
- [System Architecture](#system-architecture)
- [What I Did](#what-i-did)
- [Evidence — Screenshots](#evidence--screenshots)
- [Key Finding: MISP Publish Requirement](#key-finding-misp-publish-requirement)
- [Incident Cases Handled](#incident-cases-handled)
- [Cortex Enrichment Results](#cortex-enrichment-results)
- [SOC Dashboard Metrics](#soc-dashboard-metrics)
- [Skills Demonstrated](#skills-demonstrated)
- [Conclusion](#conclusion)

---

## Objective

My role in the SOC prototype was to ensure the **threat intelligence and incident response pipeline** functions correctly end-to-end. This involved:

- Verifying that **MISP events are ingested into TheHive as alerts**
- Converting alerts into **incident cases** and initiating the workflow
- Validating that **observables are extracted** and enriched via Cortex
- Confirming that analyst decisions can be made based on enrichment output

This work aligns with the **Cyber Defence Analyst** function — specifically incident triage, alert handling, and threat analysis workflow.

---

## System Architecture

```
MISP (Threat Intelligence)
        │
        │  API / Event Ingestion
        ▼
  TheHive (Incident Management)
        │
        │  Observable Analysis
        ▼
   Cortex (Automated Enrichment)
        │
        │  Results (VirusTotal, AbuseIPDB, IPInfo, ThreatIntelAnalyzer)
        ▼
  Analyst Decision → Case Closed / Escalated
        │
        ▼
  SOC Dashboard (Catnip Games — localhost:5050)
```

> MISP deployment and Cortex analyzer development were handled by other team members.  
> My focus: **integration validation, incident workflow, and end-to-end testing.**

---

## What I Did

### 1. MISP → TheHive Integration Testing
- Configured and verified the API connection between MISP and TheHive
- Discovered and resolved a critical workflow issue *(see Key Finding below)*
- Confirmed that MISP event metadata — including TLP, severity, and tags — transfers correctly into TheHive alerts

### 2. Incident Handling in TheHive
- Imported MISP-generated alerts into TheHive
- Converted alerts into structured **incident cases**
- Verified automatic **observable extraction** (IP addresses, domains)
- Assigned cases and initiated the analyst workflow

### 3. Investigation Workflow Validation
- Accessed observables within active cases
- Triggered enrichment analyzers via **Cortex** (VirusTotal, AbuseIPDB, IPInfo, ThreatIntelAnalyzer)
- Interpreted enrichment results to determine risk level and threat classification
- Closed cases with documented decisions (e.g., FalsePositive for benign domain)

---

## Evidence — Screenshots

### SOC Dashboard Overview
> Catnip Games — Security Operations Centre Dashboard (`localhost:5050`)

![SOC Dashboard](screenshots/soc_dashboard.png)

| Metric | Value |
|--------|-------|
| Active Incidents | 10 open cases in TheHive |
| Threat Events | 2 published events from MISP |
| IOC Count | 3 tracked indicators |
| Completed Jobs | 44 successful Cortex analytics jobs |

---

### TheHive — Cases List
> 12 total cases at time of capture (`localhost:9000/cases`)

![Cases List](screenshots/thehive_cases_list.png)

Key cases visible:
- **#12** — activity case (New · Medium · linked to MISP event)
- **#11** — suspicious login (FalsePositive · Medium · resolved)
- **#10** — SOC TEST - Dashboard Validation
- **#9** — Suspicious Login Activity

---

### Case #12 — Activity Case (Linked to MISP)
> Demonstrates successful MISP → TheHive ingestion

![Case 12 Details](screenshots/case12_activity.png)

- Case linked to MISP event: `https://misp-core/events/5`
- Description: `unauthorized activity`
- Tag: `risk:low`
- Status: **New** (active investigation)
- Created by: SOC Analyst · 15/04/2026 11:11

---

### Case #11 — Suspicious Login (Full Workflow)
> Demonstrates complete investigation from alert to closure

![Case 11 Observables](screenshots/case11_observables.png)

**Observable extracted:** `google[.]com` (domain)  
**Enrichment tags returned:**
- `VT:GetReport="0/94"` — 0 detections out of 94 vendors
- `VT:GetReport="200 resolution(s)"` — valid domain with resolutions
- `CustomThreatIntel:Classification` — classified via custom analyzer
- `CustomThreatIntel:Risk="Low"` — low risk assessment

**Decision:** Marked as `benign` → Case closed as **FalsePositive**

---

### Case #11 — Time Metrics
> Evidence of detection and response timing

![Case 11 Time Metrics](screenshots/case11_time_metrics.png)

| Metric | Value |
|--------|-------|
| Detection | **50 seconds** |
| Triage | **11 minutes, 46 seconds** |
| Acknowledge | **12 minutes, 36 seconds** |

---

### Case #11 — Export to MISP
> Demonstrates bidirectional MISP integration (TheHive → MISP)

![Export to MISP](screenshots/case11_export_misp.png)

- MISP server `misp-lab (2.5.32)` shown as **Available**
- TheHive can export resolved case data back to MISP for intelligence sharing

---

### MISP — Event #4
> Phishing campaign threat intelligence created in MISP

![MISP Event 4](screenshots/misp_event4.png)

- **Event:** Phishing campaign targeting finance department — April 2026
- **Org:** Catnip Games International
- **Threat Level:** High
- **Analysis:** Ongoing
- **Date:** 2026-04-15

---

### Cortex — Analyzer Jobs (IP: 1.2.3.4)
> Multiple analyzers run successfully on the same observable

![Cortex Jobs IP](screenshots/cortex_jobs_ip.png)

Analyzers executed:
- `VirusTotal_GetReport_3_1` — **Success**
- `AbuseIPDB_2_0` — **Success**
- `ThreatIntelAnalyzer_1_0` — **Success**
- `IPInfo_Details_1_0` — **Success**

---

### Cortex — Analyzer Jobs (IP: 8.8.8.8)
> Shows real-world test with mixed results (success and failure)

![Cortex Jobs 8.8.8.8](screenshots/cortex_jobs_8888.png)

- Majority of jobs: **Success**
- One job: **Failure** (ThreatIntelAnalyzer — API/config issue, documented)
- Demonstrates real testing — not just cherry-picked results

---

## Key Finding: MISP Publish Requirement

> ⚠️ **Critical discovery during integration testing**

During initial testing, MISP events were **not appearing in TheHive** despite the API connection being correctly configured.

**Root Cause Identified:**  
MISP events must be explicitly **Published** before they can be ingested by TheHive. Events that are created but left in draft/unpublished state are invisible to the integration.

**Resolution:**  
Published the MISP events using the `Publish Event` action. Alerts immediately appeared in TheHive with all metadata (TLP, severity, tags) correctly preserved.

**Impact:**  
This finding is critical for anyone setting up MISP–TheHive integration. It is not clearly documented in default configuration guides and was identified through systematic troubleshooting.

---

## Incident Cases Handled

| Case # | Title | Status | Observables | Decision |
|--------|-------|--------|-------------|----------|
| #12 | activity case | New | 1 (IP) | Under investigation |
| #11 | suspicious login | FalsePositive | 1 (domain: google.com) | Closed — benign |
| #10 | SOC TEST - Dashboard Validation | New | 0 | Testing |
| #9 | Suspicious Login Activity | New | 0 | Pending |
| #8 | #2 Malicious IP Test | New | — | Testing |

All cases linked to MISP events where applicable. Observable extraction confirmed working automatically.

---

## Cortex Enrichment Results

### Analyzers Used

| Analyzer | Purpose | Result |
|----------|---------|--------|
| `VirusTotal_GetReport_3_1` | Check IP/domain against 94 AV vendors | Success |
| `AbuseIPDB_2_0` | Check IP abuse reports and confidence score | Success |
| `ThreatIntelAnalyzer_1_0` | Custom threat intelligence lookup | Success / Failure (API) |
| `IPInfo_Details_1_0` | Geolocation and ASN info for IPs | Success |

### Sample Result — Case #11 (domain: google.com)
```
VT:GetReport        → 0/94 detections     (CLEAN)
VT:Resolution       → 200 valid resolutions (LEGITIMATE DOMAIN)
CustomThreatIntel   → Risk: Low, Classification: Benign
Decision            → FalsePositive — case closed
```

---

## SOC Dashboard Metrics

The Catnip Games SOC Dashboard (`localhost:5050`) aggregates data from TheHive, MISP, and Cortex in real time.

At the time of capture:

```
Active Incidents  → 10   (open TheHive cases)
Threat Events     → 2    (published MISP events)
IOC Count         → 3    (tracked indicators)
Completed Jobs    → 44   (Cortex analysis jobs)
```

**Charts visible:**
- **Incident Severity** — donut chart (Critical / High / Medium / Low split)
- **Job Status** — donut chart (Success / Failure / Running)
- **Threat Timeline** — published MISP events over time
- **Top Analyzers** — most-used Cortex analyzers by job count

---

## Skills Demonstrated

| Skill | Evidence |
|-------|---------|
| MISP–TheHive API integration | Cases linked to MISP events (Case #12) |
| Incident triage and case management | 12 cases handled across multiple severity levels |
| Observable extraction and analysis | domain/IP observables in Case #11, #12 |
| Cortex analyzer execution | 44 completed jobs across 4 analyzer types |
| Threat classification | FalsePositive decision on Case #11 with evidence |
| Troubleshooting and problem-solving | MISP publish issue identified and resolved |
| Bidirectional MISP integration | Export to MISP confirmed available |
| SOC dashboard interpretation | Live metrics from unified dashboard |

---

## Conclusion

The integration and testing confirm that the **SOC platform is operational** and capable of supporting real incident response activities. 

My contribution ensured that:

1. ✅ **MISP → TheHive ingestion** works correctly when events are published
2. ✅ **Alerts are converted into cases** with observable extraction
3. ✅ **Cortex enrichment** provides actionable analysis results
4. ✅ **Analyst decisions** can be made and documented with evidence
5. ✅ **Bidirectional MISP integration** allows exporting resolved cases back

> The workflow between MISP, TheHive, and Cortex functions correctly and supports effective threat analysis for Catnip Games International.

---


---

*Catnip Games International | SOC Prototype Project | April 2026*  
*Role: Integration Testing & Incident Workflow Validation*
