# Catnip Games International — SOC Platform

Prototype Security Operations Centre platform for Catnip Games International, built to support the launch of their first major multiplayer game.

## Platform Overview

| Component | Purpose | Port |
|-----------|---------|------|
| TheHive | Case & incident management | (Need to edit) |
| MISP | Threat intelligence sharing | (Need to edit) |
| Cortex | Automated analysis & response | (Need to edit) |
| Elasticsearch | Log storage & search | (Need to edit) |
| Kibana | Log visualisation & dashboards | (Need to edit) |

## Repository Structure

```
catnip-soc-platform/
├── .github/                    # GitHub templates and workflows
├── docs/                       # Architecture, procedures, runbooks
├── thehive/                    # TheHive config, roles, dashboards
├── misp/                       # MISP feeds, taxonomies, templates
├── cortex-automation/          # Cortex analysers and responders
├── infrastructure-cortex       # Deployment of Cortex
├── python-automation/          # Python scripts and alert enrichment
├── elasticsearch/              # Index templates and retention policies
├── playbooks/                  # Incident response playbooks
├── metrics/                    # KPI definitions and reporting
└── tests/                      # Integration and smoke tests
```

## Quick Start

1. Clone this repository onto your VM
2. Follow `docs/architecture/deployment-guide.md`
3. Run `automation/scripts/health_check.sh` to verify all services

## Team Roles

| Role | Owner | Key Deliverables |
|------|-------|-----------------|
| Infrastructure & Deployment | TBC | VM setup, Docker, service config |
| Incident Response Lead | TBC | Playbooks, escalation procedures |
| MISP & Threat Intelligence | TBC | IOC feeds, intelligence sharing |
| Cortex & Automation | TBC | Analysers, automated workflows |
| Platform Reliability & Git | TBC | Backup/recovery, repo, user roles, alert enrichment |
| Metrics & Reporting | TBC | KPI dashboard, response time tracking |

## Non-Functional Requirements

- Alert triage: ≤ 15 minutes
- Alert throughput: 1,000 alerts/day
- Intelligence sharing latency: < 5 minutes
- Concurrent incidents supported: 100
- Availability: 24/7

## Branching Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, demo-ready code only |
| `develop` | Integration branch for all features |
| `feature/<name>` | Individual feature development |
| `hotfix/<name>` | Urgent fixes to main |

## Commit Convention

```
<type>(<scope>): <short description>

Types: feat, fix, docs, config, test, chore
Example: feat(thehive): add account-compromise custom fields
```

## Licence

Internal use only — Catnip Games International SOC Team.
