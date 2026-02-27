# Cortex Deployment (Tosin)

## Description
Cortex 3 deployed via Docker and integrated with TheHive 5.

## Deployment Steps

cd infrastructure/cortex
docker compose up -d

## Integration
- Connected to TheHive via API key
- Verified analyzers:
  - VirusTotal_GetReport_3_1
  - AbuseIPDB_1_1
  - IPInfo_Details_1_0

## Validation
curl http://cortex-app:9001/api/status
