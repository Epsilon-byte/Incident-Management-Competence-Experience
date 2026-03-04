# Backup & Recovery Runbook
**Owner:** Platform Reliability  
**Last Updated:** 2026-04  
**Review Cycle:** Monthly

---

## Scope

This runbook covers automated backup and recovery procedures for all SOC platform components:
- TheHive (case data, attachments, configuration)
- MISP (threat intelligence database, event attachments)
- Elasticsearch (log indices, alert history)
- Cortex (analyser configuration)

---

## Backup Schedule

| Component | Frequency | Retention | Method |
|-----------|-----------|-----------|--------|
| TheHive data | Nightly 02:00 | 30 days | tar + rsync |
| MISP database | Nightly 02:30 | 30 days | mysqldump |
| MISP attachments | Nightly 02:45 | 30 days | tar + rsync |
| Elasticsearch | Nightly 03:00 | 14 days | Snapshot API |
| All configs | On every change | 90 days | Git (this repo) |

---

## Automated Backup Script

Location: `automation/scripts/backup.sh`

The backup script runs via cron on the host VM. To verify it is scheduled:

```bash
crontab -l | grep backup
```

Expected output:
```
0 2 * * * /opt/catnip-soc/automation/scripts/backup.sh >> /var/log/soc-backup.log 2>&1
```

To run a manual backup at any time:
```bash
sudo /opt/catnip-soc/automation/scripts/backup.sh
```

---

## Recovery Procedures

### TheHive Recovery

1. Stop TheHive service:
   ```bash
   sudo systemctl stop thehive
   ```

2. Restore data directory from backup:
   ```bash
   sudo tar -xzf /opt/backups/thehive/thehive-YYYY-MM-DD.tar.gz -C /opt/thehive/
   ```

3. Restore Elasticsearch indices (TheHive uses ES as its backend):
   ```bash
   # See Elasticsearch recovery section below
   ```

4. Restart TheHive:
   ```bash
   sudo systemctl start thehive
   sudo systemctl status thehive
   ```

5. Verify: Log in to TheHive UI at http://localhost:9000 and confirm cases are present.

---

### MISP Recovery

1. Stop MISP:
   ```bash
   sudo systemctl stop apache2
   ```

2. Restore database:
   ```bash
   mysql -u misp -p misp < /opt/backups/misp/misp-YYYY-MM-DD.sql
   ```

3. Restore attachments:
   ```bash
   sudo tar -xzf /opt/backups/misp/misp-attachments-YYYY-MM-DD.tar.gz -C /var/www/MISP/app/files/
   ```

4. Restart MISP:
   ```bash
   sudo systemctl start apache2
   ```

5. Verify: Log in to MISP and confirm events and feeds are present.

---

### Elasticsearch Recovery

1. Check available snapshots:
   ```bash
   curl -X GET "localhost:9200/_snapshot/soc_backup/_all?pretty"
   ```

2. Restore from snapshot:
   ```bash
   curl -X POST "localhost:9200/_snapshot/soc_backup/SNAPSHOT_NAME/_restore" \
     -H "Content-Type: application/json" \
     -d '{"indices": "*", "ignore_unavailable": true}'
   ```

3. Verify cluster health:
   ```bash
   curl -X GET "localhost:9200/_cluster/health?pretty"
   ```

---

## Health Check

Run the platform health check script to verify all services after recovery:

```bash
bash automation/scripts/health_check.sh
```

Expected output when all services are healthy:
```
[OK] TheHive     — responding on :9000
[OK] Cortex      — responding on :9001
[OK] Elasticsearch — responding on :9200
[OK] Kibana      — responding on :5601
[OK] MISP        — responding on :443
```

---

## Backup Verification

Backups should be tested monthly. To verify a backup is restorable:

1. Spin up a test VM (or Docker container)
2. Follow the recovery procedure above using the most recent backup
3. Run `health_check.sh` to confirm services start cleanly
4. Log the test result in `docs/procedures/backup-test-log.md`

---

## Escalation

If backup or recovery fails:

| Issue | Action |
|-------|--------|
| Script fails silently | Check `/var/log/soc-backup.log` |
| Elasticsearch snapshot fails | Check disk space with `df -h` |
| MISP database restore fails | Verify MySQL service is running |
| Recovery still fails | Escalate to Infrastructure lead |
