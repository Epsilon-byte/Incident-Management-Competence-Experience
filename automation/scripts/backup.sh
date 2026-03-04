#!/bin/bash
# =============================================================
# Catnip Games SOC Platform — Automated Backup Script
# Owner: Platform Reliability
# Schedule: Nightly via cron (see docs/runbooks/backup-recovery.md)
# =============================================================

set -euo pipefail

# --- Configuration ---
BACKUP_ROOT="/opt/backups"
DATE=$(date +%Y-%m-%d)
RETENTION_DAYS=30
LOG_FILE="/var/log/soc-backup.log"

THEHIVE_DATA="/opt/thehive/data"
MISP_ATTACHMENTS="/var/www/MISP/app/files"
MISP_DB_USER="misp"
MISP_DB_NAME="misp"

ES_HOST="localhost:9200"
ES_SNAPSHOT_REPO="soc_backup"

# --- Colour output ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
success() { log "${GREEN}[OK]${NC} $1"; }
warn() { log "${YELLOW}[WARN]${NC} $1"; }
fail() { log "${RED}[FAIL]${NC} $1"; exit 1; }

# --- Create backup directories ---
mkdir -p "$BACKUP_ROOT"/{thehive,misp,elasticsearch}

log "========================================"
log "SOC Platform Backup — $DATE"
log "========================================"

# --- 1. TheHive Backup ---
log "Backing up TheHive data..."
if [ -d "$THEHIVE_DATA" ]; then
    tar -czf "$BACKUP_ROOT/thehive/thehive-${DATE}.tar.gz" -C "$(dirname $THEHIVE_DATA)" "$(basename $THEHIVE_DATA)"
    success "TheHive backup complete → thehive-${DATE}.tar.gz"
else
    warn "TheHive data directory not found at $THEHIVE_DATA — skipping"
fi

# --- 2. MISP Database Backup ---
log "Backing up MISP database..."
if mysqladmin -u "$MISP_DB_USER" status > /dev/null 2>&1; then
    mysqldump -u "$MISP_DB_USER" "$MISP_DB_NAME" > "$BACKUP_ROOT/misp/misp-${DATE}.sql"
    gzip -f "$BACKUP_ROOT/misp/misp-${DATE}.sql"
    success "MISP database backup complete → misp-${DATE}.sql.gz"
else
    warn "MySQL not accessible — skipping MISP database backup"
fi

# --- 3. MISP Attachments Backup ---
log "Backing up MISP attachments..."
if [ -d "$MISP_ATTACHMENTS" ]; then
    tar -czf "$BACKUP_ROOT/misp/misp-attachments-${DATE}.tar.gz" -C "$(dirname $MISP_ATTACHMENTS)" "$(basename $MISP_ATTACHMENTS)"
    success "MISP attachments backup complete → misp-attachments-${DATE}.tar.gz"
else
    warn "MISP attachments directory not found — skipping"
fi

# --- 4. Elasticsearch Snapshot ---
log "Taking Elasticsearch snapshot..."
ES_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://$ES_HOST")
if [ "$ES_RESPONSE" = "200" ]; then
    curl -s -X PUT "http://$ES_HOST/_snapshot/$ES_SNAPSHOT_REPO/snapshot-${DATE}" \
        -H "Content-Type: application/json" \
        -d '{"indices": "*", "ignore_unavailable": true, "include_global_state": false}' \
        >> "$LOG_FILE"
    success "Elasticsearch snapshot initiated → snapshot-${DATE}"
else
    warn "Elasticsearch not responding (HTTP $ES_RESPONSE) — skipping snapshot"
fi

# --- 5. Prune Old Backups ---
log "Pruning backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_ROOT" -type f \( -name "*.tar.gz" -o -name "*.sql.gz" \) -mtime +$RETENTION_DAYS -delete
success "Old backups pruned"

# --- Summary ---
log "========================================"
log "Backup complete. Files in $BACKUP_ROOT:"
find "$BACKUP_ROOT" -name "*${DATE}*" | while read f; do
    SIZE=$(du -sh "$f" | cut -f1)
    log "  $SIZE  $f"
done
log "========================================"
