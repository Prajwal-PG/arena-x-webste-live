#!/usr/bin/env bash
# ==============================================================================
# ARENA X 2026 // Automated Online SQLite Database Backup Script
# Performs non-blocking atomic backup of WAL database and prunes old archives
# Run manually or via cron: sudo bash deploy/backup_database.sh
# ==============================================================================

set -euo pipefail

DB_PATH="/var/www/arena_x/data/arena_x.db"
BACKUP_DIR="/var/backups/arena_x"
LOG_FILE="/var/log/arena_x/backup.log"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/arena_x_${TIMESTAMP}.db"

mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_msg "[START] Initiating online database backup..."

if [ ! -f "$DB_PATH" ]; then
    log_msg "[WARN] Database file $DB_PATH not found. Skipping backup."
    exit 0
fi

# Ensure sqlite3 CLI is installed
if ! command -v sqlite3 &> /dev/null; then
    apt-get update -y && apt-get install -y sqlite3
fi

# Execute atomic non-blocking online backup using SQLite's backup API
sqlite3 "$DB_PATH" ".backup '${BACKUP_FILE}'"

# Secure backup permissions
chmod 600 "$BACKUP_FILE"
chown root:root "$BACKUP_FILE"

FILE_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
log_msg "[SUCCESS] Backup completed: ${BACKUP_FILE} (Size: ${FILE_SIZE})"

# Prune archives older than 14 days
log_msg "[CLEANUP] Pruning database backups older than 14 days..."
find "$BACKUP_DIR" -type f -name "arena_x_*.db" -mtime +14 -exec rm -f {} \; -exec echo "Deleted old backup: {}" >> "$LOG_FILE" \;

log_msg "[COMPLETE] Backup task finished cleanly."
