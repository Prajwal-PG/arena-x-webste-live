#!/usr/bin/env bash
# ==============================================================================
# ARENA X 2026 // Automated Online SQLite Database Backup Script
# Performs non-blocking atomic backup of WAL database, compresses archives,
# prunes old backups (14-day retention), and supports optional off-server sync.
# Run manually or via cron: sudo bash deploy/backup.sh
# ==============================================================================

set -euo pipefail

DB_PATH="/var/www/arena_x/data/arena_x.db"
BACKUP_DIR="/var/backups/arena_x"
LOG_FILE="/var/log/arena_x/backup.log"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RAW_BACKUP="${BACKUP_DIR}/arena_x_${TIMESTAMP}.db"
COMPRESSED_BACKUP="${RAW_BACKUP}.gz"

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
sqlite3 "$DB_PATH" ".backup '${RAW_BACKUP}'"

# Compress archive to save disk space on KVM 1
gzip -9 "$RAW_BACKUP"

# Secure backup permissions
chmod 600 "$COMPRESSED_BACKUP"
chown root:root "$COMPRESSED_BACKUP"

FILE_SIZE=$(du -h "$COMPRESSED_BACKUP" | cut -f1)
log_msg "[SUCCESS] Atomic backup created: ${COMPRESSED_BACKUP} (Size: ${FILE_SIZE})"

# Optional Off-Server Sync (Configured via environment or rclone/scp)
if [ -n "${BACKUP_REMOTE_DEST:-}" ]; then
    log_msg "[SYNC] Transferring backup to remote off-server storage: ${BACKUP_REMOTE_DEST}..."
    if command -v rclone &> /dev/null; then
        rclone copy "$COMPRESSED_BACKUP" "$BACKUP_REMOTE_DEST"
        log_msg "[SYNC] Remote off-server sync completed successfully via rclone."
    elif command -v scp &> /dev/null; then
        scp -q "$COMPRESSED_BACKUP" "$BACKUP_REMOTE_DEST"
        log_msg "[SYNC] Remote off-server sync completed successfully via scp."
    fi
fi

# Prune archives older than 14 days
log_msg "[CLEANUP] Pruning local backups older than 14 days..."
find "$BACKUP_DIR" -type f -name "arena_x_*.db.gz" -mtime +14 -exec rm -f {} \; -exec echo "Deleted old backup: {}" >> "$LOG_FILE" \;

log_msg "[COMPLETE] Backup task finished cleanly."
