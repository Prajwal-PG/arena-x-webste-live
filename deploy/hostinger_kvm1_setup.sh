#!/usr/bin/env bash
# ==============================================================================
# ARENA X 2026 // Turnkey Production Deployment for Hostinger KVM 1 (Ubuntu)
# Run with: sudo bash deploy/hostinger_kvm1_setup.sh
# ==============================================================================

set -euo pipefail

echo "======================================================================"
echo "  ARENA X 2026 // HOSTINGER KVM 1 AUTOMATED PROVISIONING SCRIPT"
echo "======================================================================"

# 1. Update OS packages & install core dependencies
echo "[1/8] Updating system packages & installing core software..."
apt-get update -y && apt-get upgrade -y
apt-get install -y python3 python3-pip python3-venv python3-dev build-essential \
    nginx ufw curl git redis-server sqlite3 fail2ban \
    libjpeg-dev zlib1g-dev libffi-dev libssl-dev

# 2. Configure & Start Redis Server
echo "[2/8] Configuring Redis shared rate-limiter..."
systemctl enable redis-server
systemctl restart redis-server

# 3. Setup project directories & permissions
echo "[3/8] Configuring application paths..."
APP_DIR="/var/www/arena_x"
LOG_DIR="/var/log/arena_x"
BACKUP_DIR="/var/backups/arena_x"

mkdir -p "$APP_DIR" "$LOG_DIR" "$BACKUP_DIR" "$APP_DIR/data" "$APP_DIR/uploads"
chown -R www-data:www-data "$APP_DIR" "$LOG_DIR"
chmod 750 "$APP_DIR"
chmod 770 "$APP_DIR/data" "$APP_DIR/uploads"
chmod 700 "$BACKUP_DIR"

# 4. Setup Python Virtual Environment
echo "[4/8] Setting up Python virtual environment..."
if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
if [ -f "$APP_DIR/requirements.txt" ]; then
    "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
fi

# 5. Install systemd service
echo "[5/8] Registering systemd service..."
if [ -f "$APP_DIR/deploy/arena_x.service" ]; then
    cp "$APP_DIR/deploy/arena_x.service" /etc/systemd/system/arena_x.service
    systemctl daemon-reload
    systemctl enable arena_x.service
    systemctl restart arena_x.service
fi

# 6. Configure Nginx
echo "[6/8] Configuring Nginx reverse proxy..."
if [ -f "$APP_DIR/deploy/cloudflare_nginx.conf" ]; then
    cp "$APP_DIR/deploy/cloudflare_nginx.conf" /etc/nginx/sites-available/arena_x
    ln -sf /etc/nginx/sites-available/arena_x /etc/nginx/sites-enabled/arena_x
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl restart nginx
fi

# 7. Setup Automated Database Backup Cron
echo "[7/8] Configuring automated daily database backup cron..."
if [ -f "$APP_DIR/deploy/backup_database.sh" ]; then
    chmod +x "$APP_DIR/deploy/backup_database.sh"
    cat << 'CRONEOF' > /etc/cron.d/arena_x_backup
# ARENA X 2026 Nightly WAL Database Backup at 03:00 AM
0 3 * * * root /bin/bash /var/www/arena_x/deploy/backup_database.sh > /dev/null 2>&1
CRONEOF
    chmod 644 /etc/cron.d/arena_x_backup
fi

# 8. Apply Cloudflare Origin Firewall (UFW)
echo "[8/8] Applying Cloudflare origin firewall (UFW)..."
if [ -f "$APP_DIR/deploy/setup_cloudflare_firewall.sh" ]; then
    chmod +x "$APP_DIR/deploy/setup_cloudflare_firewall.sh"
    bash "$APP_DIR/deploy/setup_cloudflare_firewall.sh"
fi

# Verification
echo "======================================================================"
echo "[VERIFICATION SUMMARY]"
systemctl is-active --quiet redis-server && echo "  [OK] Redis Server: RUNNING" || echo "  [WARN] Redis Server not active"
systemctl is-active --quiet arena_x.service && echo "  [OK] ARENA X Gunicorn: RUNNING" || echo "  [WARN] ARENA X service not active"
systemctl is-active --quiet nginx && echo "  [OK] Nginx Web Server: RUNNING" || echo "  [WARN] Nginx not active"
echo "======================================================================"
echo "  Hostinger KVM 1 Server Setup Finished Successfully!"
echo "  Run: python deploy/generate_production_keys.py to generate your .env"
echo "======================================================================"
