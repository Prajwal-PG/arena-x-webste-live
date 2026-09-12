#!/usr/bin/env bash
# ==============================================================================
# ARENA X 2026 // Production Deployment Script for Hostinger KVM 1 (Ubuntu/Debian)
# Run with: sudo bash deploy/deploy.sh
# ==============================================================================

set -euo pipefail

echo "======================================================================"
echo "  ARENA X 2026 // PRODUCTION DEPLOYMENT ENGINE (HOSTINGER KVM 1)"
echo "======================================================================"

# 1. Update OS packages & install core dependencies
echo "[1/8] Updating system packages & installing core dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y
apt-get install -y python3 python3-pip python3-venv python3-dev build-essential \
    nginx ufw curl git redis-server sqlite3 fail2ban logrotate \
    libjpeg-dev zlib1g-dev libffi-dev libssl-dev

# 2. Configure & Harden Redis Server (Localhost only)
echo "[2/8] Configuring Redis shared rate-limiter (127.0.0.1 binding)..."
sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf || true
sed -i 's/^protected-mode no/protected-mode yes/' /etc/redis/redis.conf || true
systemctl enable redis-server
systemctl restart redis-server

# 3. Setup project directories & Least-Privilege Permissions
echo "[3/8] Applying least-privilege permissions structure..."
APP_DIR="/var/www/arena_x"
LOG_DIR="/var/log/arena_x"
BACKUP_DIR="/var/backups/arena_x"

mkdir -p "$APP_DIR" "$LOG_DIR" "$BACKUP_DIR" "$APP_DIR/data" "$APP_DIR/uploads"

# Least privilege: application code owned by root:www-data, read-only to web user
chown -R root:www-data "$APP_DIR"
find "$APP_DIR" -type d -exec chmod 750 {} +
find "$APP_DIR" -type f -exec chmod 640 {} +

# Runtime directories writable by www-data
chown -R www-data:www-data "$APP_DIR/data" "$APP_DIR/uploads" "$LOG_DIR"
chmod 770 "$APP_DIR/data" "$APP_DIR/uploads"
chmod 750 "$LOG_DIR"

# Restrict .env permissions if present
if [ -f "$APP_DIR/.env" ]; then
    chown root:www-data "$APP_DIR/.env"
    chmod 640 "$APP_DIR/.env"
fi

# Backups restricted to root
chown -R root:root "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# 4. Setup Python Virtual Environment
echo "[4/8] Configuring Python virtual environment..."
if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
if [ -f "$APP_DIR/requirements.txt" ]; then
    "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
fi

# 5. Register & Harden Systemd Service
echo "[5/8] Registering sandboxed systemd service..."
if [ -f "$APP_DIR/deploy/arena_x.service" ]; then
    cp "$APP_DIR/deploy/arena_x.service" /etc/systemd/system/arena_x.service
    systemctl daemon-reload
    systemctl enable arena_x.service
    systemctl restart arena_x.service
fi

# 6. Configure Nginx Reverse Proxy
echo "[6/8] Configuring Nginx reverse proxy..."
NGINX_CONF="$APP_DIR/deploy/nginx.conf"
if [ -f "$APP_DIR/deploy/cloudflare_nginx.conf" ] && [ -f "/etc/ssl/certs/cloudflare_origin.pem" ]; then
    NGINX_CONF="$APP_DIR/deploy/cloudflare_nginx.conf"
fi
cp "$NGINX_CONF" /etc/nginx/sites-available/arena_x
ln -sf /etc/nginx/sites-available/arena_x /etc/nginx/sites-enabled/arena_x
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

# 7. Setup Automated Daily Backup Cron & Logrotate
echo "[7/8] Configuring automated daily database backup and log rotation..."
if [ -f "$APP_DIR/deploy/backup.sh" ]; then
    chmod 750 "$APP_DIR/deploy/backup.sh"
    chown root:root "$APP_DIR/deploy/backup.sh"
    cat << 'CRONEOF' > /etc/cron.d/arena_x_backup
# ARENA X 2026 Daily WAL Database Backup at 03:00 AM UTC
0 3 * * * root /bin/bash /var/www/arena_x/deploy/backup.sh > /dev/null 2>&1
CRONEOF
    chmod 644 /etc/cron.d/arena_x_backup
fi

if [ -f "$APP_DIR/deploy/logrotate_arena_x" ]; then
    cp "$APP_DIR/deploy/logrotate_arena_x" /etc/logrotate.d/arena_x
    chmod 644 /etc/logrotate.d/arena_x
fi

# 8. Configure UFW Firewall (Only 22, 80, 443 permitted)
echo "[8/8] Hardening UFW firewall (Ports 22, 80, 443 only)..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP Web'
ufw allow 443/tcp comment 'HTTPS Secure Web'
# Ensure internal ports 5000, 6379 are NEVER open
ufw delete allow 5000 2>/dev/null || true
ufw delete allow 6379 2>/dev/null || true
ufw --force enable

echo "======================================================================"
echo "[VERIFICATION SUMMARY]"
systemctl is-active --quiet redis-server && echo "  [OK] Redis Server (127.0.0.1): RUNNING" || echo "  [WARN] Redis Server not active"
systemctl is-active --quiet arena_x.service && echo "  [OK] ARENA X Gunicorn Service: RUNNING" || echo "  [WARN] ARENA X service not active"
systemctl is-active --quiet nginx && echo "  [OK] Nginx Web Server: RUNNING" || echo "  [WARN] Nginx not active"
echo "======================================================================"
echo "  ARENA X 2026 Production Deployment Completed Successfully!"
echo "  Next Step: Ensure /var/www/arena_x/.env is configured with strong secrets."
echo "======================================================================"
