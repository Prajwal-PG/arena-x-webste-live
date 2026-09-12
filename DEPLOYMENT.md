# ARENA X 2026 // Hostinger KVM 1 Production Deployment Guide

This production operations manual provides complete, step-by-step instructions for deploying and running the **ARENA X 2026 Web Portal** on a **Hostinger KVM 1 VPS** (Ubuntu 22.04 LTS / Debian 12) with Nginx, Gunicorn, Redis, and SQLite behind Cloudflare or direct Let's Encrypt SSL.

---

## 1. System Specifications & Architecture

### Target Hardware (Hostinger KVM 1)
- **vCPU:** 1 Core
- **RAM:** 4 GB
- **Storage:** NVMe SSD (20–50 GB)
- **OS:** Ubuntu 22.04 LTS (Recommended) or Debian 12
- **Network:** 1 Gbps / IPv4 + IPv6

### Software Stack
```
[Visitor / Athlete / Admin]
           │
           ▼ (HTTPS: 443)
┌────────────────────────────────────────────────────────┐
│ Cloudflare Edge CDN / WAF (Optional DNS & DDoS Proxy)  │
└────────────────────────────────────────────────────────┘
           │
           ▼ (HTTPS: 443 / HTTP: 80)
┌────────────────────────────────────────────────────────┐
│ Nginx 1.18+ Reverse Proxy (Rate Limiting, SSL, Cache)  │
│ Port 80 -> 301 Redirect to HTTPS                       │
│ Static file caching & script execution blocking        │
└────────────────────────────────────────────────────────┘
           │
           ▼ (HTTP: 127.0.0.1:5000)
┌────────────────────────────────────────────────────────┐
│ Gunicorn 23.0 WSGI Server (2 Workers for 1 vCPU)       │
│ Sandboxed Systemd Service (arena_x.service)            │
│ Least-privilege user (www-data)                        │
└────────────────────────────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────────────────┐
│ Flask 3.1 Python Backend Application                   │
├───────────────────────────┬────────────────────────────┤
│ SQLite 3.37+ (data/)      │ Redis 6.0+ (127.0.0.1)     │
│ - WAL Mode                │ - Shared Sliding-Window    │
│ - Fernet Field Encryption │   Rate Limiter             │
│ - Busy Timeout: 5000ms    │ - Memory-efficient keys    │
│ - Secure Delete ON        │ - Protected mode ON        │
└───────────────────────────┴────────────────────────────┘
```

---

## 2. Server Provisioning & Initial Setup

### Step 2.1: Connect to VPS via SSH
Log in to your newly provisioned Hostinger VPS using the root credentials:
```bash
ssh root@YOUR_SERVER_IP
```

### Step 2.2: Update System & Install Core Packages
```bash
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y
apt-get install -y python3 python3-pip python3-venv python3-dev build-essential \
    nginx ufw curl git redis-server sqlite3 fail2ban logrotate certbot python3-certbot-nginx \
    libjpeg-dev zlib1g-dev libffi-dev libssl-dev
```

### Step 2.3: Configure UFW Firewall
Allow only SSH, HTTP, and HTTPS. Internal ports (5000, 6379) must never be open publicly.
```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP Web'
ufw allow 443/tcp comment 'HTTPS Secure Web'
ufw --force enable
```

### Step 2.4: Secure Redis Rate-Limiter
Ensure Redis only listens on loopback (`127.0.0.1`):
```bash
sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf || true
sed -i 's/^protected-mode no/protected-mode yes/' /etc/redis/redis.conf || true
systemctl enable redis-server
systemctl restart redis-server
```
Verify Redis is running locally:
```bash
redis-cli ping
# Expected response: PONG
```

---

## 3. Application Installation & File Permissions

### Step 3.1: Create Application Directory Structure
```bash
mkdir -p /var/www/arena_x /var/log/arena_x /var/backups/arena_x
mkdir -p /var/www/arena_x/data /var/www/arena_x/uploads
```

### Step 3.2: Upload Application Files
From your local machine, upload the clean release archive:
```bash
scp arena_x_2026_clean_portal.zip root@YOUR_SERVER_IP:/var/www/arena_x/
```
On the server, unzip and clean up the archive:
```bash
cd /var/www/arena_x
unzip -o arena_x_2026_clean_portal.zip
rm -f arena_x_2026_clean_portal.zip
```

### Step 3.3: Set Least-Privilege Permissions
Never run `chown -R www-data:www-data /var/www/arena_x` on the entire codebase. Apply least privilege:
```bash
# Code is owned by root, readable by www-data
chown -R root:www-data /var/www/arena_x
find /var/www/arena_x -type d -exec chmod 750 {} +
find /var/www/arena_x -type f -exec chmod 640 {} +

# Specific runtime directories writable by www-data
chown -R www-data:www-data /var/www/arena_x/data /var/www/arena_x/uploads /var/log/arena_x
chmod 770 /var/www/arena_x/data /var/www/arena_x/uploads
chmod 750 /var/log/arena_x

# Backups restricted strictly to root
chown -R root:root /var/backups/arena_x
chmod 700 /var/backups/arena_x
```

### Step 3.4: Setup Python Virtual Environment
```bash
cd /var/www/arena_x
python3 -m venv venv
venv/bin/pip install --upgrade pip setuptools wheel
venv/bin/pip install -r requirements.txt
```

---

## 4. Cryptographic Secrets Generation & Environment Configuration

> [!CRITICAL]
> The development secrets (e.g. `arenax2026`) must be considered compromised. You MUST generate fresh, unique 256-bit CSPRNG secrets before production deployment.

### Step 4.1: Generate Production Keys
Run the included cryptographic key generator:
```bash
/var/www/arena_x/venv/bin/python deploy/generate_production_keys.py
```
Or generate each value manually using Python's `secrets` module:
```bash
# SECRET_KEY (Flask session & CSRF signing)
python3 -c "import secrets; print(secrets.token_hex(32))"

# ARENA_ADMIN_KEY (Admin portal passkey)
python3 -c "import secrets; print('AX2026_' + secrets.token_urlsafe(16))"

# DB_PASSWORD (Fernet database field encryption master key)
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Step 4.2: Create and Lock `.env` File
Create `/var/www/arena_x/.env` and insert your generated values:
```bash
cat << 'EOF' > /var/www/arena_x/.env
# ARENA X 2026 // Production Secrets
FLASK_ENV=production
FLASK_DEBUG=false
SESSION_COOKIE_SECURE=true

# Mandatory Generated Cryptographic Keys
SECRET_KEY=<INSERT_GENERATED_SECRET_KEY>
ARENA_ADMIN_KEY=<INSERT_GENERATED_ADMIN_KEY>
DB_PASSWORD=<INSERT_GENERATED_DB_PASSWORD>

# Reverse Proxy & Cloudflare IP Trust
BEHIND_PROXY=true
PROXIES_COUNT=1
TRUST_CLOUDFLARE_IP=true
TRUSTED_PROXIES=127.0.0.1,::1

# Strict CORS Allowlist (Your actual domains)
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Redis Shared Rate Limiter
REDIS_URL=redis://127.0.0.1:6379/0

# Gmail SMTP Credentials
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-organization-email@gmail.com
SMTP_PASSWORD=<YOUR_16_CHAR_GMAIL_APP_PASSWORD>
SENDER_EMAIL=your-organization-email@gmail.com
REPLY_TO_EMAIL=your-organization-email@gmail.com
EOF
```

Lock permissions on `.env` so only `root` and the `www-data` service can read it:
```bash
chown root:www-data /var/www/arena_x/.env
chmod 640 /var/www/arena_x/.env
```

---

## 5. Systemd Service Configuration & Sandboxing

### Step 5.1: Install Hardened Systemd Service
The application uses `deploy/arena_x.service` featuring Linux namespaces, private tmp, and sandboxing:
```bash
cp /var/www/arena_x/deploy/arena_x.service /etc/systemd/system/arena_x.service
systemctl daemon-reload
systemctl enable arena_x.service
systemctl restart arena_x.service
```

### Step 5.2: Verify Service Status
```bash
systemctl status arena_x.service
```
Test local Gunicorn response:
```bash
curl -I http://127.0.0.1:5000/api/matches
# Expected response: HTTP/1.1 200 OK
```

---

## 6. Nginx Web Server & HTTPS Configuration

### Option A: Standard Deployment with Let's Encrypt (Certbot)
If you are pointing your domain directly to the VPS without Cloudflare:
```bash
cp /var/www/arena_x/deploy/nginx.conf /etc/nginx/sites-available/arena_x
ln -sf /etc/nginx/sites-available/arena_x /etc/nginx/sites-enabled/arena_x
rm -f /etc/nginx/sites-enabled/default

# Replace domain placeholders
sed -i 's/YOUR_DOMAIN.COM/yourdomain.com/g' /etc/nginx/sites-available/arena_x

# Obtain SSL Certificate via Certbot
certbot --nginx -d yourdomain.com -d www.yourdomain.com

nginx -t && systemctl restart nginx
```

### Option B: Cloudflare Origin Certificate (Recommended)
If using Cloudflare DNS + Proxy (Orange Cloud):
1. In Cloudflare Dashboard: **SSL/TLS** -> **Origin Server** -> **Create Certificate**.
2. Save certificate to `/etc/ssl/certs/cloudflare_origin.pem` (chmod 644).
3. Save private key to `/etc/ssl/private/cloudflare_origin.key` (chmod 600).
4. Set Cloudflare SSL/TLS mode to **Full (strict)**.
5. Deploy Cloudflare Nginx config:
```bash
cp /var/www/arena_x/deploy/cloudflare_nginx.conf /etc/nginx/sites-available/arena_x
ln -sf /etc/nginx/sites-available/arena_x /etc/nginx/sites-enabled/arena_x
rm -f /etc/nginx/sites-enabled/default

# Update server_name to your domain
sed -i 's/arenax.in/yourdomain.com/g' /etc/nginx/sites-available/arena_x

nginx -t && systemctl restart nginx
```

---

## 7. Automated Database Backups & Log Rotation

### Step 7.1: Configure Daily Backup Cron
The atomic online backup script performs SQLite WAL backups and prunes files older than 14 days:
```bash
chmod 750 /var/www/arena_x/deploy/backup.sh
chown root:root /var/www/arena_x/deploy/backup.sh

cat << 'CRONEOF' > /etc/cron.d/arena_x_backup
# ARENA X 2026 Daily WAL Database Backup at 03:00 AM UTC
0 3 * * * root /bin/bash /var/www/arena_x/deploy/backup.sh > /dev/null 2>&1
CRONEOF
chmod 644 /etc/cron.d/arena_x_backup
```

### Step 7.2: Test Manual Backup Execution
```bash
sudo bash /var/www/arena_x/deploy/backup.sh
ls -lh /var/backups/arena_x/
# Verified output: arena_x_YYYYMMDD_HHMMSS.db.gz
```

### Step 7.3: Configure Off-Site Backups (Optional but Recommended)
To prevent data loss if the VPS fails, configure `rclone` to sync backups to Google Drive, Backblaze B2, or Amazon S3:
```bash
apt-get install -y rclone
rclone config # Configure your remote (e.g., 'b2_remote:arena-backups')

# Add sync to /etc/cron.d/arena_x_backup or export BACKUP_REMOTE_DEST:
echo 'export BACKUP_REMOTE_DEST="b2_remote:arena-backups"' >> /etc/environment
```

### Step 7.4: Configure Logrotate
Ensure `/var/log/arena_x/*.log` files are rotated daily:
```bash
cp /var/www/arena_x/deploy/logrotate_arena_x /etc/logrotate.d/arena_x
chmod 644 /etc/logrotate.d/arena_x
```

---

## 8. SSH Hardening (After Verifying Key Access)

> [!CAUTION]
> Ensure you have verified that your SSH key works BEFORE disabling password authentication!

1. Add your SSH public key to `/root/.ssh/authorized_keys`.
2. Test SSH access from a separate terminal window.
3. Edit `/etc/ssh/sshd_config`:
```ini
PermitRootLogin prohibit-password
PasswordAuthentication no
X11Forwarding no
MaxAuthTries 4
```
4. Restart SSH service:
```bash
systemctl restart ssh
```

---

## 9. Post-Deployment Verification & Smoke Tests

Run the following smoke tests against your live deployment:

1. **Homepage:** Navigate to `https://yourdomain.com`. Ensure HTTPS is active and assets load.
2. **Registration:** Submit a test registration with a screenshot proof. Verify success response.
3. **Admin Login:** Navigate to `https://yourdomain.com/admin`. Enter your `ARENA_ADMIN_KEY`. Verify dashboard loads.
4. **Bracket & Score Update:** Update scores and select a winner in the Live Match Manager. Verify auto-save.
5. **CSV Export:** Click "Export CSV". Verify decrypted fields download cleanly in Excel.
6. **Rate Limiting:** Attempt rapid invalid logins (5 attempts) to verify HTTP 429 lockout.
7. **Security Tests:** Run the automated security test suite on the server:
```bash
/var/www/arena_x/venv/bin/python /var/www/arena_x/tests/security_test_suite.py
# All 36 tests must pass!
```

---

## 10. Maintenance & Rollback Procedures

### Updating Application Code
```bash
cd /var/www/arena_x
# Perform backup before update
bash deploy/backup.sh

# Unzip new release archive (preserves data/ and .env)
unzip -o arena_x_new_release.zip

# Update permissions
chown -R root:www-data /var/www/arena_x
chown -R www-data:www-data /var/www/arena_x/data /var/www/arena_x/uploads
chmod 770 /var/www/arena_x/data /var/www/arena_x/uploads

# Restart service
systemctl restart arena_x.service
```

### Restoring from Backup
```bash
# Stop application
systemctl stop arena_x.service

# Restore database from archive
BACKUP_FILE="/var/backups/arena_x/arena_x_YYYYMMDD_HHMMSS.db.gz"
gunzip -c "$BACKUP_FILE" > /var/www/arena_x/data/arena_x.db
chown www-data:www-data /var/www/arena_x/data/arena_x.db
chmod 660 /var/www/arena_x/data/arena_x.db

# Restart application
systemctl start arena_x.service
```
