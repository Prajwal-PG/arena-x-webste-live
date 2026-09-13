# 🚀 Hostinger KVM 1 VPS Deployment Guide for ARENA X 2026

This guide provides the exact instructions to deploy the ARENA X 2026 Web Portal on **Hostinger KVM 1 VPS** (1 vCPU, 4 GB RAM, 50 GB NVMe Storage).

---

## 1. Specifications & Sizing Analysis

| Resource | Hostinger KVM 1 Spec | ARENA X Requirements | Headroom / Capacity |
| :--- | :--- | :--- | :--- |
| **vCPU** | 1 Dedicated Core | ~0.15 Core active | **~85% CPU Free** for traffic spikes |
| **RAM** | 4 GB | ~180 MB (Gunicorn + Nginx + App) | **~3.8 GB Free RAM** |
| **Storage** | 50 GB NVMe SSD | ~150 MB Portal + DB + Proofs | **> 49 GB Free** |
| **Bandwidth** | 1 TB to 4 TB / month | Static assets offloaded to Cloudflare | **Virtually Unlimited capacity** |

**Verdict:** Hostinger KVM 1 is an **excellent, cost-effective, high-performance fit** for the ARENA X 2026 portal.

---

## 2. Setting Up Your Hostinger VPS (Post-Purchase)

1. In the Hostinger Dashboard, select **Operating System**:
   - Choose **Ubuntu 24.04 LTS (64-bit)** *(or Ubuntu 22.04 LTS)*.
2. Set a strong root password and record your **Server Public IP**.
3. (Optional but recommended) Add your SSH Public Key for passwordless login.

---

## 3. Uploading the Clean Portal to Your VPS

From your local machine (PowerShell or Terminal), upload `arena_x_2026_clean_portal.zip`:

```bash
# Using SCP (replace with your Hostinger IP):
scp "arena_x_2026_clean_portal.zip" root@YOUR_HOSTINGER_IP:/root/
```

---

## 4. One-Command Server Provisioning

Log in to your VPS via SSH:
```bash
ssh root@YOUR_HOSTINGER_IP
```

Extract the clean zip to `/var/www/arena_x`:
```bash
apt-get update -y && apt-get install -y unzip
mkdir -p /var/www/arena_x
unzip -o /root/arena_x_2026_clean_portal.zip -d /var/www/arena_x/
cd /var/www/arena_x
```

Make the setup script executable and run it:
```bash
chmod +x deploy/hostinger_kvm1_setup.sh deploy/setup_cloudflare_firewall.sh
bash deploy/hostinger_kvm1_setup.sh
```

---

## 5. Configure Your Production `.env`

Copy the production sample template:
```bash
cp /var/www/arena_x/.env.production.sample /var/www/arena_x/.env
```

Generate fresh, high-entropy cryptographic keys:
```bash
/var/www/arena_x/venv/bin/python /var/www/arena_x/deploy/generate_production_keys.py
```

Edit `/var/www/arena_x/.env`:
```bash
nano /var/www/arena_x/.env
```

Ensure all keys, domains, and credentials are configured:
```ini
# Flask Core & Security
FLASK_ENV=production
FLASK_DEBUG=false
SESSION_COOKIE_SECURE=true

# High-Entropy Cryptographic Keys (Generated via deploy/generate_production_keys.py)
SECRET_KEY=<INSERT_GENERATED_SECRET_KEY>
ARENA_ADMIN_KEY=<INSERT_GENERATED_ADMIN_KEY>
DB_PASSWORD=<INSERT_GENERATED_DB_PASSWORD>

# Reverse Proxy & Cloudflare IP Trust
BEHIND_PROXY=true
PROXIES_COUNT=1
TRUST_CLOUDFLARE_IP=true
TRUSTED_PROXIES=127.0.0.1,::1

# Strict CORS Allowlist (No wildcards)
ALLOWED_ORIGINS=https://YOUR-DOMAIN.com,https://www.YOUR-DOMAIN.com

# Redis Shared Sliding-Window Rate Limiter
REDIS_URL=redis://127.0.0.1:6379/0

# Gmail SMTP Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-production-email@gmail.com
SMTP_PASSWORD=<YOUR_16_CHAR_GMAIL_APP_PASSWORD>
SENDER_EMAIL=your-production-email@gmail.com
REPLY_TO_EMAIL=your-production-email@gmail.com
```

Set secure file permissions (readable only by root and www-data):
```bash
chown root:www-data /var/www/arena_x/.env
chmod 640 /var/www/arena_x/.env
```

---

## 6. Restart & Verify

Restart the backend service:
```bash
systemctl restart arena_x.service
systemctl status arena_x.service
```

Check Nginx and Gunicorn logs:
```bash
# Service status
systemctl is-active arena_x.service

# Local Gunicorn loopback test
curl -I http://127.0.0.1:5000/api/matches

# Live application error logs
tail -f /var/log/arena_x/error.log
```

---

## 7. Official Admin Portal Access

The official production administration portal URL is:
```
https://YOUR-DOMAIN.com/admin
```
- **Authentication:** Validated solely against `ARENA_ADMIN_KEY` by the backend `/api/admin/login` endpoint.
- **Security:** All client-side fallback hashes have been completely removed.
- **Rate Limit:** 5 failed attempts per IP per 15 minutes (HTTP 429 lockout).
- **Session:** Secure, HttpOnly, SameSite=Lax, with CSRF protection on all state-changing endpoints.

---

## 8. Useful Operational Commands

| Action | Command |
| :--- | :--- |
| **Restart App Backend** | `systemctl restart arena_x.service` |
| **View Live Logs** | `journalctl -u arena_x.service -f` |
| **Restart Nginx** | `systemctl restart nginx` |
| **Check Firewall (UFW)** | `ufw status verbose` |
| **Backup SQLite DB** | `sqlite3 /var/www/arena_x/data/arena_x.db ".backup /root/arena_x_backup.db"` |
