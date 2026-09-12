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

Create `/var/www/arena_x/.env`:
```bash
nano /var/www/arena_x/.env
```

Paste your production secrets:
```ini
# Flask Security Keys
SECRET_KEY=<generate_with_python_deploy/generate_production_keys.py>
ARENA_ADMIN_KEY=<choose_a_strong_admin_passkey>
DB_PASSWORD=<choose_a_strong_database_passphrase>

# Gmail SMTP Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-production-email@gmail.com
SMTP_PASSWORD=<configure_your_16_char_google_app_password>
SENDER_EMAIL=your-production-email@gmail.com

# Cloudflare Proxy Integration
TRUST_CLOUDFLARE_IP=true
```

Set secure file permissions:
```bash
chown www-data:www-data /var/www/arena_x/.env
chmod 600 /var/www/arena_x/.env
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

# Live error logs
tail -f /var/log/arena_x/error.log
```

---

## 7. Useful Operational Commands

| Action | Command |
| :--- | :--- |
| **Restart App Backend** | `systemctl restart arena_x.service` |
| **View Live Logs** | `journalctl -u arena_x.service -f` |
| **Restart Nginx** | `systemctl restart nginx` |
| **Check Firewall (UFW)** | `ufw status verbose` |
| **Backup SQLite DB** | `sqlite3 /var/www/arena_x/data/arena_x.db ".backup /root/arena_x_backup.db"` |
