# ARENA X 2026 // Production Deployment Checklist

Use this pre-flight checklist before making the website live on Hostinger KVM 1 VPS.

---

### Phase 1: Secrets & Sensitive Data Sanitization
- [ ] `.env` file is strictly excluded from git and deployment archive (`arena_x_2026_clean_portal.zip`).
- [ ] Old development passwords and admin keys (`arenax2026`, `arenaxnipe.nitte.fiza`) are completely abandoned and rotated.
- [ ] Gmail App Password rotated and newly generated in Google Account settings.
- [ ] New 256-bit `SECRET_KEY` generated via `secrets.token_hex(32)`.
- [ ] New strong `ARENA_ADMIN_KEY` generated (e.g. `AX2026_<random_token>`).
- [ ] New strong `DB_PASSWORD` generated for Fernet authenticated PII encryption.
- [ ] `.env` file permissions set to `chmod 640` and owned by `root:www-data`.
- [ ] `.env.example` and `.env.production.sample` contain zero real credentials or real email addresses.

### Phase 2: Application Configuration & Hardening
- [ ] `FLASK_ENV=production` configured in `.env`.
- [ ] `SESSION_COOKIE_SECURE=true` configured and verified.
- [ ] `FLASK_DEBUG=false` enforced (debug mode forbidden).
- [ ] `BEHIND_PROXY=true` and `PROXIES_COUNT=1` configured.
- [ ] `ALLOWED_ORIGINS` configured strictly to actual domain (no wildcard `*` or broad regex).
- [ ] Client-side auth bypasses completely removed: admin login strictly server-authoritative via `/api/admin/login`.
- [ ] Official admin URL confirmed: `https://YOUR-DOMAIN.com/admin`.
- [ ] Admin rate limiting active: 5 failed attempts per 15 minutes (900s) with generic error message.
- [ ] CSRF tokens enforced on all state-changing administrative requests (`POST`, `PUT`, `DELETE`, `PATCH`).
- [ ] Redis configured and listening strictly on `127.0.0.1:6379`.
- [ ] SQLite database created with WAL mode, foreign keys, and busy timeout.
- [ ] Screenshot uploads capped at 300 KB with Pillow decoding & metadata stripping.
- [ ] Upload directory `/uploads/` gated strictly behind `@admin_required`.

### Phase 3: Infrastructure & Server Hardening
- [ ] Hostinger KVM 1 updated (`apt-get update && apt-get upgrade`).
- [ ] Least-privilege permissions applied (`/var/www/arena_x` owned by `root:www-data` 750/640; `data/` and `uploads/` 770).
- [ ] Systemd service `arena_x.service` configured with 2 workers and security sandboxing (`NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=strict`, `ProtectHome=true`).
- [ ] Gunicorn bound strictly to localhost (`127.0.0.1:5000`).
- [ ] Nginx configured with HTTP -> HTTPS 301 redirect.
- [ ] Nginx blocks sensitive file extensions (`.db`, `.sqlite`, `.env`, `.py`, `.key`, `.pem`, `.bak`, `.backup`, `.log`).
- [ ] Nginx disables direct script execution in `/uploads/`.
- [ ] Security headers active (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`).
- [ ] UFW firewall enabled allowing ONLY ports 22, 80, 443 (ports 5000 and 6379 blocked).
- [ ] SSH hardened with public key authentication (`PasswordAuthentication no`).

### Phase 4: Backups & Monitoring
- [ ] Atomic online database backup script (`deploy/backup.sh`) tested and functional.
- [ ] Daily cron job installed at `/etc/cron.d/arena_x_backup` (runs at 03:00 AM UTC).
- [ ] Backup retention policy active (prunes archives older than 14 days).
- [ ] Off-site backup strategy documented (rclone / S3 / scp).
- [ ] Log rotation configured at `/etc/logrotate.d/arena_x`.

### Phase 5: Verification & Go-Live
- [ ] Automated security test suite executed: `python tests/security_test_suite.py` (**36/36 passed**).
- [ ] Public registration flow tested with live screenshot upload.
- [ ] Admin login tested and verified with rate limiter.
- [ ] Digital pass QR lookup tested and data minimization verified.
- [ ] Gate check-in API tested.
- [ ] Match manager winner selection & live score update tested.
- [ ] Registration CSV decrypted export tested.
