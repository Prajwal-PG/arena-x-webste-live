# ARENA X 2026 // Esports Championship Web Portal & Gate Accreditation System

Official web portal, athlete registration system, match management dashboard, and on-site QR gate accreditation system for **ARENA X 2026** at Fiza by Nexus Mall, Mangaluru. Powered by GAMEBOT & Nitte University.

---

## 🔒 SECURITY NOTICE

**CRITICAL DEPLOYMENT SAFETY RULES:**
- Sensitive runtime files (`.env`, `data/`, `uploads/`, `*.db`, `*.pem`, `*.key`) are excluded from source control via `.gitignore` and `.dockerignore`.
- **NEVER** commit `.env` or production SQLite databases into any Git repository or public storage.
- If committing code or exporting source archives, verify that only code, static assets, and template files are packaged.

---

## 🚀 Quick Start (Local Development)

### 1. Prerequisites
- Python 3.10+
- Virtualenv recommended

### 2. Setup Environment
```bash
# Clone the repository
git clone https://github.com/your-org/arena-x-2026-web-portal.git
cd arena-x-2026-web-portal

# Create and activate virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Secrets
Create a `.env` file based on `.env.example`:
```bash
cp .env.example .env
```
Generate strong random keys:
```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('DB_PASSWORD=' + secrets.token_hex(32))"
```
Set `ARENA_ADMIN_KEY` to your desired organizer administrator passkey.

### 4. Run Development Server
```bash
python app.py
```
Visit:
- Public Portal: `http://127.0.0.1:5000`
- Organizer Admin Dashboard: `http://127.0.0.1:5000/admin`

---

## 🛡️ Security Architecture & Hardening Overview

1. **Mandatory Secrets with Zero Fallbacks**: `SECRET_KEY`, `ARENA_ADMIN_KEY`, and `DB_PASSWORD` are strictly enforced on startup. If any secret is missing or empty, startup halts immediately.
2. **AES-256 PII Encryption at Rest**: Participant WhatsApp numbers, emails, emergency contacts, gamer UIDs, and BookMyShow Booking IDs are encrypted in SQLite using AES-256 (Fernet) keys derived via PBKDF2-HMAC-SHA256 (200,000 iterations).
3. **Proof Upload Validation**:
   - Max file size strictly capped at 300 KB (`validate_uploaded_image`).
   - Allowed formats: **PNG and JPG only**.
   - Deep inspection: verifies magic byte signatures and Pillow image canvas headers, rejecting renamed scripts or disguised executables.
   - Uploads stored outside web root with randomized hex filenames.
   - `/uploads/<filename>` strictly gated behind `@admin_required`.
4. **Traversal & Disclosure Protection**: Whitelisted static routing explicitly blocks `.env`, `.py`, `.db`, `data/`, `uploads/`, and dotfiles.
5. **Anti-Brute Force Rate Limiting**: Redis-backed distributed rate limiter with automatic in-memory fallback for admin logins, registration submissions, and QR pass scans.
6. **CSRF Defense**: Automatic CSRF token generation and validation for all state-changing endpoints, with self-healing fetch interceptors in the admin dashboard.
7. **Local QR Pass Generation**: Gate QR codes are rendered directly in memory using `qrcode[pil]` with zero dependency on third-party tracking APIs.
8. **Permissions Policy**: `camera=(self)` permits on-site marshals to use live webcam/phone camera QR scanning while blocking third-party camera injection.

---

## 📦 Production Deployment (Gunicorn / Nginx / Render)

### Procfile
```text
web: gunicorn --workers=4 --threads=2 --bind 0.0.0.0:$PORT --timeout 120 wsgi:app
```

### Mandatory Production Environment Variables
- `FLASK_ENV=production`
- `SESSION_COOKIE_SECURE=true`
- `SECRET_KEY=<64-char-hex>`
- `ARENA_ADMIN_KEY=<secure-passkey>`
- `DB_PASSWORD=<aes-256-key>`
- `REDIS_URL=redis://...`
- `ALLOWED_ORIGINS=https://yourdomain.com`
- `BEHIND_PROXY=true`
- `TRUST_CLOUDFLARE_IP=true`
