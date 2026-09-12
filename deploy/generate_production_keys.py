#!/usr/bin/env python3
"""
ARENA X 2026 // Cryptographic Production Secret Generator
Generates high-entropy CSPRNG secrets for production deployments.

Usage:
    python deploy/generate_production_keys.py
"""

import secrets
import string
import os

def generate_strong_secret(length=32):
    return secrets.token_urlsafe(length)

def generate_strong_password(length=24):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_admin_passkey(length=20):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def main():
    print("=" * 70)
    print("  ARENA X 2026 // PRODUCTION CRYPTOGRAPHIC KEY GENERATOR")
    print("=" * 70)

    secret_key = secrets.token_hex(32)        # 256-bit AES/HMAC session key
    db_password = secrets.token_hex(32)       # 256-bit PBKDF2 DB master key
    admin_key = "AX2026_" + generate_admin_passkey(16)

    print("\n[SUCCESS] Generated high-entropy production credentials:\n")
    print(f"SECRET_KEY={secret_key}")
    print(f"ARENA_ADMIN_KEY={admin_key}")
    print(f"DB_PASSWORD={db_password}")

    output_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env.production.sample')
    template = f"""# ==============================================================================
# ARENA X 2026 // Production Secrets Template
# Rename or copy to /var/www/arena_x/.env on your production VPS
# Permissions: chmod 600 /var/www/arena_x/.env && chown www-data:www-data /var/www/arena_x/.env
# ==============================================================================

FLASK_ENV=production
SESSION_COOKIE_SECURE=true
SECRET_KEY={secret_key}
ARENA_ADMIN_KEY={admin_key}
DB_PASSWORD={db_password}

# Gmail SMTP Delivery Credentials
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-production-email@gmail.com
SMTP_PASSWORD=<CONFIGURE_YOUR_16_CHAR_GMAIL_APP_PASSWORD>
SENDER_EMAIL=your-production-email@gmail.com
REPLY_TO_EMAIL=your-production-email@gmail.com

# Cloudflare Proxy Integration
TRUST_CLOUDFLARE_IP=true
TRUSTED_PROXIES=127.0.0.1,::1

# Shared Rate Limiting (Redis)
REDIS_URL=redis://127.0.0.1:6379/0

# Allowed CORS Origins (Replace with your actual domain)
ALLOWED_ORIGINS=https://arenax.in,https://www.arenax.in
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(template)

    print(f"\n[OK] Sample production file created at: {output_path}")
    print("[NOTE] Never commit this file or your actual .env to public Git repositories.")
    print("=" * 70)

if __name__ == '__main__':
    main()
