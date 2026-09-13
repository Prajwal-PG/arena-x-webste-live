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
    print("\n[INSTRUCTIONS]")
    print("1. Copy .env.production.sample to /var/www/arena_x/.env on your Hostinger VPS.")
    print("2. Paste the generated SECRET_KEY, ARENA_ADMIN_KEY, and DB_PASSWORD into /var/www/arena_x/.env.")
    print("3. Set your production domain, Gmail address, and Gmail App Password.")
    print("4. Restrict permissions: chmod 600 /var/www/arena_x/.env && chown www-data:www-data /var/www/arena_x/.env")
    print("5. NEVER commit your live .env to public Git repositories.")
    print("=" * 70)

if __name__ == '__main__':
    main()
