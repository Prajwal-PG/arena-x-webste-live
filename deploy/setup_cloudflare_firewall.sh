#!/usr/bin/env bash
# ==============================================================================
# ARENA X 2026 // Origin Server Firewall (UFW) Hardening for Cloudflare
# Run with: sudo bash deploy/setup_cloudflare_firewall.sh
# 
# This locks down your origin Linux server so ONLY Cloudflare's IP addresses
# can connect to HTTP (80) and HTTPS (443), preventing attackers from bypassing
# Cloudflare WAF/DDoS protection by hitting your public server IP directly.
# ==============================================================================

set -euo pipefail

echo "======================================================================"
echo "  ARENA X 2026 // CLOUDFLARE ORIGIN FIREWALL (UFW) CONFIGURATION"
echo "======================================================================"

# Ensure UFW is installed
if ! command -v ufw &> /dev/null; then
    echo "[*] Installing UFW firewall..."
    apt-get update -y && apt-get install -y ufw
fi

# Reset existing rules if needed or set secure defaults
echo "[*] Setting secure default policies (Deny all incoming, Allow outgoing)..."
ufw default deny incoming
ufw default allow outgoing

# CRITICAL: Always keep SSH open so you don't lock yourself out!
echo "[*] Allowing SSH access on port 22..."
ufw allow 22/tcp comment 'SSH Management'

# Delete any open 80 / 443 rules that permit direct non-Cloudflare traffic
ufw delete allow 80/tcp 2>/dev/null || true
ufw delete allow 443/tcp 2>/dev/null || true
ufw delete allow 80 2>/dev/null || true
ufw delete allow 443 2>/dev/null || true

echo "[*] Adding official Cloudflare IPv4 subnet rules..."
CF_IPV4=(
    "173.245.48.0/20"
    "103.21.244.0/22"
    "103.22.200.0/22"
    "103.31.4.0/22"
    "141.101.64.0/18"
    "108.162.192.0/18"
    "190.93.240.0/20"
    "188.114.96.0/20"
    "197.234.240.0/22"
    "198.41.128.0/17"
    "162.158.0.0/15"
    "104.16.0.0/13"
    "104.24.0.0/14"
    "172.64.0.0/13"
    "131.0.72.0/22"
)

for ip in "${CF_IPV4[@]}"; do
    ufw allow proto tcp from "$ip" to any port 80,443 comment "Cloudflare IPv4"
done

echo "[*] Adding official Cloudflare IPv6 subnet rules..."
CF_IPV6=(
    "2400:cb00::/32"
    "2606:4700::/32"
    "2803:f800::/32"
    "2405:b500::/32"
    "2405:8100::/32"
    "2a06:98c0::/29"
    "2c0f:f248::/32"
)

for ip6 in "${CF_IPV6[@]}"; do
    ufw allow proto tcp from "$ip6" to any port 80,443 comment "Cloudflare IPv6"
done

# Enable UFW
echo "[*] Enabling UFW firewall..."
ufw --force enable

echo "======================================================================"
echo "[SUCCESS] Origin firewall is ACTIVE and locked to Cloudflare IPs only!"
echo "Attackers can no longer bypass Cloudflare by directly targeting port 80/443."
echo "======================================================================"
ufw status verbose
