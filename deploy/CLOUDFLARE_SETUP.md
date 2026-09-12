# ☁️ Cloudflare Setup Guide for ARENA X 2026

This guide walks you through connecting **Cloudflare** to the ARENA X 2026 Web Portal to enable enterprise-grade DDoS protection, edge caching, web application firewall (WAF), and automated SSL/TLS encryption.

---

## 1. Add Your Domain to Cloudflare
1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/) (Sign up for free if you don't have an account).
2. Click **Add a site**, enter your domain name (e.g. `arenax.in`), and select the **Free Plan**.
3. Cloudflare will scan your existing DNS records.

---

## 2. Update DNS Nameservers
1. Cloudflare will provide you with two nameservers, for example:
   - `alec.ns.cloudflare.com`
   - `zoe.ns.cloudflare.com`
2. Go to your domain registrar (GoDaddy, Namecheap, Hostinger, etc.).
3. Replace your existing nameservers with Cloudflare's assigned nameservers.
4. Propagation takes anywhere from 5 to 60 minutes.

---

## 3. Configure DNS Records with Proxy Status
In your Cloudflare Dashboard under **DNS** > **Records**:
1. Add an **A Record**:
   - **Type**: `A`
   - **Name**: `@` (or `arenax.in`)
   - **IPv4 Address**: `YOUR_SERVER_PUBLIC_IP`
   - **Proxy Status**: **Proxied (Orange Cloud ON)** ☁️
2. Add a **CNAME Record**:
   - **Type**: `CNAME`
   - **Name**: `www`
   - **Target**: `arenax.in`
   - **Proxy Status**: **Proxied (Orange Cloud ON)** ☁️

---

## 4. Configure SSL/TLS Encryption
Under **SSL/TLS**:
1. In the **Overview** tab, set encryption mode to:
   - **Full (Strict)** (Recommended if using Cloudflare Origin CA certificate on your server).
   - Or **Full** (If using self-signed or Let's Encrypt certificates).
2. In the **Edge Certificates** tab:
   - Toggle **Always Use HTTPS**: **ON** ✅
   - Toggle **Automatic HTTPS Rewrites**: **ON** ✅
   - Minimum TLS Version: **TLS 1.2**

---

## 5. Security & WAF Configuration
Under **Security** > **Settings / WAF**:
1. **Security Level**: Set to **Medium** (or **High** during tournament kickoff peak traffic).
2. **Bot Fight Mode**: Toggle **ON** ✅ (Blocks malicious scrapers and brute-force botnets automatically).
3. **Challenge Passage**: Set to **30 minutes**.

---

## 6. Cloudflare Caching Rules (Critical)
Under **Caching** > **Cache Rules**:
Create rule #1: **Bypass Cache for Admin & APIs**
- **Field**: URI Path
- **Operator**: starts with
- **Value**: `/api/` OR `/admin` OR `/uploads/`
- **Action**: **Bypass Cache** (Prevents caching real-time registrations and admin session data).

Create rule #2: **Cache Static Game Assets at Edge**
- **Field**: URI Path
- **Operator**: contains
- **Value**: `.png` OR `.jpg` OR `.jpeg` OR `.webp` OR `.css` OR `.js`
- **Action**: **Eligible for Cache** > Edge TTL: 7 days.

---

## 7. Server-Side Real IP & Nginx Integration
The ARENA X backend is already pre-configured for Cloudflare:
- In `.env`:
  ```bash
  TRUST_CLOUDFLARE_IP=true
  ```
- The backend automatically extracts `CF-Connecting-IP` so rate-limiting and logging record the visitor's real IP address rather than Cloudflare's proxy IPs.
- Use `deploy/cloudflare_nginx.conf` on your Linux VPS/server for full real-IP restoration and proxying to Flask.
