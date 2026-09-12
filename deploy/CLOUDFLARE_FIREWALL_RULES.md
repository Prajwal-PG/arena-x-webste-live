# 🛡️ Cloudflare Web Application Firewall (WAF) Rules for ARENA X 2026

Configure these rules in **Cloudflare Dashboard** > **Security** > **WAF** > **Custom Rules** (Click **Create rule** for each).

---

### Rule 1: Block Sensitive Runtime & Database Probing at Edge
*Stops attackers, scrapers, and scanners before requests ever reach your origin server.*

- **Rule Name**: `Block Sensitive Probes & Hidden Files`
- **When incoming requests match**: (Use Expression Editor)
```text
(http.request.uri.path contains ".env") or 
(http.request.uri.path contains ".git") or 
(http.request.uri.path contains ".db") or 
(http.request.uri.path contains ".sqlite") or 
(http.request.uri.path contains "wp-admin") or 
(http.request.uri.path contains "phpmyadmin") or 
(http.request.uri.path contains "xmlrpc.php") or
(http.request.uri.path contains "eval(") or
(http.request.uri.path contains "base64_decode")
```
- **Action**: **Block** 🚫

---

### Rule 2: Protect Tournament Admin Portal (`/admin`)
*Challenges suspicious traffic and threat scores targeting the organizer login portal.*

- **Rule Name**: `Challenge Suspicious Admin Access`
- **When incoming requests match**:
```text
(http.request.uri.path starts_with "/admin" or http.request.uri.path starts_with "/api/admin") and 
(cf.threat_score gt 5 or cf.client.bot)
```
- **Action**: **Managed Challenge** 🛡️ (Presents Cloudflare interactive check)

---

### Rule 3: Anti-DDoS Rate Limiting on Registration API (`/api/register`)
*Prevents automated bots from spamming fake registrations and ticket uploads.*

*(Configure under **Security** > **WAF** > **Rate limiting rules**)*
- **Rule Name**: `Rate Limit Registration Submissions`
- **If incoming requests match**:
```text
http.request.uri.path eq "/api/register" and http.request.method eq "POST"
```
- **Rate Limit**: **10 requests per 1 minute**
- **Action**: **Block for 10 minutes** (or **Managed Challenge**)

---

### Rule 4: Block Malicious User-Agents & Security Scanners
*Blocks automated reconnaissance tools like sqlmap, nikto, and dirbuster.*

- **Rule Name**: `Block Automated Attack Tools`
- **When incoming requests match**:
```text
(http.user_agent contains "sqlmap") or 
(http.user_agent contains "nikto") or 
(http.user_agent contains "acunetix") or 
(http.user_agent contains "dirbuster") or 
(http.user_agent contains "gobuster") or 
(http.user_agent contains "masscan") or
(http.user_agent contains "nmap")
```
- **Action**: **Block** 🚫

---

### Rule 5: Turn On Cloudflare Bot Fight Mode
1. Go to **Security** > **Bots**.
2. Toggle **Bot Fight Mode**: **ON** ✅.
   - Automatically blocks known malicious botnets, brute-force dictionaries, and automated crawlers.

---

### Rule 6: Enable Cloudflare DDoS Protection Defaults
1. Go to **Security** > **DDoS**.
2. Ensure **HTTP DDoS Attack Protection** is set to **High** (Mitigates L7 volumetric floods instantly at the edge).
