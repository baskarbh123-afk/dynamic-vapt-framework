# Approved Tooling Reference

## Policy

Only tools listed in this document may be used during the engagement. All tools must be run in a controlled, rate-limited manner consistent with `docs/RULES.md`.

---

## 1. Network & HTTP Tools

### curl
**Purpose:** HTTP request crafting, response analysis, header inspection
```bash
# Standard usage pattern
curl -si -X GET "https://target/endpoint" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -w "\nHTTP: %{http_code}\n"

# Flags: -s (silent), -i (include headers), -L (follow redirects), --max-time 5
```
**Restrictions:** No `--parallel` flooding; max 10 req/sec

### nuclei
**Purpose:** Template-based vulnerability scanning
```bash
# Technology detection (safe)
nuclei -u https://target -t technologies/ -silent

# CVE scanning (check authorized CVE list first)
nuclei -u https://target -t cves/ -severity critical,high -silent

# Config/exposure checks
nuclei -u https://target -t exposures/ -t misconfiguration/ -silent
```
**Restrictions:** Use `-rate-limit 5` to stay within safe bounds

### ffuf
**Purpose:** Directory and parameter fuzzing
```bash
# Directory discovery
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u https://target/FUZZ \
  -mc 200,301,302,403 \
  -rate 10 \
  -o /tmp/ffuf_output.json

# Parameter discovery
ffuf -w params.txt \
  -u "https://target/api/search?FUZZ=test" \
  -mc 200 -rate 10
```
**Restrictions:** `-rate 10` (10 req/sec max), no `-rate 0` (unlimited)

### dirsearch
**Purpose:** Web path discovery
```bash
dirsearch -u https://target \
  -e php,asp,aspx,js,json,html,txt,bak,config \
  -t 5 \
  --delay=0.5 \
  --exclude-status=400,404
```
**Restrictions:** `-t 5` (5 threads max), `--delay=0.5`

---

## 2. Proxy & Interception Tools

### Burp Suite (Community / Professional)
**Purpose:** Intercept, modify, and replay HTTP/S traffic; active scanning
**Usage:**
- Configure browser proxy: `127.0.0.1:8080`
- Use Repeater for manual request modification
- Use Intruder only with **Sniper mode** and low thread count (1-2)
- Use Collaborator for OOB SSRF/SSRF detection
- Do NOT use Scanner in automated mode without authorization

### OWASP ZAP
**Purpose:** Passive scanning, spider, and active scanning (authorized scope only)
```bash
# Passive scan only (safe)
zap-cli quick-scan --self-contained \
  --start-options '-config api.disablekey=true' \
  https://target
```

---

## 3. Automation & Scripting

### Python 3
**Purpose:** Custom test scripts, payload generation, response analysis
```bash
pip install requests beautifulsoup4 pyjwt cryptography
```

### Selenium / Playwright
**Purpose:** Browser automation for auth flows, session handling, DOM-based testing
```bash
# Install
pip install selenium playwright
playwright install chromium

# Usage pattern (headless)
python3 test_auth.py --target https://target --headless
```
**Restrictions:** No headless scraping of user data; only test accounts

---

## 4. SQL Injection Testing

### sqlmap (Safe Mode ONLY)
**Purpose:** SQL injection detection and database fingerprinting
```bash
# Safe mode — detection only, no exploitation
sqlmap -u "https://target/api?id=1" \
  --cookie="session=TOKEN" \
  --level=2 \
  --risk=1 \
  --technique=T \       # Time-based blind only
  --no-cast \
  --batch \
  --random-agent \
  --delay=1 \
  --output-dir=/tmp/sqlmap_output

# DO NOT USE:
# --dump, --dump-all, --passwords, --os-shell, --os-cmd
```
**Restrictions:** `--level=1 --risk=1 --technique=BT` only (Boolean + Time). Never `--dump`.

---

## 5. Subdomain & DNS Tools

### subfinder / amass (passive only)
```bash
# Passive subdomain enumeration only
subfinder -d target.com -silent -o /tmp/subdomains.txt

# Passive amass
amass enum -passive -d target.com -o /tmp/amass_subs.txt
```

### dnsx
```bash
# Resolve subdomain list
dnsx -l /tmp/subdomains.txt -silent -o /tmp/resolved.txt
```

---

## 6. JWT Tools

### jwt_tool
```bash
# Decode and analyze JWT
python3 jwt_tool.py TOKEN

# Test known attacks
python3 jwt_tool.py TOKEN -X a    # alg:none
python3 jwt_tool.py TOKEN -X s    # RS256 to HS256

# Crack weak secret
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt
```

---

## 7. Out-of-Band / Interaction Logging

### Burp Collaborator
**Purpose:** OOB DNS/HTTP callbacks for blind SSRF, XXE, blind XSS
- Available in Burp Suite Professional
- Use `YOUR_ID.burpcollaborator.net` as callback domain

### interactsh (open-source alternative)
```bash
# Start interaction server
interactsh-client -v

# Use generated URL for OOB callbacks
# e.g., YOUR_ID.interact.sh
```

---

## 8. SSL/TLS Testing

### sslyze
```bash
sslyze --regular target.com:443 2>/dev/null \
  | grep -E "VULNERABLE|OK|TLS|cipher|HSTS"
```

### testssl.sh
```bash
./testssl.sh --quiet --color 0 https://target.com
```

---

## Prohibited Tools

The following tools are NOT permitted in this engagement:

| Tool | Reason |
|---|---|
| hydra / medusa / THC Hydra | Brute force — prohibited |
| hashcat / john (on prod hashes) | Cannot extract/crack real user passwords |
| sqlmap --dump / --os-shell | Data exfiltration / RCE prohibited |
| Masscan / nmap aggressive (-A) | DoS risk / out-of-scope network scan |
| msfconsole exploits | Full exploitation prohibited (PoC only) |
| Nikto (-Tuning 9) | DoS risk |
| Any credential stuffing tool | Brute force prohibited |
