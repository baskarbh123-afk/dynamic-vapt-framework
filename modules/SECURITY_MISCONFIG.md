# Security Misconfiguration Testing

## Objective

Identify security misconfigurations including missing/weak HTTP security headers, exposed administrative interfaces, default credentials, verbose error messages, unnecessary features, and cloud/infrastructure misconfigurations.

---

## 1. HTTP Security Headers

```bash
# Capture all response headers
curl -si https://target/ | grep -iE \
  "strict-transport|content-security|x-frame|x-content-type|x-xss|referrer-policy|permissions-policy|expect-ct|cache-control"
```

### Required Headers Assessment

| Header | Expected Value | Risk if Missing |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HTTPS bypass, MITM |
| `Content-Security-Policy` | Restrictive policy | XSS amplification |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing attacks |
| `Referrer-Policy` | `no-referrer` or `strict-origin-when-cross-origin` | URL leakage |
| `Permissions-Policy` | Restrictive | Camera/mic/location abuse |
| `Cache-Control` | `no-store` on auth pages | Sensitive data caching |

```bash
# Full automated header check
curl -si https://target/ | python3 -c "
import sys
headers = {}
for line in sys.stdin:
    line = line.strip()
    if ':' in line:
        k, v = line.split(':', 1)
        headers[k.lower()] = v.strip()

checks = [
    ('strict-transport-security', 'HSTS'),
    ('content-security-policy', 'CSP'),
    ('x-frame-options', 'X-Frame-Options'),
    ('x-content-type-options', 'X-Content-Type-Options'),
    ('referrer-policy', 'Referrer-Policy'),
    ('permissions-policy', 'Permissions-Policy'),
]
for h, name in checks:
    status = 'PRESENT' if h in headers else 'MISSING'
    print(f'{status}: {name} = {headers.get(h, \"\")}')
"
```

---

## 2. Information Disclosure via Headers

```bash
# Check for version disclosure
curl -si https://target/ | grep -iE "server:|x-powered-by:|x-aspnet|x-generator|x-version"

# Examples of problematic responses:
# Server: Apache/2.4.49 (Ubuntu)  → CVE lookup possible
# X-Powered-By: PHP/7.4.3        → outdated PHP
# X-AspNet-Version: 4.0.30319    → .NET version
```

---

## 3. Debug Endpoints & Admin Interfaces

```bash
# Probe for common debug/admin paths
DEBUG_PATHS=(
  "/.env"
  "/.git/config"
  "/.git/HEAD"
  "/config.json"
  "/config.php"
  "/phpinfo.php"
  "/info.php"
  "/test.php"
  "/debug"
  "/actuator"
  "/actuator/env"
  "/actuator/health"
  "/actuator/mappings"
  "/actuator/beans"
  "/api/debug"
  "/_profiler"
  "/telescope"
  "/horizon"
  "/swagger-ui.html"
  "/swagger-ui/"
  "/api-docs"
  "/v2/api-docs"
  "/v3/api-docs"
  "/openapi.json"
  "/openapi.yaml"
  "/wp-admin"
  "/admin"
  "/phpmyadmin"
  "/adminer"
  "/console"
  "/manager"
)

for PATH in "${DEBUG_PATHS[@]}"; do
  RESP=$(curl -si "https://target$PATH" -o /dev/null -w "%{http_code}" 2>/dev/null)
  if [[ "$RESP" != "404" && "$RESP" != "400" ]]; then
    echo "HTTP $RESP: $PATH"
  fi
  sleep 0.15
done
```

---

## 4. Verbose Error Messages

```bash
# Trigger errors to check verbosity

# SQL error
curl -si "https://target/api/users?id='" | grep -iE "sql|mysql|postgresql|syntax|error|exception|stack"

# File not found
curl -si "https://target/nonexistent_page_xyz" | grep -iE "exception|stack trace|at line|debug|error"

# Type confusion
curl -si -X POST https://target/api/users \
  -H "Content-Type: application/json" \
  -d '{"id":"string_not_int"}' | grep -iE "exception|traceback|error|debug"
```

---

## 5. Directory Listing

```bash
# Check if directory listing is enabled
for DIR in /uploads /files /images /static /assets /backup /logs; do
  RESP=$(curl -si "https://target$DIR/" | grep -iE "index of|directory listing|parent directory")
  if [[ -n "$RESP" ]]; then
    echo "Directory listing found: $DIR"
  fi
done
```

---

## 6. Default / Weak Credentials on Admin Panels

```bash
# Test common default credentials on discovered admin interfaces
ADMIN_URL="https://target/admin"

CREDS=("admin:admin" "admin:password" "admin:admin123" "admin:1234" "root:root" "admin:changeme")

for CRED in "${CREDS[@]}"; do
  USER=$(echo $CRED | cut -d: -f1)
  PASS=$(echo $CRED | cut -d: -f2)
  RESP=$(curl -si -X POST "$ADMIN_URL/login" \
    -d "username=$USER&password=$PASS" -w "%{http_code}" | tail -1)
  echo "$CRED → HTTP $RESP"
  sleep 0.5
done
```

---

## 7. CORS Misconfiguration

See `modules/CORS.md` for detailed CORS testing. Quick check:

```bash
# Check CORS response for arbitrary origin
curl -si https://target/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=USER_TOKEN" | grep -iE "access-control-allow"
```

---

## 8. HTTPS / TLS Assessment

```bash
# Check SSL configuration
curl -si https://target/ | grep -i "strict-transport"

# SSL/TLS audit
sslyze --regular target.com:443 2>/dev/null | grep -E "VULNERABLE|OK|TLS|cipher"

# Check for HTTP to HTTPS redirect
curl -si http://target/ | grep -iE "location:|strict-transport"

# Check HSTS preload
curl -si https://target/ | grep -i "strict-transport-security"
# Expected: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

## 9. Content Security Policy Analysis

```bash
# Extract CSP
CSP=$(curl -si https://target/ | grep -i "content-security-policy" | cut -d: -f2-)
echo "CSP: $CSP"

# Analyze for weaknesses
echo $CSP | tr ';' '\n' | while read directive; do
  echo "Directive: $directive"
  # Look for:
  # unsafe-inline → allows inline scripts
  # unsafe-eval → allows eval()
  # * wildcard → allows any host
  # data: → allows data: URIs in script-src
  echo $directive | grep -E "unsafe-inline|unsafe-eval|\*|data:" && echo "⚠ WEAK"
done
```

---

## 10. Source Code / Backup File Exposure

```bash
# Check for exposed source/config files
FILES=(
  "/.env"
  "/.env.local"
  "/.env.production"
  "/config.yml"
  "/config.yaml"
  "/database.yml"
  "/settings.py"
  "/app.config.js"
  "/web.config"
  "/composer.json"
  "/package.json"
  "/Gemfile"
  "/requirements.txt"
  "/backup.zip"
  "/backup.sql"
  "/database.sql"
  "/.DS_Store"
  "/sitemap.xml"
  "/robots.txt"
)

for FILE in "${FILES[@]}"; do
  RESP=$(curl -si "https://target$FILE" -o /dev/null -w "%{http_code}")
  if [[ "$RESP" == "200" ]]; then
    echo "EXPOSED HTTP 200: $FILE"
  fi
  sleep 0.1
done
```

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| HSTS header missing | Pass/Fail | Medium |
| CSP missing or weak (unsafe-inline) | Pass/Fail | Medium |
| X-Frame-Options missing | Pass/Fail | Medium |
| Server version disclosure | Pass/Fail | Low |
| Debug endpoint accessible (/actuator, /phpinfo) | Pass/Fail | High |
| .env file exposed | Pass/Fail | Critical |
| Directory listing enabled | Pass/Fail | Medium |
| Default admin credentials | Pass/Fail | Critical |
| Verbose stack traces | Pass/Fail | Low-Medium |
| Swagger/API docs exposed | Pass/Fail | Low-Medium |
