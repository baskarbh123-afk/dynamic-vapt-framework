# HTTP Header Security Analysis

## Objective

Analyze HTTP request and response headers for security misconfigurations, information leakage, CORS weaknesses, and missing security controls.

---

## 1. Automated Header Collection

```bash
# Collect headers from key pages
PAGES=("/" "/login" "/dashboard" "/api/v1/users" "/admin")

for PAGE in "${PAGES[@]}"; do
  echo "=== $PAGE ==="
  curl -si "https://target$PAGE" \
    -H "Cookie: session=USER_TOKEN" | head -30
  echo ""
done
```

---

## 2. Security Header Audit

```bash
# Automated security header check
curl -si https://target/ | python3 << 'EOF'
import sys

headers = {}
for line in sys.stdin:
    line = line.strip()
    if ': ' in line:
        k, v = line.split(': ', 1)
        headers[k.lower()] = v

required = {
    'strict-transport-security': {
        'required': True,
        'expected': 'max-age=31536000',
        'risk': 'HSTS missing — HTTP downgrade attack possible'
    },
    'content-security-policy': {
        'required': True,
        'expected': "default-src 'self'",
        'risk': 'CSP missing — XSS attack surface increased'
    },
    'x-frame-options': {
        'required': True,
        'expected': 'DENY or SAMEORIGIN',
        'risk': 'Clickjacking attacks possible'
    },
    'x-content-type-options': {
        'required': True,
        'expected': 'nosniff',
        'risk': 'MIME sniffing attack possible'
    },
    'referrer-policy': {
        'required': True,
        'expected': 'no-referrer or strict-origin-when-cross-origin',
        'risk': 'URL leakage via Referer header'
    },
    'permissions-policy': {
        'required': False,
        'expected': 'Restrict camera, microphone, geolocation',
        'risk': 'Browser feature abuse possible'
    },
}

print("\n=== SECURITY HEADER ASSESSMENT ===\n")
for header, info in required.items():
    if header in headers:
        print(f"✓  PRESENT: {header}: {headers[header]}")
    else:
        status = "✗  MISSING" if info['required'] else "⚠  ABSENT"
        print(f"{status}: {header} — {info['risk']}")

print("\n=== INFORMATION DISCLOSURE HEADERS ===\n")
leak_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'via', 'x-version']
for h in leak_headers:
    if h in headers:
        print(f"⚠  LEAKS: {h}: {headers[h]}")
EOF
```

---

## 3. CORS Configuration Testing

### Basic CORS Test
```bash
# Test with arbitrary origin
curl -si https://target/api/v1/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=USER_TOKEN" | grep -iE "access-control|origin"

# Test with null origin
curl -si https://target/api/v1/me \
  -H "Origin: null" \
  -H "Cookie: session=USER_TOKEN" | grep -iE "access-control"

# Preflight OPTIONS request
curl -si -X OPTIONS https://target/api/v1/users \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: Authorization" \
  | grep -iE "access-control"
```

### CORS Vulnerability Patterns
```
Access-Control-Allow-Origin: *                           ← Wildcard (Medium if no cookies)
Access-Control-Allow-Origin: https://evil.com            ← Reflects attacker origin (Critical)
Access-Control-Allow-Origin: null                        ← null origin (High)
Access-Control-Allow-Credentials: true + wildcard        ← Invalid combo but check behavior
Access-Control-Allow-Origin: https://target.com.evil.com ← Domain check bypass
```

### CORS with Credentials Test
```bash
# Critical: ACAO reflects origin + ACAC: true
curl -si https://target/api/v1/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=REAL_TOKEN" | grep -iE "access-control-allow-origin|allow-credentials"

# If both present:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → Attacker can read authenticated API responses cross-origin
```

---

## 4. Cache Header Analysis

```bash
# Check caching headers on sensitive pages
SENSITIVE=(
  "/profile"
  "/dashboard"
  "/api/v1/me"
  "/account/settings"
  "/api/v1/payment-methods"
)

for PAGE in "${SENSITIVE[@]}"; do
  echo "=== $PAGE ==="
  curl -si "https://target$PAGE" \
    -H "Cookie: session=USER_TOKEN" | grep -iE "cache-control|pragma|expires|etag|last-modified"
  echo ""
done
```

**Expected on authenticated/sensitive pages:**
- `Cache-Control: no-store, no-cache, must-revalidate`
- `Pragma: no-cache`

**Vulnerable if:**
- No `Cache-Control` or `Pragma: no-cache` on auth pages
- `Cache-Control: public` on pages showing PII

---

## 5. Custom Header Injection Testing

```bash
# Test if custom headers influence application behavior
curl -si https://target/api/v1/me \
  -H "Cookie: session=USER_TOKEN" \
  -H "X-Original-URL: /admin" | grep HTTP

curl -si https://target/api/v1/me \
  -H "Cookie: session=USER_TOKEN" \
  -H "X-Forwarded-Host: evil.com" | grep -iE "location:|host:|evil.com"

curl -si https://target/api/v1/users \
  -H "Cookie: session=USER_TOKEN" \
  -H "X-Original-IP: 127.0.0.1" | grep HTTP

# Role bypass via header
curl -si https://target/admin \
  -H "Cookie: session=USER_TOKEN" \
  -H "X-Role: admin" | grep HTTP

curl -si https://target/admin \
  -H "Cookie: session=USER_TOKEN" \
  -H "X-Admin: true" | grep HTTP
```

---

## 6. Host Header Analysis

```bash
# Check if Host header is trusted for routing sensitive operations
# Password reset Host injection
curl -si -X POST https://target/forgot-password \
  -H "Host: evil.com" \
  -d "email=victim@target.com" | grep HTTP
# If reset email contains link to evil.com → critical finding

# Check application behavior with arbitrary Host header
curl -si https://target/ \
  -H "Host: evil.com" | grep -iE "location:|evil.com|host"
```

---

## 7. Cookie Header Analysis

```bash
# Extract and analyze all Set-Cookie headers
curl -si https://target/login \
  -X POST -d "username=test&password=test" | grep -i "set-cookie"

# Analysis script
curl -si https://target/login \
  -X POST -d "username=test&password=test" | python3 << 'EOF'
import sys, re

print("\n=== COOKIE SECURITY ANALYSIS ===\n")
for line in sys.stdin:
    if line.lower().startswith('set-cookie'):
        cookie = line.strip()
        print(f"Cookie: {cookie}")
        issues = []
        if 'httponly' not in cookie.lower(): issues.append("MISSING HttpOnly")
        if 'secure' not in cookie.lower(): issues.append("MISSING Secure")
        if 'samesite' not in cookie.lower(): issues.append("MISSING SameSite")
        elif 'samesite=none' in cookie.lower(): issues.append("SameSite=None (CSRF risk)")
        for issue in issues:
            print(f"  ⚠  {issue}")
        print()
EOF
```

---

## 8. Content-Type Header Validation

```bash
# Test if application validates Content-Type on API endpoints
# JSON endpoint with XML Content-Type
curl -si -X POST https://target/api/v1/users \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><user><admin>true</admin></user>' | grep HTTP

# JSON endpoint with no Content-Type
curl -si -X POST https://target/api/v1/login \
  -d '{"username":"admin","password":"admin"}' | grep HTTP
```

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| HSTS header missing | Pass/Fail | Medium |
| CSP missing or unsafe-inline | Pass/Fail | Medium |
| X-Frame-Options missing | Pass/Fail | Medium |
| CORS reflects arbitrary origin + credentials | Pass/Fail | Critical |
| CORS allows null origin | Pass/Fail | High |
| Sensitive pages cacheable | Pass/Fail | Medium |
| Host header injection (password reset) | Pass/Fail | High |
| X-Forwarded-Host reflected | Pass/Fail | Medium |
| Server version disclosure | Pass/Fail | Low |
| Missing HttpOnly on session cookie | Pass/Fail | Medium |
