# Session Handling Security Testing

## Overview

Session management flaws allow attackers to hijack authenticated sessions, bypass logout, or reuse expired tokens. This module covers cookie security, token lifecycle, and session fixation/hijacking vectors.

---

## 1. Cookie Security Flags

### What to Check

For every session-related cookie, verify all security flags are set:

```bash
curl -I https://target.com/login -d "user=test&pass=test" | grep -i set-cookie
```

### Flag Assessment

| Flag | Expected | Risk if Missing |
|---|---|---|
| `HttpOnly` | Present | XSS can steal cookie via `document.cookie` |
| `Secure` | Present | Cookie transmitted over HTTP (plaintext) |
| `SameSite=Strict` or `Lax` | Present | CSRF attacks possible |
| `Path=/` | Scoped | Cookie leaked to unintended paths |
| `Domain` | Not set or specific | Cookie leaks to subdomains |
| Short `Max-Age`/`Expires` | Present | Long-lived session tokens |

### Test Procedure
1. Login and capture `Set-Cookie` response header
2. Verify each flag above
3. Test `Secure` flag: attempt to make request over HTTP and observe if cookie is sent
4. Test `HttpOnly` flag: via XSS PoC — attempt `document.cookie` extraction

---

## 2. Session Token Entropy & Predictability

### Entropy Analysis
```bash
# Collect multiple tokens
for i in $(seq 1 20); do
  curl -si -X POST https://target/login \
    -d "username=user$i&password=testpass" \
    | grep -i set-cookie | awk -F'=' '{print $2}' | awk -F';' '{print $1}'
done
```

Assessment criteria:
- Token length should be ≥ 128 bits (16 bytes / 32 hex chars)
- Tokens must be cryptographically random (no sequential patterns)
- Check for timestamps, user IDs, or predictable components embedded in token

---

## 3. Session Fixation

### Test Procedure
1. Obtain a valid pre-auth session token (from login page before authenticating)
2. Complete authentication using that token
3. Check if the server issues a **new** session token post-login

**Vulnerable** if the same token is used before and after authentication.

```http
GET /login HTTP/1.1
→ Set-Cookie: SESSID=ABC123

POST /login HTTP/1.1
Cookie: SESSID=ABC123
→ Set-Cookie: SESSID=ABC123   ← VULNERABLE: same token after auth
→ Set-Cookie: SESSID=XYZ999   ← SECURE: new token issued
```

---

## 4. Session Invalidation on Logout

### Test Procedure
1. Log in and copy the session token
2. Log out
3. Replay the original session token in a new request to an authenticated endpoint
4. Also test: close browser, reopen, and check if session still works (persistent sessions)

```bash
# Step 1: capture token
SESSION="your_captured_token_here"

# Step 4: replay after logout
curl -s https://target/dashboard \
  -H "Cookie: session=$SESSION" \
  -w "\nHTTP: %{http_code}"
```

**Vulnerable** if HTTP 200 is returned after logout.

---

## 5. Concurrent Session Controls

### Test Procedure
1. Log in from Browser A — note session token A
2. Log in from Browser B with same credentials — note session token B
3. Use token A — verify if it is still valid (should be invalidated if single-session policy exists)
4. Check if application enforces single-device session

---

## 6. Session Timeout

### Idle Timeout Test
1. Log in and remain idle
2. After the stated timeout period (or 15/30 min), attempt to use the session
3. Expected: session expired, redirect to login

### Absolute Timeout Test
1. Log in and actively use the application
2. Continue past the absolute max session duration
3. Expected: forced re-authentication regardless of activity

---

## 7. Token in URL (Anti-Pattern)

### Detection
```bash
# Check if session token appears in URL
curl -v https://target/dashboard?sessionid=XYZ 2>&1 | grep -i "sessionid\|token\|auth"
```

If tokens appear in URLs they will be:
- Logged in server/proxy access logs
- Exposed in browser history
- Leaked via `Referer` header

---

## 8. Cross-Subdomain Session Leakage

### Test Procedure
1. Identify if `Domain=.target.com` is set (note the leading dot)
2. Find any subdomain that can be influenced (e.g., user-controlled content subdomain)
3. If found, the session cookie is accessible from that subdomain

```bash
# Check cookie scope
curl -I https://target.com/login | grep -i "set-cookie.*domain"
```

---

## Findings Summary Template

| Test | Result | Severity |
|---|---|---|
| HttpOnly flag | Pass/Fail | - |
| Secure flag | Pass/Fail | - |
| SameSite flag | Pass/Fail | - |
| Token entropy | Pass/Fail | - |
| Session fixation | Pass/Fail | High |
| Logout invalidation | Pass/Fail | High |
| Idle timeout | Pass/Fail | Medium |
| Token in URL | Pass/Fail | Medium |
