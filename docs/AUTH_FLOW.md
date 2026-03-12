# Authentication Flow Mapping

## Purpose

Map all authentication mechanisms present in the target application before running authentication/session tests. This document is completed during Phase 1 reconnaissance.

---

## 1. Login Mechanism Inventory

| # | Endpoint | Method | Auth Type | MFA | Notes |
|---|---|---|---|---|---|
| 1 | /login | POST | Form-based | No | |
| 2 | /api/auth | POST | JSON/JWT | Yes | |
| 3 | /oauth/authorize | GET | OAuth 2.0 | - | |
| 4 | /sso/saml | POST | SAML | - | |

*(Fill in during engagement)*

---

## 2. Form-Based Authentication

### Endpoint Details
- **Login URL**:
- **Logout URL**:
- **Password Reset URL**:
- **Registration URL**:

### Request Structure
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=user&password=pass&_csrf=TOKEN
```

### Response Indicators
- **Success**: HTTP 302 redirect to dashboard, Set-Cookie header present
- **Failure**: HTTP 200 with error message
- **Account lockout**: HTTP 429 or error after N attempts

### Observations
- CSRF token present in login form: Yes / No
- Username enumeration via response difference: Yes / No
- Error message reveals valid usernames: Yes / No

---

## 3. Token-Based Authentication (JWT / API Key)

### Token Location
- [ ] Authorization: Bearer header
- [ ] Cookie: `token=`
- [ ] Request body field
- [ ] Query parameter

### JWT Structure (if applicable)
```
Header: {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"user_id","role":"user","exp":1234567890}
Signature: [HMAC-SHA256]
```

### Observed JWT Claims
| Claim | Value | Testable? |
|---|---|---|
| sub | user ID | Yes — IDOR via sub claim |
| role | user/admin | Yes — privilege escalation |
| exp | timestamp | Yes — token expiry bypass |
| iss | issuer | Yes — algorithm confusion |

---

## 4. OAuth 2.0 / OIDC Flow

### Flow Type
- [ ] Authorization Code
- [ ] Authorization Code + PKCE
- [ ] Implicit (legacy)
- [ ] Client Credentials

### Endpoints
- **Authorization**: `GET /oauth/authorize?client_id=X&redirect_uri=Y&response_type=code&state=Z`
- **Token**: `POST /oauth/token`
- **UserInfo**: `GET /oauth/userinfo`
- **JWKS**: `GET /.well-known/jwks.json`

### Parameters to Test
- `redirect_uri` — open redirect / token theft via redirect_uri manipulation
- `state` — CSRF protection; test with missing/replayed state
- `scope` — scope escalation attempt
- `response_type` — try switching to `token` if `code` expected

---

## 5. SAML / SSO

### SP-Initiated vs IdP-Initiated
- Type: SP-initiated / IdP-initiated
- **ACS URL**:
- **EntityID**:
- **NameID Format**: emailAddress / transientID / persistent

### Test Points
- XML signature wrapping
- NameID manipulation
- InResponseTo replay
- SP metadata exposure

---

## 6. Multi-Factor Authentication (MFA)

### MFA Type
- [ ] TOTP (Google Authenticator style)
- [ ] Email OTP
- [ ] SMS OTP
- [ ] Hardware token
- [ ] Push notification

### MFA Bypass Test Points
- Directly access post-login endpoint without completing MFA step
- Replay previously used OTP
- Test OTP with very long expiry window
- Test with OTP `000000` or other common values
- Check if MFA can be skipped via API endpoint that login form uses

---

## 7. Session Token Analysis

### Cookie Flags
| Cookie Name | HttpOnly | Secure | SameSite | Path | Expiry |
|---|---|---|---|---|---|
| session | Yes/No | Yes/No | Lax/Strict/None | / | Session/Persistent |

### Token Entropy Check
```bash
# Collect 10 session tokens and check entropy
for i in {1..10}; do
  curl -s -c /tmp/cookie$i.txt -d "user=test&pass=test" https://target/login
  grep session /tmp/cookie$i.txt | awk '{print $7}'
done
```

### Observations
- Token length:
- Token charset:
- Tokens appear random: Yes / No
- Token reused after logout: Yes / No
