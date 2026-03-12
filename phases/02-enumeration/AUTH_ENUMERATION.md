# Authentication Enumeration

## Objective
Map all authentication mechanisms, session handling, and access control implementations in the target application.

---

## 1. Login Mechanism Inventory

| # | Endpoint | Method | Auth Type | MFA | Notes |
|---|----------|--------|-----------|-----|-------|
| 1 | /login | POST | Form-based | | |
| 2 | /api/auth | POST | JSON/JWT | | |
| 3 | /oauth/authorize | GET | OAuth 2.0 | | |

---

## 2. Session Token Analysis

### Token Collection
```bash
# Collect session tokens from multiple logins
for i in $(seq 1 5); do
  RESP=$(curl -si -X POST "https://<target>/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"TestPass@1"}')
  echo "$RESP" | grep -i "set-cookie\|authorization\|token"
  sleep 1
done
```

### Cookie Flag Analysis
```bash
curl -si -X POST "https://<target>/login" \
  -d "username=test&password=TestPass@1" | \
  grep -i set-cookie
```

| Cookie | HttpOnly | Secure | SameSite | Path | Expiry |
|--------|----------|--------|----------|------|--------|
| | | | | | |

### JWT Analysis (if applicable)
```bash
# Decode JWT (do NOT send to online decoders)
echo "<JWT_TOKEN>" | cut -d. -f1 | base64 -d 2>/dev/null
echo "<JWT_TOKEN>" | cut -d. -f2 | base64 -d 2>/dev/null
```

| Claim | Value | Testable |
|-------|-------|----------|
| alg | | Algorithm confusion |
| sub | | IDOR via claim |
| role | | Privilege escalation |
| exp | | Token expiry bypass |

---

## 3. Role-Based Access Mapping

For each role in credentials/accounts.md, test access to all endpoints:

### Permission Matrix

| Endpoint | Anonymous | User | Premium | Moderator | Admin | Expected |
|----------|-----------|------|---------|-----------|-------|----------|
| GET /dashboard | | | | | | |
| GET /admin | | | | | | |
| POST /api/users | | | | | | |
| DELETE /api/users/{id} | | | | | | |

### Access Control Test
```bash
# Test each endpoint as each role
ROLES=("anonymous" "user_a" "admin")
ENDPOINTS=("/dashboard" "/admin" "/api/users" "/api/settings")

for endpoint in "${ENDPOINTS[@]}"; do
  for role in "${ROLES[@]}"; do
    # Get token for role (from credentials/accounts.md)
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://<target>$endpoint" \
      -H "Authorization: Bearer ${TOKEN[$role]}")
    echo "$role → $endpoint: $STATUS"
  done
done
```

---

## 4. Password Policy Analysis

| Check | Result |
|-------|--------|
| Minimum length | |
| Complexity required | |
| Common passwords blocked | |
| Account lockout after N failures | |
| Lockout duration | |
| Password history enforced | |

---

## 5. Registration & Reset Flow

### Registration
- Self-registration allowed: Yes / No
- Email verification required: Yes / No
- Can register with existing email: Yes / No
- Rate limiting on registration: Yes / No

### Password Reset
- Reset mechanism: Email link / OTP / Security questions
- Token in URL: Yes / No
- Token expiry: 
- Token reuse possible: Yes / No
- Rate limiting: Yes / No

---

## Outputs
Update these files with enumeration results:
- docs/AUTH_FLOW.md — Authentication flow documentation
- docs/SESSION_HANDLING.md — Session analysis
- targets/attack_surface.md — Auth-related attack vectors

---

## Checklist
- [ ] All login mechanisms identified
- [ ] Session tokens analyzed (entropy, flags, structure)
- [ ] JWT claims documented (if applicable)
- [ ] Role-based access matrix populated
- [ ] Password policy documented
- [ ] Registration and reset flows mapped
- [ ] Results documented in docs/AUTH_FLOW.md
