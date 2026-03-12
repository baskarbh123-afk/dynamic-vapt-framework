# Authorization Testing

## Objective

Verify that the application correctly enforces access control — ensuring users can only access resources and perform actions they are explicitly authorized for. Tests both server-side enforcement and RBAC integrity.

---

## 1. Forced Browsing / Direct Object Access

### Test Procedure
1. As an admin, note the URL of a restricted page (e.g., `/admin/users`)
2. Log out and try to access that URL as an anonymous user
3. Log in as a low-privilege user and access the same URL

```bash
# Admin URL discovered: /admin/users/list
# Test as unauthenticated
curl -si https://target/admin/users/list | grep -E "HTTP|redirect|unauthorized"

# Test with low-priv user session
curl -si https://target/admin/users/list \
  -H "Cookie: session=LOW_PRIV_SESSION_TOKEN" \
  | grep -E "HTTP|redirect|data"
```

**Expected:** HTTP 302 (redirect to login) for anonymous; HTTP 403 for low-priv user.

---

## 2. HTTP Method Tampering

### Test Procedure
If an endpoint rejects `GET` but allows `POST`, test all HTTP methods:

```bash
for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "Testing $METHOD"
  curl -si -X $METHOD https://target/admin/users \
    -H "Cookie: session=LOW_PRIV_TOKEN" \
    | grep -E "HTTP|Content-Length"
done
```

**Vulnerable:** If a restricted `GET /admin/users` returns 403 but `POST /admin/users` returns 200.

---

## 3. Parameter-Based Access Control Testing

### Role Parameter Injection
Intercept API calls and look for role/permission identifiers in the request:

```http
GET /api/v1/dashboard HTTP/1.1
Cookie: session=USER_TOKEN

# Try modifying hidden parameters:
GET /api/v1/dashboard?role=admin HTTP/1.1
GET /api/v1/dashboard?isAdmin=true HTTP/1.1
GET /api/v1/dashboard?access_level=5 HTTP/1.1
```

### Request Body Role Injection
```http
POST /api/v1/update-profile HTTP/1.1
Content-Type: application/json

{"name":"Test User","email":"test@test.com","role":"admin"}
```

---

## 4. API Endpoint Authorization (Unauthenticated Access)

### Test Each API Endpoint Without Authentication
```bash
# List of API endpoints from recon
ENDPOINTS=(
  "/api/v1/users"
  "/api/v1/users/1"
  "/api/v1/admin/settings"
  "/api/v1/reports"
  "/api/v1/audit-logs"
)

for EP in "${ENDPOINTS[@]}"; do
  echo "Testing: $EP"
  curl -si https://target$EP | grep "HTTP"
  sleep 0.2
done
```

---

## 5. Function-Level Access Control

### Test Admin Functions with User Token

```bash
USER_TOKEN="user_session_token_here"

# Admin: list all users
curl -si https://target/api/admin/users \
  -H "Authorization: Bearer $USER_TOKEN" | grep "HTTP"

# Admin: delete user
curl -si -X DELETE https://target/api/admin/users/5 \
  -H "Authorization: Bearer $USER_TOKEN" | grep "HTTP"

# Admin: change user role
curl -si -X PUT https://target/api/admin/users/5/role \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}' | grep "HTTP"

# Admin: view audit logs
curl -si https://target/api/admin/audit-logs \
  -H "Authorization: Bearer $USER_TOKEN" | grep "HTTP"
```

---

## 6. JWT-Based Authorization Bypass

If the application uses JWTs for authorization, refer to `modules/JWT_SECURITY.md`.

Key tests relevant to authorization:
- Modify the `role` claim in the JWT payload
- Modify the `permissions` array in the JWT payload
- Test with `alg:none` — if accepted, forge an admin token

---

## 7. GraphQL Authorization

If the application uses GraphQL, refer to `modules/GRAPHQL.md`.

Quick check — try admin queries with user token:
```graphql
query {
  allUsers { id email role }
  systemSettings { smtpPassword dbConnectionString }
}
```

---

## 8. Insecure Direct Object References (Authorization via ID)

See `modules/IDOR.md` for detailed IDOR testing.

Quick check:
- Change `userId`, `orderId`, `fileId` in URL/body to another user's ID
- Increment/decrement numeric IDs
- Swap GUIDs between roles

---

## 9. Path Traversal to Authorization Bypass

```bash
# Try path manipulation to access admin routes
curl -si https://target/user/../admin/users \
  -H "Cookie: session=USER_TOKEN" | grep "HTTP"

curl -si https://target/user/%2F..%2Fadmin%2Fusers \
  -H "Cookie: session=USER_TOKEN" | grep "HTTP"
```

---

## 10. Referrer-Based Access Control

Some applications only check the `Referer` header for authorization:

```bash
# Directly access restricted page with a trusted Referer header
curl -si https://target/admin/delete-user/5 \
  -H "Cookie: session=USER_TOKEN" \
  -H "Referer: https://target/admin/dashboard" \
  | grep "HTTP"
```

---

## Evidence to Capture

- Request showing the role/privilege being bypassed
- Response confirming unauthorized access (data returned, action performed)
- Contrast with a legitimate admin request showing same result

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Unauthenticated access to protected page | Pass/Fail | High-Critical |
| Low-priv access to admin function | Pass/Fail | High-Critical |
| HTTP method bypass | Pass/Fail | High |
| Role parameter injection | Pass/Fail | High |
| JWT role claim manipulation | Pass/Fail | Critical |
| Function-level access bypass | Pass/Fail | High |
