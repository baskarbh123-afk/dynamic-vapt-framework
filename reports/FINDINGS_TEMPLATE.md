# Vulnerability Finding Template

> **Usage:** Copy this template for each confirmed vulnerability. One finding = one completed template.

---

## Finding #[NUMBER] — [VULNERABILITY NAME]

**Date Found:** [YYYY-MM-DD]
**Tester:** [Name]
**Engagement:** [Client / App Name]

---

### 1. Overview

| Field | Details |
|---|---|
| **Vulnerability Type** | [e.g., IDOR / XSS / SQL Injection / CSRF] |
| **Severity** | [Critical / High / Medium / Low] |
| **CVSS Score** | [0.0 – 10.0] |
| **CVSS Vector** | [e.g., CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N] |
| **OWASP Category** | [e.g., A01:2021 – Broken Access Control] |
| **Affected Component** | [Endpoint, Function, Parameter] |
| **Authentication Required** | [None / User / Admin] |

---

### 2. Description

[Write a clear, technical description of the vulnerability. Explain:
- What the flaw is
- Where it exists in the application
- Why it exists (root cause — e.g., missing authorization check, no output encoding)
- What an attacker can do with it]

---

### 3. Impact

**Business Impact:**
[Describe the real-world consequence to the organization — data breach, financial loss, reputational damage, regulatory violation (GDPR, PCI-DSS)]

**Technical Impact:**
- **Confidentiality:** [High / Medium / Low / None] — [Explanation]
- **Integrity:** [High / Medium / Low / None] — [Explanation]
- **Availability:** [High / Medium / Low / None] — [Explanation]

---

### 4. Affected Endpoints / Parameters

| # | Method | Endpoint | Parameter | Notes |
|---|---|---|---|---|
| 1 | POST | /api/v1/users/{id} | `id` (path) | IDOR via numeric ID |
| 2 | GET | /api/v1/profile | — | Authenticated but no ownership check |

---

### 5. Steps to Reproduce

**Pre-conditions:**
- Test account A: `user_a@test.com` (role: user)
- Test account B: `user_b@test.com` (role: user)
- Both accounts must exist

**Step-by-step:**

1. Log in as **User A** and obtain a valid session token:
   ```http
   POST /api/login HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"email":"user_a@test.com","password":"TestPass@1"}
   ```
   Response: `{"token":"USER_A_TOKEN","userId":"1001"}`

2. Note User B's account ID (`1000`) obtained from [source].

3. Use User A's token to access User B's profile:
   ```http
   GET /api/v1/users/1000 HTTP/1.1
   Host: target.com
   Authorization: Bearer USER_A_TOKEN
   ```

4. Observe that the response returns User B's private profile data:
   ```json
   HTTP/1.1 200 OK
   {
     "id": 1000,
     "email": "user_b@target.com",
     "phone": "+1-555-0100",
     "address": "123 Private St"
   }
   ```

5. **Expected:** HTTP 403 Forbidden
   **Actual:** HTTP 200 with User B's private data

---

### 6. Evidence

**Screenshot 1:** [Description — e.g., "Burp Suite request showing User A token accessing User B endpoint"]
`[Attach: screenshot_finding_XX_request.png]`

**Screenshot 2:** [Description — e.g., "Response showing User B's PII returned"]
`[Attach: screenshot_finding_XX_response.png]`

**HTTP Request (Raw):**
```http
GET /api/v1/users/1000 HTTP/1.1
Host: target.com
Authorization: Bearer [USER_A_TOKEN_REDACTED]
```

**HTTP Response (Raw):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":1000,"email":"[REDACTED]","phone":"[REDACTED]"}
```

---

### 7. Root Cause Analysis

[Explain the technical root cause — e.g.,
"The `/api/v1/users/{id}` endpoint retrieves user data based solely on the `id` path parameter without verifying that the `id` matches the authenticated user's session. The server performs a database lookup directly: `SELECT * FROM users WHERE id = :id` without an additional `AND userId = :current_user_id` constraint."]

---

### 8. Remediation

**Primary Fix:**
[Specific, actionable recommendation. Be technical and precise.]

Example:
```
Enforce object ownership verification at the server level for all user data access endpoints.
At minimum, add the authenticated user's ID as an additional WHERE clause condition:

  SELECT * FROM users WHERE id = :id AND owner_id = :current_user_id

Do not rely on client-supplied IDs without server-side ownership validation.
```

**Secondary Controls:**
- Implement a centralized authorization middleware that validates resource ownership
- Log and alert on IDOR attempts (ID not found for requesting user → 403 + log event)
- Apply indirect reference mapping (map internal IDs to user-scoped opaque tokens)

**References:**
- OWASP IDOR: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- CWE-284: Improper Access Control

---

### 9. Retest Criteria

This finding is remediated when:
- [ ] Repeating steps 1–4 above returns HTTP 403 for User A accessing User B's profile
- [ ] User B's data is NOT included in any part of the response body
- [ ] The fix is confirmed on all affected endpoints listed in section 4

---

*Finding status: [ ] Open  [ ] In Remediation  [ ] Remediated  [ ] Accepted Risk*
