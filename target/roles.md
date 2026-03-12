# Role Definitions & Permission Matrix

## Application Roles

*(Fill in during pre-engagement based on client briefing and recon)*

| # | Role Name | Description | Privilege Level |
|---|---|---|---|
| 1 | Anonymous | Unauthenticated visitor | 0 |
| 2 | Registered User | Standard authenticated user | 1 |
| 3 | Premium User | Paid tier with extra features | 2 |
| 4 | Moderator | Content moderation capabilities | 3 |
| 5 | Admin | Full application management | 4 |
| 6 | Super Admin | System-level access | 5 |

---

## Permission Matrix

| Feature / Endpoint | Anonymous | User | Premium | Moderator | Admin |
|---|---|---|---|---|---|
| View public content | ✓ | ✓ | ✓ | ✓ | ✓ |
| Register / Login | ✓ | - | - | - | - |
| View own profile | - | ✓ | ✓ | ✓ | ✓ |
| Edit own profile | - | ✓ | ✓ | ✓ | ✓ |
| View other profiles | - | Limited | ✓ | ✓ | ✓ |
| Create content | - | ✓ | ✓ | ✓ | ✓ |
| Delete own content | - | ✓ | ✓ | ✓ | ✓ |
| Delete any content | - | - | - | ✓ | ✓ |
| View all users | - | - | - | ✓ | ✓ |
| Modify user roles | - | - | - | - | ✓ |
| Access admin panel | - | - | - | - | ✓ |
| Access billing | - | Own | Own | - | ✓ |
| API key management | - | Own | Own | - | ✓ |

*(Adapt to target application's actual role structure)*

---

## Test Account Credentials

See `target/credentials.md` for test account details per role.

---

## Horizontal Escalation Test Cases

Testing whether a user of the same role can access another user's data:

| Test Case | User A | Target | Expected | Actual |
|---|---|---|---|---|
| View User B's profile | user_a | /users/{user_b_id} | 403 | |
| Edit User B's data | user_a | PUT /users/{user_b_id} | 403 | |
| Download User B's files | user_a | /files/{user_b_file_id} | 403 | |
| View User B's orders | user_a | /orders/{user_b_order_id} | 403 | |

---

## Vertical Escalation Test Cases

Testing whether a lower-privilege user can access higher-privilege functions:

| Test Case | Role | Target Endpoint | Expected | Actual |
|---|---|---|---|---|
| Access admin dashboard | User | /admin | 403 | |
| List all users | User | /api/admin/users | 403 | |
| Change another user's role | Moderator | PUT /api/users/{id}/role | 403 | |
| Delete any user | User | DELETE /api/admin/users/{id} | 403 | |
| Access billing of all users | User | /admin/billing | 403 | |

---

## Role Enumeration Notes

- Does application expose role names in JWT claims?
- Are role names visible in API responses?
- Can role names be guessed from URL structure (e.g., `/moderator/dashboard`)?
- Are role-specific endpoints discoverable via directory brute force?
