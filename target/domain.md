# Target Domain Information

## Primary Domain

| Field | Value |
|---|---|
| Primary Domain | |
| Application Name | |
| Application Version | |
| Environment | Production / Staging / UAT |
| Base URL | https:// |

---

## URL Inventory

### Web Application URLs
| # | URL | Function | Auth Required |
|---|---|---|---|
| 1 | /login | Login page | No |
| 2 | /register | Registration | No |
| 3 | /dashboard | Main dashboard | Yes |
| 4 | /profile | User profile | Yes |
| 5 | /admin | Admin panel | Admin |
| 6 | /api/v1/ | API base | Varies |

*(Add all discovered endpoints here during recon)*

---

## API Endpoints

### REST API
| # | Method | Endpoint | Auth | Description |
|---|---|---|---|---|
| 1 | POST | /api/v1/login | No | Auth token issuance |
| 2 | GET | /api/v1/users/me | Bearer | Current user info |
| 3 | GET | /api/v1/users/{id} | Bearer | User by ID |
| 4 | PUT | /api/v1/users/{id} | Bearer | Update user |
| 5 | DELETE | /api/v1/users/{id} | Bearer | Delete user |

*(Add all discovered API endpoints)*

### GraphQL (if applicable)
| Field | Value |
|---|---|
| GraphQL Endpoint | /graphql |
| Introspection Enabled | Yes / No |
| Playground Exposed | Yes / No |

---

## Subdomains

| # | Subdomain | Purpose | In Scope |
|---|---|---|---|
| 1 | api. | API gateway | Yes / No |
| 2 | admin. | Admin interface | Yes / No |
| 3 | static. | Static assets | No |
| 4 | cdn. | Content delivery | No |

---

## Third-Party Integrations

| # | Service | Integration Type | In Scope |
|---|---|---|---|
| 1 | | OAuth provider | No |
| 2 | | Payment processor | No |
| 3 | | Email service | No |

---

## Network Notes

| Field | Value |
|---|---|
| WAF Detected | Yes / No — Product: |
| Load Balancer | Yes / No |
| CDN | Yes / No — Provider: |
| Reverse Proxy | Yes / No |
