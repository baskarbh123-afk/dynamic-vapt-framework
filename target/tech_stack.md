# Technology Stack

## Detection Methods

```bash
# Passive detection via headers
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-generator"

# Active fingerprinting
whatweb -a 3 https://target.com
nuclei -u https://target.com -t technologies/ -silent

# WAF detection
wafw00f https://target.com

# SSL/TLS analysis
sslyze --regular target.com:443
```

---

## Backend

| Field | Value |
|---|---|
| Language / Runtime | |
| Framework | |
| Web Server | |
| Application Server | |
| Version | |
| Evidence | Header / Response body / Error page |

**Examples:** Python/Django, Node.js/Express, PHP/Laravel, Java/Spring, Ruby/Rails, .NET/ASP.NET Core

---

## Frontend

| Field | Value |
|---|---|
| JavaScript Framework | |
| Template Engine | |
| CSS Framework | |
| Build Tool | |

**Examples:** React, Vue, Angular, Next.js, Handlebars, Jinja2, Thymeleaf

---

## Database

| Field | Value |
|---|---|
| Database Type | |
| ORM / Query Builder | |
| Database Version (if observable) | |

**Determines:** SQL injection type (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), NoSQL injection (MongoDB, Redis)

---

## Authentication Mechanism

| Field | Value |
|---|---|
| Session Type | Cookie / JWT / API Key / OAuth |
| Token Algorithm (JWT) | HS256 / RS256 / ES256 |
| MFA Present | Yes / No |
| OAuth Provider | Google / GitHub / Custom |
| SSO Type | SAML / OIDC |

---

## Infrastructure

| Field | Value |
|---|---|
| Cloud Provider | AWS / GCP / Azure / On-prem |
| Container Platform | Docker / Kubernetes |
| CDN | Cloudflare / Fastly / Akamai |
| WAF | Cloudflare / ModSecurity / AWS WAF |
| Load Balancer | Nginx / HAProxy / ALB |

---

## File Upload Handling

| Field | Value |
|---|---|
| Upload Allowed | Yes / No |
| Storage Type | Local / S3 / GCS / Azure Blob |
| CDN-served Uploads | Yes / No |
| Direct Execution of Uploads | Yes / No |
| MIME Type Validation | Client-side only / Server-side |

---

## API Type

| Field | Value |
|---|---|
| API Style | REST / GraphQL / gRPC / SOAP |
| API Version | v1 / v2 |
| API Documentation | Swagger/OpenAPI / None |
| Authentication | Bearer / API Key / Cookie |

---

## Security Controls Observed

| Control | Present | Notes |
|---|---|---|
| WAF | Yes/No | |
| Rate Limiting | Yes/No | |
| CAPTCHA | Yes/No | Login / Registration |
| CSP Header | Yes/No | |
| HSTS | Yes/No | |
| Input Sanitization | Yes/No | Client/Server |
