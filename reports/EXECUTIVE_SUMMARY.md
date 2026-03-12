# Executive Summary — Multi-Target Penetration Test

**Date:** 2026-03-12
**Tester:** Baskar
**Methodology:** PTES (Penetration Testing Execution Standard)
**Classification:** CONFIDENTIAL

---

## Engagement Overview

A penetration test was conducted against 13 authorized targets. Of these, 10 were reachable, 3 were unreachable (remixd.com, dashboard.remixd.com, 34.96.126.232:9801), and 1 redirected to an out-of-scope domain (fellastudios.com).

Testing followed the standard PTES lifecycle: Reconnaissance → Enumeration → Exploitation → Post-Exploitation → Reporting. All testing was non-destructive and stopped at proof-of-concept confirmation.

---

## Key Findings

**5 vulnerabilities** were confirmed across the in-scope targets:

| Severity | Count | Description |
|----------|-------|-------------|
| **Critical** | 0 | — |
| **High** | 0 | — |
| **Medium** | 3 | Swagger API exposure, API info disclosure, JS bundle leaks (gopps.global.com) |
| **Low** | 2 | WordPress user enumeration, XMLRPC enabled |

---

## Highest Risk: gopps.global.com

The **gopps.global.com** application (IIS/ASP.NET React SPA) had the most significant findings:

1. **Full Swagger API documentation exposed** — 45 API endpoints and 96 data models publicly accessible without authentication, including order management, property management, authentication, and data export endpoints.

2. **API status endpoint leaks internal details** — Application version, permission model structure, and configuration field names (database, ElasticSearch) exposed without authentication.

3. **Internal environment URLs hardcoded in JS bundle** — Development, integration, test, and UAT environment URLs discoverable in client-side code. The UAT environment (goppsuat.global.com) is publicly accessible with its own Swagger documentation exposed.

---

## Well-Secured Targets

Several targets demonstrated good security posture:

- **shop.globalbuitenreclame.nl** (Laravel) — Proper CSRF protection, session management, and CSP headers. Horizon dashboard protected behind auth. S3 bucket properly secured.
- **www.transfirm.nl** (Java/Spring) — All admin, actuator, and API endpoints properly require authentication. CSRF tokens implemented.
- **www.makesomenoise.com** and **global.madebywiser.com** (Next.js) — Minimal attack surface, no exposed APIs or sensitive endpoints.
- **www.victoriousfestival.co.uk** — WordPress REST API user endpoint properly blocked (403). iThemes Security plugin active.

---

## Recommendations (Priority Order)

1. **Immediate:** Remove Swagger documentation from production and UAT on gopps.global.com
2. **Immediate:** Restrict `/api/status` and `/api/about` endpoints behind authentication
3. **Short-term:** Remove internal environment URLs from production JavaScript bundles
4. **Short-term:** Restrict UAT/dev environments to internal networks (VPN/firewall)
5. **Medium-term:** Disable WordPress REST API user enumeration on affected sites
6. **Medium-term:** Disable XMLRPC on production.victoriousfestival.co.uk

---

## Testing Limitations

- 3 targets were unreachable during testing (remixd.com, dashboard.remixd.com, 34.96.126.232:9801)
- No authenticated testing was performed (no test credentials provided)
- Testing was limited to non-destructive techniques per engagement rules
- Rate limiting was respected (max 10 req/s)
