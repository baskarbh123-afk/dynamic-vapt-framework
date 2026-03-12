# Reports Index
> Engagement: Multi-Target Penetration Test
> Date: 2026-03-12
> Tester: Baskar

---

## Report Structure

| Report | Location | Status |
|--------|----------|--------|
| Executive Summary | reports/EXECUTIVE_SUMMARY.md | Complete |
| Individual Findings | reports/findings/F-001 to F-007 | Complete (7 findings) |

---

## Finding Index

| ID | Vulnerability | Severity | CVSS | Target | Status |
|----|---------------|----------|------|--------|--------|
| F-001 | Swagger API Documentation Publicly Exposed | Medium | 5.3 | gopps.global.com | Open |
| F-002 | API Status Endpoint Exposes Internal Application Details | Medium | 5.3 | gopps.global.com | Open |
| F-003 | Internal Environment URLs Leaked in JavaScript Bundle | Medium | 5.3 | gopps.global.com | Open |
| F-004 | WordPress REST API User Enumeration | Low | 3.7 | globalbuitenreclame.nl, fellasstudios.com, production.victoriousfestival.co.uk | Open |
| F-005 | XMLRPC Enabled with system.multicall | Low | 3.7 | production.victoriousfestival.co.uk, www.victoriousfestival.co.uk | Open |
| F-006 | ADFS OAuth Configuration Leaked via Auth Redirect | Medium | 5.3 | gopps.global.com | Open |
| F-007 | Sanity.io CMS Project ID and Dataset Exposed | Low | 3.7 | www.makesomenoise.com | Open |

---

## Severity Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 4 |
| Low | 3 |
| **Total** | **7** |

---

## Target Coverage

| # | Target | Status | Findings |
|---|--------|--------|----------|
| 1 | shop.globalbuitenreclame.nl | Tested | 0 (Laravel - well-secured) |
| 2 | globalbuitenreclame.nl | Tested | 1 (F-004: WP user enum) |
| 3 | gopps.global.com | Tested | 4 (F-001, F-002, F-003, F-006) |
| 4 | fellasstudios.com | Tested | 1 (F-004: WP user enum) |
| 5 | fellastudios.com | Redirect | N/A (redirects to out-of-scope domain) |
| 6 | remixd.com | Unreachable | N/A |
| 7 | dashboard.remixd.com | Unreachable | N/A |
| 8 | www.makesomenoise.com | Tested | 1 (F-007: Sanity.io exposure) |
| 9 | www.victoriousfestival.co.uk | Tested | 1 (F-005: XMLRPC) |
| 10 | production.victoriousfestival.co.uk | Tested | 2 (F-004, F-005) |
| 11 | www.transfirm.nl | Tested | 0 (Java/Spring - auth enforced) |
| 12 | global.madebywiser.com | Tested | 0 (Next.js - minimal attack surface) |
| 13 | 34.96.126.232:9801 | Unreachable | N/A |
