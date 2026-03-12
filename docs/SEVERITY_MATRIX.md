# Severity Classification Matrix

## Rating System

Based on OWASP Risk Rating Methodology: `Severity = f(Likelihood, Impact)`

---

## Severity Levels

### Critical
**CVSS Score Range: 9.0 – 10.0**

Immediate exploitation possible; no authentication required or trivially bypassed. Direct impact on confidentiality, integrity, or availability of sensitive systems or data.

**Examples:**
- Remote Code Execution (RCE) / Command Injection
- SQL Injection with direct data exfiltration
- Authentication bypass granting full admin access
- Server-Side Request Forgery reaching internal metadata/cloud credentials
- Stored XSS in admin panel with session hijack
- Exposed credentials / API keys with production access

**Response:** Report to client immediately. Do not attempt further exploitation.

---

### High
**CVSS Score Range: 7.0 – 8.9**

Exploitation requires some conditions (authenticated user, specific context) but has significant impact on multiple users or sensitive data.

**Examples:**
- Insecure Direct Object Reference (IDOR) exposing other users' PII
- Vertical Privilege Escalation (user → admin)
- JWT algorithm confusion / `alg:none` leading to auth bypass
- Stored XSS in user-facing page (session hijack possible)
- CSRF on account-critical actions (password change, email change)
- Path traversal reading sensitive server files
- XXE with internal file disclosure
- Mass assignment allowing role escalation

**Response:** Document with full PoC. Prioritize in report.

---

### Medium
**CVSS Score Range: 4.0 – 6.9**

Exploitation is possible under specific conditions or impact is limited in scope. Represents meaningful security gap.

**Examples:**
- Reflected XSS (requires user interaction)
- IDOR exposing non-critical user data
- Missing rate limiting on login / OTP endpoints
- Horizontal privilege escalation (user A accesses user B data)
- Open redirect (usable in phishing)
- HTML injection in user-facing content
- Weak password policy
- Missing security headers (CSP, HSTS, X-Frame-Options)
- CORS misconfiguration (allowing specific attacker-controlled origin)
- Sensitive data in error messages
- Clickjacking on sensitive action pages

**Response:** Document with reproduction steps.

---

### Low
**CVSS Score Range: 0.1 – 3.9**

Limited exploitability or requires highly specific conditions. Represents security hygiene issues.

**Examples:**
- Missing cookie `HttpOnly` or `Secure` flag (without active XSS)
- Stack traces / verbose errors without sensitive data
- Software version disclosure
- Missing `X-Content-Type-Options` header
- Autocomplete enabled on non-sensitive forms
- Cacheable HTTPS responses for public content
- Banner grabbing (server version in headers)

**Response:** Note in report appendix.

---

### Informational
**No direct security impact**

Observations that indicate non-optimal security posture but do not directly present exploitable risk.

**Examples:**
- HTTPS redirect in place but HTTP accessible
- Password complexity enforced but not complexity scored
- Security headers partially implemented
- Logout does not clear all tokens

---

## OWASP Risk Rating Factors

### Likelihood Factors

| Factor | Low (1-3) | Medium (4-6) | High (7-9) |
|---|---|---|---|
| Threat Agent Skill | Advanced attacker | Some technical skill | No skill needed |
| Motive | Low reward | Some reward | High reward |
| Opportunity | Full access needed | Some access needed | No access needed |
| Population | Rare (developers) | Authenticated users | Anonymous/all users |

### Impact Factors

| Factor | Low | Medium | High |
|---|---|---|---|
| Confidentiality | Minimal data | Critical data | All data |
| Integrity | Minor data change | Serious data change | All data corrupt |
| Availability | Minor interruption | Significant interruption | Full shutdown |
| Accountability | Fully traceable | Possibly traceable | Completely anonymous |

---

## Quick Reference — Vulnerability Severity Defaults

| Vulnerability | Default Severity | Escalation Conditions |
|---|---|---|
| RCE / Command Injection | Critical | Any |
| SQLi (data exfil) | Critical → High | Read-only vs write access |
| Auth Bypass | Critical → High | Admin vs user access |
| Stored XSS | High | Admin panel = Critical |
| SSRF | High → Critical | Cloud metadata access = Critical |
| IDOR (PII) | High | Volume of data exposed |
| CSRF (account takeover) | High | Password/email change |
| JWT alg:none | Critical | Any |
| Path Traversal (system files) | High | Credentials visible = Critical |
| Open Redirect | Medium | Token theft via redirect = High |
| CORS misconfiguration | Medium → High | Auth credentials included = High |
| Missing Rate Limiting | Medium | Account takeover possible = High |
| Clickjacking | Medium | Admin action = High |
| Sensitive Data Exposure | Medium → Critical | Depends on data type |
