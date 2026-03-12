# OWASP Top 10 → CWE → Agent Mapping

This reference maps each OWASP Top 10 (2021) category to its associated CWE weaknesses, framework exploitation modules, and the responsible agent.

---

## Agent Assignment Matrix

| Agent | OWASP Category | Module Count | Priority |
|-------|---------------|-------------|----------|
| Agent 01 | A01 — Broken Access Control | 5 modules | Critical |
| Agent 02 | A02 — Cryptographic Failures | 3 modules | High |
| Agent 03 | A03 — Injection | 7 modules | Critical |
| Agent 04 | A04 — Insecure Design | 2 modules | Medium |
| Agent 05 | A05 — Security Misconfiguration | 5 modules | High |
| Agent 06 | A06 — Vulnerable Components | 2 modules | Medium |
| Agent 07 | A07 — Auth Failures | 3 modules | Critical |
| Agent 08 | A08 — Data Integrity Failures | 3 modules | High |
| Agent 09 | A09 — Logging Failures | 1 module | Low |
| Agent 10 | A10 — SSRF | 1 module | High |

---

## Detailed Mapping

### Agent 01 — Broken Access Control (A01:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-200 | Exposure of Sensitive Information | SENSITIVE_DATA_EXPOSURE | API over-exposure, response data leakage |
| CWE-284 | Improper Access Control | AUTHORIZATION | Endpoint access control enforcement |
| CWE-285 | Improper Authorization | AUTHORIZATION | Role-based access bypass |
| CWE-352 | Cross-Site Request Forgery | CSRF | State-changing action forgery |
| CWE-639 | Authorization Bypass via User-Controlled Key | IDOR | Direct object reference manipulation |
| CWE-862 | Missing Authorization | AUTHORIZATION | Unauthenticated endpoint access |
| CWE-863 | Incorrect Authorization | PRIVILEGE_ESCALATION | Vertical/horizontal privilege escalation |
| CWE-425 | Direct Request (Forced Browsing) | AUTHORIZATION | Bypassing access control via URL |

**Modules:** `AUTHORIZATION`, `IDOR`, `PRIVILEGE_ESCALATION`, `CSRF`, `SENSITIVE_DATA_EXPOSURE`

---

### Agent 02 — Cryptographic Failures (A02:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-261 | Weak Encoding for Password | AUTHENTICATION | Password storage mechanism |
| CWE-296 | Improper Following of Chain of Trust | JWT_SECURITY | Certificate/token chain validation |
| CWE-310 | Cryptographic Issues | JWT_SECURITY | Algorithm weakness, key management |
| CWE-319 | Cleartext Transmission | SENSITIVE_DATA_EXPOSURE | HTTP vs HTTPS, unencrypted tokens |
| CWE-326 | Inadequate Encryption Strength | JWT_SECURITY | Weak algorithms, short keys |
| CWE-327 | Use of Broken Crypto Algorithm | JWT_SECURITY | MD5, SHA1, DES usage |
| CWE-328 | Use of Weak Hash | AUTHENTICATION | Password hashing analysis |
| CWE-614 | Sensitive Cookie Without Secure Flag | SESSION_HANDLING | Cookie transport security |

**Modules:** `JWT_SECURITY`, `SENSITIVE_DATA_EXPOSURE`, `AUTHENTICATION` (crypto aspects)

---

### Agent 03 — Injection (A03:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-20 | Improper Input Validation | All injection modules | Input validation bypass |
| CWE-74 | Improper Neutralization of Special Elements | COMMAND_INJECTION | OS command injection |
| CWE-79 | Cross-site Scripting (XSS) | XSS | Reflected, Stored, DOM XSS |
| CWE-89 | SQL Injection | SQL_INJECTION | Error/Boolean/Time-based SQLi |
| CWE-94 | Code Injection | SSTI | Template injection, code eval |
| CWE-116 | Improper Encoding/Escaping of Output | XSS, HTML_INJECTION | Output encoding failures |
| CWE-611 | Improper Restriction of XML External Entity | XXE | XML entity expansion |
| CWE-917 | Improper Neutralization of Server-Side Includes | SSTI | Server-side template injection |
| CWE-77 | Command Injection | COMMAND_INJECTION | Argument injection |
| CWE-78 | OS Command Injection | COMMAND_INJECTION | System command execution |

**Modules:** `XSS`, `SQL_INJECTION`, `COMMAND_INJECTION`, `SSTI`, `XXE`, `HTML_INJECTION`, `PATH_TRAVERSAL`

---

### Agent 04 — Insecure Design (A04:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-209 | Information Exposure via Error Message | SECURITY_MISCONFIG | Verbose error messages |
| CWE-256 | Plaintext Storage of Password | AUTHENTICATION | Credential storage |
| CWE-501 | Trust Boundary Violation | BUSINESS_LOGIC | Client-side trust issues |
| CWE-522 | Insufficiently Protected Credentials | AUTHENTICATION | Credential transmission |
| CWE-841 | Improper Enforcement of Behavioral Workflow | BUSINESS_LOGIC | Workflow bypass |
| CWE-799 | Improper Control of Interaction Frequency | RATE_LIMITING | Rate limiting enforcement |

**Modules:** `BUSINESS_LOGIC`, `RATE_LIMITING`

---

### Agent 05 — Security Misconfiguration (A05:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-2 | Environment Configuration | SECURITY_MISCONFIG | Debug mode, default configs |
| CWE-11 | ASP.NET Misconfiguration | SECURITY_MISCONFIG | Framework-specific misconfig |
| CWE-16 | Configuration | SECURITY_MISCONFIG | General misconfiguration |
| CWE-388 | Error Handling | SECURITY_MISCONFIG | Error page information leakage |
| CWE-942 | Permissive Cross-domain Policy | CORS | CORS misconfiguration |
| CWE-1021 | Improper Restriction of Rendered UI Layers | CLICKJACKING | Frame embedding |
| CWE-444 | Inconsistent Interpretation of HTTP Requests | HTTP_SMUGGLING | Request smuggling |
| CWE-525 | Use of Web Browser Cache | CACHE_POISONING | Cache poisoning |

**Modules:** `SECURITY_MISCONFIG`, `CORS`, `CLICKJACKING`, `HTTP_SMUGGLING`, `CACHE_POISONING`

---

### Agent 06 — Vulnerable & Outdated Components (A06:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-937 | Using Components with Known Vulns | SUBDOMAIN_TAKEOVER | Abandoned service detection |
| CWE-1035 | OWASP Top 10 2017 A9 | Tech fingerprinting | Outdated component detection |
| CWE-1104 | Use of Unmaintained Third-Party Components | Tech fingerprinting | EOL component detection |

**Modules:** `SUBDOMAIN_TAKEOVER`, tech stack analysis (Phase 1-2)

---

### Agent 07 — Identification & Authentication Failures (A07:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-255 | Credentials Management Errors | AUTHENTICATION | Credential handling flaws |
| CWE-259 | Use of Hard-coded Password | AUTHENTICATION | Default/hardcoded credentials |
| CWE-287 | Improper Authentication | AUTHENTICATION | Authentication bypass |
| CWE-288 | Authentication Bypass via Alternate Path | AUTHENTICATION | Alternative auth path bypass |
| CWE-290 | Authentication Bypass by Spoofing | AUTHENTICATION | IP/header spoofing |
| CWE-294 | Authentication Bypass by Capture-replay | OAUTH | Token replay attacks |
| CWE-295 | Improper Certificate Validation | OAUTH | Certificate/token validation |
| CWE-384 | Session Fixation | SESSION_HANDLING | Pre-auth session reuse |
| CWE-613 | Insufficient Session Expiration | SESSION_HANDLING | Token lifetime issues |

**Modules:** `AUTHENTICATION`, `OAUTH`, `SESSION_HANDLING`

---

### Agent 08 — Software & Data Integrity Failures (A08:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-345 | Insufficient Verification of Data Authenticity | MASS_ASSIGNMENT | Unsigned data acceptance |
| CWE-353 | Missing Support for Integrity Check | FILE_UPLOAD | Upload integrity bypass |
| CWE-426 | Untrusted Search Path | PATH_TRAVERSAL | Path manipulation |
| CWE-494 | Download of Code Without Integrity Check | SECURITY_MISCONFIG | CDN/resource integrity |
| CWE-502 | Deserialization of Untrusted Data | REST_API | Unsafe deserialization |
| CWE-565 | Reliance on Cookies Without Validation | SESSION_HANDLING | Cookie integrity |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | FILE_UPLOAD | Uploaded code execution |

**Modules:** `MASS_ASSIGNMENT`, `FILE_UPLOAD`, `REST_API`

---

### Agent 09 — Security Logging & Monitoring Failures (A09:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-117 | Improper Output Neutralization for Logs | LOGGING_AUDIT | Log injection |
| CWE-223 | Omission of Security-relevant Information | LOGGING_AUDIT | Missing audit events |
| CWE-532 | Insertion of Sensitive Info into Log File | LOGGING_AUDIT | Sensitive data in logs |
| CWE-778 | Insufficient Logging | LOGGING_AUDIT | Event coverage gaps |

**Modules:** `LOGGING_AUDIT` (assessed during post-exploitation)

---

### Agent 10 — Server-Side Request Forgery (A10:2021)

| CWE | Name | Module | Test Focus |
|-----|------|--------|------------|
| CWE-918 | Server-Side Request Forgery | SSRF | Internal service access |
| CWE-441 | Unintended Proxy or Intermediary | SSRF | Proxy abuse |
| CWE-601 | URL Redirection to Untrusted Site | OPEN_REDIRECT | Redirect chain to SSRF |

**Modules:** `SSRF`, `OPEN_REDIRECT`

---

## Quick Reference: CWE → Agent Lookup

| CWE | Agent | OWASP |
|-----|-------|-------|
| CWE-20 | Agent 03 | A03 |
| CWE-74 | Agent 03 | A03 |
| CWE-77 | Agent 03 | A03 |
| CWE-78 | Agent 03 | A03 |
| CWE-79 | Agent 03 | A03 |
| CWE-89 | Agent 03 | A03 |
| CWE-94 | Agent 03 | A03 |
| CWE-116 | Agent 03 | A03 |
| CWE-117 | Agent 09 | A09 |
| CWE-200 | Agent 01 | A01 |
| CWE-209 | Agent 04 | A04 |
| CWE-255 | Agent 07 | A07 |
| CWE-259 | Agent 07 | A07 |
| CWE-261 | Agent 02 | A02 |
| CWE-284 | Agent 01 | A01 |
| CWE-285 | Agent 01 | A01 |
| CWE-287 | Agent 07 | A07 |
| CWE-288 | Agent 07 | A07 |
| CWE-290 | Agent 07 | A07 |
| CWE-294 | Agent 07 | A07 |
| CWE-295 | Agent 07 | A07 |
| CWE-296 | Agent 02 | A02 |
| CWE-310 | Agent 02 | A02 |
| CWE-319 | Agent 02 | A02 |
| CWE-326 | Agent 02 | A02 |
| CWE-327 | Agent 02 | A02 |
| CWE-345 | Agent 08 | A08 |
| CWE-352 | Agent 01 | A01 |
| CWE-353 | Agent 08 | A08 |
| CWE-384 | Agent 07 | A07 |
| CWE-425 | Agent 01 | A01 |
| CWE-426 | Agent 08 | A08 |
| CWE-441 | Agent 10 | A10 |
| CWE-444 | Agent 05 | A05 |
| CWE-494 | Agent 08 | A08 |
| CWE-501 | Agent 04 | A04 |
| CWE-502 | Agent 08 | A08 |
| CWE-522 | Agent 04 | A04 |
| CWE-525 | Agent 05 | A05 |
| CWE-532 | Agent 09 | A09 |
| CWE-565 | Agent 08 | A08 |
| CWE-601 | Agent 10 | A10 |
| CWE-611 | Agent 03 | A03 |
| CWE-613 | Agent 07 | A07 |
| CWE-614 | Agent 02 | A02 |
| CWE-639 | Agent 01 | A01 |
| CWE-778 | Agent 09 | A09 |
| CWE-799 | Agent 04 | A04 |
| CWE-829 | Agent 08 | A08 |
| CWE-841 | Agent 04 | A04 |
| CWE-862 | Agent 01 | A01 |
| CWE-863 | Agent 01 | A01 |
| CWE-917 | Agent 03 | A03 |
| CWE-918 | Agent 10 | A10 |
| CWE-937 | Agent 06 | A06 |
| CWE-942 | Agent 05 | A05 |
| CWE-1021 | Agent 05 | A05 |
| CWE-1035 | Agent 06 | A06 |
| CWE-1104 | Agent 06 | A06 |
