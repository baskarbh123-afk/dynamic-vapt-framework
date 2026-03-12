# Attack Surface Map
> Auto-generated from config.yaml on 2026-03-12 21:20:54
> Complete this during the Reconnaissance and Enumeration phases.

---

## Attack Surface Overview

### Entry Points

| # | Entry Point | Type | Auth | Risk Level | Notes |
|---|-------------|------|------|------------|-------|
| 1 | Login form | Web Form | None | High | Credential-based |
| 2 | Registration | Web Form | None | Medium | Account creation |
| 3 | API | REST/GraphQL | Bearer | High | Data access |
| 4 | File Upload | Form | User | High | Code execution risk |
| 5 | Search | Query Param | None | Medium | Injection risk |
| 6 | Password Reset | Web Form | None | High | Account takeover |

*(Customize based on target application)*

---

## Authentication Surface

| Mechanism | Endpoint | Test Priority |
|-----------|----------|---------------|
| Form Login | | High |
| JWT Issuance | | High |
| OAuth Flow | | High |
| MFA | | Medium |
| Password Reset | | High |
| API Key Auth | | Medium |

---

## Data Flow Diagram

```
[User Browser] → [CDN/WAF] → [Load Balancer] → [Web Server] → [App Server] → [Database]
                                                      ↕                              ↕
                                               [File Storage]                 [Cache Layer]
                                                      ↕
                                               [Third-Party APIs]
```

---

## High-Value Targets

| Target | Why | Phase to Test |
|--------|-----|---------------|
| Admin Panel | Full system control | Exploitation |
| User Data API | PII exposure | Exploitation |
| File Upload | Code execution | Exploitation |
| Payment Flow | Financial impact | Exploitation |
| Auth Tokens | Session hijack | Enumeration + Exploitation |

---

## Security Controls Observed

| Control | Present | Effectiveness | Notes |
|---------|---------|---------------|-------|
| WAF | | | |
| Rate Limiting | | | |
| CAPTCHA | | | |
| CSP Header | | | |
| HSTS | | | |
| Input Sanitization | | | |
| CORS Policy | | | |
