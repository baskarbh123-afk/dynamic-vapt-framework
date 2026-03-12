# Penetration Testing Methodology

## Framework Alignment

This framework aligns with industry-standard penetration testing methodologies:

| Standard | Coverage |
|----------|----------|
| **PTES** (Penetration Testing Execution Standard) | Full lifecycle |
| **OWASP WSTG** (Web Security Testing Guide v4.2) | Web-specific testing |
| **OWASP Top 10 (2021)** | Risk categorization |
| **CVSS v3.1** | Vulnerability scoring |
| **CWE** (Common Weakness Enumeration) | Weakness classification |

---

## Phase Model

```
┌─────────────────────────────────────────────────────────────┐
│                    PRE-ENGAGEMENT                            │
│  config.yaml → setup.py → Scope + Authorization Confirmed   │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  PHASE 1: RECONNAISSANCE                                     │
│  Passive OSINT → DNS → CT Logs → Active Fingerprinting       │
│  Output: Attack surface understanding                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  PHASE 2: ENUMERATION                                        │
│  Services → Endpoints → APIs → Auth Flows → Parameters       │
│  Output: Complete application map                            │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  PHASE 3: EXPLOITATION                                       │
│  Auth → Web → API → Infrastructure → Business Logic          │
│  Output: Confirmed vulnerabilities with PoC                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  PHASE 4: POST-EXPLOITATION                                  │
│  Priv Esc → Data Access → Lateral Movement → Persistence     │
│  Output: Full impact assessment + Cleanup                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  PHASE 5: REPORTING                                          │
│  Executive Summary → Technical Report → Findings → PoCs      │
│  Output: Professional deliverables                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Differences: VA vs PT

| Aspect | Vulnerability Assessment (VA) | Penetration Testing (PT) |
|--------|-------------------------------|--------------------------|
| **Approach** | Identify vulnerabilities | Exploit vulnerabilities |
| **Depth** | Broad, shallow scanning | Deep, targeted testing |
| **Exploitation** | None or automated only | Manual + controlled exploitation |
| **Post-Exploitation** | Not included | Impact assessment included |
| **Attack Chains** | Individual findings only | Multi-step attack paths |
| **Output** | Vulnerability list | Business impact demonstration |
| **Methodology** | Scan → Report | Recon → Enum → Exploit → Post-Exploit → Report |

---

## OWASP WSTG Mapping

| WSTG Category | Framework Phase | Modules |
|---------------|----------------|---------|
| WSTG-INFO | Phase 1 (Recon) | PASSIVE_RECON, ACTIVE_RECON |
| WSTG-CONF | Phase 2 (Enum) + Phase 3 | SECURITY_MISCONFIG, SERVICE_ENUM |
| WSTG-IDNT | Phase 2 (Enum) | AUTH_ENUMERATION |
| WSTG-ATHN | Phase 3 (Exploit) | AUTHENTICATION, JWT_SECURITY, OAUTH |
| WSTG-ATHZ | Phase 3 (Exploit) | AUTHORIZATION, IDOR, PRIVILEGE_ESCALATION |
| WSTG-SESS | Phase 2 (Enum) | AUTH_ENUMERATION, SESSION_HANDLING |
| WSTG-INPV | Phase 3 (Exploit) | XSS, SQLi, SSRF, CMDi, XXE, SSTI |
| WSTG-ERRH | Phase 2 (Enum) | WEB_ENUMERATION |
| WSTG-CRYP | Phase 2 (Enum) | AUTH_ENUMERATION (token analysis) |
| WSTG-BUSN | Phase 3 (Exploit) | BUSINESS_LOGIC, RATE_LIMITING |
| WSTG-CLNT | Phase 3 (Exploit) | XSS, CLICKJACKING, OPEN_REDIRECT |

---

## Evidence Standards

For every confirmed finding:
1. **HTTP Request** — Full curl-reproducible command
2. **HTTP Response** — Relevant response excerpt
3. **Screenshot** — Browser/Burp evidence (PII redacted)
4. **Timestamp** — When the finding was confirmed
5. **Environment** — Browser, tools, network context
