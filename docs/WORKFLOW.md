# Penetration Testing Engagement Workflow

## Methodology: 5-Phase PT Lifecycle

This framework follows a structured penetration testing methodology aligned with PTES (Penetration Testing Execution Standard) and OWASP WSTG.

---

## Phase 0 — Pre-Engagement Setup

### Configuration
- [ ] Fill `config.yaml` with all engagement parameters
- [ ] Run `python3 setup.py --validate` to check configuration
- [ ] Run `python3 setup.py` to populate all target folders
- [ ] Review generated files in scope/, targets/, credentials/

### Authorization
- [ ] Obtain signed Rules of Engagement (RoE) document
- [ ] Set `authorization.roe_signed: true` in config.yaml
- [ ] Confirm testing window and emergency contact
- [ ] Whitelist tester IPs if required

### Verification
```bash
python3 setup.py --validate    # Check config completeness
python3 setup.py               # Populate folders
python3 setup.py --status      # Display engagement status
```

---

## Phase 1 — Reconnaissance
**Directory:** `phases/01-recon/`

Gather intelligence about the target without causing impact.

| Step | Module | Type |
|------|--------|------|
| 1.1 | PASSIVE_RECON.md | Passive — DNS, OSINT, CT logs, dorking |
| 1.2 | SUBDOMAIN_ENUM.md | Passive/Active — Subdomain discovery |
| 1.3 | ACTIVE_RECON.md | Active — Fingerprinting, endpoint discovery |

### Key Outputs
- targets/domain.md — Updated with discoveries
- targets/tech_stack.md — Stack fingerprinted
- targets/attack_surface.md — Initial attack surface

### Completion
- [ ] Technology stack identified
- [ ] Subdomains enumerated
- [ ] Initial endpoint list built
- [ ] Update logs/phase_tracker.md

---

## Phase 2 — Enumeration
**Directory:** `phases/02-enumeration/`

Systematically catalog all services, endpoints, and authentication mechanisms.

| Step | Module | Focus |
|------|--------|-------|
| 2.1 | SERVICE_ENUMERATION.md | Ports, protocols, methods |
| 2.2 | WEB_ENUMERATION.md | Pages, forms, parameters |
| 2.3 | API_ENUMERATION.md | REST, GraphQL, WebSocket |
| 2.4 | AUTH_ENUMERATION.md | Auth flows, sessions, RBAC |

### Key Outputs
- targets/endpoints.md — Full endpoint inventory
- docs/AUTH_FLOW.md — Authentication flows mapped
- docs/SESSION_HANDLING.md — Session analysis

### Completion
- [ ] All endpoints documented
- [ ] Authentication flows mapped
- [ ] Input vectors identified
- [ ] Update logs/phase_tracker.md

---

## Phase 3 — Exploitation
**Directory:** `phases/03-exploitation/`

Confirm vulnerabilities with controlled proof-of-concept testing.

### Module Selection
Select modules based on tech stack and enumeration findings:

| Category | Modules | When to Run |
|----------|---------|-------------|
| **auth/** | AUTHENTICATION, AUTHORIZATION, JWT_SECURITY, OAUTH, IDOR | Always |
| **web/** | XSS, SQL_INJECTION, CSRF, SSRF, etc. | Based on input vectors |
| **api/** | REST_API, GRAPHQL, WEBSOCKET, MASS_ASSIGNMENT | If APIs discovered |
| **infra/** | SECURITY_MISCONFIG, CORS, CLICKJACKING, etc. | Always (config checks) |

### Per Finding
1. Confirm with minimum safe payload
2. Capture HTTP request/response evidence
3. Create finding report: `reports/findings/F-XXX.md`
4. Create PoC: `reports/poc/POC-XXX.md`
5. Log in engagement log

### Completion
- [ ] All applicable modules executed
- [ ] All findings documented
- [ ] Critical/High findings reported immediately
- [ ] Update logs/phase_tracker.md

---

## Phase 4 — Post-Exploitation
**Directory:** `phases/04-post-exploitation/`

Assess the full impact of confirmed vulnerabilities (assessment only — no full exploitation).

| Step | Module | Focus |
|------|--------|-------|
| 4.1 | PRIVILEGE_ESCALATION.md | Escalation paths from confirmed vulns |
| 4.2 | DATA_ACCESS_ASSESSMENT.md | Data types reachable via vulns |
| 4.3 | LATERAL_MOVEMENT_ASSESSMENT.md | Pivot potential (theoretical) |
| 4.4 | PERSISTENCE_ASSESSMENT.md | Persistence risk evaluation |
| 4.5 | CLEANUP.md | Remove ALL test artifacts |

### Completion
- [ ] Impact fully assessed
- [ ] Attack chains documented
- [ ] All test artifacts cleaned up
- [ ] Update logs/phase_tracker.md

---

## Phase 5 — Reporting
**Directory:** `phases/05-reporting/`

Compile findings into professional, actionable reports.

| Deliverable | Template | Audience |
|-------------|----------|----------|
| Executive Summary | EXECUTIVE_SUMMARY_TEMPLATE.md | Management |
| Technical Report | TECHNICAL_REPORT_TEMPLATE.md | Security/Dev teams |
| Individual Findings | FINDINGS_TEMPLATE.md | Developers |
| Proof of Concepts | POC_TEMPLATE.md | Developers/QA |

### Report Quality Checklist
- [ ] Every finding has CVSS 3.1 score + vector
- [ ] Every finding has step-by-step reproduction
- [ ] Remediation is specific with code examples
- [ ] PII redacted from all evidence
- [ ] CWE and OWASP WSTG references included

### Completion
- [ ] All reports generated
- [ ] Reports reviewed for accuracy
- [ ] Delivered to client
- [ ] Update logs/phase_tracker.md

---

## Master Checklist

```
[ ] Phase 0 — Config populated, setup.py executed, authorization confirmed
[ ] Phase 1 — Reconnaissance complete (passive + active)
[ ] Phase 2 — Enumeration complete (services, web, API, auth)
[ ] Phase 3 — Exploitation complete (all modules, all findings documented)
[ ] Phase 4 — Post-exploitation assessed, cleanup done
[ ] Phase 5 — Reports generated, reviewed, and delivered
```

---

## Quick Reference: CLI Commands

```bash
# Setup
python3 setup.py --validate       # Validate config
python3 setup.py                   # Populate folders
python3 setup.py --status          # Show engagement status
python3 setup.py --update          # Re-read and update

# Claude Commands
/pt-start                         # Initialize PT session
/pt-exploit                       # Controlled exploitation prompt
/pt-report                        # Generate reports
/pt-phase [N]                     # Execute phase N
/pt-module [name]                 # Execute specific module
/pt-status                        # Show progress
```
