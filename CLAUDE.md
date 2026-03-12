# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This is a professional, modular Markdown-based framework for conducting structured, controlled **Web Application Penetration Testing (PT)** engagements. It follows the PTES (Penetration Testing Execution Standard) methodology with a 5-phase lifecycle: Reconnaissance → Enumeration → Exploitation → Post-Exploitation → Reporting.

All content is documentation and testing methodology — the framework provides structured guidance for each phase of a penetration test.

---

## Dependencies

Python 3 with `pyyaml` (`pip3 install pyyaml`). No other external dependencies for the framework scripts.

## Quick Start

```bash
# 1. Fill config.yaml with engagement parameters
# 2. Validate configuration
python3 setup.py --validate

# 3. Populate all target folders
python3 setup.py

# 4. Check status
python3 setup.py --status

# 5. Initialize Claude session with prompts/START_PT_SESSION.md
```

---

## Centralized Configuration

**All engagement parameters live in `config.yaml`** — this is the single source of truth.

The setup script (`setup.py`) reads config.yaml and auto-populates:
- `scope/` — targets, exclusions, constraints
- `targets/` — domain, tech_stack, endpoints, attack_surface
- `credentials/` — accounts, api_keys, oauth
- `reports/` — INDEX.md initialized
- `logs/` — engagement.log + phase_tracker.md
- `evidence/` — screenshots/ + http-logs/ directories

---

## Engagement Workflow

Follow this 5-phase sequence for every engagement (`docs/WORKFLOW.md`):

1. **Pre-Engagement** — Fill `config.yaml`, run `setup.py`, confirm authorization
2. **Phase 1: Reconnaissance** — Passive OSINT, active fingerprinting, subdomain enumeration (`phases/01-recon/`)
3. **Phase 2: Enumeration** — Services, endpoints, APIs, auth flows (`phases/02-enumeration/`)
4. **Phase 3: Exploitation** — Controlled PoC testing across auth, web, API, infra modules (`phases/03-exploitation/`)
5. **Phase 4: Post-Exploitation** — Impact assessment, attack chains, cleanup (`phases/04-post-exploitation/`)
6. **Phase 5: Reporting** — Executive summary, technical report, findings, PoCs (`phases/05-reporting/`)

---

## Absolute Rules (`docs/RULES.md`)

- Test **only** targets listed in `scope/targets.md` (from config.yaml)
- **No DoS**, no brute force, no destructive payloads
- **Stop at proof-of-concept** — confirm the vulnerability, do not exploit further
- **No real user data extraction** — note field types only, not values
- All testing requires **prior written authorization** (`authorization.roe_signed: true`)
- Complete phases **in order** — do not skip to exploitation without enumeration
- **Log all actions** in `logs/engagement.log`

---

## Allowed Tools (`tools/ALLOWED_TOOLS.md`)

`curl`, `nuclei`, `ffuf`, `dirsearch`, `Burp Suite`, `sqlmap` (safe mode only — `--level=2 --risk=1 --technique=BT`, never `--dump`), `Python/Selenium/Playwright`, `jwt_tool`, `sslyze`, `subfinder`, `subjack`, `interactsh`. No brute-force tools.

---

## Phase & Module Index

### Phase 1: Reconnaissance (`phases/01-recon/`)

| Module | Focus |
|--------|-------|
| PASSIVE_RECON | DNS, OSINT, CT logs, search engine dorking |
| ACTIVE_RECON | Tech fingerprinting, endpoint discovery, SSL/TLS |
| SUBDOMAIN_ENUM | Subdomain discovery, takeover checks |

### Phase 2: Enumeration (`phases/02-enumeration/`)

| Module | Focus |
|--------|-------|
| SERVICE_ENUMERATION | Ports, protocols, HTTP methods |
| WEB_ENUMERATION | Pages, forms, parameters, input vectors |
| API_ENUMERATION | REST, GraphQL, WebSocket discovery |
| AUTH_ENUMERATION | Auth flows, sessions, RBAC mapping |

### Phase 3: Exploitation (`phases/03-exploitation/`)

| Category | Modules |
|----------|---------|
| **auth/** | AUTHENTICATION, AUTHORIZATION, JWT_SECURITY, OAUTH, IDOR |
| **web/** | XSS, SQL_INJECTION, COMMAND_INJECTION, SSRF, CSRF, FILE_UPLOAD, PATH_TRAVERSAL, XXE, SSTI, OPEN_REDIRECT, HTML_INJECTION, BUSINESS_LOGIC, RATE_LIMITING |
| **api/** | REST_API, GRAPHQL, WEBSOCKET, MASS_ASSIGNMENT |
| **infra/** | SECURITY_MISCONFIG, CORS, CLICKJACKING, HTTP_SMUGGLING, CACHE_POISONING, SUBDOMAIN_TAKEOVER, SENSITIVE_DATA_EXPOSURE |

### Phase 4: Post-Exploitation (`phases/04-post-exploitation/`)

| Module | Focus |
|--------|-------|
| PRIVILEGE_ESCALATION | Vertical/horizontal escalation assessment |
| DATA_ACCESS_ASSESSMENT | Data scope and sensitivity evaluation |
| LATERAL_MOVEMENT_ASSESSMENT | Pivot potential (theoretical only) |
| PERSISTENCE_ASSESSMENT | Persistence risk evaluation |
| CLEANUP | Remove all test artifacts |

### Phase 5: Reporting (`phases/05-reporting/`)

| Template | Use |
|----------|-----|
| FINDINGS_TEMPLATE.md | One per confirmed vulnerability — CVSS, reproduction, remediation |
| POC_TEMPLATE.md | One per finding — runnable reproduction script |
| EXECUTIVE_SUMMARY_TEMPLATE.md | Management-level summary |
| TECHNICAL_REPORT_TEMPLATE.md | Full technical report with methodology |

---

## Reporting

Severity classification: `docs/SEVERITY_MATRIX.md` (OWASP Low/Medium/High/Critical with CVSS 3.1)

All findings indexed in: `reports/INDEX.md`

Individual findings: `reports/findings/F-XXX.md`

Proof of concepts: `reports/poc/POC-XXX.md`

---

## Logging & Tracking

| File | Purpose |
|------|---------|
| `logs/engagement.log` | Timestamped log of all testing actions |
| `logs/phase_tracker.md` | Phase progress and finding counters |
| `reports/INDEX.md` | Finding index with severity and status |

---

## Claude Skill — PT Assistant

Use the following commands when operating Claude as a PT assistant:

```
/pt-start              → Read prompts/START_PT_SESSION.md and initialize session
/pt-exploit            → Read prompts/CONTROLLED_EXPLOITATION_PROMPT.md
/pt-report             → Read prompts/REPORT_GENERATION_PROMPT.md
/pt-phase [N]          → Execute phase N (read phases/0N-*/PHASE_README.md)
/pt-module [name]      → Read and execute specific module
/pt-status             → Run python3 setup.py --status
```

---

## Multi-Agent System (`agents/`)

The framework includes 10 specialized agents, each mapped to an OWASP Top 10 (2021) category with corresponding CWE coverage. Agents are defined as YAML files and coordinated by `agents/orchestrator.py`.

### Agent Overview

| Agent | OWASP Category | Priority | CWEs | Finding Prefix |
|-------|---------------|----------|------|----------------|
| 01 | A01 — Broken Access Control | CRITICAL | 8 | F-A01-XXX |
| 02 | A02 — Cryptographic Failures | HIGH | 8 | F-A02-XXX |
| 03 | A03 — Injection | CRITICAL | 10 | F-A03-XXX |
| 04 | A04 — Insecure Design | MEDIUM | 6 | F-A04-XXX |
| 05 | A05 — Security Misconfiguration | HIGH | 7 | F-A05-XXX |
| 06 | A06 — Vulnerable & Outdated Components | MEDIUM | 3 | F-A06-XXX |
| 07 | A07 — Identification & Auth Failures | CRITICAL | 9 | F-A07-XXX |
| 08 | A08 — Software & Data Integrity Failures | HIGH | 7 | F-A08-XXX |
| 09 | A09 — Security Logging & Monitoring Failures | LOW | 4 | F-A09-XXX |
| 10 | A10 — Server-Side Request Forgery | HIGH | 3 | F-A10-XXX |

**Total: 65 CWEs covered across 10 agents**

### Agent Commands

```
/pt-agents list        → List all agents with status and CWE counts
/pt-agents plan        → Show execution plan based on config.yaml priorities
/pt-agents run         → Run all enabled agents in priority order
/pt-agents run 01,03   → Run specific agents by number
/pt-agents status      → Show execution status of all agents
/pt-agents report      → Generate consolidated agent summary report
```

### Agent Orchestrator CLI

```bash
python3 agents/orchestrator.py --list          # List agents
python3 agents/orchestrator.py --plan          # Show execution plan
python3 agents/orchestrator.py --run           # Run all enabled agents
python3 agents/orchestrator.py --agent 01,03   # Run specific agents
python3 agents/orchestrator.py --status        # Show agent status
python3 agents/orchestrator.py --report        # Generate summary report
```

### Agent Execution Order

Agents run in priority order by default: **Critical → High → Medium → Low**

1. Agent 01 (A01 — Broken Access Control) — CRITICAL
2. Agent 03 (A03 — Injection) — CRITICAL
3. Agent 07 (A07 — Auth Failures) — CRITICAL
4. Agent 02 (A02 — Cryptographic Failures) — HIGH
5. Agent 05 (A05 — Security Misconfiguration) — HIGH
6. Agent 08 (A08 — Data Integrity Failures) — HIGH
7. Agent 10 (A10 — SSRF) — HIGH
8. Agent 04 (A04 — Insecure Design) — MEDIUM
9. Agent 06 (A06 — Vulnerable Components) — MEDIUM
10. Agent 09 (A09 — Logging Failures) — LOW

### Agent Logs & Reports

| File | Purpose |
|------|---------|
| `logs/agent_execution.log` | Timestamped agent execution log |
| `logs/agent_status.json` | Machine-readable agent status tracker |
| `reports/AGENT_SUMMARY.md` | Consolidated findings report across all agents |
| `agents/OWASP_CWE_MAP.md` | Full OWASP → CWE mapping reference |

### Agent Configuration (config.yaml)

Enable/disable agents and set execution order in `config.yaml` under `preferences.agents`:

```yaml
agents:
  enabled: true
  run_order: "priority"    # priority | sequential | parallel
  agents_to_run:
    agent_01_access_control: true
    agent_02_cryptographic: true
    agent_03_injection: true
    # ... etc
```

---

## Interactive Initialization (MANDATORY)

**When the user says "run the pentest", "start testing", or any similar command, Claude MUST follow the interactive initialization workflow in `prompts/INTERACTIVE_INIT_PROMPT.md` BEFORE running any tests.**

The workflow requires 6 steps in order:

1. **Scope Confirmation** — Ask if `scope/targets.md` is updated. Show current targets. Ask where to update if needed.
2. **Credentials & Auth** — Ask for credentials, API keys, authorization headers, role-based accounts. Store in `credentials/`. If unauthenticated only, confirm.
3. **Reporting Email** — Ask for From/To/CC email addresses. Configure the email sender.
4. **Run Pentest** — Execute all 5 phases. **All findings saved as DRAFT status.**
5. **Agent Validation** — Present all draft findings in a table. Ask user to validate each: Valid / Invalid / Needs More Info / Severity Change.
6. **Finalize & Send** — Only after user confirms, generate final reports and send emails.

**NEVER skip steps. NEVER send emails without Step 6 confirmation. NEVER mark findings as CONFIRMED without Step 5 validation. ALWAYS ask user permission before sending EACH individual email — never batch-send without per-email approval.**

---

## Email Report Format

All vulnerability email reports follow the standard format defined in `reports/EMAIL_REPORT_TEMPLATE.md`.

**Email tooling:**

| Script | Purpose |
|--------|---------|
| `reports/emails/generate_email.py` | Generate email files from finding data |
| `reports/emails/send_emails.py` | Send emails via Gmail SMTP with HTML + screenshots |

**Email format structure:**
- Title as H1 heading
- Reporter, Severity, CVSS, OWASP metadata
- Sections: Summary → Affected Assets → Vulnerability Details → Steps to Reproduce → Impact → Proof of Concept → Recommendations → Severity Justification
- Reporter signature at bottom
- POC screenshots auto-attached from `evidence/screenshots/`

---

**Behavior contract for Claude in this repo:**
- **ALWAYS run the Interactive Initialization (Steps 1-3) before any testing**
- Always read config.yaml and scope/targets.md before any test
- Never suggest or execute DoS, brute force, or destructive payloads
- Always stop at PoC confirmation — never escalate exploitation
- For any finding, immediately create a finding entry using the template
- **All findings start as DRAFT until user validates in Step 5**
- **Never send email reports without explicit user confirmation in Step 6**
- Flag any test result that involves real PII and stop data collection
- Log all significant actions in logs/engagement.log
- Complete phases in order — Recon → Enumeration → Exploitation → Post-Exploitation → Reporting
