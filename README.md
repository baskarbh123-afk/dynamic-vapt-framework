# Web Application Penetration Testing Framework

A professional, modular Markdown-based framework for conducting structured, controlled Web Application Penetration Testing engagements following the PTES methodology.

---

## Key Features

- **Centralized Configuration** — Single `config.yaml` file drives the entire engagement
- **5-Phase PT Methodology** — Recon → Enumeration → Exploitation → Post-Exploitation → Reporting
- **Auto-Setup** — `setup.py` reads config and populates all target folders automatically
- **29 Exploitation Modules** — Organized by category (auth, web, API, infrastructure)
- **Structured Logging** — Engagement log, phase tracker, evidence management
- **Professional Reporting** — Executive summary, technical report, finding templates, PoC templates
- **Safety Controls** — PoC-only exploitation, rate limiting, scope enforcement

---

## Quick Start

```bash
# 1. Fill config.yaml with engagement parameters
nano config.yaml

# 2. Validate configuration
python3 setup.py --validate

# 3. Auto-populate all folders
python3 setup.py

# 4. Check engagement status
python3 setup.py --status

# 5. Begin testing with Claude or manually
# Use prompts/START_PT_SESSION.md to initialize an AI-assisted session
```

---

## Framework Structure

```
penetration-testing-framework/
├── config.yaml                  # ← Single source of truth for all engagement params
├── setup.py                     # ← Auto-reads config, populates all folders
├── CLAUDE.md                    # Project instructions for Claude AI assistant
│
├── scope/                       # Auto-populated from config.yaml
│   ├── targets.md               # In-scope targets and API endpoints
│   ├── exclusions.md            # Out-of-scope domains and actions
│   └── constraints.md           # Testing constraints and authorization status
│
├── targets/                     # Auto-populated from config.yaml
│   ├── domain.md                # Domain info, subdomains, network characteristics
│   ├── tech_stack.md            # Backend, frontend, DB, auth, infrastructure
│   ├── endpoints.md             # Full endpoint inventory (populated during enum)
│   └── attack_surface.md        # Attack surface map (populated during recon/enum)
│
├── credentials/                 # Auto-populated from config.yaml
│   ├── accounts.md              # Test accounts per role
│   ├── api_keys.md              # API keys and tokens
│   └── oauth.md                 # OAuth credentials and provider accounts
│
├── phases/                      # PT methodology — 5 phases
│   ├── 01-recon/                # Phase 1: Reconnaissance
│   │   ├── PHASE_README.md
│   │   ├── PASSIVE_RECON.md     # DNS, OSINT, CT logs, dorking
│   │   ├── ACTIVE_RECON.md      # Fingerprinting, endpoint discovery
│   │   └── SUBDOMAIN_ENUM.md    # Subdomain discovery and takeover checks
│   │
│   ├── 02-enumeration/          # Phase 2: Enumeration
│   │   ├── PHASE_README.md
│   │   ├── SERVICE_ENUMERATION.md
│   │   ├── WEB_ENUMERATION.md
│   │   ├── API_ENUMERATION.md
│   │   └── AUTH_ENUMERATION.md
│   │
│   ├── 03-exploitation/         # Phase 3: Exploitation
│   │   ├── PHASE_README.md
│   │   ├── auth/                # Auth modules (5 modules)
│   │   ├── web/                 # Web vuln modules (13 modules)
│   │   ├── api/                 # API modules (4 modules)
│   │   └── infra/               # Infrastructure modules (7 modules)
│   │
│   ├── 04-post-exploitation/    # Phase 4: Post-Exploitation
│   │   ├── PHASE_README.md
│   │   ├── PRIVILEGE_ESCALATION.md
│   │   ├── DATA_ACCESS_ASSESSMENT.md
│   │   ├── LATERAL_MOVEMENT_ASSESSMENT.md
│   │   ├── PERSISTENCE_ASSESSMENT.md
│   │   └── CLEANUP.md
│   │
│   └── 05-reporting/            # Phase 5: Reporting
│       ├── PHASE_README.md
│       ├── FINDINGS_TEMPLATE.md
│       ├── POC_TEMPLATE.md
│       ├── EXECUTIVE_SUMMARY_TEMPLATE.md
│       └── TECHNICAL_REPORT_TEMPLATE.md
│
├── modules/                     # Core vulnerability test modules (referenced by phases)
├── api-testing/                 # API-specific test modules (referenced by phases)
│
├── reports/                     # Generated reports
│   ├── INDEX.md                 # Finding index
│   ├── findings/                # Individual finding reports (F-001.md, F-002.md, ...)
│   └── poc/                     # Proof of concept scripts (POC-001.md, ...)
│
├── logs/                        # Engagement logs
│   ├── engagement.log           # Timestamped action log
│   └── phase_tracker.md         # Phase progress and finding counters
│
├── evidence/                    # Evidence collection
│   ├── screenshots/             # Browser/Burp screenshots
│   └── http-logs/               # HTTP request/response dumps
│
├── docs/                        # Reference documentation
│   ├── WORKFLOW.md              # 5-phase engagement workflow
│   ├── METHODOLOGY.md           # PT methodology and standards mapping
│   ├── RULES.md                 # Rules of engagement
│   ├── SEVERITY_MATRIX.md       # OWASP severity classification
│   ├── AUTH_FLOW.md             # Authentication flow mapping
│   └── SESSION_HANDLING.md      # Session management analysis
│
├── prompts/                     # Claude AI session prompts
│   ├── START_PT_SESSION.md      # Initialize PT session
│   ├── CONTROLLED_EXPLOITATION_PROMPT.md
│   └── REPORT_GENERATION_PROMPT.md
│
└── tools/                       # Approved tooling reference
    └── ALLOWED_TOOLS.md
```

---

## Engagement Lifecycle

1. **Pre-Engagement** — Fill `config.yaml`. Run `python3 setup.py`. Confirm authorization.
2. **Reconnaissance** — Map attack surface: DNS, OSINT, fingerprinting, subdomain enumeration.
3. **Enumeration** — Catalog all endpoints, APIs, auth mechanisms, parameters.
4. **Exploitation** — Confirm vulnerabilities with controlled PoC. Document each finding.
5. **Post-Exploitation** — Assess impact: privilege escalation, data access, attack chains. Clean up.
6. **Reporting** — Generate executive summary, technical report, findings, and PoCs.

---

## Absolute Rules

- Test only targets in `scope/targets.md`
- No DoS, no brute force, no destructive payloads
- Stop at proof-of-concept — confirm, do not exploit further
- All testing requires prior written authorization
- Log all actions in `logs/engagement.log`

---

## Standards Alignment

| Standard | Usage |
|----------|-------|
| PTES | Overall methodology |
| OWASP WSTG v4.2 | Web testing procedures |
| OWASP Top 10 (2021) | Risk categorization |
| CVSS v3.1 | Vulnerability scoring |
| CWE | Weakness classification |
