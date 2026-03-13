# Dynamic VAPT Framework — Complete User Walkthrough

A comprehensive step-by-step guide to running a full penetration test using this framework with Claude Code — from initial setup to final email delivery.

---

## Table of Contents

1. [What This Framework Does](#what-this-framework-does)
2. [Architecture Overview](#architecture-overview)
3. [Prerequisites & Installation](#prerequisites--installation)
4. [Configuration](#configuration)
5. [Running a Pentest — The 6-Step Interactive Flow](#running-a-pentest--the-6-step-interactive-flow)
6. [AI Orchestrator (Advanced)](#ai-orchestrator-advanced)
7. [Multi-Agent System](#multi-agent-system)
8. [PoC Screenshot System](#poc-screenshot-system)
9. [Email Reporting Pipeline](#email-reporting-pipeline)
10. [Project Directory Structure](#project-directory-structure)
11. [Common Commands](#common-commands)
12. [Safety Rules](#safety-rules)
13. [Troubleshooting](#troubleshooting)
14. [Quick Start (TL;DR)](#quick-start-tldr)

---

## What This Framework Does

This is a professional, AI-powered web application penetration testing framework that follows the **PTES (Penetration Testing Execution Standard)** methodology. You provide target domains, and the framework will:

1. **Reconnaissance** — Discover subdomains, DNS records, technologies, SSL/TLS configuration
2. **Enumeration** — Map endpoints, APIs, authentication flows, input vectors
3. **Exploitation** — Test for real vulnerabilities safely (proof-of-concept only)
4. **Post-Exploitation** — Assess impact, map attack chains, evaluate escalation paths
5. **Reporting** — Generate professional vulnerability reports with PoC evidence
6. **Notification** — Email reports with browser-based screenshots directly to the client

Everything is controlled through a natural language conversation with Claude Code. No manual coding required.

---

## Architecture Overview

The framework has two execution modes:

### 1. Interactive Mode (Claude Code Conversation)

Say `run the pentest` and Claude walks you through an interactive 6-step workflow. Best for ad-hoc engagements and learning the framework.

### 2. AI Orchestrator Mode (CLI)

Use `python3 run.py` for automated, scriptable execution with 8 specialized AI agents. Best for repeatable engagements and CI/CD integration.

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI ORCHESTRATOR PIPELINE                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  config.yaml ──→ Orchestrator ──→ Agent Pipeline ──→ Reports    │
│                                                                 │
│  Agents:                                                        │
│  1. ReconAgent        → assets database                         │
│  2. EnumerationAgent  → endpoints database                      │
│  3. VulnerabilityAgent → vulnerabilities (DRAFT)                │
│  4. PoCAgent          → poc_results + evidence                  │
│  5. ExploitAgent      → deeper exploitation evidence            │
│  6. AttackChainAgent  → attack_paths database                   │
│  7. ReportAgent       → reports/ (findings, summary)            │
│  8. NotificationAgent → email delivery via Gmail SMTP           │
│                                                                 │
│  Knowledge Base (data/):                                        │
│  assets.json, endpoints.json, vulnerabilities.json,             │
│  poc_results.json, evidence.json, attack_paths.json             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites & Installation

### System Requirements

- Python 3.8+ on macOS or Linux
- Claude Code CLI installed (`npm install -g @anthropic-ai/claude-code`)
- Git (for version control)

### Python Dependencies

```bash
# Core dependency
pip3 install pyyaml

# For terminal-style PoC screenshots (optional)
pip3 install Pillow

# For browser-based PoC screenshots (recommended)
pip3 install playwright
python3 -m playwright install chromium
```

### Gmail App Password (for email delivery)

1. Go to https://myaccount.google.com/apppasswords
2. Select "Mail" and your device
3. Click "Generate"
4. Copy the 16-character password (format: `xxxx xxxx xxxx xxxx`)
5. Add it to `config.yaml` under `notifications.gmail.app_password`

---

## Configuration

All engagement parameters live in **`config.yaml`** — the single source of truth.

### Minimum Required Configuration

Before starting any engagement, fill in these fields:

```yaml
# 1. Engagement identity
engagement:
  name: "Acme Corp Penetration Test"
  id: "PT-2026-ACME-001"
  client: "Acme Corp"
  lead_tester: "Your Name"
  start_date: "2026-01-15"

# 2. Authorization (MUST be true before testing)
authorization:
  roe_signed: true

# 3. Target scope
scope:
  in_scope:
    domains:
      - domain: "acme.com"
        notes: "Primary domain"
      - domain: "*.acme.com"
        notes: "All subdomains"

# 4. Target URLs
target:
  primary_domain: "https://www.acme.com"
  base_url: "https://www.acme.com"

# 5. Email settings (optional — for report delivery)
notifications:
  gmail:
    enabled: true
    sender_email: "your-email@gmail.com"
    app_password: "xxxx xxxx xxxx xxxx"
    recipients:
      to: "client@acme.com"
```

### Validate Configuration

```bash
python3 setup.py --validate    # Check for missing fields
python3 setup.py               # Populate scope/, targets/, credentials/
python3 setup.py --status      # View setup status
```

---

## Running a Pentest — The 6-Step Interactive Flow

### Starting

Open terminal in the project folder and launch Claude Code:

```bash
cd /path/to/dynamic-vapt-framework
claude
```

Then type: **`run the pentest`**

Claude enforces a mandatory 6-step interactive workflow. It will **never** skip steps or send emails without your permission.

---

### Step 1: Scope Confirmation

Claude asks: **"Is the scope up to date?"**

It shows current targets from `scope/targets.md`. Your options:

| You Say | What Happens |
|---------|-------------|
| `yes` | Targets confirmed, move to Step 2 |
| `change the target` | Claude asks for new domains |
| `example.com and all subdomains` | Scope updated with wildcard |
| `add api.example.com` | Target added to existing scope |

**Example:**

```
You: change the target
Claude: What are the new targets?
You: example.com and its all subdomains
Claude: ✓ Scope updated to example.com + *.example.com. Moving to Step 2.
```

---

### Step 2: Credentials & Authentication

Claude asks: **"Do you have any credentials?"**

| You Say | What Happens |
|---------|-------------|
| `unauthenticated` | Test public-facing attack surface only |
| `username: admin, password: test123` | Credentials stored in `credentials/` |
| `Bearer token: eyJhbG...` | API authorization header configured |
| `here's the API key: abc123` | API key stored for authenticated testing |

**Example:**

```
Claude: Do you have any credentials or authorization headers?
You: unauthenticated
Claude: Got it — testing public access only. Moving to Step 3.
```

---

### Step 3: Email Setup

Claude asks: **"Where should the reports be sent?"**

Provide:
- **From:** Your Gmail address (must have App Password configured)
- **To:** Client email, bug bounty program, or your own email for review

**Example:**

```
Claude: Email configuration — From: tester@gmail.com, To: client@company.com — confirm?
You: change the to email security@acme.com
Claude: ✓ Updated. From: tester@gmail.com → To: security@acme.com. Moving to Step 4.
```

---

### Step 4: The Pentest Runs

Claude automatically executes 5 phases in order:

| Phase | What Happens | Typical Time |
|-------|-------------|--------------|
| 1. Reconnaissance | Subdomain discovery, DNS records, tech fingerprinting, SSL/TLS analysis | 1-3 min |
| 2. Enumeration | Endpoint probing, API discovery, auth flow mapping, input vector identification | 2-5 min |
| 3. Exploitation | Safe vulnerability testing across 25+ modules (XSS, SQLi, IDOR, SSRF, etc.) | 3-10 min |
| 4. Post-Exploitation | Impact assessment, attack chain analysis, privilege escalation evaluation | 1-2 min |
| 5. Reporting | Finding creation with severity ratings, CVSS scores, OWASP mapping | 1-2 min |

**You don't need to do anything during this step.** Just wait for the results.

All findings are saved as **DRAFT** status — nothing is finalized or sent until you review them.

---

### Step 5: Review Your Findings

Claude presents all draft findings in a table:

```
| #     | Finding                                  | Severity | CVSS | Target              | Status |
|-------|------------------------------------------|----------|------|---------------------|--------|
| F-001 | Swagger API Documentation Exposed        | Medium   | 5.3  | api.example.com     | DRAFT  |
| F-002 | WordPress REST API User Enumeration      | Low      | 3.7  | blog.example.com    | DRAFT  |
| F-003 | Missing Content-Security-Policy Header   | Low      | 3.1  | www.example.com     | DRAFT  |
```

Your review options:

| You Say | What Happens |
|---------|-------------|
| `all valid` | Confirm all findings at once |
| `valid` | Confirm current finding |
| `remove F-003` | Remove a false positive |
| `change F-002 to medium` | Adjust severity rating |
| `need more info on F-001` | Claude investigates further |
| `merge F-001 and F-002` | Combine related findings |

**Example:**

```
You: remove F-003, keep the rest
Claude: ✓ F-003 removed. 2 findings confirmed. Ready for Step 6.
```

---

### Step 6: Generate & Send Reports

Claude asks for final confirmation before sending anything.

| You Say | What Happens |
|---------|-------------|
| `make it as a draft` | Generate email files to `reports/emails/` for manual review |
| `generate POC screenshots` | Create browser-based evidence images using Playwright |
| `send` | Send emails (with per-email confirmation) |
| `send all` | Send all with batch confirmation |

**Per-email confirmation (default behavior):**

```
[F-001] Processing...
  To:      security@acme.com
  Subject: Acme Corp - Vulnerability Report: Swagger API Documentation Exposed
  Screenshots: 3 attached

  Send this email? (y/n/q to quit): _
```

- Press **y** to send this email
- Press **n** to skip this finding
- Press **q** to stop all remaining emails

**You will need your Gmail App Password at this point.**

---

## AI Orchestrator (Advanced)

For automated, CLI-driven execution:

```bash
# Run all phases end-to-end
python3 run.py

# Dry run — preview actions without executing
python3 run.py --dry-run

# Run specific phases only
python3 run.py --phase recon,enumeration

# Run with custom config file
python3 run.py --config my_engagement.yaml

# Check available security tools
python3 run.py --tools

# View knowledge base summary
python3 run.py --summary

# Show system status
python3 run.py --status

# Debug mode
python3 run.py --log-level DEBUG
```

### Phase Execution Order

```
recon → enumeration → vulnerability → poc_validation → exploit → attack_chain → report → notification
```

Each phase feeds data into the **Knowledge Base** (`data/*.json`), which subsequent phases read from.

---

## Multi-Agent System

The framework includes **10 specialized OWASP agents**, each mapped to an OWASP Top 10 (2021) category covering **65 CWEs total**.

### Agent Overview

| Agent | OWASP Category | Priority | CWEs |
|-------|---------------|----------|------|
| 01 | A01 — Broken Access Control | CRITICAL | 8 |
| 02 | A02 — Cryptographic Failures | HIGH | 8 |
| 03 | A03 — Injection | CRITICAL | 10 |
| 04 | A04 — Insecure Design | MEDIUM | 6 |
| 05 | A05 — Security Misconfiguration | HIGH | 7 |
| 06 | A06 — Vulnerable Components | MEDIUM | 3 |
| 07 | A07 — Auth Failures | CRITICAL | 9 |
| 08 | A08 — Data Integrity Failures | HIGH | 7 |
| 09 | A09 — Logging Failures | LOW | 4 |
| 10 | A10 — SSRF | HIGH | 3 |

### Agent CLI

```bash
python3 agents/orchestrator.py --list         # List agents
python3 agents/orchestrator.py --plan         # Show execution plan
python3 agents/orchestrator.py --run          # Run all enabled agents
python3 agents/orchestrator.py --agent 01,03  # Run specific agents
python3 agents/orchestrator.py --status       # Show agent status
python3 agents/orchestrator.py --report       # Generate summary report
```

### Execution Order

Agents run in priority order: **Critical → High → Medium → Low**

---

## PoC Screenshot System

The framework provides **3 levels** of screenshot generation:

### Level 1: Terminal-Style (Pillow)

Static screenshots with curl command output rendered as terminal images.

```bash
python3 evidence/poc_template.py                 # All findings
python3 evidence/poc_template.py --finding F-001 # Specific finding
```

### Level 2: Browser-Style (Pillow)

Browser chrome overlays on curl output — looks more professional.

```bash
python3 evidence/poc_browser.py                  # All findings
python3 evidence/poc_browser.py --finding F-001  # Specific finding
```

### Level 3: Real Browser Screenshots (Playwright) — Recommended

**Agentic AI PoC Screenshot System** — navigates to actual targets in a real Chromium browser, demonstrates the vulnerability live, and captures authentic screenshots with URL bars.

```bash
python3 agents/poc_screenshot_agent.py                        # All findings
python3 agents/poc_screenshot_agent.py --finding F-001        # Specific finding
python3 agents/poc_screenshot_agent.py --finding F-001,F-002  # Multiple findings
python3 agents/poc_screenshot_agent.py --list                 # List strategies
```

Each finding gets **3 screenshots**, all from real browser navigations:

| Screenshot | What It Captures |
|-----------|-----------------|
| POC-1 | Live target page with injected Chrome-style URL bar |
| POC-2 | view-source, login page, or OpenID configuration endpoint |
| POC-3 | Evidence endpoint (xmlrpc.php, API error, SAML endpoint, etc.) |

### Screenshot Strategies

The agent automatically selects the best strategy based on vulnerability type:

| Strategy | Used For | Screenshots |
|----------|---------|-------------|
| `VERSION_DISCLOSURE` | Plugin/version exposure | Live page → view-source → evidence endpoint |
| `MISSING_HEADERS` | Missing security headers, CSP issues | Live page → view-source → evidence endpoint |
| `AZURE_AD_EXPOSURE` | SAML/OAuth tenant ID exposure | Redirect landing → OpenID config → SAML endpoint |
| `API_ERROR_DISCLOSURE` | API framework/error disclosure | API response → login page → root URL |
| `SECURITY_MISCONFIGURATION` | General misconfigs | Live page → view-source → evidence endpoint |

---

## Email Reporting Pipeline

### How It Works

```
Finding Markdown → generate_email.py → .txt + .html files → send_emails.py → Gmail SMTP
                                                                    ↓
                                                        POC screenshots attached
```

### Email Format

Every vulnerability email follows this professional HTML structure:

```
┌─────────────────────────────────────────────────┐
│  [Title]  (centered h1)                         │
├─────────────────────────────────────────────────┤
│  Affected Application                           │
│    URL: https://target.example.com              │
│    Affected Component: /api/endpoint             │
│    Risk Rating: Medium                          │
├─────────────────────────────────────────────────┤
│  Vulnerability Description                      │
│  Impact                                         │
│  Steps to Reproduce                             │
│  Root Cause                                     │
│  Recommendation / Fix                           │
│    ├── Backend Fixes                            │
│    └── Additional Security Controls             │
│  Risk Rating Justification                      │
├─────────────────────────────────────────────────┤
│  Evidence screenshots attached                  │
│  [POC_1.png] [POC_2.png] [POC_3.png]           │
└─────────────────────────────────────────────────┘
```

### MIME Structure

```
Content-Type: multipart/mixed
├── Content-Type: multipart/alternative
│   ├── text/plain (fallback)
│   └── text/html  (primary — styled HTML)
└── image/png (screenshot attachments × 3)
```

### Email CLI

```bash
# Generate email files from findings
python3 reports/emails/generate_email.py
python3 reports/emails/generate_email.py --finding F-001
python3 reports/emails/generate_email.py --list

# Send emails
python3 reports/emails/send_emails.py --password "xxxx xxxx xxxx xxxx"
python3 reports/emails/send_emails.py --finding F-001 --password "xxxx xxxx xxxx xxxx"
python3 reports/emails/send_emails.py --dry-run
```

### Pre-Send Checklist (Mandatory)

Before sending any email, verify:

1. **Issue Name/Title** — Confirm the finding title is correct
2. **Severity** — Confirm severity rating and CVSS score
3. **PoC Evidence** — Confirm screenshots exist in `evidence/screenshots/`

If screenshots are missing, **do not send** — generate them first.

---

## Project Directory Structure

```
dynamic-vapt-framework/
│
├── config.yaml                  ← Central configuration (EDIT THIS FIRST)
├── CLAUDE.md                    ← Rules and behavior for Claude Code
├── WALKTHROUGH.md               ← This file
├── run.py                       ← AI Orchestrator entry point
├── setup.py                     ← Initial setup script
├── generate_screenshots.py      ← Batch screenshot generator
│
├── scope/                       ← Engagement scope definition
│   ├── targets.md               ←   Authorized targets
│   ├── exclusions.md            ←   Out-of-scope items
│   └── constraints.md           ←   Testing constraints
│
├── agents/                      ← Multi-agent AI system
│   ├── orchestrator.py          ←   Agent coordinator
│   ├── base_agent.py            ←   Abstract base class
│   ├── recon_agent.py           ←   Phase 1: Reconnaissance
│   ├── enumeration_agent.py     ←   Phase 2: Enumeration
│   ├── vulnerability_agent.py   ←   Phase 3: Vulnerability discovery
│   ├── poc_agent.py             ←   Phase 4: PoC validation
│   ├── poc_screenshot_agent.py  ←   Playwright screenshot capture
│   ├── exploit_agent.py         ←   Phase 5: Exploitation
│   ├── attack_chain_agent.py    ←   Phase 6: Attack chain analysis
│   ├── report_agent.py          ←   Phase 7: Report generation
│   ├── notification_agent.py    ←   Phase 8: Email notification
│   └── agent_01..10.yaml        ←   OWASP agent configs
│
├── core/                        ← Framework core modules
│   ├── orchestrator.py          ←   Central AI orchestrator
│   ├── knowledge_base.py        ←   JSON database manager
│   └── tool_integrations.py     ←   Security tool wrappers
│
├── data/                        ← Knowledge base (JSON databases)
│   ├── assets.json              ←   Discovered assets
│   ├── endpoints.json           ←   API endpoints
│   ├── vulnerabilities.json     ←   Findings
│   ├── poc_results.json         ←   PoC validation results
│   ├── evidence.json            ←   Evidence references
│   └── attack_paths.json        ←   Attack chains
│
├── evidence/                    ← Test artifacts
│   ├── screenshots/             ←   PoC screenshot images (PNG)
│   ├── http_logs/               ←   HTTP request/response captures
│   ├── payload_results/         ←   Payload validation JSON
│   ├── poc_template.py          ←   Terminal-style screenshots
│   ├── poc_browser.py           ←   Browser-style screenshots
│   └── poc_screenshot.py        ←   Simple curl-based screenshots
│
├── reports/                     ← Testing reports
│   ├── findings/                ←   Individual finding files (F-001.md, etc.)
│   ├── emails/                  ←   Generated email files + send script
│   │   ├── generate_email.py    ←   Email generator
│   │   └── send_emails.py       ←   Email sender (Gmail SMTP)
│   ├── INDEX.md                 ←   Master finding index
│   ├── EXECUTIVE_SUMMARY.md     ←   Management summary
│   ├── AGENT_SUMMARY.md         ←   Agent execution report
│   ├── EMAIL_REPORT_TEMPLATE.md ←   Email format specification
│   ├── FINDINGS_TEMPLATE.md     ←   Finding markdown template
│   ├── POC_TEMPLATE.md          ←   PoC markdown template
│   └── EXECUTIVE_SUMMARY_TEMPLATE.md
│
├── phases/                      ← PTES methodology phases
│   ├── 01-recon/                ←   Passive/active recon, subdomain enum
│   ├── 02-enumeration/          ←   Service, web, API, auth enumeration
│   ├── 03-exploitation/         ←   25+ exploitation modules
│   ├── 04-post-exploitation/    ←   Privilege escalation, cleanup
│   └── 05-reporting/            ←   Report templates
│
├── modules/                     ← 25+ exploitation modules
│   ├── XSS.md, SQL_INJECTION.md, SSRF.md, IDOR.md, ...
│   └── (Full OWASP Top 10 coverage)
│
├── targets/                     ← Target information
├── credentials/                 ← Authentication credentials
├── logs/                        ← Engagement logs
├── docs/                        ← Framework documentation
├── prompts/                     ← Claude AI prompts
├── tools/                       ← Allowed tools reference
└── api-testing/                 ← API testing guides
```

---

## Common Commands

### Claude Code Commands

| What You Say | What Happens |
|-------------|-------------|
| `run the pentest` | Starts the full 6-step interactive workflow |
| `change the target` | Update scope with new domains |
| `unauthenticated` | Skip credentials — test public access only |
| `make it as a draft` | Generate email reports without sending |
| `generate POC screenshots` | Create browser-based evidence images |
| `send` | Send reports (with per-email confirmation) |
| `remove F-XXX` | Remove a finding from the report |
| `change F-XXX to high` | Adjust a finding's severity |
| `all valid` | Confirm all findings at once |
| `need more info on F-XXX` | Claude investigates a finding further |

### CLI Commands

```bash
# Framework setup
python3 setup.py --validate          # Validate config
python3 setup.py                     # Populate directories
python3 setup.py --status            # Check setup status

# AI Orchestrator
python3 run.py                       # Run all phases
python3 run.py --dry-run             # Preview without executing
python3 run.py --phase recon         # Run specific phase
python3 run.py --tools               # List available tools
python3 run.py --summary             # Knowledge base summary

# Agent System
python3 agents/orchestrator.py --list    # List agents
python3 agents/orchestrator.py --run     # Run all agents
python3 agents/orchestrator.py --agent 01,03  # Run specific agents

# Screenshots
python3 agents/poc_screenshot_agent.py --finding F-001  # Browser screenshots
python3 evidence/poc_template.py --finding F-001        # Terminal screenshots

# Email
python3 reports/emails/generate_email.py --list              # List findings
python3 reports/emails/generate_email.py --finding F-001     # Generate email
python3 reports/emails/send_emails.py --dry-run              # Preview send
python3 reports/emails/send_emails.py --password "xxxx xxxx xxxx xxxx"  # Send
```

---

## Safety Rules

This framework is designed to be safe. It will **never**:

- Run denial-of-service or volumetric attacks
- Brute force passwords
- Extract real user data (notes field types only, not values)
- Delete or modify anything on the target
- Go beyond proof-of-concept (proves the bug exists, then stops)
- Send emails without your explicit permission
- Test targets not in your authorized scope
- Skip the interactive initialization workflow
- Use destructive payloads or exploitation tools beyond safe mode

### Allowed Tools

`curl`, `nuclei`, `ffuf`, `dirsearch`, `sqlmap` (safe mode: `--level=2 --risk=1 --technique=BT`), `Playwright`, `jwt_tool`, `sslyze`, `subfinder`, `subjack`, `interactsh`

### Forbidden

No brute-force tools. No `sqlmap --dump`. No DoS tools. No social engineering.

---

## Troubleshooting

**"pyyaml not installed"**
```bash
pip3 install pyyaml
```

**"Pillow not installed"**
```bash
pip3 install Pillow
```

**"Playwright not installed" or "Browser not found"**
```bash
pip3 install playwright
python3 -m playwright install chromium
```

**"Authentication failed" when sending emails**
- Use a Gmail App Password, not your regular password
- Get one at: https://myaccount.google.com/apppasswords
- Ensure 2-Step Verification is enabled on your Google account

**"Cloudflare blocking requests"**
- Some targets have aggressive bot protection
- The framework will note these and focus on accessible subdomains
- Try again later or test from a different IP

**"Finding seems like a false positive"**
- During Step 5, say "remove F-XXX" to drop it
- Or say "need more info on F-XXX" for Claude to re-investigate

**"I want to edit an email before sending"**
1. Say "make it as a draft" to generate files
2. Edit `reports/emails/F-XXX_email.txt` or `F-XXX_email.html` directly
3. Then say "send" when ready

**"Screenshots don't show URL bars"**
- Use the Playwright-based agent: `python3 agents/poc_screenshot_agent.py`
- This injects Chrome-style URL bars into headless browser captures

**"Wrong screenshots attached to email"**
- Check `evidence/screenshots/` for `{finding_id}_POC_*.png` files
- Regenerate: `python3 agents/poc_screenshot_agent.py --finding F-XXX`

---

## Quick Start (TL;DR)

```
1. Edit config.yaml — fill in engagement name, targets, email settings
2. Open terminal → cd to project folder → type "claude"
3. Say: "run the pentest"
4. Give your targets when asked (or confirm existing scope)
5. Say "unauthenticated" if no credentials
6. Provide email addresses for reporting
7. Wait for results (5 phases run automatically)
8. Review findings — remove false positives, adjust severity
9. Say "generate POC screenshots" for browser-based evidence
10. Say "send" — approve each email one by one
11. Done!
```

---

## For New Engagements

To run a new pentest on different targets:

1. Edit `config.yaml` with new engagement details
2. Start Claude Code in this folder
3. Say **"run the pentest"**
4. When asked about scope, say **"change the target"** and provide new domains
5. Follow the same 6-step flow

Each engagement's findings get unique IDs (F-001, F-002, etc.). Evidence files (screenshots, HTTP logs, payloads) are regenerated per engagement.

---

*Dynamic VAPT Framework | PTES Methodology | OWASP Top 10 2021 | 65 CWEs | 25+ Exploitation Modules*
