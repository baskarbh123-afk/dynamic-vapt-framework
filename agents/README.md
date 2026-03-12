# Multi-Agent Penetration Testing System

## Overview

This framework uses **10 specialized agents**, each mapped to an OWASP Top 10 (2021) category. Each agent independently manages its own set of CWE vulnerabilities, exploitation modules, and execution workflow while sharing a common configuration and reporting infrastructure.

---

## Architecture

```
                    ┌──────────────────────┐
                    │     config.yaml      │
                    │  (single source of   │
                    │       truth)         │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │    orchestrator.py    │
                    │  (reads config,      │
                    │   coordinates agents) │
                    └──────────┬───────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                      │
    ┌────▼────┐          ┌─────▼─────┐          ┌────▼────┐
    │ CRITICAL │          │   HIGH    │          │  MED/LOW │
    │ Agents   │          │  Agents   │          │  Agents  │
    ├──────────┤          ├───────────┤          ├──────────┤
    │ Agent 01 │          │ Agent 02  │          │ Agent 04 │
    │ Agent 03 │          │ Agent 05  │          │ Agent 06 │
    │ Agent 07 │          │ Agent 08  │          │ Agent 09 │
    │          │          │ Agent 10  │          │          │
    └────┬─────┘         └─────┬─────┘          └────┬─────┘
         │                     │                      │
         └─────────────────────┼──────────────────────┘
                               │
                    ┌──────────▼───────────┐
                    │   Findings & Reports │
                    │  reports/findings/   │
                    │  reports/poc/        │
                    │  logs/               │
                    └──────────────────────┘
```

---

## Agent Index

| # | Agent | OWASP | Priority | CWEs | Focus |
|---|-------|-------|----------|------|-------|
| 01 | Access Control | A01:2021 | Critical | 8 | IDOR, AuthZ, CSRF, Privilege Escalation |
| 02 | Cryptographic | A02:2021 | High | 8 | JWT, TLS, Secrets, Encryption |
| 03 | Injection | A03:2021 | Critical | 10 | XSS, SQLi, CMDi, SSTI, XXE, LFI |
| 04 | Insecure Design | A04:2021 | Medium | 6 | Business Logic, Rate Limiting |
| 05 | Misconfiguration | A05:2021 | High | 7 | Headers, CORS, Smuggling, Cache |
| 06 | Vulnerable Components | A06:2021 | Medium | 3 | CVEs, Subdomain Takeover |
| 07 | Auth Failures | A07:2021 | Critical | 9 | Login, MFA, OAuth, Sessions |
| 08 | Data Integrity | A08:2021 | High | 7 | Mass Assignment, File Upload, Deserialization |
| 09 | Logging | A09:2021 | Low | 4 | Log Injection, Audit Coverage |
| 10 | SSRF | A10:2021 | High | 3 | SSRF, Open Redirect, Cloud Metadata |

**Total: 65 CWE vulnerabilities covered across 10 agents**

---

## Usage

### List All Agents
```bash
python3 agents/orchestrator.py --list
```

### View Execution Plan
```bash
python3 agents/orchestrator.py --plan
```

### Run All Agents (priority order)
```bash
python3 agents/orchestrator.py
```

### Run Specific Agents
```bash
# Single agent
python3 agents/orchestrator.py --agent 01

# Multiple agents
python3 agents/orchestrator.py --agent 01,03,07

# All critical agents
python3 agents/orchestrator.py --agent 01,03,07
```

### Check Status
```bash
python3 agents/orchestrator.py --status
```

### Generate Summary Report
```bash
python3 agents/orchestrator.py --report
```

---

## Execution Order

Agents execute in **priority order** by default:

1. **CRITICAL** — Agents 01, 03, 07 (Access Control, Injection, Auth)
2. **HIGH** — Agents 02, 05, 08, 10 (Crypto, Misconfig, Integrity, SSRF)
3. **MEDIUM** — Agents 04, 06 (Design, Components)
4. **LOW** — Agent 09 (Logging)

This can be changed in `config.yaml` under `preferences.agents.run_order`.

---

## Agent Configuration

Each agent is configured via:
1. **config.yaml** — Global engagement settings and module enable/disable
2. **agents/agent_XX_*.yaml** — Agent-specific CWE mappings and execution steps
3. **Orchestrator** — Coordinates execution and status tracking

### Enable/Disable Agents in config.yaml:
```yaml
preferences:
  agents:
    enabled: true
    agents_to_run:
      agent_01_access_control: true
      agent_02_cryptographic: true
      agent_03_injection: true
      # ... etc
```

### Enable/Disable Modules in config.yaml:
```yaml
preferences:
  exploitation_modules:
    xss: true
    sql_injection: true
    html_injection: false    # Disabled — Agent 03 will skip this module
    clickjacking: false      # Disabled — Agent 05 will skip this module
```

---

## Finding Management

Each agent uses a unique finding prefix:

| Agent | Prefix | Example |
|-------|--------|---------|
| 01 | F-A01 | F-A01-001 (IDOR finding) |
| 02 | F-A02 | F-A02-001 (JWT weakness) |
| 03 | F-A03 | F-A03-001 (SQL injection) |
| 04 | F-A04 | F-A04-001 (Logic bypass) |
| 05 | F-A05 | F-A05-001 (CORS misconfig) |
| 06 | F-A06 | F-A06-001 (CVE found) |
| 07 | F-A07 | F-A07-001 (Auth bypass) |
| 08 | F-A08 | F-A08-001 (Mass assignment) |
| 09 | F-A09 | F-A09-001 (Missing logging) |
| 10 | F-A10 | F-A10-001 (SSRF confirmed) |

---

## Logs & Status

| File | Purpose |
|------|---------|
| logs/agent_execution.log | Detailed agent execution log |
| logs/agent_status.json | Machine-readable agent status |
| reports/AGENT_SUMMARY.md | Human-readable agent report |
| logs/engagement.log | Main engagement log |

---

## Integration with PT Workflow

The agent system integrates into the existing 5-phase PT methodology:

- **Phase 1-2 (Recon/Enum)**: Provides data that agents need
- **Phase 3 (Exploitation)**: Agents execute their modules here
- **Phase 4 (Post-Exploitation)**: Agent 09 and escalation assessments
- **Phase 5 (Reporting)**: `orchestrator.py --report` generates summary

### Claude Commands
```
/pt-agents list          → List all agents
/pt-agents plan          → Show execution plan
/pt-agents run [01,03]   → Run specific agents
/pt-agents status        → Show agent progress
/pt-agents report        → Generate agent summary
```
