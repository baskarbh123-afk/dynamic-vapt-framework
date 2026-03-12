# Agent Definitions Index

This directory contains 10 OWASP Top 10 (2021) agent definition YAML files, each focusing on a specific vulnerability category with comprehensive CWE mappings.

## Agent Overview

| Agent | OWASP Category | Priority | File |
|-------|----------------|----------|------|
| Agent 01 | A01:2021 — Broken Access Control | CRITICAL | `agent_01_access_control.yaml` |
| Agent 02 | A02:2021 — Cryptographic Failures | HIGH | `agent_02_cryptographic.yaml` |
| Agent 03 | A03:2021 — Injection | CRITICAL | `agent_03_injection.yaml` |
| Agent 04 | A04:2021 — Insecure Design | MEDIUM | `agent_04_insecure_design.yaml` |
| Agent 05 | A05:2021 — Security Misconfiguration | HIGH | `agent_05_misconfiguration.yaml` |
| Agent 06 | A06:2021 — Vulnerable & Outdated Components | MEDIUM | `agent_06_vulnerable_components.yaml` |
| Agent 07 | A07:2021 — Identification & Authentication Failures | CRITICAL | `agent_07_auth_failures.yaml` |
| Agent 08 | A08:2021 — Software & Data Integrity Failures | HIGH | `agent_08_data_integrity.yaml` |
| Agent 09 | A09:2021 — Security Logging & Monitoring Failures | LOW | `agent_09_logging.yaml` |
| Agent 10 | A10:2021 — Server-Side Request Forgery (SSRF) | HIGH | `agent_10_ssrf.yaml` |

## Agent Structure

Each YAML file contains:

### Top-Level Fields
- **agent.id** — Unique identifier (e.g., `agent-01-access-control`)
- **agent.name** — Human-readable name
- **agent.owasp_category** — OWASP Top 10 2021 category
- **agent.priority** — Severity level (CRITICAL, HIGH, MEDIUM, LOW)
- **agent.description** — Detailed vulnerability description

### CWE Coverage
- Comprehensive list of related CWE vulnerabilities
- Each CWE includes ID, name, and specific testing approach

### Modules
- Testing modules from the framework phases
- Priority-ordered execution sequence
- Descriptions of testing scope

### Pre-Conditions
- Required completed phases
- Necessary documentation files
- Required test credentials/accounts

### Execution Order
- Step-by-step testing sequence
- Clear action descriptions
- Logging requirements

### Output
- **findings_prefix** — Consistent naming for findings (e.g., F-A01)
- **report_tags** — Tags for filtering and categorization

## Usage

Load agent definitions in penetration testing workflow:

```yaml
# Example: Load Agent 01 for access control testing
python3 -c "
import yaml
with open('agents/agent_01_access_control.yaml', 'r') as f:
    agent = yaml.safe_load(f)
    print(f\"Testing {agent['agent']['name']}\")
    for module in agent['modules']:
        print(f\"  - {module['description']}\")
"
```

## CWE-to-OWASP Mapping

The agent definitions map the following CWE vulnerabilities to OWASP categories:

- **A01** — Access Control: CWE-200, 284, 285, 352, 639, 862, 863, 425
- **A02** — Cryptography: CWE-261, 296, 310, 319, 326, 327, 328, 614
- **A03** — Injection: CWE-20, 74, 77, 78, 79, 89, 94, 116, 611, 917
- **A04** — Insecure Design: CWE-209, 256, 501, 522, 841, 799
- **A05** — Misconfiguration: CWE-2, 16, 388, 942, 1021, 444, 525
- **A06** — Components: CWE-937, 1035, 1104
- **A07** — Authentication: CWE-255, 259, 287, 288, 290, 294, 295, 384, 613
- **A08** — Data Integrity: CWE-345, 353, 426, 494, 502, 565, 829
- **A09** — Logging: CWE-117, 223, 532, 778
- **A10** — SSRF: CWE-918, 441, 601

## Integration with Framework

Agents reference testing modules from:
- `phases/03-exploitation/` — Active exploitation modules
- `phases/04-post-exploitation/` — Post-exploitation assessment
- `phases/01-recon/` — Reconnaissance and fingerprinting
- `phases/02-enumeration/` — Service/endpoint enumeration

## Findings Naming Convention

All findings are prefixed by the agent's `findings_prefix`:

- Agent 01 findings: `F-A01-001`, `F-A01-002`, etc.
- Agent 03 findings: `F-A03-001`, `F-A03-002`, etc.
- Agent 10 findings: `F-A10-001`, `F-A10-002`, etc.

## Execution Workflow

**Recommended execution order:**
1. Agent 06 (Components) — Identify outdated/vulnerable software
2. Agent 01 (Access Control) — Test authorization enforcement
3. Agent 07 (Authentication) — Test authentication mechanisms
4. Agent 02 (Cryptography) — Test encryption and secrets handling
5. Agent 03 (Injection) — Test input validation and injection flaws
6. Agent 04 (Insecure Design) — Test business logic and workflows
7. Agent 05 (Misconfiguration) — Test headers and configuration
8. Agent 08 (Data Integrity) — Test file uploads and mass assignment
9. Agent 10 (SSRF) — Test request forgery vulnerabilities
10. Agent 09 (Logging) — Assess detection and logging capabilities

---
**Framework Version:** 2.0
**Updated:** 2026-03-09
