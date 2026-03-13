#!/usr/bin/env python3
"""
Report Agent — Phase 8: Report Generation
===========================================
Generates executive summary, compiles vulnerability findings,
includes proof-of-concept steps, calculates CVSS scores,
and produces the final pentest report.
"""

import logging
from datetime import datetime
from pathlib import Path

from agents.base_agent import BaseAgent
from typing import Any, List

logger = logging.getLogger("agent.report")

BASE_DIR = Path(__file__).parent.parent.resolve()
REPORTS_DIR = BASE_DIR / "reports"
FINDINGS_DIR = REPORTS_DIR / "findings"


class ReportAgent(BaseAgent):
    name = "ReportAgent"
    description = "Report generation — executive summary, findings compilation, CVSS scoring, final report"
    phase = "report"

    def plan(self) -> List[dict]:
        actions = [
            {"action": "generate_findings", "target": "all",
             "description": "Generate individual finding reports"},
            {"action": "generate_executive_summary", "target": "all",
             "description": "Generate executive summary"},
            {"action": "generate_technical_report", "target": "all",
             "description": "Generate full technical report"},
            {"action": "update_index", "target": "all",
             "description": "Update findings index"},
        ]
        return actions

    def execute(self, plan: List[dict]) -> List[dict]:
        results = []
        for action in plan:
            self._log(f"Executing: {action['description']}")

            if action["action"] == "generate_findings":
                result = self._generate_findings()
            elif action["action"] == "generate_executive_summary":
                result = self._generate_executive_summary()
            elif action["action"] == "generate_technical_report":
                result = self._generate_technical_report()
            elif action["action"] == "update_index":
                result = self._update_index()
            else:
                result = {"status": "skipped"}

            result["action"] = action["action"]
            results.append(result)
        return results

    def _generate_findings(self) -> dict:
        """Generate individual finding markdown files organized by domain/subdomain."""
        FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
        vulns = self.kb.get_vulnerabilities()
        generated = 0

        for vuln in vulns:
            fid = vuln.get("finding_id", "")
            if not fid:
                continue

            # Build domain/subdomain directory path
            domain = vuln.get("domain", "unknown")
            subdomain = vuln.get("subdomain", domain)
            if subdomain == domain:
                # No subdomain — store directly under domain/
                finding_dir = FINDINGS_DIR / domain
            else:
                finding_dir = FINDINGS_DIR / domain / subdomain
            finding_dir.mkdir(parents=True, exist_ok=True)
            filepath = finding_dir / f"{fid}.md"
            evidence = self.kb.get_evidence(fid)
            poc_records = self.kb.query("poc_results", finding_id=fid)

            content = f"""# {fid}: {vuln.get('title', 'Untitled')}

**Status:** {vuln.get('status', 'DRAFT')}
**Severity:** {vuln.get('severity', 'N/A')}
**CVSS v3.1:** {vuln.get('cvss', 'N/A')}
**OWASP Category:** {vuln.get('owasp_category', 'N/A')}
**CWE:** {vuln.get('cwe', 'N/A')}
**Vulnerability Type:** {vuln.get('vuln_type', 'N/A')}

---

## Affected Endpoint

`{vuln.get('endpoint', 'N/A')}`

---

## Description

{vuln.get('description', 'No description provided.')}

---

## Steps to Reproduce

"""
            steps = vuln.get("steps_to_reproduce", [])
            if steps:
                for i, step in enumerate(steps, 1):
                    content += f"{i}. {step}\n"
            else:
                content += "*(Steps not recorded — see PoC script)*\n"

            content += f"""
---

## Impact

{vuln.get('impact', 'Impact assessment pending.')}

---

## Remediation

{vuln.get('remediation', 'Remediation recommendations pending.')}

---

## Proof of Concept

"""
            if poc_records:
                poc = poc_records[0]
                verified = poc.get("verified_poc", False)
                content += f"**PoC Verified:** {'YES' if verified else 'NO'}\n"
                content += f"**PoC Mode:** {poc.get('poc_mode', 'N/A')}\n"
                content += f"**Payload Used:** `{poc.get('payload', 'N/A')}`\n"
                content += f"**Validation:** {poc.get('successes', 0)}/{poc.get('retries', 0)} attempts successful\n"
            else:
                content += "*(No automated PoC generated)*\n"

            content += """
---

## Evidence

| # | Type | Path |
|---|------|------|
"""
            for i, ev in enumerate(evidence, 1):
                content += f"| {i} | {ev.get('type', '')} | `{ev.get('path', '')}` |\n"

            if not evidence:
                content += "| — | No evidence captured | — |\n"

            # List screenshots separately for easy reference
            screenshots = [ev for ev in evidence if ev.get("type") == "screenshot"]
            if screenshots:
                content += "\n### Screenshots\n\n"
                for ss in screenshots:
                    content += f"- `{ss.get('path', '')}`\n"

            content += f"""
---

*Generated by ReportAgent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
            with open(filepath, "w") as f:
                f.write(content)
            generated += 1

        return {"status": "ok", "findings_generated": generated}

    def _generate_executive_summary(self) -> dict:
        """Generate executive summary report."""
        eng = self.config.get("engagement", {})
        vulns = self.kb.get_vulnerabilities()
        chains = self.kb.get_attack_paths()
        summary_data = self.kb.summary()

        sev_counts = summary_data.get("vulnerabilities_by_severity", {})
        total = len(vulns)

        # Determine overall risk
        if sev_counts.get("Critical", 0) > 0:
            overall = "CRITICAL"
        elif sev_counts.get("High", 0) > 0:
            overall = "HIGH"
        elif sev_counts.get("Medium", 0) > 0:
            overall = "MEDIUM"
        else:
            overall = "LOW"

        content = f"""# Executive Summary — Penetration Test Report

> **Engagement:** {eng.get('name', 'N/A')}
> **Client:** {eng.get('client', 'N/A')}
> **Engagement ID:** {eng.get('id', 'N/A')}
> **Report Date:** {datetime.now().strftime('%Y-%m-%d')}
> **Lead Tester:** {eng.get('lead_tester', 'N/A')}

---

## Overall Risk Rating: {overall}

---

## Key Findings

| Severity | Count |
|----------|-------|
| Critical | {sev_counts.get('Critical', 0)} |
| High | {sev_counts.get('High', 0)} |
| Medium | {sev_counts.get('Medium', 0)} |
| Low | {sev_counts.get('Low', 0)} |
| **Total** | **{total}** |

---

## Scope

| Metric | Value |
|--------|-------|
| Assets Discovered | {summary_data.get('assets', 0)} |
| Endpoints Tested | {summary_data.get('endpoints', 0)} |
| Vulnerabilities Found | {total} |
| Attack Chains Identified | {len(chains)} |
| Evidence Items | {summary_data.get('evidence', 0)} |

---

## Critical & High Findings Summary

| ID | Title | Severity | CVSS |
|----|-------|----------|------|
"""
        for v in sorted(vulns, key=lambda x: x.get("cvss", 0), reverse=True):
            if v.get("severity") in ("Critical", "High"):
                content += f"| {v.get('finding_id', '')} | {v.get('title', '')} | {v.get('severity', '')} | {v.get('cvss', '')} |\n"

        if chains:
            content += f"""
---

## Attack Chains

| Chain | Combined Severity | Vulnerabilities |
|-------|-------------------|-----------------|
"""
            for c in chains:
                vuln_ids = ", ".join(c.get("vulnerabilities", []))
                content += f"| {c.get('name', '')} | {c.get('combined_severity', '')} | {vuln_ids} |\n"

        content += f"""
---

## Recommendations

1. **Immediate:** Address all Critical and High severity findings
2. **Short-term:** Remediate Medium severity findings and broken attack chains
3. **Long-term:** Implement security headers, rate limiting, and monitoring

---

*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by VAPT Framework*
"""
        filepath = REPORTS_DIR / "EXECUTIVE_SUMMARY.md"
        with open(filepath, "w") as f:
            f.write(content)

        return {"status": "ok", "path": str(filepath), "overall_risk": overall}

    def _generate_technical_report(self) -> dict:
        """Generate full technical report."""
        eng = self.config.get("engagement", {})
        vulns = self.kb.get_vulnerabilities()
        assets = self.kb.get_all("assets")
        endpoints = self.kb.get_all("endpoints")
        chains = self.kb.get_attack_paths()

        content = f"""# Technical Penetration Test Report

> **Engagement:** {eng.get('name', 'N/A')}
> **Client:** {eng.get('client', 'N/A')}
> **Engagement ID:** {eng.get('id', 'N/A')}
> **Report Date:** {datetime.now().strftime('%Y-%m-%d')}
> **Lead Tester:** {eng.get('lead_tester', 'N/A')}
> **Classification:** {self.config.get('preferences', {}).get('reporting', {}).get('classification', 'CONFIDENTIAL')}

---

## 1. Methodology

This penetration test followed the PTES (Penetration Testing Execution Standard) methodology:

1. **Reconnaissance** — Passive and active information gathering
2. **Enumeration** — Service, endpoint, and API discovery
3. **Vulnerability Discovery** — Automated and manual vulnerability testing
4. **Exploitation** — Controlled proof-of-concept validation
5. **Attack Chain Analysis** — Vulnerability chaining and escalation assessment
6. **Reporting** — Findings documentation and remediation guidance

---

## 2. Scope

### 2.1 In-Scope Targets

"""
        scope = self.config.get("scope", {}).get("in_scope", {})
        for d in scope.get("domains", []):
            if isinstance(d, dict) and d.get("domain"):
                content += f"- `{d['domain']}` — {d.get('notes', '')}\n"

        content += f"""
### 2.2 Discovered Assets

| # | Domain/Asset | Type | Source |
|---|-------------|------|--------|
"""
        for i, a in enumerate(assets[:50], 1):
            content += f"| {i} | {a.get('domain', a.get('tech_name', ''))} | {a.get('type', '')} | {a.get('source', '')} |\n"

        content += f"""
### 2.3 Endpoints Discovered

Total endpoints: **{len(endpoints)}**

---

## 3. Findings

"""
        # Group by domain → severity
        domain_groups: dict = {}
        for v in vulns:
            d = v.get("domain", "unknown")
            domain_groups.setdefault(d, []).append(v)

        section_num = 1
        for domain in sorted(domain_groups.keys()):
            content += f"### 3.{section_num} {domain}\n\n"
            domain_vulns = sorted(domain_groups[domain], key=lambda x: x.get("cvss", 0), reverse=True)
            for v in domain_vulns:
                sev = v.get('severity', 'N/A')
                subdomain = v.get('subdomain', domain)
                target_label = f" ({subdomain})" if subdomain != domain else ""
                content += f"#### {v.get('finding_id', '')} — {v.get('title', '')}{target_label}\n\n"
                content += f"- **Severity:** {sev}\n"
                content += f"- **CVSS:** {v.get('cvss', 'N/A')}\n"
                content += f"- **Type:** {v.get('vuln_type', '')}\n"
                content += f"- **OWASP:** {v.get('owasp_category', '')}\n"
                content += f"- **CWE:** {v.get('cwe', '')}\n"
                content += f"- **Endpoint:** `{v.get('endpoint', '')}`\n"
                content += f"- **Status:** {v.get('status', 'DRAFT')}\n\n"
                content += f"{v.get('description', '')}\n\n"
            section_num += 1

        if chains:
            content += f"""
---

## 4. Attack Chain Analysis

"""
            for i, c in enumerate(chains, 1):
                content += f"### Chain {i}: {c.get('name', '')}\n\n"
                content += f"**Combined Severity:** {c.get('combined_severity', '')}\n\n"
                content += f"**Impact:** {c.get('impact', '')}\n\n"
                for step in c.get("steps", []):
                    content += f"- Step {step.get('step', '')}: {step.get('action', '')} ({step.get('finding', '')})\n"
                content += "\n"

        content += f"""
---

## 5. Remediation Roadmap

| Priority | Action | Findings |
|----------|--------|----------|
| P0 (Immediate) | Fix Critical vulnerabilities | {', '.join(v.get('finding_id', '') for v in vulns if v.get('severity') == 'Critical')} |
| P1 (1 week) | Fix High vulnerabilities | {', '.join(v.get('finding_id', '') for v in vulns if v.get('severity') == 'High')} |
| P2 (1 month) | Fix Medium vulnerabilities | {', '.join(v.get('finding_id', '') for v in vulns if v.get('severity') == 'Medium')} |
| P3 (Backlog) | Fix Low vulnerabilities | {', '.join(v.get('finding_id', '') for v in vulns if v.get('severity') == 'Low')} |

---

*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by VAPT Framework*
"""
        filepath = REPORTS_DIR / "TECHNICAL_REPORT.md"
        with open(filepath, "w") as f:
            f.write(content)

        return {"status": "ok", "path": str(filepath)}

    def _update_index(self) -> dict:
        """Update the findings index, organized by domain/subdomain."""
        eng = self.config.get("engagement", {})
        vulns = self.kb.get_vulnerabilities()

        content = f"""# Reports Index
> Engagement: {eng.get('name', 'N/A')} ({eng.get('id', 'N/A')})
> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Finding Index (by Domain)

"""
        # Group findings by domain → subdomain
        domain_groups: dict = {}
        for v in sorted(vulns, key=lambda x: x.get("cvss", 0), reverse=True):
            domain = v.get("domain", "unknown")
            subdomain = v.get("subdomain", domain)
            domain_groups.setdefault(domain, {}).setdefault(subdomain, []).append(v)

        for domain in sorted(domain_groups.keys()):
            content += f"### {domain}\n\n"
            for subdomain in sorted(domain_groups[domain].keys()):
                if subdomain != domain:
                    content += f"#### {subdomain}\n\n"
                content += "| ID | Vulnerability | Severity | CVSS | Type | Status | Path |\n"
                content += "|----|---------------|----------|------|------|--------|------|\n"
                for v in domain_groups[domain][subdomain]:
                    fid = v.get('finding_id', '')
                    if subdomain == domain:
                        rel_path = f"findings/{domain}/{fid}.md"
                    else:
                        rel_path = f"findings/{domain}/{subdomain}/{fid}.md"
                    content += (f"| {fid} | {v.get('title', '')} | "
                                f"{v.get('severity', '')} | {v.get('cvss', '')} | "
                                f"{v.get('vuln_type', '')} | {v.get('status', 'DRAFT')} | "
                                f"`{rel_path}` |\n")
                content += "\n"

        content += f"""---

## Reports

| Report | Location | Status |
|--------|----------|--------|
| Executive Summary | reports/EXECUTIVE_SUMMARY.md | Generated |
| Technical Report | reports/TECHNICAL_REPORT.md | Generated |
| Individual Findings | reports/findings/<domain>/<subdomain>/ | {len(vulns)} generated |

---

*Updated by ReportAgent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        filepath = REPORTS_DIR / "INDEX.md"
        with open(filepath, "w") as f:
            f.write(content)

        return {"status": "ok", "findings_indexed": len(vulns)}

    def report(self) -> dict:
        vulns = self.kb.get_vulnerabilities()
        return {
            "agent": self.name,
            "phase": self.phase,
            "state": self.state,
            "findings_documented": len(vulns),
            "reports_generated": ["EXECUTIVE_SUMMARY.md", "TECHNICAL_REPORT.md", "INDEX.md"],
            "actions_executed": len(self.results),
        }
