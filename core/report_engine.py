"""
core/report_engine.py

Professional report generation engine.
Produces: HTML report, plain-text technical report, executive summary,
per-finding sections, attack chain diagrams (Mermaid), and bug bounty
submission format (HackerOne / Bugcrowd markdown).

Architecture reference: ARCHITECTURE.md § 11 "Reporting Engine"
"""

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#d63031",
    "high":     "#e17055",
    "medium":   "#fdcb6e",
    "low":      "#00b894",
    "info":     "#74b9ff",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ------------------------------------------------------------------
# Data containers
# ------------------------------------------------------------------

@dataclass
class EngagementMeta:
    title: str
    target: str
    start_date: str
    end_date: str
    tester: str
    client: str
    engagement_id: str
    classification: str = "CONFIDENTIAL"


# ------------------------------------------------------------------
# HTML Report Generator
# ------------------------------------------------------------------

class HTMLReportGenerator:
    """
    Generates a self-contained HTML report with embedded CSS.
    No external dependencies — single .html file deliverable.
    """

    def generate(
        self,
        meta: EngagementMeta,
        findings: list[dict],
        attack_chains: list[dict],
        output_path: str,
    ) -> str:
        findings_sorted = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info").lower(), 99),
        )

        severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in findings_sorted:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        risk_score = self._compute_risk_score(findings_sorted)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{meta.title} — Security Assessment Report</title>
<style>
  {self._css()}
</style>
</head>
<body>
<div class="container">

  <!-- Cover -->
  <div class="cover">
    <div class="cover-badge">{meta.classification}</div>
    <h1>Security Assessment Report</h1>
    <h2>{meta.title}</h2>
    <div class="cover-meta">
      <div><span>Target</span> {meta.target}</div>
      <div><span>Period</span> {meta.start_date} – {meta.end_date}</div>
      <div><span>Client</span> {meta.client}</div>
      <div><span>Tested By</span> {meta.tester}</div>
      <div><span>Report Date</span> {datetime.utcnow().strftime('%Y-%m-%d')}</div>
      <div><span>Engagement ID</span> {meta.engagement_id}</div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <h2>Executive Summary</h2>
    <div class="risk-gauge">
      <div class="gauge-label">Overall Risk Score</div>
      <div class="gauge-value" style="color:{self._risk_color(risk_score)}">{risk_score}/10</div>
    </div>

    <div class="severity-grid">
      {self._severity_badges(severity_counts)}
    </div>

    <p>This security assessment identified <strong>{len(findings_sorted)}</strong> vulnerabilities
    across the target environment, including
    <strong style="color:{SEVERITY_COLORS['critical']}">{severity_counts['critical']} Critical</strong> and
    <strong style="color:{SEVERITY_COLORS['high']}">{severity_counts['high']} High</strong> severity findings.
    {self._executive_narrative(severity_counts, attack_chains)}
    </p>
  </div>

  <!-- Findings Table -->
  <div class="section">
    <h2>Findings Summary</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>Endpoint</th>
          <th>OWASP</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {self._findings_table_rows(findings_sorted)}
      </tbody>
    </table>
  </div>

  <!-- Attack Chains -->
  {self._attack_chains_section(attack_chains)}

  <!-- Individual Findings -->
  <div class="section">
    <h2>Detailed Findings</h2>
    {''.join(self._finding_section(f) for f in findings_sorted)}
  </div>

  <!-- Footer -->
  <div class="footer">
    <p>{meta.classification} — {meta.title} — Generated {datetime.utcnow().isoformat()}Z</p>
    <p>This report is intended solely for the named client and authorised recipients.</p>
  </div>

</div>
</body>
</html>"""

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"[ReportEngine] HTML report written: {output_path}")
        return output_path

    # ------------------------------------------------------------------
    # HTML section builders
    # ------------------------------------------------------------------

    def _severity_badges(self, counts: dict) -> str:
        parts = []
        for sev, count in counts.items():
            color = SEVERITY_COLORS.get(sev, "#aaa")
            parts.append(
                f'<div class="sev-badge" style="border-color:{color}">'
                f'<div class="sev-count" style="color:{color}">{count}</div>'
                f'<div class="sev-label">{sev.upper()}</div>'
                f'</div>'
            )
        return "".join(parts)

    def _findings_table_rows(self, findings: list[dict]) -> str:
        rows = []
        for f in findings:
            sev = f.get("severity", "info").lower()
            color = SEVERITY_COLORS.get(sev, "#aaa")
            fid = f.get("id", "")
            rows.append(
                f'<tr>'
                f'<td><a href="#{fid}">{fid}</a></td>'
                f'<td>{f.get("title", "")}</td>'
                f'<td><span class="sev-tag" style="background:{color}">{sev.upper()}</span></td>'
                f'<td>{f.get("cvss", "N/A")}</td>'
                f'<td class="mono">{f.get("endpoint", "")[:60]}</td>'
                f'<td>{f.get("owasp_category", "")}</td>'
                f'<td>{f.get("status", "")}</td>'
                f'</tr>'
            )
        return "".join(rows)

    def _finding_section(self, finding: dict) -> str:
        sev = finding.get("severity", "info").lower()
        color = SEVERITY_COLORS.get(sev, "#aaa")
        fid = finding.get("id", "")
        screenshots = finding.get("evidence", {}).get("screenshots", [])
        screenshot_html = ""
        if screenshots:
            screenshot_html = f'<div class="screenshot-note">📸 {len(screenshots)} screenshot(s) available in evidence package.</div>'

        steps = finding.get("steps_to_reproduce", [])
        steps_html = ""
        if steps:
            items = "".join(f"<li>{s}</li>" for s in steps)
            steps_html = f"<ol>{items}</ol>"

        return f"""
<div class="finding" id="{fid}">
  <div class="finding-header" style="border-left: 4px solid {color}">
    <span class="finding-id">{fid}</span>
    <span class="finding-title">{finding.get("title", "")}</span>
    <span class="sev-tag" style="background:{color}">{sev.upper()}</span>
    <span class="cvss-tag">CVSS {finding.get("cvss", "N/A")}</span>
  </div>
  <div class="finding-body">
    <div class="meta-grid">
      <div><strong>OWASP</strong> {finding.get("owasp_category", "")}</div>
      <div><strong>CWE</strong> {finding.get("cwe", "")}</div>
      <div><strong>Endpoint</strong> <code>{finding.get("endpoint", "")}</code></div>
      <div><strong>Parameter</strong> <code>{finding.get("parameter", "N/A")}</code></div>
      <div><strong>Status</strong> {finding.get("status", "")}</div>
    </div>

    <h4>Description</h4>
    <p>{finding.get("description", "")}</p>

    <h4>Steps to Reproduce</h4>
    {steps_html or "<p>See attached PoC script.</p>"}

    <h4>Impact</h4>
    <p>{finding.get("impact", "")}</p>

    <h4>Remediation</h4>
    <p>{finding.get("remediation", "")}</p>

    {screenshot_html}
  </div>
</div>"""

    def _attack_chains_section(self, chains: list[dict]) -> str:
        if not chains:
            return ""
        chain_html = "".join(self._chain_card(c) for c in chains)
        return f"""
<div class="section">
  <h2>Attack Chain Analysis</h2>
  <p>The following multi-step attack chains were identified by correlating verified vulnerabilities.</p>
  {chain_html}
</div>"""

    def _chain_card(self, chain: dict) -> str:
        sev = chain.get("severity", "high").lower()
        color = SEVERITY_COLORS.get(sev, "#aaa")
        steps = chain.get("steps", [])
        steps_html = " → ".join(
            f'<span class="chain-step">{s.get("vulnerability_type", "?")}</span>'
            for s in steps
        )
        mermaid = self._chain_to_mermaid(chain)
        return f"""
<div class="chain-card" style="border-left: 4px solid {color}">
  <div class="chain-header">
    <strong>{chain.get("chain_id", "")}</strong>: {chain.get("name", "")}
    <span class="sev-tag" style="background:{color}">{sev.upper()}</span>
    <span class="chain-score">Score: {chain.get("chain_score", 0)}/10</span>
  </div>
  <div class="chain-flow">{steps_html}</div>
  <p>{chain.get("narrative", chain.get("description", ""))}</p>
  <div class="chain-impact"><strong>Impact:</strong> {chain.get("combined_impact", "")}</div>
  <div class="mermaid-block"><pre>{mermaid}</pre></div>
</div>"""

    @staticmethod
    def _chain_to_mermaid(chain: dict) -> str:
        """Generate Mermaid flowchart syntax for the chain."""
        steps = chain.get("steps", [])
        if not steps:
            return ""
        lines = ["graph LR"]
        for i, step in enumerate(steps):
            node_id = f"S{i}"
            next_id = f"S{i+1}"
            label = step.get("vulnerability_type", "?")
            result = step.get("result", "")[:40]
            lines.append(f'  {node_id}["{label}"]')
            if i < len(steps) - 1:
                lines.append(f'  {node_id} -->|"{result}"| {next_id}')
        lines.append(f'  S{len(steps)-1}["{chain.get("combined_impact", "IMPACT")[:30]}"]')
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Scoring / narrative
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score(findings: list[dict]) -> float:
        if not findings:
            return 0.0
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        total = sum(weights.get(f.get("severity", "info").lower(), 0) for f in findings)
        max_possible = len(findings) * 10
        return round((total / max_possible) * 10, 1) if max_possible else 0.0

    @staticmethod
    def _risk_color(score: float) -> str:
        if score >= 8:
            return SEVERITY_COLORS["critical"]
        if score >= 6:
            return SEVERITY_COLORS["high"]
        if score >= 4:
            return SEVERITY_COLORS["medium"]
        return SEVERITY_COLORS["low"]

    @staticmethod
    def _executive_narrative(counts: dict, chains: list) -> str:
        chain_note = ""
        if chains:
            chain_note = (
                f" {len(chains)} multi-step attack chain(s) were identified, "
                f"where individual vulnerabilities can be combined to achieve greater impact."
            )
        if counts.get("critical", 0) > 0:
            return (
                f"Immediate remediation is required for critical findings before the application "
                f"can be considered safe for production use.{chain_note}"
            )
        if counts.get("high", 0) > 0:
            return (
                f"High severity findings should be remediated within 30 days.{chain_note}"
            )
        return f"No critical issues were identified. Medium/low findings should be addressed per the remediation schedule.{chain_note}"

    # ------------------------------------------------------------------
    # CSS
    # ------------------------------------------------------------------

    @staticmethod
    def _css() -> str:
        return """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       margin: 0; padding: 0; background: #f8f9fa; color: #2d3436; }
.container { max-width: 1100px; margin: 0 auto; padding: 40px 20px; }
.cover { background: #1a1a2e; color: white; border-radius: 12px; padding: 60px 40px;
         margin-bottom: 40px; text-align: center; }
.cover h1 { font-size: 2rem; margin: 20px 0 10px; }
.cover h2 { font-size: 1.4rem; color: #74b9ff; margin: 0 0 30px; }
.cover-badge { display: inline-block; background: #d63031; color: white;
               padding: 4px 16px; border-radius: 4px; font-size: 0.8rem;
               letter-spacing: 2px; font-weight: bold; }
.cover-meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;
              margin-top: 30px; text-align: left; }
.cover-meta div { background: rgba(255,255,255,0.05); padding: 12px 16px;
                  border-radius: 8px; }
.cover-meta span { display: block; color: #74b9ff; font-size: 0.75rem;
                   text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
.section { background: white; border-radius: 12px; padding: 32px; margin-bottom: 24px;
           box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
.section h2 { font-size: 1.4rem; border-bottom: 2px solid #f0f0f0;
              padding-bottom: 12px; margin-top: 0; }
.risk-gauge { text-align: center; margin: 20px 0; }
.gauge-label { color: #636e72; font-size: 0.9rem; }
.gauge-value { font-size: 3rem; font-weight: bold; }
.severity-grid { display: flex; gap: 16px; margin: 24px 0; flex-wrap: wrap; }
.sev-badge { border: 2px solid; border-radius: 8px; padding: 12px 20px;
             text-align: center; min-width: 80px; }
.sev-count { font-size: 2rem; font-weight: bold; }
.sev-label { font-size: 0.75rem; font-weight: 600; letter-spacing: 1px; margin-top: 4px; }
.sev-tag { display: inline-block; color: white; padding: 2px 10px; border-radius: 4px;
           font-size: 0.75rem; font-weight: bold; letter-spacing: 1px; }
.cvss-tag { display: inline-block; background: #f0f0f0; padding: 2px 8px;
            border-radius: 4px; font-size: 0.8rem; margin-left: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th { background: #f8f9fa; padding: 10px 12px; text-align: left; font-weight: 600;
     border-bottom: 2px solid #e9ecef; }
td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
tr:hover td { background: #f8f9fa; }
.mono { font-family: 'Courier New', monospace; font-size: 0.8rem; }
.finding { border: 1px solid #e9ecef; border-radius: 8px; margin-bottom: 20px;
           overflow: hidden; }
.finding-header { background: #f8f9fa; padding: 14px 20px; display: flex;
                  align-items: center; gap: 12px; }
.finding-id { font-family: monospace; font-weight: bold; color: #636e72; }
.finding-title { flex: 1; font-weight: 600; }
.finding-body { padding: 20px; }
.meta-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;
             background: #f8f9fa; padding: 16px; border-radius: 8px; margin-bottom: 20px;
             font-size: 0.85rem; }
code { background: #f0f0f0; padding: 1px 6px; border-radius: 3px;
       font-family: monospace; font-size: 0.85em; }
.chain-card { border: 1px solid #e9ecef; border-radius: 8px; margin-bottom: 16px;
              padding: 20px; }
.chain-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px;
                flex-wrap: wrap; }
.chain-score { margin-left: auto; color: #636e72; font-size: 0.9rem; }
.chain-flow { display: flex; align-items: center; gap: 8px; margin: 12px 0;
              flex-wrap: wrap; }
.chain-step { background: #f0f0f0; padding: 4px 12px; border-radius: 4px;
              font-size: 0.85rem; font-weight: 600; }
.chain-impact { background: #fff3e0; border-left: 3px solid #e17055;
                padding: 10px 14px; border-radius: 4px; margin-top: 12px;
                font-size: 0.9rem; }
.mermaid-block { background: #f8f9fa; border-radius: 4px; padding: 12px;
                 margin-top: 12px; overflow-x: auto; }
.mermaid-block pre { margin: 0; font-size: 0.75rem; white-space: pre-wrap; }
.screenshot-note { background: #e3f2fd; border-radius: 4px; padding: 8px 12px;
                   font-size: 0.85rem; margin-top: 12px; }
.footer { text-align: center; color: #aaa; font-size: 0.8rem; margin-top: 40px; }
h4 { color: #2d3436; margin: 20px 0 8px; font-size: 1rem; }
"""


# ------------------------------------------------------------------
# Bug Bounty Submission Formatter
# ------------------------------------------------------------------

class BugBountyFormatter:
    """
    Formats findings for HackerOne (Markdown) or Bugcrowd (HTML) submission.
    """

    def format_hackerone(self, finding: dict) -> str:
        """Generate HackerOne-compatible Markdown report."""
        steps = finding.get("steps_to_reproduce", [])
        steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
        default_steps = "1. Navigate to the affected endpoint\n2. Observe the vulnerability"
        steps_section = steps_md if steps_md else default_steps

        payload = finding.get("payload_used", "See steps below")
        poc_script = finding.get("poc_script", "")
        poc_block = f"\n```bash\n{poc_script}\n```\n" if poc_script else ""

        return f"""## Summary
{finding.get("description", "")}

**Severity:** {finding.get("severity", "").upper()}
**CVSS Score:** {finding.get("cvss", "N/A")} ({finding.get("cvss_vector", "")})
**OWASP Category:** {finding.get("owasp_category", "")}
**CWE:** {finding.get("cwe", "")}

## Affected Assets
- **URL:** `{finding.get("endpoint", "")}`
- **Parameter:** `{finding.get("parameter", "N/A")}`
- **Method:** `{finding.get("method", "GET")}`

## Steps to Reproduce
{steps_section}

## Proof of Concept
**Payload used:**
```
{payload}
```
{poc_block}

## Impact
{finding.get("impact", "")}

## Remediation Recommendation
{finding.get("remediation", "")}

## Severity Justification
- **Confidentiality:** {finding.get("confidentiality_impact", "High")}
- **Integrity:** {finding.get("integrity_impact", "High")}
- **Availability:** {finding.get("availability_impact", "None")}
- **Authentication Required:** {finding.get("auth_required", False)}
"""

    def format_bugcrowd(self, finding: dict) -> str:
        """Generate Bugcrowd-compatible report (simplified HTML)."""
        return f"""<h2>{finding.get("title", "")}</h2>
<p><strong>Severity:</strong> {finding.get("severity", "").upper()} (CVSS {finding.get("cvss", "N/A")})</p>
<p><strong>Endpoint:</strong> <code>{finding.get("endpoint", "")}</code></p>
<h3>Description</h3>
<p>{finding.get("description", "")}</p>
<h3>Steps to Reproduce</h3>
<ol>{''.join(f"<li>{s}</li>" for s in finding.get("steps_to_reproduce", []))}</ol>
<h3>Impact</h3>
<p>{finding.get("impact", "")}</p>
<h3>Remediation</h3>
<p>{finding.get("remediation", "")}</p>"""


# ------------------------------------------------------------------
# Main report engine
# ------------------------------------------------------------------

class ReportEngine:
    """
    Orchestrates report generation across all formats.
    """

    def __init__(self, config: dict, output_dir: str = "reports"):
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._html_gen = HTMLReportGenerator()
        self._bb_formatter = BugBountyFormatter()

    def generate_all(
        self,
        findings: list[dict],
        attack_chains: list[dict],
        engagement_id: str = "ENG-001",
    ) -> dict[str, str]:
        """
        Generate all report formats. Returns dict of format → file path.
        """
        meta = self._build_meta(engagement_id)
        output_paths: dict[str, str] = {}

        # HTML report
        html_path = str(self.output_dir / f"{engagement_id}_report.html")
        self._html_gen.generate(meta, findings, attack_chains, html_path)
        output_paths["html"] = html_path

        # Executive summary (text)
        exec_path = str(self.output_dir / "EXECUTIVE_SUMMARY.md")
        self._write_executive_summary(meta, findings, attack_chains, exec_path)
        output_paths["executive"] = exec_path

        # Technical report (text)
        tech_path = str(self.output_dir / "TECHNICAL_REPORT.md")
        self._write_technical_report(meta, findings, attack_chains, tech_path)
        output_paths["technical"] = tech_path

        # Bug bounty submissions
        bb_dir = self.output_dir / "bug_bounty"
        bb_dir.mkdir(exist_ok=True)
        for finding in findings:
            fid = finding.get("id", "F-000")
            bb_path = str(bb_dir / f"{fid}_hackerone.md")
            with open(bb_path, "w") as f:
                f.write(self._bb_formatter.format_hackerone(finding))
            output_paths[f"bb_{fid}"] = bb_path

        # Index
        index_path = str(self.output_dir / "INDEX.md")
        self._write_index(findings, attack_chains, output_paths, index_path)
        output_paths["index"] = index_path

        logger.info(f"[ReportEngine] Generated {len(output_paths)} report files in {self.output_dir}")
        return output_paths

    def _build_meta(self, engagement_id: str) -> EngagementMeta:
        target_cfg = self.config.get("target", {})
        engagement_cfg = self.config.get("engagement", {})
        return EngagementMeta(
            title=engagement_cfg.get("name", "Security Assessment"),
            target=target_cfg.get("domain", "Target"),
            start_date=engagement_cfg.get("start_date", datetime.utcnow().strftime("%Y-%m-%d")),
            end_date=datetime.utcnow().strftime("%Y-%m-%d"),
            tester=engagement_cfg.get("tester", "Security Team"),
            client=engagement_cfg.get("client", "Client"),
            engagement_id=engagement_id,
        )

    def _write_executive_summary(
        self,
        meta: EngagementMeta,
        findings: list[dict],
        chains: list[dict],
        path: str,
    ):
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        content = f"""# Executive Summary — {meta.title}

**Client:** {meta.client}
**Target:** {meta.target}
**Assessment Period:** {meta.start_date} – {meta.end_date}
**Prepared By:** {meta.tester}
**Classification:** {meta.classification}

## Risk Posture

| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get("critical", 0)} |
| High     | {severity_counts.get("high", 0)} |
| Medium   | {severity_counts.get("medium", 0)} |
| Low      | {severity_counts.get("low", 0)} |
| Info     | {severity_counts.get("info", 0)} |
| **Total**| **{len(findings)}** |

## Key Findings

{"No critical findings." if not severity_counts.get("critical") else
"Immediate attention required for critical findings before production deployment."}

## Attack Chains Identified

{len(chains)} multi-step attack chain(s) were identified during this assessment.

{"- " + chr(10).join(f"**{c.get('name', '')}** (Score: {c.get('chain_score', 0)}/10)" for c in chains[:5]) if chains else "None identified."}

## Recommendations

1. Remediate all Critical findings within 24-48 hours.
2. Remediate all High findings within 30 days.
3. Schedule re-testing after remediation to verify fixes.
4. Address attack chains by fixing the first link in each chain.
"""
        with open(path, "w") as f:
            f.write(content)

    def _write_technical_report(
        self,
        meta: EngagementMeta,
        findings: list[dict],
        chains: list[dict],
        path: str,
    ):
        finding_sections = "\n\n".join(
            self._finding_md(f) for f in sorted(
                findings,
                key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info").lower(), 99),
            )
        )

        chain_sections = "\n\n".join(
            f"""### {c.get("chain_id")} — {c.get("name")}
**Severity:** {c.get("severity", "").upper()} | **Score:** {c.get("chain_score", 0)}/10

{c.get("narrative", c.get("description", ""))}

**Impact:** {c.get("combined_impact", "")}

**Remediation:** {c.get("remediation", "")}"""
            for c in chains
        ) or "No attack chains identified."

        content = f"""# Technical Report — {meta.title}

**Engagement ID:** {meta.engagement_id}
**Classification:** {meta.classification}

## Methodology

This assessment followed the PTES (Penetration Testing Execution Standard) 5-phase lifecycle:

1. **Reconnaissance** — Passive and active asset discovery
2. **Enumeration** — Endpoint, API, and authentication mapping
3. **Exploitation** — Controlled proof-of-concept testing
4. **Post-Exploitation** — Attack chain analysis and impact assessment
5. **Reporting** — Finding documentation and remediation guidance

## Scope

- **Target:** {meta.target}
- **Period:** {meta.start_date} – {meta.end_date}

## Findings

{finding_sections}

## Attack Chains

{chain_sections}
"""
        with open(path, "w") as f:
            f.write(content)

    @staticmethod
    def _finding_md(finding: dict) -> str:
        fid = finding.get("id", "")
        steps = finding.get("steps_to_reproduce", [])
        steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
        return f"""### {fid} — {finding.get("title", "")}

| Field | Value |
|-------|-------|
| Severity | {finding.get("severity", "").upper()} |
| CVSS | {finding.get("cvss", "N/A")} |
| OWASP | {finding.get("owasp_category", "")} |
| CWE | {finding.get("cwe", "")} |
| Endpoint | `{finding.get("endpoint", "")}` |
| Status | {finding.get("status", "")} |

**Description:** {finding.get("description", "")}

**Steps to Reproduce:**
{steps_md or "See PoC script."}

**Impact:** {finding.get("impact", "")}

**Remediation:** {finding.get("remediation", "")}"""

    def _write_index(
        self,
        findings: list[dict],
        chains: list[dict],
        paths: dict[str, str],
        index_path: str,
    ):
        rows = "\n".join(
            f"| {f.get('id','')} | {f.get('title','')} | "
            f"{f.get('severity','').upper()} | {f.get('cvss','N/A')} | {f.get('status','')} |"
            for f in findings
        )
        generated_at = datetime.utcnow().isoformat() + "Z"
        content = f"""# Report Index

Generated: {generated_at}

## Findings

| ID | Title | Severity | CVSS | Status |
|----|-------|----------|------|--------|
{rows}

## Generated Files

{chr(10).join(f"- **{k}**: `{v}`" for k, v in paths.items())}

## Attack Chains

{len(chains)} chain(s) detected. See TECHNICAL_REPORT.md for details.
"""
        with open(index_path, "w") as f:
            f.write(content)
