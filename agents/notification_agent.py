#!/usr/bin/env python3
"""
Notification Agent — Phase 9: Email Notification System
=========================================================
Sends alert emails when critical vulnerabilities are discovered.
Sends final report via Gmail when pentest is completed.

Uses Gmail SMTP with app passwords for delivery.
"""

import json
import logging
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

from agents.base_agent import BaseAgent
from typing import Any, List, Optional

logger = logging.getLogger("agent.notification")

BASE_DIR = Path(__file__).parent.parent.resolve()
SCREENSHOTS_DIR = BASE_DIR / "evidence" / "screenshots"
EMAIL_DIR = BASE_DIR / "reports" / "emails"


class NotificationAgent(BaseAgent):
    name = "NotificationAgent"
    description = "Email notifications — critical alerts, finding reports, final report delivery"
    phase = "notification"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gmail_config = self.config.get("notifications", {}).get("gmail", {})
        self.smtp_server = self.gmail_config.get("smtp_server", "smtp.gmail.com")
        self.smtp_port = self.gmail_config.get("smtp_port", 465)
        self.sender_email = self.gmail_config.get("sender_email", "")
        self.app_password = self.gmail_config.get("app_password", "")
        self.recipients = self.gmail_config.get("recipients", {})
        self.enabled = self.gmail_config.get("enabled", False)

    def plan(self) -> List[dict]:
        actions = []

        if not self.enabled:
            self._log("Notifications disabled in config — skipping")
            return actions

        if not self.sender_email or not self.app_password:
            self._log("Gmail credentials not configured — skipping", level="warning")
            return actions

        vulns = self.kb.get_vulnerabilities()

        # Critical vulnerability alerts
        critical = [v for v in vulns if v.get("severity") == "Critical"]
        if critical:
            actions.append({
                "action": "send_critical_alert",
                "target": "security_team",
                "description": f"Send {len(critical)} critical vulnerability alert(s)",
                "vulnerabilities": critical,
            })

        # Individual finding emails (for all confirmed findings)
        confirmed = [v for v in vulns if v.get("status") in ("EXPLOITED", "CONFIRMED")]
        for vuln in confirmed:
            actions.append({
                "action": "send_finding_email",
                "target": vuln.get("finding_id", ""),
                "description": f"Send finding report: {vuln.get('finding_id', '')}",
                "vulnerability": vuln,
            })

        # Final completion report
        actions.append({
            "action": "send_completion_report",
            "target": "all_recipients",
            "description": "Send pentest completion report",
        })

        return actions

    def execute(self, plan: List[dict]) -> List[dict]:
        results = []
        for action in plan:
            self._log(f"Executing: {action['description']}")

            if action["action"] == "send_critical_alert":
                result = self._send_critical_alert(action.get("vulnerabilities", []))
            elif action["action"] == "send_finding_email":
                result = self._send_finding_email(action.get("vulnerability", {}))
            elif action["action"] == "send_completion_report":
                result = self._send_completion_report()
            else:
                result = {"status": "skipped"}

            result["action"] = action["action"]
            result["target"] = action.get("target", "")
            results.append(result)
        return results

    def _build_finding_html(self, vuln: dict) -> str:
        """Build HTML email body for a finding."""
        eng = self.config.get("engagement", {})
        return f"""
<html>
<body style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
<h1 style="color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 8px;">
    Vulnerability Report: {vuln.get('title', '')}
</h1>
<table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
    <tr><td style="padding: 4px 12px; font-weight: bold;">Reporter:</td>
        <td>{eng.get('lead_tester', '')}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">Severity:</td>
        <td style="color: {'#d32f2f' if vuln.get('severity') == 'Critical' else '#f57c00' if vuln.get('severity') == 'High' else '#fbc02d' if vuln.get('severity') == 'Medium' else '#388e3c'}; font-weight: bold;">
        {vuln.get('severity', '')}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">CVSS v3.1:</td>
        <td>{vuln.get('cvss', '')}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">OWASP:</td>
        <td>{vuln.get('owasp_category', '')}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">CWE:</td>
        <td>{vuln.get('cwe', '')}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">Finding ID:</td>
        <td>{vuln.get('finding_id', '')}</td></tr>
</table>
<hr>
<h2>Summary</h2>
<p>{vuln.get('description', '')}</p>
<h2>Affected Endpoint</h2>
<p><code>{vuln.get('endpoint', '')}</code></p>
<h2>Steps to Reproduce</h2>
<ol>
{''.join(f'<li>{step}</li>' for step in vuln.get('steps_to_reproduce', ['See attached PoC']))}
</ol>
<h2>Impact</h2>
<p>{vuln.get('impact', 'Impact assessment in full report.')}</p>
<h2>Remediation</h2>
<p>{vuln.get('remediation', 'See full report for remediation details.')}</p>
<hr>
<p style="color: #666; font-size: 12px;">
    Engagement: {eng.get('name', '')} ({eng.get('id', '')})<br>
    Report Date: {datetime.now().strftime('%Y-%m-%d')}<br>
    Reported by: {eng.get('lead_tester', '')}
</p>
</body>
</html>
"""

    def _find_screenshots(self, finding_id: str) -> List[Path]:
        """Find screenshots for a finding."""
        if not SCREENSHOTS_DIR.exists():
            return []
        return sorted(SCREENSHOTS_DIR.glob(f"{finding_id}*"))

    def _send_email(self, to: str, subject: str, html_body: str,
                    attachments: Optional[List[Path]] = None, cc: str = "") -> dict:
        """Send an email via Gmail SMTP."""
        if not self.sender_email or not self.app_password:
            return {"status": "error", "error": "Gmail credentials not configured"}

        msg = MIMEMultipart()
        msg["From"] = self.sender_email
        msg["To"] = to
        msg["Subject"] = subject
        if cc:
            msg["Cc"] = cc

        msg.attach(MIMEText(html_body, "html"))

        # Attach screenshots
        for filepath in (attachments or []):
            if filepath.exists():
                with open(filepath, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition",
                                    f"attachment; filename={filepath.name}")
                    msg.attach(part)

        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context) as server:
                server.login(self.sender_email, self.app_password)
                recipients = [to] + ([cc] if cc else [])
                server.sendmail(self.sender_email, recipients, msg.as_string())
            self._log(f"Email sent to {to}: {subject}")
            return {"status": "ok", "to": to, "subject": subject}
        except Exception as e:
            self._log(f"Email failed: {e}", level="error")
            return {"status": "error", "error": str(e)}

    def _save_email_file(self, finding_id: str, subject: str, body: str) -> Path:
        """Save email to disk as a text file (for review/audit)."""
        EMAIL_DIR.mkdir(parents=True, exist_ok=True)
        filepath = EMAIL_DIR / f"{finding_id}_email.txt"
        content = f"Subject: {subject}\n\n{body}"
        with open(filepath, "w") as f:
            f.write(content)
        return filepath

    def _send_critical_alert(self, vulns: List[dict]) -> dict:
        """Send critical vulnerability alert."""
        to = self.recipients.get("security_team", self.recipients.get("to", ""))
        cc = self.recipients.get("cc", "")
        eng = self.config.get("engagement", {})

        subject = f"[CRITICAL] {len(vulns)} Critical Vulnerability(s) — {eng.get('id', '')}"
        findings_list = "\n".join(
            f"<li><strong>{v.get('finding_id', '')}:</strong> {v.get('title', '')} "
            f"(CVSS {v.get('cvss', 'N/A')})</li>"
            for v in vulns
        )

        html = f"""
<html><body style="font-family: Arial;">
<h1 style="color: #d32f2f;">CRITICAL Vulnerability Alert</h1>
<p><strong>Engagement:</strong> {eng.get('name', '')}</p>
<p>{len(vulns)} critical vulnerability(s) discovered during penetration testing:</p>
<ul>{findings_list}</ul>
<p>Immediate remediation recommended. See attached reports for details.</p>
<hr><p style="font-size: 12px; color: #666;">
Reported by {eng.get('lead_tester', '')} on {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
</body></html>
"""
        if to:
            return self._send_email(to, subject, html, cc=cc)
        return {"status": "skipped", "reason": "No recipient configured"}

    def _send_finding_email(self, vuln: dict) -> dict:
        """Send individual finding email."""
        finding_id = vuln.get("finding_id", "")
        to = self.recipients.get("to", "")
        cc = self.recipients.get("cc", "")
        eng = self.config.get("engagement", {})

        subject = f"Vulnerability Report: {vuln.get('title', '')} [{vuln.get('severity', '')}]"
        html = self._build_finding_html(vuln)
        screenshots = self._find_screenshots(finding_id)

        # Save email to disk for audit
        self._save_email_file(finding_id, subject, vuln.get("description", ""))

        if to:
            return self._send_email(to, subject, html, attachments=screenshots, cc=cc)
        return {"status": "saved_only", "path": str(EMAIL_DIR / f"{finding_id}_email.txt")}

    def _send_completion_report(self) -> dict:
        """Send final pentest completion notification."""
        to = self.recipients.get("to", "")
        cc = self.recipients.get("cc", "")
        eng = self.config.get("engagement", {})
        summary = self.kb.summary()

        subject = f"Penetration Test Complete — {eng.get('id', '')}"
        sev = summary.get("vulnerabilities_by_severity", {})

        html = f"""
<html><body style="font-family: Arial;">
<h1>Penetration Test Complete</h1>
<table style="border-collapse: collapse;">
    <tr><td style="padding: 4px 12px; font-weight: bold;">Engagement:</td>
        <td>{eng.get('name', '')}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">ID:</td>
        <td>{eng.get('id', '')}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">Completed:</td>
        <td>{datetime.now().strftime('%Y-%m-%d %H:%M')}</td></tr>
</table>
<hr>
<h2>Summary</h2>
<table style="border-collapse: collapse; border: 1px solid #ddd;">
    <tr style="background: #f5f5f5;"><th style="padding: 8px;">Metric</th><th style="padding: 8px;">Count</th></tr>
    <tr><td style="padding: 8px;">Assets Discovered</td><td style="padding: 8px;">{summary.get('assets', 0)}</td></tr>
    <tr><td style="padding: 8px;">Endpoints Tested</td><td style="padding: 8px;">{summary.get('endpoints', 0)}</td></tr>
    <tr><td style="padding: 8px;">Vulnerabilities</td><td style="padding: 8px;">{summary.get('vulnerabilities', 0)}</td></tr>
    <tr><td style="padding: 8px; color: #d32f2f;">Critical</td><td style="padding: 8px;">{sev.get('Critical', 0)}</td></tr>
    <tr><td style="padding: 8px; color: #f57c00;">High</td><td style="padding: 8px;">{sev.get('High', 0)}</td></tr>
    <tr><td style="padding: 8px; color: #fbc02d;">Medium</td><td style="padding: 8px;">{sev.get('Medium', 0)}</td></tr>
    <tr><td style="padding: 8px; color: #388e3c;">Low</td><td style="padding: 8px;">{sev.get('Low', 0)}</td></tr>
    <tr><td style="padding: 8px;">Attack Chains</td><td style="padding: 8px;">{summary.get('attack_paths', 0)}</td></tr>
</table>
<p>Full reports attached. See EXECUTIVE_SUMMARY.md and TECHNICAL_REPORT.md for details.</p>
<hr>
<p style="font-size: 12px; color: #666;">
Reported by {eng.get('lead_tester', '')} — VAPT Framework</p>
</body></html>
"""
        if to:
            # Attach report files
            report_files = []
            for fname in ["EXECUTIVE_SUMMARY.md", "TECHNICAL_REPORT.md"]:
                fpath = BASE_DIR / "reports" / fname
                if fpath.exists():
                    report_files.append(fpath)
            return self._send_email(to, subject, html, attachments=report_files, cc=cc)
        return {"status": "skipped", "reason": "No recipient configured"}

    def report(self) -> dict:
        emails_sent = sum(1 for r in self.results if r.get("status") == "ok")
        return {
            "agent": self.name,
            "phase": self.phase,
            "state": self.state,
            "emails_sent": emails_sent,
            "emails_saved": sum(1 for r in self.results if r.get("status") == "saved_only"),
            "errors": [r for r in self.results if r.get("status") == "error"],
            "actions_executed": len(self.results),
        }
