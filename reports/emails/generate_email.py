#!/usr/bin/env python3
"""
Generate email report files from finding data using the standard template.
Reads finding markdown files from reports/findings/ and generates email-ready
reports in reports/emails/.

Usage:
  python3 generate_email.py                      # Generate emails for all findings
  python3 generate_email.py --finding F-001      # Generate for specific finding
  python3 generate_email.py --list               # List available findings
  python3 generate_email.py --send               # Generate and send immediately
  python3 generate_email.py --send --password XX  # Generate and send with password
"""

import os
import sys
import re
import glob
import argparse

# ── Configuration ────────────────────────────────────────────────
TESTER_NAME = "Baskar Mariyappan"
TESTER_EMAIL = "baskar18022001@gmail.com"
RECIPIENT_EMAIL = "baskarmi510@gmail.com"

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FINDINGS_DIR = os.path.join(BASE_DIR, "reports", "findings")
EMAILS_DIR = os.path.dirname(os.path.abspath(__file__))
# ─────────────────────────────────────────────────────────────────

# OWASP category lookup
OWASP_CATEGORIES = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery (SSRF)",
}


def parse_finding_md(filepath):
    """Parse a finding markdown file and extract structured data."""
    with open(filepath, "r") as f:
        content = f.read()

    data = {}

    # Extract finding ID from filename
    basename = os.path.basename(filepath)
    data["id"] = basename.replace(".md", "")

    # Extract title from ## Finding #F-XXX — Title line
    title_match = re.search(r'^##\s+Finding\s+#F-\d+\s+—\s+(.+)$', content, re.MULTILINE)
    if title_match:
        # Strip trailing "(target)" if present
        title = re.sub(r'\s*\([^)]+\)\s*$', '', title_match.group(1))
        data["title"] = title.strip()
    else:
        title_match = re.search(r'^#\s+.*?—\s+(.+)$', content, re.MULTILINE)
        if title_match:
            data["title"] = title_match.group(1).strip()
        else:
            title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
            data["title"] = title_match.group(1).strip() if title_match else "Unknown"

    # Extract key fields from table or bold labels
    def extract_field(pattern, text):
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else ""

    data["severity"] = extract_field(r'\*\*Severity[:\s]*\*\*\s*[|]?\s*(.+?)(?:\s*\||\s*$)', content)
    if not data["severity"]:
        data["severity"] = extract_field(r'Severity[:\s]+(\w+)', content)

    data["cvss_score"] = extract_field(r'CVSS\s*(?:Score)?[:\s]+(\d+\.?\d*)', content)
    data["cvss_vector"] = extract_field(r'(CVSS:3\.1/[^\s|]+)', content)
    data["owasp"] = extract_field(r'(A\d{2}:2021[^|]*)', content)
    data["target"] = extract_field(r'\*\*(?:Target|Host|Affected)[:\s]*\*\*\s*(.+?)$', content)
    if not data["target"]:
        data["target"] = extract_field(r'Target[:\s]+(.+?)$', content)

    # Extract sections
    sections = {}
    current_section = None
    current_lines = []

    for line in content.split("\n"):
        heading_match = re.match(r'^#{2,3}\s+(?:\d+\.\s+)?(.+)', line)
        if heading_match:
            if current_section:
                sections[current_section.lower()] = "\n".join(current_lines).strip()
            current_section = heading_match.group(1).strip()
            current_lines = []
        elif current_section:
            current_lines.append(line)

    if current_section:
        sections[current_section.lower()] = "\n".join(current_lines).strip()

    data["sections"] = sections
    data["raw"] = content

    return data


def build_email_body(data):
    """Build the email body in the standard report format."""
    finding_id = data["id"]
    title = data["title"]
    severity = data["severity"] or "Medium"
    cvss_score = data["cvss_score"] or "N/A"
    cvss_vector = data["cvss_vector"] or "N/A"
    owasp = data["owasp"] or "A05:2021 - Security Misconfiguration"
    target = data["target"] or "See details below"
    sections = data["sections"]

    # Build description from available sections
    description = ""
    for key in ["description", "overview", "vulnerability details", "details"]:
        if key in sections:
            description = sections[key]
            break

    # Build impact
    impact = ""
    for key in ["impact", "business impact", "technical impact"]:
        if key in sections:
            impact = sections[key]
            break

    # Build steps to reproduce
    steps = ""
    for key in ["steps to reproduce", "reproduction", "reproduce", "proof of concept"]:
        if key in sections:
            steps = sections[key]
            break

    # Build remediation
    remediation = ""
    for key in ["remediation", "recommendations", "fix", "mitigation"]:
        if key in sections:
            remediation = sections[key]
            break

    # Build affected endpoints
    affected = ""
    for key in ["affected endpoints", "affected endpoints / parameters", "affected assets", "affected components"]:
        if key in sections:
            affected = sections[key]
            break

    # Clean up severity for display
    sev_clean = severity.split("(")[0].strip().upper()
    if "CRITICAL" in sev_clean:
        sev_display = "Critical"
    elif "HIGH" in sev_clean:
        sev_display = "High"
    elif "MEDIUM" in sev_clean:
        sev_display = "Medium"
    elif "LOW" in sev_clean:
        sev_display = "Low"
    else:
        sev_display = severity

    body = f"""# Vulnerability Report: {title}

**Reporter:** {TESTER_NAME}
**Severity:** {sev_display}
**CVSS v3.1:** {cvss_score} ({cvss_vector})
**OWASP Category:** {owasp}

---

## Summary

{description}

---

## Affected Assets

**Host:** {target}

{affected}

---

## Vulnerability Details

{description}

---

## Steps to Reproduce

{steps}

---

## Impact

{impact}

---

## Proof of Concept

Evidence screenshots demonstrating the vulnerability have been captured during testing and are attached to this report.

---

## Recommendations

{remediation}

---

## Severity Justification

Based on the analysis, this vulnerability is rated **{sev_display} severity** with a **CVSS score of {cvss_score}**.

---

**Reported by:**
{TESTER_NAME}"""

    return body


def generate_email_file(data):
    """Generate an email text file from finding data."""
    finding_id = data["id"]
    title = data["title"]
    severity = data["severity"] or "Medium"
    target = data["target"] or ""

    sev_clean = severity.split("(")[0].strip().capitalize()

    subject = f"Vulnerability Report: {title}"

    body = build_email_body(data)

    email_content = f"""From: {TESTER_EMAIL}
To: {RECIPIENT_EMAIL}
Subject: {subject}

{body}"""

    output_path = os.path.join(EMAILS_DIR, f"{finding_id}_email.txt")
    with open(output_path, "w") as f:
        f.write(email_content)

    return output_path


def list_findings():
    """List all available findings."""
    findings = sorted(glob.glob(os.path.join(FINDINGS_DIR, "F-*.md")))
    if not findings:
        print("No findings found in", FINDINGS_DIR)
        return

    print(f"\n{'='*60}")
    print(f"  Available Findings ({len(findings)})")
    print(f"{'='*60}\n")

    for f in findings:
        data = parse_finding_md(f)
        email_exists = os.path.exists(os.path.join(EMAILS_DIR, f"{data['id']}_email.txt"))
        status = "email exists" if email_exists else "no email yet"
        print(f"  {data['id']}  {data['title'][:50]:50s}  [{status}]")

    print()


def main():
    parser = argparse.ArgumentParser(description="Generate email reports from findings")
    parser.add_argument("--finding", "-f", help="Generate for specific finding (e.g., F-001)")
    parser.add_argument("--list", "-l", action="store_true", help="List available findings")
    parser.add_argument("--send", "-s", action="store_true", help="Send after generating")
    parser.add_argument("--password", "-p", help="Gmail App Password (for --send)")
    parser.add_argument("--all", "-a", action="store_true", help="Regenerate all finding emails")
    args = parser.parse_args()

    if args.list:
        list_findings()
        return

    # Collect finding files
    if args.finding:
        pattern = os.path.join(FINDINGS_DIR, f"{args.finding}.md")
        finding_files = sorted(glob.glob(pattern))
        if not finding_files:
            print(f"[ERROR] No finding file found: {pattern}")
            sys.exit(1)
    else:
        finding_files = sorted(glob.glob(os.path.join(FINDINGS_DIR, "F-*.md")))

    if not finding_files:
        print("[ERROR] No finding files found in", FINDINGS_DIR)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Email Report Generator")
    print(f"  Template: Standard Vulnerability Report Format")
    print(f"  Findings: {len(finding_files)}")
    print(f"{'='*60}\n")

    generated = 0
    for filepath in finding_files:
        data = parse_finding_md(filepath)
        output = generate_email_file(data)
        print(f"  [{data['id']}] Generated: {os.path.basename(output)}")
        print(f"           Title: {data['title']}")
        generated += 1

    print(f"\n  Total: {generated} email(s) generated in {EMAILS_DIR}")

    # Optionally send
    if args.send:
        print("\n  Sending emails...")
        send_script = os.path.join(EMAILS_DIR, "send_emails.py")
        cmd = f'python3 "{send_script}"'
        if args.password:
            cmd += f' --password "{args.password}"'
        if args.finding:
            cmd += f' --finding {args.finding}'
        os.system(cmd)


if __name__ == "__main__":
    main()
