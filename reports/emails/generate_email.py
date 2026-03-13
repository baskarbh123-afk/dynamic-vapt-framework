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
TESTER_NAME = ""       # e.g., "John Doe"
TESTER_EMAIL = ""      # e.g., "tester@gmail.com"
RECIPIENT_EMAIL = ""   # e.g., "client@company.com"
APP_NAME = ""          # e.g., "Acme Corp" — used in subject line: "[AppName] - Vulnerability Report: ..."

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
    # Extract target: first try Affected Component table row, then bold labels
    data["target"] = extract_field(r'\*\*Affected Component\*\*\s*\|\s*(https?://[^\s|]+)', content)
    if not data["target"]:
        data["target"] = extract_field(r'\*\*Target[:\s]*\*\*\s*[|]?\s*(https?://[^\s|]+)', content)
    if not data["target"]:
        data["target"] = extract_field(r'\*\*Host[:\s]*\*\*\s*[|]?\s*(https?://[^\s|]+)', content)
    if not data["target"]:
        # Extract from finding title parenthetical (e.g., "... (sub.example.com)")
        paren_match = re.search(r'^##\s+Finding\s+#F-\d+\s+—\s+.+\(([^)]+)\)\s*$', content, re.MULTILINE)
        if paren_match:
            host = paren_match.group(1).strip()
            data["target"] = f"https://{host}" if not host.startswith("http") else host
    if not data["target"]:
        # Try URL pattern anywhere in first 30 lines
        for line in content.split("\n")[:30]:
            url_match = re.search(r'https?://[\w.-]+', line)
            if url_match:
                data["target"] = url_match.group(0)
                break

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


def get_section(sections, *keys):
    """Get the first matching section content from a list of possible keys."""
    for key in keys:
        if key in sections:
            return sections[key]
    return ""


def normalize_severity(severity):
    """Normalize severity string to title case."""
    sev_clean = severity.split("(")[0].strip().upper()
    if "CRITICAL" in sev_clean:
        return "Critical"
    elif "HIGH" in sev_clean:
        return "High"
    elif "MEDIUM" in sev_clean:
        return "Medium"
    elif "LOW" in sev_clean:
        return "Low"
    return severity


def md_section_to_html(md_text):
    """Convert a markdown section to HTML paragraphs, lists, and code blocks."""
    if not md_text:
        return ""

    html_parts = []
    lines = md_text.split("\n")
    in_list = False
    in_ordered = False
    in_nested = False
    in_code = False
    list_type = None

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Code blocks
        if stripped.startswith("```"):
            if in_code:
                html_parts.append("</code></pre>")
                in_code = False
            else:
                html_parts.append("<pre><code>")
                in_code = True
            i += 1
            continue

        if in_code:
            html_parts.append(line.replace("<", "&lt;").replace(">", "&gt;"))
            i += 1
            continue

        # Skip table lines and horizontal rules
        if stripped.startswith("|") or stripped == "---" or stripped == "":
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            if in_ordered:
                html_parts.append("</ol>")
                in_ordered = False
            i += 1
            continue

        # Bold-label lines (like **Business Impact:** ...)
        if stripped.startswith("**") and ":**" in stripped:
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', stripped)
            text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
            html_parts.append(f"<p>{text}</p>")
            i += 1
            continue

        # Nested list items (  - item or  * item)
        if re.match(r'^  +[-*]\s', line):
            text = re.sub(r'^  +[-*]\s+', '', line).strip()
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
            if not in_nested:
                html_parts.append("<ul>")
                in_nested = True
            html_parts.append(f"<li><p>{text}</p></li>")
            i += 1
            continue
        else:
            if in_nested:
                html_parts.append("</ul>")
                in_nested = False

        # Bullet list items (- item or * item)
        if re.match(r'^[-*]\s', stripped):
            text = re.sub(r'^[-*]\s+', '', stripped)
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
            if in_ordered:
                html_parts.append("</ol>")
                in_ordered = False
            if not in_list:
                html_parts.append("<ul>")
                in_list = True
            html_parts.append(f"<li><p>{text}</p></li>")
            i += 1
            continue
        else:
            if in_list:
                html_parts.append("</ul>")
                in_list = False

        # Numbered list items
        num_match = re.match(r'^(\d+)\.\s+(.+)', stripped)
        if num_match:
            text = num_match.group(2)
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            if not in_ordered:
                html_parts.append("<ol>")
                in_ordered = True
            html_parts.append(f"<li><p>{text}</p></li>")
            i += 1
            continue
        else:
            if in_ordered:
                html_parts.append("</ol>")
                in_ordered = False

        # Sub-headings within sections (### Backend Fixes etc.)
        h3_match = re.match(r'^#{3}\s+(.+)', stripped)
        if h3_match:
            html_parts.append(f"<h3>{h3_match.group(1)}</h3>")
            i += 1
            continue

        # Regular paragraph
        if stripped:
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', stripped)
            text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
            text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2">\1</a>', text)
            html_parts.append(f"<p>{text}</p>")

        i += 1

    # Close any open lists
    if in_nested:
        html_parts.append("</ul>")
    if in_list:
        html_parts.append("</ul>")
    if in_ordered:
        html_parts.append("</ol>")
    if in_code:
        html_parts.append("</code></pre>")

    return "\n".join(html_parts)


def build_email_html(data):
    """Build HTML email body matching the original AdPower email format."""
    title = data["title"]
    severity = normalize_severity(data["severity"] or "Medium")
    target = data["target"] or "See details below"
    sections = data["sections"]

    # Extract affected component from sections or target
    affected_component = ""
    for key in ["affected endpoints / parameters", "affected endpoints", "affected assets", "affected components"]:
        if key in sections:
            section_text = sections[key]
            # Extract all endpoint URLs from the section
            urls = re.findall(r'https?://[\w./-]+', section_text)
            if urls:
                affected_component = ", ".join(urls[:3])  # Show up to 3 endpoints
            else:
                # Try to get a clean text description
                first_line = section_text.strip().split("\n")[0]
                affected_component = re.sub(r'[|#*]', '', first_line).strip()
            break
    if not affected_component:
        url_match = re.search(r'https?://[\w.-]+', target)
        affected_component = url_match.group(0) if url_match else target

    # Get section content
    description = get_section(sections, "description", "overview", "vulnerability details", "details")
    impact = get_section(sections, "impact", "business impact", "technical impact")
    steps = get_section(sections, "steps to reproduce", "reproduction", "reproduce")
    root_cause = get_section(sections, "root cause analysis", "root cause", "cause")
    remediation = get_section(sections, "remediation", "recommendations", "fix", "mitigation")
    severity_justification = get_section(sections, "severity justification", "risk rating justification")

    # Build severity justification if not present
    cvss_score = data["cvss_score"] or "N/A"
    if not severity_justification:
        severity_justification = f"Based on the analysis, this vulnerability is rated **{severity}** severity with a **CVSS score of {cvss_score}**."

    # Split remediation into Backend Fixes + Additional Security Controls if it has sub-sections
    remediation_html = ""
    if "**Primary Fix:**" in remediation or "**Secondary Controls:**" in remediation:
        parts = re.split(r'\*\*(Primary Fix|Secondary Controls)[:\s]*\*\*', remediation)
        backend_fix = ""
        additional = ""
        for idx, part in enumerate(parts):
            if "Primary Fix" in part and idx + 1 < len(parts):
                backend_fix = parts[idx + 1]
            elif "Secondary Controls" in part and idx + 1 < len(parts):
                additional = parts[idx + 1]
        remediation_html = f"<h3>Backend Fixes</h3>\n{md_section_to_html(backend_fix)}\n<h3>Additional Security Controls</h3>\n{md_section_to_html(additional)}"
    else:
        remediation_html = md_section_to_html(remediation)

    # Extract clean target URL
    url_match = re.search(r'https?://[\w.-]+(?:/[\w.-]*)*', target)
    if url_match:
        target_url = url_match.group(0)
    elif target and not target.startswith("http"):
        target_url = f"https://{target}"
    else:
        target_url = target

    html = f"""<div dir="ltr">
<h1 style="text-align:center"><strong style="font-size:small">   {title}</strong></h1>

<h2><font size="2">Affected Application</font></h2>
<p><strong>URL:</strong> <a href="{target_url}">{target_url}</a><br>
<strong>Affected Component:</strong> {affected_component}<br><br>Risk Rating: <b>{severity}</b></p>

<h2><font size="2">Vulnerability Description</font></h2>
{md_section_to_html(description)}

<h2><font size="2">Impact</font></h2>
{md_section_to_html(impact)}

<h2><font size="2">Steps to Reproduce</font></h2>
{md_section_to_html(steps)}

<h2><font size="2">Root Cause</font></h2>
{md_section_to_html(root_cause)}

<h2><font size="2">Recommendation / Fix</font></h2>
{remediation_html}

<h2><font size="2">Risk Rating Justification</font></h2>
{md_section_to_html(severity_justification)}

<h2><span style="font-size:small;font-weight:normal">Evidence screenshots demonstrating the vulnerability are attached to this report.<br><br></span></h2>
</div>"""

    return html


def build_email_plaintext(data):
    """Build plain text email body as fallback."""
    title = data["title"]
    severity = normalize_severity(data["severity"] or "Medium")
    target = data["target"] or "See details below"
    sections = data["sections"]

    description = get_section(sections, "description", "overview", "vulnerability details", "details")
    impact = get_section(sections, "impact", "business impact", "technical impact")
    steps = get_section(sections, "steps to reproduce", "reproduction", "reproduce")
    root_cause = get_section(sections, "root cause analysis", "root cause", "cause")
    remediation = get_section(sections, "remediation", "recommendations", "fix", "mitigation")
    severity_justification = get_section(sections, "severity justification", "risk rating justification")
    cvss_score = data["cvss_score"] or "N/A"

    if not severity_justification:
        severity_justification = f"Based on the analysis, this vulnerability is rated {severity} severity with a CVSS score of {cvss_score}."

    body = f"""{title}

Affected Application
URL: {target}
Risk Rating: {severity}

Vulnerability Description
{description}

Impact
{impact}

Steps to Reproduce
{steps}

Root Cause
{root_cause}

Recommendation / Fix
{remediation}

Risk Rating Justification
{severity_justification}

Evidence screenshots demonstrating the vulnerability are attached to this report.
"""
    return body


def generate_email_file(data):
    """Generate an email text file from finding data (plain text + HTML stored as JSON)."""
    finding_id = data["id"]
    title = data["title"]
    target = data["target"] or ""

    # Extract app name from target domain
    app_name = APP_NAME
    if target and app_name:
        # Use subdomain as app context if available
        url_match = re.search(r'https?://(?:[\w-]+\.)?([\w-]+\.\w+)', target)
        if url_match:
            base_domain = url_match.group(1)
            sub_match = re.search(r'https?://([\w-]+)\.' + re.escape(base_domain), target)
            if sub_match and sub_match.group(1) != "www":
                app_name = f"{APP_NAME} ({sub_match.group(1)})"

    subject = f"{app_name} - Vulnerability Report: {title}" if app_name else f"Vulnerability Report: {title}"

    plaintext = build_email_plaintext(data)
    html = build_email_html(data)

    # Store as structured email file with headers + plaintext body
    # The HTML is stored separately for send_emails.py to use
    email_content = f"""From: {TESTER_NAME} <{TESTER_EMAIL}>
To: {RECIPIENT_EMAIL}
Subject: {subject}
X-HTML-Body: yes

{plaintext}"""

    output_path = os.path.join(EMAILS_DIR, f"{finding_id}_email.txt")
    with open(output_path, "w") as f:
        f.write(email_content)

    # Store HTML version alongside
    html_path = os.path.join(EMAILS_DIR, f"{finding_id}_email.html")
    with open(html_path, "w") as f:
        f.write(html)

    return output_path


def find_all_findings():
    """Find all finding markdown files across domain/subdomain directories."""
    # Search both flat and nested directory structures
    patterns = [
        os.path.join(FINDINGS_DIR, "F-*.md"),
        os.path.join(FINDINGS_DIR, "*", "*", "F-*.md"),
        os.path.join(FINDINGS_DIR, "*", "F-*.md"),
    ]
    all_files = set()
    for pattern in patterns:
        all_files.update(glob.glob(pattern))
    return sorted(all_files)


def list_findings():
    """List all available findings."""
    findings = find_all_findings()
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
        # Search across all directory structures
        patterns = [
            os.path.join(FINDINGS_DIR, f"{args.finding}.md"),
            os.path.join(FINDINGS_DIR, "*", "*", f"{args.finding}.md"),
            os.path.join(FINDINGS_DIR, "*", f"{args.finding}.md"),
        ]
        finding_files = []
        for pattern in patterns:
            finding_files.extend(glob.glob(pattern))
        finding_files = sorted(set(finding_files))
        if not finding_files:
            print(f"[ERROR] No finding file found for {args.finding}")
            sys.exit(1)
    else:
        finding_files = find_all_findings()

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
