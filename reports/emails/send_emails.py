#!/usr/bin/env python3
"""
Automated email sender for penetration test findings.
Sends all F-XXX_email.txt files via Gmail SMTP with POC screenshots attached.
Converts markdown body to HTML for clean rendering in email clients.

Usage:
  python3 send_emails.py                    # Interactive (prompts for app password)
  python3 send_emails.py --password XXXX    # Pass app password as argument
  python3 send_emails.py --dry-run          # Preview emails without sending
  python3 send_emails.py --finding F-001    # Send only a specific finding
"""

import smtplib
import ssl
import os
import sys
import glob
import getpass
import argparse
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

# ── Configuration ────────────────────────────────────────────────
FROM_EMAIL = "baskar18022001@gmail.com"
TO_EMAIL = "bugbounty@geizhals.at"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

EMAILS_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(os.path.dirname(EMAILS_DIR), "..", "evidence")
SCREENSHOTS_DIR = os.path.join(EVIDENCE_DIR, "screenshots")
# ─────────────────────────────────────────────────────────────────


def parse_email_file(filepath):
    """Parse an email text file and extract Subject and Body."""
    with open(filepath, "r") as f:
        content = f.read()

    lines = content.split("\n")
    subject = ""
    body_start = 0

    for i, line in enumerate(lines):
        if line.startswith("Subject:"):
            subject = line.replace("Subject:", "").strip()
        if line.startswith("From:") or line.startswith("To:") or line.startswith("Subject:"):
            continue
        if i > 0 and not line.startswith("From:") and not line.startswith("To:") and not line.startswith("Subject:"):
            body_start = i
            break

    body = "\n".join(lines[body_start:])
    return subject, body.strip()


def markdown_to_html(md_text):
    """Convert markdown-formatted text to clean HTML for email rendering."""
    html_lines = []
    in_list = False
    in_code_block = False
    in_nested_list = False

    for line in md_text.split("\n"):
        stripped = line.strip()

        # Code blocks
        if stripped.startswith("```"):
            if in_code_block:
                html_lines.append("</code></pre>")
                in_code_block = False
            else:
                html_lines.append('<pre style="background-color:#f6f8fa;padding:12px 16px;border-radius:6px;font-family:Consolas,Monaco,monospace;font-size:13px;line-height:1.5;overflow-x:auto;border:1px solid #e1e4e8;"><code>')
                in_code_block = True
            continue

        if in_code_block:
            html_lines.append(line.replace("<", "&lt;").replace(">", "&gt;"))
            continue

        # Horizontal rules
        if stripped == "---":
            html_lines.append('<hr style="border:none;border-top:1px solid #d0d7de;margin:24px 0;">')
            continue

        # Headings
        if stripped.startswith("# "):
            text = stripped[2:]
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            html_lines.append(f'<h1 style="font-size:22px;font-weight:600;color:#1f2328;margin:28px 0 12px 0;padding-bottom:8px;border-bottom:1px solid #d0d7de;">{text}</h1>')
            continue
        if stripped.startswith("## "):
            text = stripped[3:]
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            html_lines.append(f'<h2 style="font-size:18px;font-weight:600;color:#1f2328;margin:24px 0 10px 0;padding-bottom:6px;border-bottom:1px solid #d0d7de;">{text}</h2>')
            continue

        # Bold text lines (like **Reporter:** value)
        if stripped.startswith("**") and ":**" in stripped:
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', stripped)
            text = re.sub(r'`(.+?)`', r'<code style="background:#f0f3f6;padding:2px 6px;border-radius:3px;font-size:13px;">\1</code>', text)
            html_lines.append(f'<p style="margin:4px 0;color:#1f2328;line-height:1.6;">{text}</p>')
            continue

        # Nested list items (  * item)
        if re.match(r'^  +\*\s', line):
            text = re.sub(r'^  +\*\s+', '', line)
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            text = re.sub(r'`(.+?)`', r'<code style="background:#f0f3f6;padding:2px 6px;border-radius:3px;font-size:13px;">\1</code>', text)
            if not in_nested_list:
                html_lines.append('<ul style="margin:4px 0 4px 20px;padding-left:16px;">')
                in_nested_list = True
            html_lines.append(f'<li style="margin:3px 0;color:#1f2328;line-height:1.6;">{text}</li>')
            continue
        else:
            if in_nested_list:
                html_lines.append("</ul>")
                in_nested_list = False

        # Top-level list items (* item)
        if stripped.startswith("* "):
            text = stripped[2:]
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            text = re.sub(r'`(.+?)`', r'<code style="background:#f0f3f6;padding:2px 6px;border-radius:3px;font-size:13px;">\1</code>', text)
            text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2" style="color:#0969da;">\1</a>', text)
            if not in_list:
                html_lines.append('<ul style="margin:8px 0;padding-left:24px;">')
                in_list = True
            html_lines.append(f'<li style="margin:4px 0;color:#1f2328;line-height:1.6;">{text}</li>')
            continue
        else:
            if in_list:
                html_lines.append("</ul>")
                in_list = False

        # Numbered list items
        num_match = re.match(r'^(\d+)\.\s+(.+)', stripped)
        if num_match:
            text = num_match.group(2)
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            text = re.sub(r'`(.+?)`', r'<code style="background:#f0f3f6;padding:2px 6px;border-radius:3px;font-size:13px;">\1</code>', text)
            text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2" style="color:#0969da;">\1</a>', text)
            html_lines.append(f'<p style="margin:6px 0 6px 8px;color:#1f2328;line-height:1.6;"><strong>{num_match.group(1)}.</strong> {text}</p>')
            continue

        # Indented code-like lines (3+ spaces, looks like a command)
        if re.match(r'^   +\S', line) and not stripped.startswith("*"):
            text = stripped.replace("<", "&lt;").replace(">", "&gt;")
            html_lines.append(f'<pre style="background-color:#f6f8fa;padding:10px 14px;border-radius:6px;font-family:Consolas,Monaco,monospace;font-size:13px;margin:6px 0 6px 8px;border:1px solid #e1e4e8;overflow-x:auto;"><code>{text}</code></pre>')
            continue

        # Empty lines
        if not stripped:
            html_lines.append('<div style="height:8px;"></div>')
            continue

        # Regular paragraph
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', stripped)
        text = re.sub(r'`(.+?)`', r'<code style="background:#f0f3f6;padding:2px 6px;border-radius:3px;font-size:13px;">\1</code>', text)
        text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2" style="color:#0969da;">\1</a>', text)
        html_lines.append(f'<p style="margin:6px 0;color:#1f2328;line-height:1.6;">{text}</p>')

    # Close any open lists
    if in_nested_list:
        html_lines.append("</ul>")
    if in_list:
        html_lines.append("</ul>")
    if in_code_block:
        html_lines.append("</code></pre>")

    body_html = "\n".join(html_lines)

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;color:#1f2328;max-width:720px;margin:0 auto;padding:20px;background-color:#ffffff;">
{body_html}
</body>
</html>"""


def find_screenshots(finding_id):
    """Find all POC screenshot PNGs for a given finding ID."""
    screenshots = []
    if not os.path.isdir(SCREENSHOTS_DIR):
        return screenshots

    pattern = os.path.join(SCREENSHOTS_DIR, f"{finding_id}*.png")
    screenshots = sorted(glob.glob(pattern))
    return screenshots


def send_email(subject, body, screenshots, app_password, dry_run=False):
    """Send a single email with HTML body and optional screenshot attachments."""
    msg = MIMEMultipart("mixed")
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg["Subject"] = subject

    # Convert markdown to HTML and attach both versions
    html_body = markdown_to_html(body)
    alt_part = MIMEMultipart("alternative")
    alt_part.attach(MIMEText(body, "plain", "utf-8"))
    alt_part.attach(MIMEText(html_body, "html", "utf-8"))
    msg.attach(alt_part)

    # Attach screenshots
    for screenshot_path in screenshots:
        filename = os.path.basename(screenshot_path)
        with open(screenshot_path, "rb") as img_file:
            img = MIMEImage(img_file.read(), name=filename)
            img.add_header("Content-Disposition", "attachment", filename=filename)
            msg.attach(img)

    if dry_run:
        attach_names = [os.path.basename(s) for s in screenshots]
        print(f"  [DRY RUN] Would send: {subject}")
        print(f"            Attachments: {attach_names if attach_names else 'None'}")
        return True

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(FROM_EMAIL, app_password)
            server.sendmail(FROM_EMAIL, TO_EMAIL, msg.as_string())
        return True
    except smtplib.SMTPAuthenticationError:
        print("  [ERROR] Authentication failed. Check your App Password.")
        print("          Get one at: https://myaccount.google.com/apppasswords")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Send PT finding emails via Gmail")
    parser.add_argument("--password", "-p", help="Gmail App Password")
    parser.add_argument("--dry-run", "-d", action="store_true", help="Preview without sending")
    parser.add_argument("--finding", "-f", help="Send only a specific finding (e.g., F-001)")
    parser.add_argument("--no-confirm", action="store_true", help="Skip per-email confirmation prompts")
    args = parser.parse_args()

    # Collect email files
    if args.finding:
        pattern = os.path.join(EMAILS_DIR, f"{args.finding}_email.txt")
        email_files = sorted(glob.glob(pattern))
        if not email_files:
            print(f"[ERROR] No email file found for {args.finding}")
            sys.exit(1)
    else:
        email_files = sorted(glob.glob(os.path.join(EMAILS_DIR, "F-*_email.txt")))

    if not email_files:
        print("[ERROR] No email files found in", EMAILS_DIR)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  PT Finding Email Sender")
    print(f"  From: {FROM_EMAIL}")
    print(f"  To:   {TO_EMAIL}")
    print(f"  Findings: {len(email_files)}")
    print(f"  Format: HTML (markdown rendered)")
    print(f"{'='*60}\n")

    # Get password
    app_password = None
    if not args.dry_run:
        app_password = args.password or getpass.getpass("Enter Gmail App Password: ")
        if not app_password:
            print("[ERROR] App password is required.")
            print("Get one at: https://myaccount.google.com/apppasswords")
            sys.exit(1)

    # Send each finding
    sent = 0
    failed = 0
    skipped = 0

    for email_file in email_files:
        basename = os.path.basename(email_file)
        finding_id = basename.replace("_email.txt", "")

        print(f"[{finding_id}] Processing...")

        subject, body = parse_email_file(email_file)
        screenshots = find_screenshots(finding_id)

        print(f"  To:      {TO_EMAIL}")
        print(f"  Subject: {subject}")
        print(f"  Screenshots: {len(screenshots)} attached")

        # Ask for permission before each email
        if not args.dry_run and not args.no_confirm:
            confirm = input(f"\n  Send this email? (y/n/q to quit): ").strip().lower()
            if confirm == "q":
                print("\n[STOPPED] User cancelled remaining emails.")
                break
            if confirm != "y":
                print(f"  -> Skipped.")
                skipped += 1
                continue

        success = send_email(subject, body, screenshots, app_password, dry_run=args.dry_run)

        if success:
            print(f"  -> Sent successfully!" if not args.dry_run else "")
            sent += 1
        else:
            failed += 1
            if not args.dry_run:
                print("\n[STOPPED] Fix the error above and retry.")
                break

    print(f"\n{'='*60}")
    print(f"  Results: {sent} sent, {skipped} skipped, {failed} failed")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
