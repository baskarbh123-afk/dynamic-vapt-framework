# Email Vulnerability Report Template

> **Usage:** This template defines the standard email format for vulnerability reports.
> The `generate_email.py` script auto-generates emails from finding files using this structure.
> The HTML output uses a professional vulnerability report email format.

---

## Email Headers

```
From: [Tester Name] <tester@gmail.com>
To: client@company.com
Subject: [AppName] - Vulnerability Report: [VULNERABILITY_TITLE]
```

---

## HTML Section Order

The email body uses minimal HTML styling with the following section structure:

1. **Title** (h1, centered, small font)
2. **Affected Application** (h2) — URL, Affected Component, Risk Rating
3. **Vulnerability Description** (h2) — Technical description paragraphs
4. **Impact** (h2) — Bullet list of impact points
5. **Steps to Reproduce** (h2) — Numbered steps with code blocks
6. **Root Cause** (h2) — Bullet list of root causes
7. **Recommendation / Fix** (h2) — With sub-headings:
   - Backend Fixes (h3)
   - Additional Security Controls (h3)
8. **Risk Rating Justification** (h2) — Severity reasoning
9. **Evidence note** — Screenshots attached to the email

---

## MIME Structure

```
Content-Type: multipart/mixed
├── Content-Type: multipart/alternative
│   ├── Content-Type: text/plain (fallback)
│   └── Content-Type: text/html (primary)
└── Content-Type: image/png (screenshot attachments)
    Content-Disposition: attachment
    Content-Transfer-Encoding: base64
```

---

## HTML Template

```html
<div dir="ltr">
<h1 style="text-align:center"><strong style="font-size:small">   [TITLE]</strong></h1>

<h2><font size="2">Affected Application</font></h2>
<p><strong>URL:</strong> <a href="[TARGET_URL]">[TARGET_URL]</a><br>
<strong>Affected Component:</strong> [COMPONENT]<br><br>Risk Rating: <b>[SEVERITY]</b></p>

<h2><font size="2">Vulnerability Description</font></h2>
<p>[Description paragraphs...]</p>

<h2><font size="2">Impact</font></h2>
<ul>
<li><p>[Impact point 1]</p></li>
<li><p>[Impact point 2]</p></li>
</ul>

<h2><font size="2">Steps to Reproduce</font></h2>
<ol>
<li><p>[Step 1]</p></li>
<li><p>[Step 2]</p></li>
</ol>
<pre><code>[code example]</code></pre>

<h2><font size="2">Root Cause</font></h2>
<ul>
<li><p>[Root cause 1]</p></li>
<li><p>[Root cause 2]</p></li>
</ul>

<h2><font size="2">Recommendation / Fix</font></h2>
<h3>Backend Fixes</h3>
<ul>
<li><p>[Fix 1]</p></li>
</ul>
<h3>Additional Security Controls</h3>
<ul>
<li><p>[Control 1]</p></li>
</ul>

<h2><font size="2">Risk Rating Justification</font></h2>
<p>[Justification text...]</p>
<p>Thus, the severity of this vulnerability is <strong>[SEVERITY]</strong>.</p>

<h2><span style="font-size:small;font-weight:normal">Evidence screenshots demonstrating the vulnerability are attached to this report.<br><br></span></h2>
</div>
```

---

## Email Sender Usage

```bash
# Generate emails for all findings (creates .txt + .html files)
python3 reports/emails/generate_email.py

# Generate for specific finding
python3 reports/emails/generate_email.py --finding F-012

# List available findings
python3 reports/emails/generate_email.py --list

# Send all findings
python3 reports/emails/send_emails.py --password "xxxx xxxx xxxx xxxx"

# Send single finding
python3 reports/emails/send_emails.py --password "xxxx xxxx xxxx xxxx" --finding F-012

# Preview without sending
python3 reports/emails/send_emails.py --dry-run
```
