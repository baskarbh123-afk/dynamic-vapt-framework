# Email Vulnerability Report Template

> **Usage:** Copy this template for each confirmed vulnerability to generate professional email reports.
> Replace all `[PLACEHOLDER]` values with actual finding data.
> Save as `reports/emails/F-XXX_email.txt` and send using `send_emails.py`.

---

```
From: [TESTER_EMAIL]
To: [RECIPIENT_EMAIL]
Subject: Vulnerability Report: [VULNERABILITY_TITLE]
```

---

## Template Body (copy below this line into email file)

```markdown
# Vulnerability Report: [VULNERABILITY_TITLE]

**Reporter:** [TESTER_NAME]
**Severity:** [Critical / High / Medium / Low]
**CVSS v3.1:** [SCORE] ([CVSS_VECTOR])
**OWASP Category:** [OWASP_ID] – [OWASP_NAME]

---

## Summary

During the penetration testing engagement, it was identified that [brief description of what was found]. This [exposure/vulnerability/misconfiguration] allows [who — any external user / authenticated user / attacker] to [what they can do].

[Second paragraph explaining what specific information or access is exposed and why it matters from a security perspective.]

---

## Affected Assets

**Host:** [TARGET_HOST]

**Accessible Endpoints:**

* [ENDPOINT_URL_1]
* [ENDPOINT_URL_2]
* [ENDPOINT_URL_3]

---

## Vulnerability Details

[Opening sentence describing the core technical issue.]

The exposed [resource/endpoint/configuration] reveals detailed internal information including:

* [DETAIL_CATEGORY_1] related to:

  * [Sub-detail A]
  * [Sub-detail B]
  * [Sub-detail C]

* [DETAIL_CATEGORY_2] describing [what].

* [DETAIL_CATEGORY_3] including:

  * [Sub-detail A]
  * [Sub-detail B]

Additionally, [any secondary findings or related issues discovered].

[Closing sentence summarizing why this exposure is significant from an attacker's perspective.]

---

## Steps to Reproduce

1. [First step — e.g., Open a browser and navigate to URL, or run a curl command]

   [URL or command]

2. [Second step — what to observe]

3. Alternatively, [command-line reproduction]:

   [curl/command example]

4. Observe that [what the response reveals — confirming the vulnerability].

---

## Impact

[Description of what this vulnerability] may lead to:

* [Impact point 1]
* [Impact point 2]
* [Impact point 3]
* [Impact point 4]
* [Impact point 5]

[Sentence describing how attackers can leverage this information for further attacks.]

---

## Proof of Concept

Evidence screenshots demonstrating the [vulnerability description] have been captured during testing and are attached to this report.

---

## Recommendations

1. [Primary recommendation with specific technical guidance.]

   [Code example or configuration if applicable]:

   [code block]

2. Restrict access to [specific endpoints]:

   * [Endpoint 1]
   * [Endpoint 2]

3. [Additional hardening recommendation.]

4. If [resource] must remain accessible, restrict it via:

   * Authentication
   * IP allow-listing
   * VPN access

---

## Severity Justification

[Explain why this severity rating was chosen. Describe what the vulnerability does and does not expose directly, and how it contributes to the overall attack surface.]

Therefore, the issue is rated **[Severity] severity** with a **CVSS score of [SCORE]**.

---

**Reported by:**
[TESTER_NAME]
```

---

## Quick Reference — Severity Levels

| Severity | CVSS Range | Description |
|----------|-----------|-------------|
| Critical | 9.0 – 10.0 | Immediate exploitation risk, full system compromise |
| High | 7.0 – 8.9 | Significant data exposure or privilege escalation |
| Medium | 4.0 – 6.9 | Information disclosure, limited access impact |
| Low | 0.1 – 3.9 | Minor information leak, requires chaining |

## Common OWASP Categories

| ID | Category |
|----|----------|
| A01:2021 | Broken Access Control |
| A02:2021 | Cryptographic Failures |
| A03:2021 | Injection |
| A04:2021 | Insecure Design |
| A05:2021 | Security Misconfiguration |
| A06:2021 | Vulnerable and Outdated Components |
| A07:2021 | Identification and Authentication Failures |
| A08:2021 | Software and Data Integrity Failures |
| A09:2021 | Security Logging and Monitoring Failures |
| A10:2021 | Server-Side Request Forgery (SSRF) |

## Email Sender Usage

```bash
# Send all findings
python3 reports/emails/send_emails.py --password "xxxx xxxx xxxx xxxx"

# Send single finding
python3 reports/emails/send_emails.py --password "xxxx xxxx xxxx xxxx" --finding F-001

# Preview without sending
python3 reports/emails/send_emails.py --dry-run

# Generate email file from this template
python3 reports/emails/generate_email.py --finding F-001 --title "Swagger Exposed" --severity Medium --cvss 5.3
```
