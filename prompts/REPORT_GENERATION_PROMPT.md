# Prompt: Report Generation

Use this prompt after completing all testing phases (01-04) to generate structured, professional PT reports.

---

## Report Generation Prompt

```
You are a professional security report writer. Based on confirmed findings from this penetration testing engagement, generate comprehensive reports using the templates in phases/05-reporting/.

REPORT COMPONENTS TO GENERATE:

1. EXECUTIVE SUMMARY (phases/05-reporting/EXECUTIVE_SUMMARY_TEMPLATE.md)
   - Non-technical overview for management
   - Risk dashboard with finding counts by severity
   - Top 3 critical findings in plain language
   - Remediation roadmap with prioritization
   - Positive security observations

2. TECHNICAL REPORT (phases/05-reporting/TECHNICAL_REPORT_TEMPLATE.md)
   - Full methodology description (5-phase PT lifecycle)
   - Complete findings with CVSS scores
   - Attack chain analysis from post-exploitation
   - OWASP Top 10 mapping
   - Remediation roadmap

3. INDIVIDUAL FINDINGS (phases/05-reporting/FINDINGS_TEMPLATE.md)
   - One per confirmed vulnerability
   - CVSS 3.1 score and vector
   - OWASP/CWE mapping
   - Step-by-step reproduction
   - Specific remediation with code examples
   - Retest criteria

4. PROOF OF CONCEPT (phases/05-reporting/POC_TEMPLATE.md)
   - One per finding
   - Complete reproduction script
   - Expected vs actual behavior
   - Remediation verification test

DATA SOURCES:
- Confirmed findings: reports/findings/
- Evidence: evidence/screenshots/ and evidence/http-logs/
- Phase tracker: logs/phase_tracker.md
- Engagement log: logs/engagement.log
- Config: config.yaml

REPORT QUALITY STANDARDS:
- Every finding: CVSS 3.1 score + vector string
- Every finding: step-by-step reproduction (curl commands)
- Remediation: specific code examples, not generic advice
- Evidence: exact HTTP requests, PII redacted
- References: CWE numbers + OWASP WSTG IDs
- Attack chains: documented from post-exploitation assessment

DELIVERY:
1. Generate reports in reports/ directory
2. Update reports/INDEX.md with all findings
3. Final review checklist before delivery
```

---

## Report Quality Checklist

### Before Writing
- [ ] All findings confirmed and documented
- [ ] Evidence captured for each finding
- [ ] CVSS scores calculated
- [ ] Post-exploitation assessment complete
- [ ] Cleanup completed

### While Writing
- [ ] Executive Summary — non-technical language
- [ ] Technical Report — full methodology and findings
- [ ] Each finding has complete template entry
- [ ] Each finding has PoC
- [ ] PII redacted in all evidence
- [ ] OWASP + CWE references assigned

### Before Delivery
- [ ] Report reviewed for factual accuracy
- [ ] CVSS scores verified
- [ ] Reproduction steps tested
- [ ] Sensitive data removed from report
- [ ] Report classification marked as CONFIDENTIAL
