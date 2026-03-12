# Phase 05 — Reporting

## Objective
Compile all findings, evidence, and analysis into professional, actionable security reports for both technical and executive audiences.

## Pre-Conditions
- [ ] All testing phases completed (01-04)
- [ ] All findings documented in reports/findings/
- [ ] All PoCs documented in reports/poc/
- [ ] Cleanup completed (Phase 04)
- [ ] Evidence preserved in evidence/

## Report Components

| Document | Audience | Template |
|----------|----------|----------|
| Executive Summary | Management / C-Suite | EXECUTIVE_SUMMARY_TEMPLATE.md |
| Technical Report | Development / Security teams | TECHNICAL_REPORT_TEMPLATE.md |
| Individual Findings | Developers | FINDINGS_TEMPLATE.md (one per vuln) |
| Proof of Concepts | Developers / QA | POC_TEMPLATE.md (one per finding) |

## Report Generation Workflow
1. Verify all findings are complete (CVSS, CWE, OWASP mapping)
2. Generate Executive Summary from finding aggregation
3. Compile Technical Report with full methodology + findings
4. Review all PoCs for accuracy and reproducibility
5. Final review — redact PII, verify accuracy, check CVSS scores
6. Deliver to client

## Quality Standards
- Every finding MUST have a CVSS 3.1 score and vector
- Every finding MUST have step-by-step reproduction
- Remediation MUST be specific (code examples, not generic advice)
- All PII in evidence MUST be redacted
- Reference CWE numbers and OWASP WSTG IDs

## Completion Criteria
- [ ] Executive Summary complete
- [ ] Technical Report complete
- [ ] All individual findings documented
- [ ] All PoCs verified
- [ ] PII redacted from all evidence
- [ ] Report reviewed for accuracy
- [ ] Report delivered to client
