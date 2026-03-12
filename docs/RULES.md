# Rules of Engagement (RoE)

## Absolute Constraints

### 1. Scope Enforcement
- Test ONLY targets listed in scope/targets.md (populated from config.yaml)
- Before any request, verify the target host is in scope
- If a test payload redirects to an out-of-scope system, abort immediately
- Do not test third-party services unless explicitly authorized in config.yaml

### 2. Non-Destructive Testing
- **No Denial of Service (DoS)**: No flood attacks, no resource exhaustion
- **No Brute Force**: No credential stuffing or password spraying
- **No Data Deletion/Modification**: Do not alter production data
- **No Persistent Backdoors**: Do not install shells or persistent access
- **No Real User Data Extraction**: Note field types only, not values

### 3. Proof-of-Concept Boundary
- Confirm vulnerability existence — do not fully exploit
- Use minimum payload required for confirmation
- Stop immediately after confirming — do not escalate
- Document evidence (HTTP request/response) and stop

### 4. Rate Limiting
- Respect max_requests_per_second from config.yaml (default: 10)
- Use tool rate limits: `dirsearch -t 5 --delay=0.5`, `ffuf -rate 10`
- For rate limit testing, use defined low-count tests (max 20 requests)

### 5. Data Handling
- Do not store real user credentials or PII from target
- Note field TYPES only (e.g., "email address visible"), not actual values
- Sanitize all screenshots before sharing
- Securely delete credentials/ files after engagement

### 6. Communication
- Report Critical/High findings to client immediately
- If testing causes unexpected downtime, notify emergency contact
- Log all significant actions in logs/engagement.log

### 7. Phase Discipline
- Complete phases in order: Recon → Enumeration → Exploitation → Post-Exploitation → Reporting
- Do not skip to exploitation without completing enumeration
- Always execute cleanup (Phase 04) before reporting

---

## Authorization Verification

Before starting, confirm in config.yaml:
- [ ] `authorization.roe_signed: true`
- [ ] `authorization.emergency_contact` populated
- [ ] `authorization.tester_ips` populated
- [ ] `authorization.testing_window` defined
- [ ] `python3 setup.py --validate` passes

---

## Engagement Termination Triggers

Stop testing immediately if:
- An action causes unintended system instability
- Real production data is exposed beyond vulnerability confirmation needs
- Testing deviates into out-of-scope systems
- Client requests a stop via emergency contact
- Testing window expires

---

## Safe Payload Guidelines

| Category | Safe Payloads | Forbidden |
|----------|--------------|-----------|
| SQLi | `sleep(1)`, `1=1`, `version()` | `--dump`, `DROP TABLE`, `--os-shell` |
| XSS | `alert(document.domain)` | Session theft from real users |
| SSRF | Collaborator/interactsh callback | Internal infrastructure enumeration |
| File Upload | .txt with test content | Interactive webshells |
| CMDi | `id`, `whoami`, `hostname` | `rm`, `wget`, persistence commands |
| Path Traversal | `/etc/passwd`, `/etc/hosts` | `.env`, private keys (unless needed for severity) |
| JWT | Modify one claim, test one endpoint | Full admin session abuse |
