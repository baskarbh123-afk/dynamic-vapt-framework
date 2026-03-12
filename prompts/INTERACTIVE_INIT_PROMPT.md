# Interactive Penetration Test Initialization

> **Purpose:** Before running any penetration test, Claude MUST walk through this interactive checklist with the user. Do NOT proceed to testing until all steps are confirmed.

---

## Step 1: Scope Confirmation

**Ask the user:**

> "Has the scope information been updated? Please confirm the targets in `scope/targets.md` are current."
>
> "If updates are needed, would you like to:"
> - Edit `scope/targets.md` directly
> - Update `config.yaml` and regenerate with `setup.py`
> - Provide the new scope here and I'll update both files

**Wait for user confirmation before proceeding.**

---

## Step 2: Credentials & Authorization

**Ask the user:**

> "Do you have any credentials, API keys, or authorization headers to provide for this engagement?"
>
> "Please share any of the following that apply:"
> - **User accounts** (username/password pairs for different roles)
> - **API keys or tokens** (Bearer tokens, API keys)
> - **Authorization headers** (custom headers required for access)
> - **OAuth tokens** (client IDs, secrets, refresh tokens)
> - **Session cookies** (if testing authenticated areas)
> - **Role-based accounts** (admin, user, viewer, etc.)
>
> "If no credentials are needed (unauthenticated testing only), please confirm."

**Store provided credentials in `credentials/` directory. Wait for confirmation.**

---

## Step 3: Reporting Email Configuration

**Ask the user:**

> "Where should the vulnerability reports be sent?"
>
> "Please provide:"
> - **From email:** (your email address)
> - **To email:** (recipient/client email address)
> - **CC emails:** (optional — additional recipients)
>
> "I'll configure the email sender with these addresses."

**Update `reports/emails/send_emails.py` configuration. Wait for confirmation.**

---

## Step 4: Run Penetration Test (Findings as Draft)

**Inform the user:**

> "I'll now run the penetration test against the confirmed scope. All findings will be saved as **DRAFT** status."

**Execute the 5-phase pentest:**
1. Reconnaissance
2. Enumeration
3. Exploitation (PoC only)
4. Post-Exploitation
5. Reporting (draft findings)

**Mark all findings as DRAFT in reports/INDEX.md and individual finding files.**

---

## Step 5: Agent Validation

**After findings are generated, ask the user:**

> "I've identified the following findings. Please review each one:"
>
> | # | Finding | Severity | Target | Status |
> |---|---------|----------|--------|--------|
> | F-001 | [Title] | [Sev] | [Host] | DRAFT |
> | ... | ... | ... | ... | DRAFT |
>
> "For each finding, please confirm:"
> - **Valid** — Confirmed vulnerability, proceed to final report
> - **Invalid / False Positive** — Remove from report
> - **Needs More Info** — I'll investigate further
> - **Severity Change** — Adjust the severity rating
>
> "Would you like to validate all findings now, or review them one by one?"

**Wait for user to validate each finding.**

---

## Step 6: Finalize & Send

**After validation, ask:**

> "The following findings are confirmed and ready to send:"
>
> | # | Finding | Severity | Status |
> |---|---------|----------|--------|
> | F-001 | [Title] | [Sev] | CONFIRMED |
> | ... | ... | ... | CONFIRMED |
>
> "Shall I:"
> 1. Generate final email reports in the standard format
> 2. Send all confirmed findings to [recipient email]
> 3. Generate PDF reports instead
> 4. Review/edit specific findings before sending
>
> "Please confirm to proceed."

**Only send emails after explicit user confirmation.**

**IMPORTANT: Before sending, remove the `Status: DRAFT — Pending Review` line from all email files. This line is only for internal tracking during the draft phase and must NOT appear in the final sent email.**

---

## Workflow Summary

```
START
  │
  ├─ Step 1: Scope confirmed? ──── NO → Update scope → Re-confirm
  │                                YES ↓
  ├─ Step 2: Credentials provided? ── NO → Unauthenticated only → Confirm
  │                                    YES → Store creds → Confirm
  │                                    ↓
  ├─ Step 3: Report email configured? ── Confirm addresses
  │                                       ↓
  ├─ Step 4: Run pentest ── Generate DRAFT findings
  │                          ↓
  ├─ Step 5: User validates each finding
  │           ├─ Valid → Mark CONFIRMED
  │           ├─ Invalid → Remove
  │           └─ Needs Info → Investigate more
  │                          ↓
  └─ Step 6: User confirms → Send final reports
```

---

## Claude Behavior Rules

1. **NEVER skip steps.** Always walk through Steps 1-3 before running any test.
2. **NEVER send emails without explicit confirmation** in Step 6.
3. **All findings start as DRAFT.** Only move to CONFIRMED after user validation.
4. **Ask one step at a time.** Don't overwhelm with all questions at once.
5. **If the user says "run the pentest"**, start at Step 1, not Step 4.
6. **Store all user responses** for audit trail in `logs/engagement.log`.
