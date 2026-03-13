# Dynamic VAPT Framework — User Walkthrough

A step-by-step guide to running a complete penetration test using this framework with Claude Code.

---

## What This Framework Does

This is an automated web application penetration testing framework. You give it a list of target websites, and it will:

1. Discover subdomains and map the attack surface
2. Enumerate endpoints, APIs, and technologies
3. Test for real vulnerabilities (safely, without breaking anything)
4. Generate professional vulnerability reports with proof-of-concept screenshots
5. Email the reports directly to the client or bug bounty program

Everything is controlled through a conversation with Claude Code. You don't need to write any code.

---

## Before You Start

**Requirements:**

- Python 3 installed on your Mac/Linux machine
- Install the one dependency: `pip3 install pyyaml Pillow`
- A Gmail account with an App Password (for sending reports)

**To get a Gmail App Password:**

1. Go to https://myaccount.google.com/apppasswords
2. Select "Mail" and your device
3. Click "Generate"
4. Copy the 16-character password (looks like: `xxxx xxxx xxxx xxxx`)

---

## How to Run a Pentest

### Step 1: Open the Project

Open your terminal and navigate to the framework folder:

```
cd /path/to/dynamic-vapt-framework
```

Then start Claude Code:

```
claude
```

### Step 2: Say "Run the Pentest"

Just type:

```
run the pentest
```

Claude will now walk you through an interactive setup. It will **never** start testing without your permission.

---

## The 6-Step Interactive Flow

### Step 1: Scope Confirmation

Claude will ask: **"Is the scope up to date?"**

It shows you the current targets from `scope/targets.md`. You can:

- Say **"yes"** if the targets are correct
- Say **"change the target"** and provide new domains
- Give a domain with wildcards like `example.com and all subdomains`

**Example:**

```
You: change the target
Claude: What are the new targets?
You: example.com and its all subdomains
Claude: ✓ Scope updated. Moving to Step 2.
```

---

### Step 2: Credentials

Claude will ask: **"Do you have any credentials?"**

If you have login accounts, API keys, or tokens for the target, provide them here. If not:

- Say **"unauthenticated"** — Claude will only test what's publicly accessible

**Example:**

```
Claude: Do you have any credentials or authorization headers?
You: unauthenticated
Claude: Got it. Moving to Step 3.
```

---

### Step 3: Email Setup

Claude will ask: **"Where should the reports be sent?"**

Provide:

- **From email:** Your Gmail address
- **To email:** Client email or bug bounty address

**Example:**

```
Claude: From: tester@gmail.com, To: client@company.com — confirm?
You: change the to mail bugbounty@example.com
Claude: ✓ Updated. Moving to Step 4.
```

---

### Step 4: The Pentest Runs

Claude will now automatically run through 5 phases:

| Phase | What Happens | Time |
|-------|-------------|------|
| 1. Reconnaissance | Discovers subdomains, fingerprints technologies, maps infrastructure | 1-3 min |
| 2. Enumeration | Probes endpoints, APIs, login pages, robots.txt, config files | 2-5 min |
| 3. Exploitation | Tests for real vulnerabilities (safely — proof-of-concept only) | 3-5 min |
| 4. Post-Exploitation | Assesses impact and attack chains | 1 min |
| 5. Reporting | Creates draft findings with severity ratings | 1 min |

**You don't need to do anything during this step.** Just wait for the results.

All findings are saved as **DRAFT** — nothing is sent to anyone yet.

---

### Step 5: Review Your Findings

Claude will show you a table like this:

```
| #     | Finding                           | Severity | Target           | Status |
|-------|-----------------------------------|----------|------------------|--------|
| F-008 | WordPress User Enumeration        | Medium   | blog.example.com | DRAFT  |
| F-009 | XMLRPC Brute Force Amplification  | Medium   | blog.example.com | DRAFT  |
| F-010 | Jitsi Meet Unauthenticated Rooms  | Medium   | meet.example.com | DRAFT  |
```

For each finding, tell Claude:

- **"valid"** — Keep it in the report
- **"remove F-010"** — Remove a false positive
- **"change F-008 to low"** — Adjust severity
- **"need more info on F-009"** — Claude will investigate further

**Example:**

```
You: remove F-010 and keep the rest
Claude: ✓ F-010 removed. 2 findings confirmed.
```

---

### Step 6: Generate & Send Reports

Claude will ask for your final confirmation before sending anything.

You can say:

- **"make it as a draft"** — Generate email files for you to review first
- **"generate POC screenshots"** — Create browser-style evidence images
- **"send"** — Send the emails (asks permission for EACH email individually)

**When sending, Claude will ask before EVERY email:**

```
[F-008] Processing...
  To:      bugbounty@example.com
  Subject: Vulnerability Report: WordPress User Enumeration
  Screenshots: 3 attached

  Send this email? (y/n/q to quit): _
```

- Press **y** to send
- Press **n** to skip this one
- Press **q** to stop completely

**You will need your Gmail App Password at this point.**

---

## Where Everything Lives

Here's a simple map of the important folders:

```
dynamic-vapt-md 2/
│
├── scope/targets.md          ← Your target list (edit this first)
│
├── reports/
│   ├── findings/             ← All vulnerability findings (F-001.md, F-002.md, etc.)
│   ├── emails/               ← Email-ready reports + send script
│   │   ├── F-001_email.txt   ← Email body for finding 001
│   │   ├── send_emails.py    ← Automated email sender
│   │   └── generate_email.py ← Generates emails from findings
│   ├── INDEX.md              ← Master list of all findings
│   └── EMAIL_REPORT_TEMPLATE.md ← Standard email format template
│
├── evidence/
│   ├── screenshots/          ← All POC screenshot images
│   ├── poc_browser.py        ← Browser-style screenshot generator
│   └── poc_template.py       ← Terminal-style screenshot generator
│
├── config.yaml               ← Main configuration file
├── CLAUDE.md                 ← Rules that Claude follows
└── setup.py                  ← Initial setup script
```

---

## Common Commands

These are things you can say to Claude at any point:

| What You Say | What Happens |
|-------------|-------------|
| `run the pentest` | Starts the full 6-step interactive workflow |
| `change the target` | Update the scope with new domains |
| `unauthenticated` | Skip credentials — test public access only |
| `make it as a draft` | Generate email reports without sending |
| `generate POC screenshots` | Create evidence images for findings |
| `send` | Send reports (with per-email confirmation) |
| `remove F-XXX` | Remove a finding from the report |
| `all valid` | Confirm all findings at once |

---

## Email Report Format

Every vulnerability report follows this professional structure:

```
# Vulnerability Report: [Title]

Reporter: Your Name
Severity: Medium
CVSS v3.1: 5.3
OWASP: A05:2021 – Security Misconfiguration

## Summary          ← What was found and why it matters
## Affected Assets  ← Which URLs/endpoints are affected
## Vulnerability Details ← Technical details
## Steps to Reproduce   ← How to recreate the issue
## Impact               ← What could go wrong
## Proof of Concept     ← Screenshots attached
## Recommendations      ← How to fix it
## Severity Justification ← Why this rating

Reported by: Your Name
```

Each email includes browser-style POC screenshots as attachments.

---

## POC Screenshots

Each finding gets **3 screenshots** showing different stages:

| Screenshot | What It Shows |
|-----------|--------------|
| POC-1: Discovery | How the vulnerability was initially found |
| POC-2: Exploitation | Proof that the vulnerability is exploitable |
| POC-3: Impact | What an attacker could gain from this |

Screenshots look like real browser windows with:
- Address bar showing the target URL
- Request command that was sent
- Response data with syntax highlighting
- Yellow annotation box explaining the finding
- Severity badge (Critical / High / Medium / Low)

---

## Safety Rules

This framework is designed to be safe. It will **never**:

- Run denial-of-service attacks
- Brute force passwords
- Extract real user data
- Delete or modify anything on the target
- Go beyond proof-of-concept (it proves the bug exists, then stops)
- Send emails without your explicit permission
- Test targets not in your scope

---

## Troubleshooting

**"Pillow not installed"**
```
pip3 install Pillow
```

**"Authentication failed" when sending emails**
- Make sure you're using a Gmail App Password, not your regular password
- Get one at: https://myaccount.google.com/apppasswords

**"Cloudflare blocking requests"**
- Some targets have aggressive bot protection
- Claude will note these and focus on accessible subdomains instead

**"Finding seems like a false positive"**
- During Step 5, just say "remove F-XXX" and Claude will drop it

**"I want to edit an email before sending"**
- Say "make it as a draft" first
- Edit the file directly in `reports/emails/F-XXX_email.txt`
- Then say "send" when ready

---

## Quick Start (TL;DR)

```
1. Open terminal → cd to project folder → type "claude"
2. Say: "run the pentest"
3. Give your targets when asked
4. Say "unauthenticated" if no credentials
5. Provide email addresses for reporting
6. Wait for results
7. Review findings — remove false positives
8. Say "send" — approve each email one by one
9. Done!
```

---

## For Future Engagements

To run a new pentest on different targets:

1. Start Claude Code in this folder
2. Say **"run the pentest"**
3. When asked about scope, say **"change the target"** and give your new domains
4. Follow the same 6-step flow

Everything from the previous engagement stays in the `reports/findings/` folder. New findings get new IDs (F-012, F-013, etc.) so nothing is overwritten.

---

*Dynamic VAPT Framework | PTES Methodology | OWASP Top 10 2021*
