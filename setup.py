#!/usr/bin/env python3
"""
Penetration Testing Framework — Setup Script
==============================================
Reads config.yaml and auto-populates:
  - scope/         (targets, exclusions, constraints)
  - targets/       (domain info, endpoints, tech stack, attack surface)
  - credentials/   (accounts, API keys, OAuth)
  - reports/       (initialized templates)
  - logs/          (engagement log initialized)

Usage:
  python3 setup.py                    # Full setup
  python3 setup.py --validate         # Validate config only
  python3 setup.py --update           # Re-read config and update folders
  python3 setup.py --status           # Show engagement status
"""

import yaml
import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path

# ============================================================================
# Constants
# ============================================================================
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = BASE_DIR / "config.yaml"
LOG_DIR = BASE_DIR / "logs"
EVIDENCE_DIR = BASE_DIR / "evidence"

# ============================================================================
# Logging Setup
# ============================================================================
def setup_logging(config):
    """Initialize logging based on config preferences."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    log_level = getattr(logging, config.get("preferences", {}).get("logging", {}).get("level", "INFO"), logging.INFO)
    log_file = BASE_DIR / config.get("preferences", {}).get("logging", {}).get("log_file", "logs/engagement.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger("pt-framework")

# ============================================================================
# Config Loading & Validation
# ============================================================================
def load_config():
    """Load and return the config.yaml file."""
    if not CONFIG_FILE.exists():
        print(f"[ERROR] Config file not found: {CONFIG_FILE}")
        print("  Create config.yaml in the project root before running setup.")
        sys.exit(1)
    
    with open(CONFIG_FILE, "r") as f:
        config = yaml.safe_load(f)
    
    if not config:
        print("[ERROR] config.yaml is empty or malformed.")
        sys.exit(1)
    
    return config

def validate_config(config):
    """Validate required fields in config.yaml."""
    errors = []
    warnings = []
    
    # Required engagement fields
    eng = config.get("engagement", {})
    if not eng.get("name"):
        errors.append("engagement.name is required")
    if not eng.get("client"):
        errors.append("engagement.client is required")
    if not eng.get("lead_tester"):
        warnings.append("engagement.lead_tester is not set")
    if not eng.get("start_date"):
        warnings.append("engagement.start_date is not set")
    
    # Authorization
    auth = config.get("authorization", {})
    if not auth.get("roe_signed"):
        errors.append("authorization.roe_signed must be true — RoE must be signed before testing")
    if not auth.get("emergency_contact", {}).get("name"):
        warnings.append("authorization.emergency_contact.name is not set")
    
    # Scope
    scope = config.get("scope", {})
    in_scope = scope.get("in_scope", {})
    domains = in_scope.get("domains", [])
    has_domain = any(d.get("domain") for d in domains if isinstance(d, dict))
    if not has_domain:
        errors.append("scope.in_scope.domains — at least one domain is required")
    
    # Target
    target = config.get("target", {})
    if not target.get("primary_domain"):
        errors.append("target.primary_domain is required")
    
    # Credentials
    creds = config.get("credentials", {})
    accounts = creds.get("test_accounts", [])
    has_account = any(a.get("username") for a in accounts if isinstance(a, dict))
    if not has_account:
        warnings.append("credentials.test_accounts — no test accounts configured")
    
    return errors, warnings

# ============================================================================
# Folder Population Functions
# ============================================================================
def populate_scope(config, logger):
    """Populate scope/ directory from config."""
    scope_dir = BASE_DIR / "scope"
    scope_dir.mkdir(parents=True, exist_ok=True)
    scope = config.get("scope", {})
    eng = config.get("engagement", {})
    auth_cfg = config.get("authorization", {})
    
    # --- scope/targets.md ---
    in_scope = scope.get("in_scope", {})
    domains = in_scope.get("domains", [])
    features = in_scope.get("features", [])
    api_eps = in_scope.get("api_endpoints", [])
    
    content = f"""# In-Scope Targets
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
> Engagement: {eng.get('name', 'N/A')} ({eng.get('id', 'N/A')})

---

## Domains

| # | Domain | IP | Notes |
|---|--------|-----|-------|
"""
    for i, d in enumerate(domains, 1):
        if isinstance(d, dict) and d.get("domain"):
            content += f"| {i} | {d.get('domain', '')} | {d.get('ip', '')} | {d.get('notes', '')} |\n"
    
    content += f"""
---

## In-Scope Features

"""
    for f in features:
        if f:
            content += f"- [x] {f}\n"
    
    content += f"""
---

## API Endpoints

| # | Method | Path | Auth | Description |
|---|--------|------|------|-------------|
"""
    for i, ep in enumerate(api_eps, 1):
        if isinstance(ep, dict) and ep.get("path"):
            content += f"| {i} | {ep.get('method', '')} | {ep.get('path', '')} | {ep.get('auth', '')} | {ep.get('description', '')} |\n"
    
    with open(scope_dir / "targets.md", "w") as f:
        f.write(content)
    logger.info("Created scope/targets.md")
    
    # --- scope/exclusions.md ---
    out_scope = scope.get("out_of_scope", {})
    excl_domains = out_scope.get("domains", [])
    excl_actions = out_scope.get("actions", [])
    
    content = f"""# Out-of-Scope Exclusions
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Excluded Domains / Assets

| # | Domain / Asset | Reason |
|---|----------------|--------|
"""
    for i, d in enumerate(excl_domains, 1):
        if isinstance(d, dict) and d.get("domain"):
            content += f"| {i} | {d.get('domain', '')} | {d.get('reason', '')} |\n"
    
    content += """
---

## Excluded Actions

"""
    for a in excl_actions:
        if a:
            content += f"- {a}\n"
    
    with open(scope_dir / "exclusions.md", "w") as f:
        f.write(content)
    logger.info("Created scope/exclusions.md")
    
    # --- scope/constraints.md ---
    constraints = scope.get("constraints", {})
    tw = auth_cfg.get("testing_window", {})
    tester_ips = auth_cfg.get("tester_ips", [])
    
    content = f"""# Testing Constraints
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Operational Constraints

| Constraint | Value |
|------------|-------|
| Production Data Access | {'Yes' if constraints.get('production_data_access') else 'No'} |
| Destructive Testing | {'Yes' if constraints.get('destructive_testing') else 'No'} |
| Rate Limit Exception | {'Yes' if constraints.get('rate_limit_exception') else 'No'} |
| Max Requests/Second | {constraints.get('max_requests_per_second', 10)} |

---

## Testing Window

| Field | Value |
|-------|-------|
| Timezone | {tw.get('timezone', 'N/A')} |
| Start Time | {tw.get('start_time', 'N/A')} |
| End Time | {tw.get('end_time', 'N/A')} |
| Days | {', '.join(tw.get('days', [])) if tw.get('days') else 'N/A'} |

---

## Authorized Tester IPs

"""
    for ip in tester_ips:
        if ip:
            content += f"- `{ip}`\n"
    if not any(tester_ips):
        content += "- *(No IPs configured)*\n"
    
    content += f"""
---

## Authorization Status

| Check | Status |
|-------|--------|
| RoE Signed | {'YES' if auth_cfg.get('roe_signed') else 'NO'} |
| RoE Date | {auth_cfg.get('roe_date', 'N/A')} |
| RoE Reference | {auth_cfg.get('roe_reference', 'N/A')} |
| Emergency Contact | {auth_cfg.get('emergency_contact', {}).get('name', 'N/A')} — {auth_cfg.get('emergency_contact', {}).get('phone', 'N/A')} |
"""
    
    with open(scope_dir / "constraints.md", "w") as f:
        f.write(content)
    logger.info("Created scope/constraints.md")

def populate_targets(config, logger):
    """Populate targets/ directory from config."""
    targets_dir = BASE_DIR / "targets"
    targets_dir.mkdir(parents=True, exist_ok=True)
    target = config.get("target", {})
    tech = config.get("tech_stack", {})
    eng = config.get("engagement", {})
    
    # --- targets/domain.md ---
    content = f"""# Target Domain Information
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
> Engagement: {eng.get('name', 'N/A')}

---

## Primary Target

| Field | Value |
|-------|-------|
| Primary Domain | {target.get('primary_domain', '')} |
| Base URL | {target.get('base_url', '')} |
| Application | {eng.get('application', '')} |
| Version | {eng.get('version', '')} |
| Environment | {eng.get('environment', '')} |

---

## Subdomains

| # | Subdomain | Purpose | In Scope |
|---|-----------|---------|----------|
"""
    for i, s in enumerate(target.get("subdomains", []), 1):
        if isinstance(s, dict) and s.get("subdomain"):
            content += f"| {i} | {s.get('subdomain', '')} | {s.get('purpose', '')} | {'Yes' if s.get('in_scope') else 'No'} |\n"
    
    content += f"""
---

## Third-Party Integrations

| # | Service | Type | In Scope |
|---|---------|------|----------|
"""
    for i, t in enumerate(target.get("third_party_integrations", []), 1):
        if isinstance(t, dict) and t.get("service"):
            content += f"| {i} | {t.get('service', '')} | {t.get('type', '')} | {'Yes' if t.get('in_scope') else 'No'} |\n"
    
    content += f"""
---

## Network Characteristics

| Field | Value |
|-------|-------|
| WAF Detected | {'Yes — ' + target.get('network', {}).get('waf_product', '') if target.get('network', {}).get('waf_detected') else 'No'} |
| Load Balancer | {'Yes' if target.get('network', {}).get('load_balancer') else 'No'} |
| CDN | {'Yes — ' + target.get('network', {}).get('cdn_provider', '') if target.get('network', {}).get('cdn') else 'No'} |
| Reverse Proxy | {'Yes' if target.get('network', {}).get('reverse_proxy') else 'No'} |
"""
    
    with open(targets_dir / "domain.md", "w") as f:
        f.write(content)
    logger.info("Created targets/domain.md")
    
    # --- targets/tech_stack.md ---
    be = tech.get("backend", {})
    fe = tech.get("frontend", {})
    db = tech.get("database", {})
    auth_tech = tech.get("authentication", {})
    infra = tech.get("infrastructure", {})
    fu = tech.get("file_upload", {})
    api = tech.get("api", {})
    
    content = f"""# Technology Stack
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Backend

| Field | Value |
|-------|-------|
| Language / Runtime | {be.get('language', '')} |
| Framework | {be.get('framework', '')} |
| Web Server | {be.get('web_server', '')} |
| Version | {be.get('version', '')} |

## Frontend

| Field | Value |
|-------|-------|
| Framework | {fe.get('framework', '')} |
| Template Engine | {fe.get('template_engine', '')} |
| CSS Framework | {fe.get('css_framework', '')} |
| Build Tool | {fe.get('build_tool', '')} |

## Database

| Field | Value |
|-------|-------|
| Type | {db.get('type', '')} |
| ORM | {db.get('orm', '')} |
| Version | {db.get('version', '')} |

## Authentication

| Field | Value |
|-------|-------|
| Session Type | {auth_tech.get('session_type', '')} |
| Token Algorithm | {auth_tech.get('token_algorithm', '')} |
| MFA Present | {'Yes' if auth_tech.get('mfa_present') else 'No'} |
| OAuth Provider | {auth_tech.get('oauth_provider', '')} |
| SSO Type | {auth_tech.get('sso_type', '')} |

## Infrastructure

| Field | Value |
|-------|-------|
| Cloud Provider | {infra.get('cloud_provider', '')} |
| Container Platform | {infra.get('container_platform', '')} |
| CDN | {infra.get('cdn', '')} |
| WAF | {infra.get('waf', '')} |

## File Upload

| Field | Value |
|-------|-------|
| Allowed | {'Yes' if fu.get('allowed') else 'No'} |
| Storage Type | {fu.get('storage_type', '')} |
| CDN Served | {'Yes' if fu.get('cdn_served') else 'No'} |
| Direct Execution | {'Yes' if fu.get('direct_execution') else 'No'} |
| MIME Validation | {fu.get('mime_validation', '')} |

## API

| Field | Value |
|-------|-------|
| Style | {api.get('style', '')} |
| Version | {api.get('version', '')} |
| Documentation | {api.get('documentation', '')} |
| Auth Method | {api.get('auth_method', '')} |

---

## Module Selection Guide

Based on the tech stack above, prioritize these exploitation modules:

| Tech Stack Indicator | Recommended Modules |
|----------------------|---------------------|
| SQL Database | SQL_INJECTION |
| Template Engine | SSTI |
| JWT Auth | JWT_SECURITY |
| File Upload | FILE_UPLOAD, PATH_TRAVERSAL |
| GraphQL API | GRAPHQL, MASS_ASSIGNMENT |
| OAuth/SSO | OAUTH |
| Any Web App | XSS, CSRF, IDOR, AUTHENTICATION, AUTHORIZATION |
"""
    
    with open(targets_dir / "tech_stack.md", "w") as f:
        f.write(content)
    logger.info("Created targets/tech_stack.md")
    
    # --- targets/endpoints.md ---
    content = f"""# Endpoint Inventory
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
> Populate this file during the Enumeration phase.

---

## Web Application URLs

| # | URL | Function | Auth Required | Notes |
|---|-----|----------|---------------|-------|
| 1 | /login | Login page | No | |
| 2 | /register | Registration | No | |
| 3 | /dashboard | Main dashboard | Yes | |
| 4 | /profile | User profile | Yes | |
| 5 | /admin | Admin panel | Admin | |

*(Add all discovered endpoints during enumeration)*

---

## API Endpoints

"""
    api_eps = config.get("scope", {}).get("in_scope", {}).get("api_endpoints", [])
    content += "| # | Method | Endpoint | Auth | Description |\n|---|--------|----------|------|-------------|\n"
    for i, ep in enumerate(api_eps, 1):
        if isinstance(ep, dict) and ep.get("path"):
            content += f"| {i} | {ep.get('method', '')} | {ep.get('path', '')} | {ep.get('auth', '')} | {ep.get('description', '')} |\n"
    
    content += """
*(Add all discovered API endpoints during enumeration)*

---

## GraphQL Endpoints (if applicable)

| Field | Value |
|-------|-------|
| Endpoint | /graphql |
| Introspection Enabled | |
| Playground Exposed | |

---

## Hidden / Discovered Endpoints

| # | URL | Method | Discovery Source | Notes |
|---|-----|--------|-----------------|-------|

*(Add endpoints found via directory brute-force, JS analysis, etc.)*
"""
    
    with open(targets_dir / "endpoints.md", "w") as f:
        f.write(content)
    logger.info("Created targets/endpoints.md")
    
    # --- targets/attack_surface.md ---
    content = f"""# Attack Surface Map
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
> Complete this during the Reconnaissance and Enumeration phases.

---

## Attack Surface Overview

### Entry Points

| # | Entry Point | Type | Auth | Risk Level | Notes |
|---|-------------|------|------|------------|-------|
| 1 | Login form | Web Form | None | High | Credential-based |
| 2 | Registration | Web Form | None | Medium | Account creation |
| 3 | API | REST/GraphQL | Bearer | High | Data access |
| 4 | File Upload | Form | User | High | Code execution risk |
| 5 | Search | Query Param | None | Medium | Injection risk |
| 6 | Password Reset | Web Form | None | High | Account takeover |

*(Customize based on target application)*

---

## Authentication Surface

| Mechanism | Endpoint | Test Priority |
|-----------|----------|---------------|
| Form Login | | High |
| JWT Issuance | | High |
| OAuth Flow | | High |
| MFA | | Medium |
| Password Reset | | High |
| API Key Auth | | Medium |

---

## Data Flow Diagram

```
[User Browser] → [CDN/WAF] → [Load Balancer] → [Web Server] → [App Server] → [Database]
                                                      ↕                              ↕
                                               [File Storage]                 [Cache Layer]
                                                      ↕
                                               [Third-Party APIs]
```

---

## High-Value Targets

| Target | Why | Phase to Test |
|--------|-----|---------------|
| Admin Panel | Full system control | Exploitation |
| User Data API | PII exposure | Exploitation |
| File Upload | Code execution | Exploitation |
| Payment Flow | Financial impact | Exploitation |
| Auth Tokens | Session hijack | Enumeration + Exploitation |

---

## Security Controls Observed

| Control | Present | Effectiveness | Notes |
|---------|---------|---------------|-------|
| WAF | | | |
| Rate Limiting | | | |
| CAPTCHA | | | |
| CSP Header | | | |
| HSTS | | | |
| Input Sanitization | | | |
| CORS Policy | | | |
"""
    
    with open(targets_dir / "attack_surface.md", "w") as f:
        f.write(content)
    logger.info("Created targets/attack_surface.md")

def populate_credentials(config, logger):
    """Populate credentials/ directory from config."""
    creds_dir = BASE_DIR / "credentials"
    creds_dir.mkdir(parents=True, exist_ok=True)
    creds = config.get("credentials", {})
    eng = config.get("engagement", {})
    
    # --- credentials/accounts.md ---
    accounts = creds.get("test_accounts", [])
    content = f"""# Test Accounts
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
> **SECURITY NOTE**: Delete or securely wipe this file after engagement.

---

## Test Accounts

| # | Role | Username | Password | Notes |
|---|------|----------|----------|-------|
"""
    for i, a in enumerate(accounts, 1):
        if isinstance(a, dict):
            content += f"| {i} | {a.get('role', '')} | {a.get('username', '')} | {a.get('password', '')} | {a.get('notes', '')} |\n"
    
    content += """
---

## Credential Rotation

If credentials are compromised during testing:
- Contact the emergency contact listed in scope/constraints.md
- Document the compromise in logs/engagement.log
- Request new credentials before continuing
"""
    
    with open(creds_dir / "accounts.md", "w") as f:
        f.write(content)
    logger.info("Created credentials/accounts.md")
    
    # --- credentials/api_keys.md ---
    api_keys = creds.get("api_keys", [])
    content = f"""# API Keys & Tokens
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
> **SECURITY NOTE**: Delete or securely wipe this file after engagement.

---

## API Keys

| # | Purpose | Key | Scope | Expiry |
|---|---------|-----|-------|--------|
"""
    for i, k in enumerate(api_keys, 1):
        if isinstance(k, dict) and k.get("purpose"):
            content += f"| {i} | {k.get('purpose', '')} | {k.get('key', '')} | {k.get('scope', '')} | {k.get('expiry', '')} |\n"
    
    with open(creds_dir / "api_keys.md", "w") as f:
        f.write(content)
    logger.info("Created credentials/api_keys.md")
    
    # --- credentials/oauth.md ---
    oauth = creds.get("oauth", {})
    content = f"""# OAuth Credentials
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
> **SECURITY NOTE**: Delete or securely wipe this file after engagement.

---

## OAuth Application

| Field | Value |
|-------|-------|
| Client ID | {oauth.get('client_id', '')} |
| Client Secret | {oauth.get('client_secret', '')} |
| Redirect URI | {oauth.get('redirect_uri', '')} |

---

## Provider Test Accounts

| # | Provider | Email | Password | Notes |
|---|----------|-------|----------|-------|
"""
    for i, p in enumerate(oauth.get("provider_accounts", []), 1):
        if isinstance(p, dict) and p.get("provider"):
            content += f"| {i} | {p.get('provider', '')} | {p.get('email', '')} | {p.get('password', '')} | {p.get('notes', '')} |\n"
    
    with open(creds_dir / "oauth.md", "w") as f:
        f.write(content)
    logger.info("Created credentials/oauth.md")

def initialize_logs(config, logger):
    """Initialize log files and evidence directories."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "screenshots").mkdir(exist_ok=True)
    (EVIDENCE_DIR / "http-logs").mkdir(exist_ok=True)
    
    eng = config.get("engagement", {})
    
    # --- logs/engagement.log header ---
    log_file = LOG_DIR / "engagement.log"
    if not log_file.exists():
        with open(log_file, "w") as f:
            f.write(f"# Penetration Testing Engagement Log\n")
            f.write(f"# Engagement: {eng.get('name', 'N/A')} ({eng.get('id', 'N/A')})\n")
            f.write(f"# Client: {eng.get('client', 'N/A')}\n")
            f.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {'='*70}\n\n")
    
    # --- logs/phase_tracker.md ---
    prefs = config.get("preferences", {})
    phases = prefs.get("phases_to_run", {})
    content = f"""# Phase Tracker
> Auto-generated from config.yaml on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Engagement Progress

| Phase | Enabled | Status | Started | Completed | Findings |
|-------|---------|--------|---------|-----------|----------|
| 01 — Reconnaissance | {'Yes' if phases.get('recon', True) else 'No'} | Not Started | | | 0 |
| 02 — Enumeration | {'Yes' if phases.get('enumeration', True) else 'No'} | Not Started | | | 0 |
| 03 — Exploitation | {'Yes' if phases.get('exploitation', True) else 'No'} | Not Started | | | 0 |
| 04 — Post-Exploitation | {'Yes' if phases.get('post_exploitation', True) else 'No'} | Not Started | | | 0 |
| 05 — Reporting | {'Yes' if phases.get('reporting', True) else 'No'} | Not Started | | | — |

---

## Finding Counter

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 0 |
| **Total** | **0** |

---

## Module Execution Log

| Module | Phase | Status | Findings | Notes |
|--------|-------|--------|----------|-------|
"""
    modules = prefs.get("exploitation_modules", {})
    for mod_name, enabled in modules.items():
        if enabled:
            content += f"| {mod_name.upper()} | 03 | Pending | 0 | |\n"
    
    with open(LOG_DIR / "phase_tracker.md", "w") as f:
        f.write(content)
    logger.info("Created logs/phase_tracker.md")

def populate_reports(config, logger):
    """Initialize the reports directory with metadata."""
    reports_dir = BASE_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "findings").mkdir(exist_ok=True)
    (reports_dir / "poc").mkdir(exist_ok=True)
    
    eng = config.get("engagement", {})
    
    content = f"""# Reports Index
> Engagement: {eng.get('name', 'N/A')} ({eng.get('id', 'N/A')})
> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Report Structure

| Report | Location | Status |
|--------|----------|--------|
| Executive Summary | reports/EXECUTIVE_SUMMARY.md | Not Started |
| Technical Report | reports/TECHNICAL_REPORT.md | Not Started |
| Individual Findings | reports/findings/F-XXX.md | Not Started |
| Proof of Concepts | reports/poc/POC-XXX.md | Not Started |

---

## Finding Index

| ID | Vulnerability | Severity | CVSS | Component | Status |
|----|---------------|----------|------|-----------|--------|

*(Findings will be added here as they are confirmed)*
"""
    
    with open(reports_dir / "INDEX.md", "w") as f:
        f.write(content)
    logger.info("Created reports/INDEX.md")

# ============================================================================
# Status Display
# ============================================================================
def show_status(config):
    """Display current engagement status."""
    eng = config.get("engagement", {})
    auth = config.get("authorization", {})
    scope = config.get("scope", {})
    prefs = config.get("preferences", {})
    
    print("\n" + "=" * 60)
    print("  PENETRATION TESTING FRAMEWORK — STATUS")
    print("=" * 60)
    print(f"  Engagement : {eng.get('name', 'N/A')}")
    print(f"  Client     : {eng.get('client', 'N/A')}")
    print(f"  ID         : {eng.get('id', 'N/A')}")
    print(f"  Type       : {eng.get('type', 'N/A')}")
    print(f"  Lead Tester: {eng.get('lead_tester', 'N/A')}")
    print(f"  Period     : {eng.get('start_date', '?')} to {eng.get('end_date', '?')}")
    print("-" * 60)
    print(f"  RoE Signed : {'YES' if auth.get('roe_signed') else 'NO'}")
    
    domains = scope.get("in_scope", {}).get("domains", [])
    active_domains = [d.get("domain") for d in domains if isinstance(d, dict) and d.get("domain")]
    print(f"  In-Scope   : {len(active_domains)} domain(s)")
    for d in active_domains:
        print(f"               - {d}")
    
    phases = prefs.get("phases_to_run", {})
    enabled = [k for k, v in phases.items() if v]
    print(f"  Phases     : {', '.join(enabled)}")
    
    modules = prefs.get("exploitation_modules", {})
    enabled_mods = [k for k, v in modules.items() if v]
    print(f"  Modules    : {len(enabled_mods)} enabled")
    print("=" * 60 + "\n")

# ============================================================================
# Main
# ============================================================================
def main():
    config = load_config()
    
    # Handle CLI args
    if "--validate" in sys.argv:
        errors, warnings = validate_config(config)
        if errors:
            print("\n[ERRORS] — Must fix before proceeding:")
            for e in errors:
                print(f"  X {e}")
        if warnings:
            print("\n[WARNINGS] — Recommended to fix:")
            for w in warnings:
                print(f"  ! {w}")
        if not errors and not warnings:
            print("\n[OK] Config validation passed — all fields populated.")
        elif not errors:
            print("\n[OK] No blocking errors. Warnings above are advisory.")
        else:
            print(f"\n[FAIL] {len(errors)} error(s) must be resolved.")
            sys.exit(1)
        return
    
    if "--status" in sys.argv:
        show_status(config)
        return
    
    # Full setup
    logger = setup_logging(config)
    logger.info("=" * 60)
    logger.info("Penetration Testing Framework — Setup Starting")
    logger.info("=" * 60)
    
    # Validate
    errors, warnings = validate_config(config)
    if warnings:
        for w in warnings:
            logger.warning(w)
    
    if errors and "--force" not in sys.argv:
        logger.error("Config validation failed:")
        for e in errors:
            logger.error(f"  X {e}")
        logger.error("Fix errors above, or use --force to override (not recommended).")
        sys.exit(1)
    elif errors:
        logger.warning("Config validation errors overridden with --force flag.")
    
    # Populate folders
    try:
        populate_scope(config, logger)
        populate_targets(config, logger)
        populate_credentials(config, logger)
        populate_reports(config, logger)
        initialize_logs(config, logger)
        
        logger.info("-" * 60)
        logger.info("Setup complete. Folders populated:")
        logger.info("  scope/        — targets, exclusions, constraints")
        logger.info("  targets/      — domain, tech_stack, endpoints, attack_surface")
        logger.info("  credentials/  — accounts, api_keys, oauth")
        logger.info("  reports/      — INDEX.md initialized")
        logger.info("  logs/         — engagement.log + phase_tracker.md")
        logger.info("  evidence/     — screenshots/ + http-logs/ ready")
        logger.info("-" * 60)
        logger.info("Next steps:")
        logger.info("  1. Review generated files for accuracy")
        logger.info("  2. Use prompts/START_PT_SESSION.md to initialize Claude")
        logger.info("  3. Begin Phase 01 — Reconnaissance")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"Setup failed: {e}")
        raise

if __name__ == "__main__":
    main()
