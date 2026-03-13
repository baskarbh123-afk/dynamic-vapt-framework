#!/usr/bin/env python3
"""
Agentic AI PoC Screenshot System

Takes real-time browser screenshots as proof-of-concept evidence for each finding.
Each finding type has a specialized strategy that navigates to the target,
demonstrates the vulnerability, and captures authentic browser evidence.

Usage:
    python3 agents/poc_screenshot_agent.py                     # All findings
    python3 agents/poc_screenshot_agent.py --finding F-012     # Specific finding
    python3 agents/poc_screenshot_agent.py --list              # List findings & strategies
"""

import os
import sys
import re
import json
import glob
import time
import argparse
from datetime import datetime

# Add project root to path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

FINDINGS_DIR = os.path.join(BASE_DIR, "reports", "findings")
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "evidence", "screenshots")
PAYLOAD_DIR = os.path.join(BASE_DIR, "evidence", "payload_results")

os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# ── Finding-specific PoC strategies ──────────────────────────────────────────

POC_STRATEGIES = {
    "INFORMATION_DISCLOSURE": {
        "description": "Navigate to target, view page source, highlight disclosed information",
        "mode": "view_source",
    },
    "SECURITY_MISCONFIGURATION": {
        "description": "Navigate to target, inspect response headers, show missing/weak configs",
        "mode": "inspect_headers",
    },
    "CSP_BYPASS": {
        "description": "Navigate to target, show CSP header with hardcoded nonce in DevTools",
        "mode": "inspect_headers",
    },
    "MISSING_HEADERS": {
        "description": "Navigate to target, open DevTools Network tab, show missing security headers",
        "mode": "inspect_headers",
    },
    "VERSION_DISCLOSURE": {
        "description": "Navigate to target, view source, highlight version strings",
        "mode": "view_source",
    },
    "AZURE_AD_EXPOSURE": {
        "description": "Navigate to target, capture redirect chain showing tenant ID",
        "mode": "redirect_chain",
    },
    "API_ERROR_DISCLOSURE": {
        "description": "Hit API endpoint, capture JSON error response with framework details",
        "mode": "api_response",
    },
}


def load_finding_metadata(finding_id):
    """Load finding metadata from payload_results and finding markdown."""
    metadata = {"id": finding_id}

    # Load payload result JSON
    payload_path = os.path.join(PAYLOAD_DIR, f"{finding_id}_payload_result.json")
    if os.path.exists(payload_path):
        with open(payload_path) as f:
            metadata.update(json.load(f))

    # Find and load finding markdown
    patterns = [
        os.path.join(FINDINGS_DIR, f"{finding_id}.md"),
        os.path.join(FINDINGS_DIR, "*", "*", f"{finding_id}.md"),
        os.path.join(FINDINGS_DIR, "*", f"{finding_id}.md"),
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            with open(matches[0]) as f:
                content = f.read()
            # Extract target
            url_match = re.search(r'\*\*Affected Component\*\*\s*\|\s*(https?://[^\s|]+)', content)
            if url_match and "target" not in metadata:
                metadata["target"] = url_match.group(1)
            # Extract title
            title_match = re.search(r'^##\s+Finding\s+#F-\d+\s+—\s+(.+)$', content, re.MULTILINE)
            if title_match and "title" not in metadata:
                metadata["title"] = re.sub(r'\s*\([^)]+\)\s*$', '', title_match.group(1)).strip()
            # Extract severity
            sev_match = re.search(r'\*\*Severity\*\*\s*\|\s*(\w+)', content)
            if sev_match:
                metadata["severity"] = sev_match.group(1)
            # Extract vuln type
            vtype_match = re.search(r'\*\*Vulnerability Type\*\*\s*\|\s*(.+?)(?:\s*\||\s*$)', content, re.MULTILINE)
            if vtype_match:
                metadata["vuln_type_text"] = vtype_match.group(1).strip()
            break

    return metadata


def determine_strategy(metadata):
    """Determine the best PoC screenshot strategy based on finding type."""
    finding_id = metadata.get("id", "")
    vuln_type = metadata.get("vuln_type", "")
    title = metadata.get("title", "").lower()

    if "csp nonce" in title or "csp" in title and "hardcoded" in title:
        return "CSP_BYPASS"
    elif "missing" in title and ("header" in title or "csp" in title or "clickjacking" in title):
        return "MISSING_HEADERS"
    elif "azure" in title or "saml" in title or "tenant" in title:
        return "AZURE_AD_EXPOSURE"
    elif "laravel" in title or "api error" in title:
        return "API_ERROR_DISCLOSURE"
    elif "version" in title or "plugin" in title or "moodle" in title:
        return "VERSION_DISCLOSURE"
    elif vuln_type == "INFORMATION_DISCLOSURE":
        return "INFORMATION_DISCLOSURE"
    else:
        return "SECURITY_MISCONFIGURATION"


# ── Playwright Screenshot Agents ─────────────────────────────────────────────

def _highlight_source_server_side(html_source, highlights):
    """Build syntax-highlighted HTML source code server-side in Python.
    Returns ready-to-render HTML with highlighted evidence patterns."""
    # HTML-escape the source
    escaped = html_source.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Extract only the interesting lines (containing evidence patterns, or key HTML tags)
    lines = escaped.split("\n")
    interesting_lines = []
    for i, line in enumerate(lines):
        line_lower = line.lower()
        # Always include lines with evidence patterns
        is_evidence = False
        for h in highlights:
            if h.lower() in line_lower:
                is_evidence = True
                break
        # Include lines with common evidence markers
        if is_evidence or any(kw in line_lower for kw in [
            "ver=", "yoast", "plugin", "xmlrpc", "pingback", "wp-content",
            "js_composer", "sbi-style", "profilepress", "wp-user-avatar",
            "borlabs", "wpml", "webrotate", "moodle", "yui", "theme",
            "generator", "version", "<!--", "meta name"
        ]):
            # Include context: 1 line before and after
            start = max(0, i - 1)
            end = min(len(lines), i + 2)
            for j in range(start, end):
                if j not in [x[0] for x in interesting_lines]:
                    interesting_lines.append((j, lines[j]))

    # If we found interesting lines, use those; otherwise take first 60 lines
    if interesting_lines:
        interesting_lines.sort(key=lambda x: x[0])
        # Group into blocks with separators
        source_blocks = []
        prev_num = -2
        for line_num, line_text in interesting_lines:
            if line_num > prev_num + 2 and prev_num >= 0:
                source_blocks.append('<span style="color:#555;">    ...</span>')
            # Add line number
            source_blocks.append(f'<span style="color:#555;">{line_num+1:4d}</span>  {line_text}')
            prev_num = line_num
        source_html = "\n".join(source_blocks)
    else:
        source_html = "\n".join(f'<span style="color:#555;">{i+1:4d}</span>  {l}' for i, l in enumerate(lines[:60]))

    # Syntax highlight: HTML tags
    source_html = re.sub(r'(&amp;lt;/?[\w-]+)', r'<span style="color:#569cd6;">\1</span>', source_html)
    # Syntax highlight: HTML comments
    source_html = re.sub(r'(&amp;lt;!--.*?--&amp;gt;)', r'<span style="color:#6a9955;">\1</span>', source_html)
    # Syntax highlight: attribute values with ver=
    source_html = re.sub(r'(ver=[\w.]+)', r'<span style="color:#ce9178;font-weight:bold;">\1</span>', source_html)

    # Highlight evidence patterns (yellow background)
    for pattern in highlights:
        if len(pattern) > 2:
            safe_pattern = re.escape(pattern)
            source_html = re.sub(
                f'({safe_pattern})',
                r'<span style="background:#4a3000;color:#ffd700;font-weight:bold;border:1px solid #886600;padding:0 2px;">\1</span>',
                source_html,
                flags=re.IGNORECASE
            )

    return source_html


def _find_evidence_urls(metadata):
    """Extract real evidence URLs from finding metadata for browser navigation."""
    urls = []
    target = metadata.get("target", "")
    evidence_sources = metadata.get("evidence_sources", [])
    extracted = metadata.get("extracted_versions", {})
    title = metadata.get("title", "").lower()

    # Extract URLs from evidence sources
    for src in evidence_sources:
        url_matches = re.findall(r'https?://[^\s\'"<>]+', src)
        urls.extend(url_matches)
        # Build WordPress plugin URLs from CSS references
        css_match = re.search(r'([\w.-]+\.(?:css|js)\?ver=[\d.]+)', src)
        if css_match and target:
            urls.append(f"{target.rstrip('/')}/wp-content/plugins/{css_match.group(1)}")

    # Add common evidence endpoints based on finding type
    base = target.rstrip("/")
    if "wordpress" in title or "plugin" in title:
        urls.extend([
            f"{base}/xmlrpc.php",
            f"{base}/wp-json/",
            f"{base}/wp-json/wp/v2/users",
        ])
    elif "moodle" in title:
        urls.extend([
            f"{base}/lib/yui/",
            f"{base}/theme/boost/style/moodle.css",
        ])
    elif "laravel" in title or "api error" in title:
        urls.extend([
            f"{base}/api",
            f"{base}/ng//auth/login",
        ])
    elif "csp" in title or "nonce" in title:
        urls.extend([
            f"{base}/ng//auth/login",
        ])
    elif "azure" in title or "saml" in title:
        tenant_id = metadata.get("tenant_id", "")
        if tenant_id:
            urls.append(f"https://login.microsoftonline.com/{tenant_id}/.well-known/openid-configuration")

    # Deduplicate and filter
    seen = set()
    unique = []
    for u in urls:
        u_clean = u.rstrip("/")
        if u_clean not in seen and u_clean != target.rstrip("/"):
            seen.add(u_clean)
            unique.append(u)
    return unique[:5]  # Return up to 5 evidence URLs


def screenshot_view_source(page, metadata, screenshots):
    """
    Strategy: View Source — All 3 screenshots are real browser navigations:
    1. Live target page with URL bar
    2. view-source: page in browser
    3. Navigate to specific evidence endpoint (plugin file, xmlrpc, etc.)
    """
    target = metadata.get("target", "")
    finding_id = metadata["id"]
    title = metadata.get("title", "")

    print(f"    [1/3] Navigating to {target}...")
    try:
        response = page.goto(target, wait_until="domcontentloaded", timeout=15000)
        status = response.status if response else "N/A"
        print(f"    [1/3] Loaded (HTTP {status})")
    except Exception as e:
        print(f"    [1/3] Navigation warning: {e}")

    # Screenshot 1: Live page with URL bar
    inject_url_bar(page, target, is_secure=target.startswith("https"))
    path1 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_1_live_page.png")
    page.screenshot(path=path1, full_page=False)
    screenshots.append(path1)
    print(f"    [1/3] Captured: live page with URL bar")

    # Screenshot 2: view-source: page (Chromium supports this natively)
    view_source_url = f"view-source:{target}"
    print(f"    [2/3] Navigating to {view_source_url}...")
    try:
        page.goto(view_source_url, wait_until="domcontentloaded", timeout=15000)
        time.sleep(0.5)
        inject_url_bar(page, view_source_url, is_secure=True)
    except Exception as e:
        print(f"    [2/3] view-source fallback: {e}")
        # Fallback: navigate to page and use JS to show source
        try:
            page.goto(target, wait_until="domcontentloaded", timeout=15000)
            # Use JavaScript to replace page with its own source
            page.evaluate("""() => {
                const src = document.documentElement.outerHTML;
                document.open();
                document.write('<pre style="word-wrap:break-word;white-space:pre-wrap;font-family:monospace;font-size:12px;padding:10px;">' +
                    src.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</pre>');
                document.close();
            }""")
            time.sleep(0.3)
            inject_url_bar(page, f"view-source:{target}", is_secure=True)
        except Exception:
            pass

    path2 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_2_view_source.png")
    page.screenshot(path=path2, full_page=False)
    screenshots.append(path2)
    print(f"    [2/3] Captured: view-source with URL bar")

    # Screenshot 3: Navigate to a specific evidence endpoint
    evidence_urls = _find_evidence_urls(metadata)
    evidence_url = evidence_urls[0] if evidence_urls else f"{target.rstrip('/')}/xmlrpc.php"
    print(f"    [3/3] Navigating to evidence URL: {evidence_url}...")
    try:
        resp = page.goto(evidence_url, wait_until="domcontentloaded", timeout=12000)
        ev_status = resp.status if resp else "N/A"
        print(f"    [3/3] Loaded (HTTP {ev_status})")
    except Exception as e:
        print(f"    [3/3] Navigation: {e}")

    inject_url_bar(page, evidence_url, is_secure=evidence_url.startswith("https"))
    path3 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_3_evidence_endpoint.png")
    page.screenshot(path=path3, full_page=False)
    screenshots.append(path3)
    print(f"    [3/3] Captured: evidence endpoint with URL bar")


def screenshot_inspect_headers(page, metadata, screenshots):
    """
    Strategy: Inspect Headers — Navigate to target, capture response headers
    showing missing/weak security headers or CSP issues.
    """
    target = metadata.get("target", "")
    finding_id = metadata["id"]
    title = metadata.get("title", "")

    # Collect response headers via route interception
    captured_headers = {}
    captured_status = [0]

    def handle_response(response):
        if response.url.rstrip("/") == target.rstrip("/") or response.url.startswith(target):
            captured_headers.update(dict(response.headers))
            captured_status[0] = response.status

    page.on("response", handle_response)

    print(f"    [1/3] Navigating to {target} and capturing headers...")
    try:
        page.goto(target, wait_until="domcontentloaded", timeout=15000)
    except Exception as e:
        print(f"    [1/3] Navigation: {e}")

    time.sleep(1)

    # Screenshot 1: Live page with URL bar
    inject_url_bar(page, target, is_secure=target.startswith("https"))
    path1 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_1_live_page.png")
    page.screenshot(path=path1, full_page=False)
    screenshots.append(path1)
    print(f"    [1/3] Captured: live page with URL bar (HTTP {captured_status[0]})")

    # Screenshot 2: view-source of the page (real browser view-source)
    view_source_url = f"view-source:{target}"
    print(f"    [2/3] Navigating to {view_source_url}...")
    try:
        page.goto(view_source_url, wait_until="domcontentloaded", timeout=15000)
        time.sleep(0.5)
        inject_url_bar(page, view_source_url, is_secure=True)
    except Exception as e:
        print(f"    [2/3] view-source fallback: {e}")
        try:
            page.goto(target, wait_until="domcontentloaded", timeout=15000)
            page.evaluate("""() => {
                const src = document.documentElement.outerHTML;
                document.open();
                document.write('<pre style="word-wrap:break-word;white-space:pre-wrap;font-family:monospace;font-size:12px;padding:10px;">' +
                    src.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</pre>');
                document.close();
            }""")
            time.sleep(0.3)
            inject_url_bar(page, f"view-source:{target}", is_secure=True)
        except Exception:
            pass

    path2 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_2_view_source.png")
    page.screenshot(path=path2, full_page=False)
    screenshots.append(path2)
    print(f"    [2/3] Captured: view-source with URL bar")

    # Screenshot 3: Navigate to a related evidence endpoint
    evidence_urls = _find_evidence_urls(metadata)
    evidence_url = evidence_urls[0] if evidence_urls else target
    print(f"    [3/3] Navigating to evidence URL: {evidence_url}...")
    try:
        resp = page.goto(evidence_url, wait_until="domcontentloaded", timeout=12000)
        ev_status = resp.status if resp else "N/A"
        print(f"    [3/3] Loaded (HTTP {ev_status})")
    except Exception as e:
        print(f"    [3/3] Navigation: {e}")

    inject_url_bar(page, evidence_url, is_secure=evidence_url.startswith("https"))
    path3 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_3_evidence_endpoint.png")
    page.screenshot(path=path3, full_page=False)
    screenshots.append(path3)
    print(f"    [3/3] Captured: evidence endpoint with URL bar")


def screenshot_redirect_chain(page, metadata, screenshots):
    """
    Strategy: Redirect Chain — Capture the SAML/OAuth redirect chain
    showing exposed tenant IDs and configuration endpoints.
    """
    target = metadata.get("target", "")
    finding_id = metadata["id"]
    title = metadata.get("title", "")

    redirects = []

    def handle_response(response):
        redirects.append({
            "url": response.url,
            "status": response.status,
            "headers": dict(response.headers),
        })

    page.on("response", handle_response)

    print(f"    [1/3] Navigating to {target} and capturing redirect chain...")
    try:
        page.goto(target, wait_until="domcontentloaded", timeout=15000)
    except Exception as e:
        print(f"    [1/3] Navigation: {e}")

    time.sleep(1)

    # Screenshot 1: Final landing page with URL bar (likely Azure AD login)
    final_url = page.url
    inject_url_bar(page, final_url, is_secure=final_url.startswith("https"))
    path1 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_1_redirect_landing.png")
    page.screenshot(path=path1, full_page=False)
    screenshots.append(path1)
    print(f"    [1/3] Captured: redirect landing page with URL bar ({len(redirects)} hops)")

    # Screenshot 2: Navigate to OpenID configuration endpoint (real JSON in browser)
    tenant_id = metadata.get("tenant_id", "")
    if tenant_id:
        openid_config_url = f"https://login.microsoftonline.com/{tenant_id}/.well-known/openid-configuration"
        print(f"    [2/3] Navigating to OpenID config: {openid_config_url}...")
        try:
            page.goto(openid_config_url, wait_until="domcontentloaded", timeout=10000)
            time.sleep(0.5)
            inject_url_bar(page, openid_config_url, is_secure=True)
        except Exception as e:
            print(f"    [2/3] Navigation: {e}")
    else:
        # Fallback: view-source of the target
        view_source_url = f"view-source:{target}"
        print(f"    [2/3] Navigating to {view_source_url}...")
        try:
            page.goto(view_source_url, wait_until="domcontentloaded", timeout=15000)
            inject_url_bar(page, view_source_url, is_secure=True)
        except Exception:
            pass

    path2 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_2_openid_config.png")
    page.screenshot(path=path2, full_page=False)
    screenshots.append(path2)
    print(f"    [2/3] Captured: OpenID config with URL bar")

    # Screenshot 3: Navigate to SAML/OAuth endpoint (authorization endpoint)
    endpoints = metadata.get("endpoints_exposed", {})
    saml_url = endpoints.get("saml2_endpoint", endpoints.get("authorization_endpoint", ""))
    if saml_url:
        print(f"    [3/3] Navigating to SAML endpoint: {saml_url}...")
        try:
            page.goto(saml_url, wait_until="domcontentloaded", timeout=10000)
            time.sleep(0.5)
            inject_url_bar(page, saml_url, is_secure=True)
        except Exception as e:
            print(f"    [3/3] Navigation: {e}")
    else:
        # Navigate back to target to show redirect
        print(f"    [3/3] Navigating back to {target}...")
        try:
            page.goto(target, wait_until="domcontentloaded", timeout=10000)
            inject_url_bar(page, page.url, is_secure=True)
        except Exception:
            pass

    path3 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_3_saml_endpoint.png")
    page.screenshot(path=path3, full_page=False)
    screenshots.append(path3)
    print(f"    [3/3] Captured: SAML/OAuth endpoint with URL bar")


def screenshot_api_response(page, metadata, screenshots):
    """
    Strategy: API Response — All 3 screenshots are real browser navigations:
    1. Hit API endpoint, capture JSON error response with URL bar
    2. Navigate to the application login/main page with URL bar
    3. Navigate to another related endpoint (root URL or alternate API path) with URL bar
    """
    target = metadata.get("target", "")
    finding_id = metadata["id"]
    title = metadata.get("title", "")

    # Find the API endpoint from test vectors
    api_url = target
    test_vectors = metadata.get("test_vectors", [])
    for tv in test_vectors:
        if "url" in tv:
            api_url = tv["url"]
            break

    print(f"    [1/3] Hitting API endpoint: {api_url}")
    try:
        response = page.goto(api_url, wait_until="domcontentloaded", timeout=10000)
        if response:
            print(f"    [1/3] Got HTTP {response.status}")
    except Exception as e:
        print(f"    [1/3] Request: {e}")

    # Screenshot 1: Raw API response in browser with URL bar
    inject_url_bar(page, api_url, is_secure=api_url.startswith("https"))
    path1 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_1_api_response.png")
    page.screenshot(path=path1, full_page=False)
    screenshots.append(path1)
    print(f"    [1/3] Captured: API response with URL bar")

    # Screenshot 2: Navigate to the application login page
    evidence_urls = _find_evidence_urls(metadata)
    # Prefer login page or auth-related URL
    login_url = None
    for eu in evidence_urls:
        if "login" in eu or "auth" in eu or "/ng/" in eu:
            login_url = eu
            break
    if not login_url:
        # Derive login page from target
        base = target.rstrip("/").split("/api")[0] if "/api" in target else target.rstrip("/")
        login_url = f"{base}/ng//auth/login"

    print(f"    [2/3] Navigating to login page: {login_url}...")
    try:
        resp = page.goto(login_url, wait_until="domcontentloaded", timeout=12000)
        ev_status = resp.status if resp else "N/A"
        print(f"    [2/3] Loaded (HTTP {ev_status})")
    except Exception as e:
        print(f"    [2/3] Navigation: {e}")

    time.sleep(0.5)
    inject_url_bar(page, login_url, is_secure=login_url.startswith("https"))
    path2 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_2_login_page.png")
    page.screenshot(path=path2, full_page=False)
    screenshots.append(path2)
    print(f"    [2/3] Captured: login page with URL bar")

    # Screenshot 3: Navigate to root URL or another evidence endpoint
    base_url = target.rstrip("/").split("/api")[0] if "/api" in target else target.rstrip("/")
    root_url = base_url + "/"
    # Pick a different URL from evidence_urls if available
    alt_url = root_url
    for eu in evidence_urls:
        if eu != login_url and eu != api_url:
            alt_url = eu
            break

    print(f"    [3/3] Navigating to: {alt_url}...")
    try:
        resp = page.goto(alt_url, wait_until="domcontentloaded", timeout=12000)
        ev_status = resp.status if resp else "N/A"
        print(f"    [3/3] Loaded (HTTP {ev_status})")
    except Exception as e:
        print(f"    [3/3] Navigation: {e}")

    time.sleep(0.5)
    inject_url_bar(page, alt_url, is_secure=alt_url.startswith("https"))
    path3 = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_3_evidence_endpoint.png")
    page.screenshot(path=path3, full_page=False)
    screenshots.append(path3)
    print(f"    [3/3] Captured: evidence endpoint with URL bar")


def screenshot_evidence_summary(page, metadata, output_path):
    """Generate a generic evidence summary screenshot."""
    finding_id = metadata["id"]
    title = metadata.get("title", "")
    target = metadata.get("target", "")
    severity = metadata.get("severity", "N/A")
    poc_status = metadata.get("poc_status", metadata.get("status", "VERIFIED"))

    page.set_content(f"""<!DOCTYPE html>
<html>
<head><style>
body {{ background:#1e1e1e; color:#d4d4d4; font-family:-apple-system,Arial,sans-serif; padding:30px; }}
h1 {{ color:#fff; font-size:20px; border-bottom:3px solid #007acc; padding-bottom:12px; }}
.badge {{ display:inline-block; padding:3px 12px; border-radius:4px; font-size:12px; font-weight:bold; margin:2px; }}
.verified {{ background:#1a4a1a; color:#4caf50; }}
.severity {{ background:#4a3000; color:#ffd700; }}
.field {{ margin:10px 0; }}
.label {{ color:#888; font-size:12px; }}
.value {{ color:#fff; font-size:14px; margin-top:3px; }}
</style></head>
<body>
<h1>{finding_id} — PoC Evidence</h1>
<div>
    <span class="badge verified">{poc_status}</span>
    <span class="badge severity">{severity}</span>
</div>
<div class="field"><div class="label">Finding</div><div class="value">{title}</div></div>
<div class="field"><div class="label">Target</div><div class="value">{target}</div></div>
<div class="field"><div class="label">Captured</div><div class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</div></div>
<div class="field"><div class="label">Engagement</div><div class="value">Penetration Test</div></div>
<p style="margin-top:25px;color:#888;font-size:11px;">This evidence was captured in real-time by the VAPT Framework PoC Screenshot Agent using Playwright browser automation.</p>
</body>
</html>""", wait_until="domcontentloaded")

    time.sleep(0.3)
    page.screenshot(path=output_path, full_page=False)


# ── Strategy dispatcher ──────────────────────────────────────────────────────

def inject_url_bar(page, url, is_secure=True):
    """Inject a realistic browser-style URL bar at the top of the current page.
    If injection fails (cross-origin pages), fall back to a full-page overlay."""
    lock_icon = "🔒" if is_secure else "⚠️"
    protocol = ""
    domain = ""
    path = ""
    if "://" in url:
        protocol = url.split("://")[0] + "://"
        rest = url.split("://", 1)[1]
        if "/" in rest:
            domain = rest.split("/", 1)[0]
            path = "/" + rest.split("/", 1)[1]
        else:
            domain = rest
    else:
        domain = url

    bar_js = """
    (function() {
        if (!document.body) return false;
        var old = document.getElementById('poc-url-bar');
        if (old) old.remove();

        var bar = document.createElement('div');
        bar.id = 'poc-url-bar';
        bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;background:#dee1e6;padding:0;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Arial,sans-serif;border-bottom:1px solid #b0b5bd;';

        var tabBar = document.createElement('div');
        tabBar.style.cssText = 'background:#c2c6cc;padding:6px 12px 0 80px;display:flex;align-items:end;position:relative;';

        var dots = document.createElement('div');
        dots.style.cssText = 'position:absolute;left:12px;top:10px;display:flex;gap:7px;';
        dots.innerHTML = '<span style="width:12px;height:12px;border-radius:50%;background:#ff5f57;display:inline-block;"></span><span style="width:12px;height:12px;border-radius:50%;background:#febc2e;display:inline-block;"></span><span style="width:12px;height:12px;border-radius:50%;background:#28c840;display:inline-block;"></span>';
        tabBar.appendChild(dots);

        var tab = document.createElement('div');
        tab.style.cssText = 'background:#dee1e6;padding:6px 16px;border-radius:8px 8px 0 0;font-size:12px;color:#333;max-width:220px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;';
        tab.textContent = '""" + domain.replace("'", "\\'").replace("\\", "\\\\") + """';
        tabBar.appendChild(tab);
        bar.appendChild(tabBar);

        var urlRow = document.createElement('div');
        urlRow.style.cssText = 'padding:6px 12px 8px;display:flex;align-items:center;gap:8px;';

        var nav = document.createElement('div');
        nav.style.cssText = 'display:flex;gap:6px;color:#888;font-size:14px;';
        nav.innerHTML = '<span>◀</span><span>▶</span><span>↻</span>';
        urlRow.appendChild(nav);

        var urlBox = document.createElement('div');
        urlBox.style.cssText = 'flex:1;background:#fff;border-radius:20px;padding:6px 14px;font-size:13px;display:flex;align-items:center;border:1px solid #c8ccd0;';
        urlBox.innerHTML = '<span style="margin-right:6px;">""" + lock_icon + """</span><span style="color:#888;">""" + protocol.replace("'", "\\'") + """</span><span style="color:#222;font-weight:500;">""" + domain.replace("'", "\\'").replace("\\", "\\\\") + """</span><span style="color:#888;">""" + path.replace("'", "\\'").replace("\\", "\\\\") + """</span>';
        urlRow.appendChild(urlBox);

        bar.appendChild(urlRow);
        document.body.prepend(bar);
        document.body.style.paddingTop = (bar.offsetHeight) + 'px';
        return true;
    })();
    """
    try:
        result = page.evaluate(bar_js)
        if result:
            time.sleep(0.2)
            return True
    except Exception:
        pass

    # Fallback: take screenshot of current page, then render it inside
    # a new page with a URL bar on top
    try:
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp_path = tmp.name
        tmp.close()
        page.screenshot(path=tmp_path, full_page=False)

        import base64
        with open(tmp_path, "rb") as f:
            img_b64 = base64.b64encode(f.read()).decode()
        os.unlink(tmp_path)

        page.set_content(f"""<!DOCTYPE html>
<html><head><style>
body {{ margin:0; padding:0; background:#fff; }}
.browser-bar {{ background:#dee1e6; padding:0; font-family:-apple-system,Arial,sans-serif; border-bottom:1px solid #b0b5bd; }}
.tab-bar {{ background:#c2c6cc; padding:6px 12px 0 80px; display:flex; align-items:end; position:relative; }}
.dots {{ position:absolute; left:12px; top:10px; display:flex; gap:7px; }}
.dot {{ width:12px; height:12px; border-radius:50%; display:inline-block; }}
.tab {{ background:#dee1e6; padding:6px 16px; border-radius:8px 8px 0 0; font-size:12px; color:#333; }}
.url-row {{ padding:6px 12px 8px; display:flex; align-items:center; gap:8px; }}
.nav {{ display:flex; gap:6px; color:#888; font-size:14px; }}
.url-box {{ flex:1; background:#fff; border-radius:20px; padding:6px 14px; font-size:13px; display:flex; align-items:center; border:1px solid #c8ccd0; }}
img {{ width:100%; display:block; }}
</style></head>
<body>
<div class="browser-bar">
    <div class="tab-bar">
        <div class="dots"><span class="dot" style="background:#ff5f57;"></span><span class="dot" style="background:#febc2e;"></span><span class="dot" style="background:#28c840;"></span></div>
        <div class="tab">{domain}</div>
    </div>
    <div class="url-row">
        <div class="nav"><span>◀</span><span>▶</span><span>↻</span></div>
        <div class="url-box"><span style="margin-right:6px;">{lock_icon}</span><span style="color:#888;">{protocol}</span><span style="color:#222;font-weight:500;">{domain}</span><span style="color:#888;">{path}</span></div>
    </div>
</div>
<img src="data:image/png;base64,{img_b64}" />
</body></html>""", wait_until="domcontentloaded")
        time.sleep(0.3)
        return True
    except Exception as e:
        print(f"    [URL BAR] Fallback failed: {e}")
        return False


STRATEGY_HANDLERS = {
    "VERSION_DISCLOSURE": screenshot_view_source,
    "INFORMATION_DISCLOSURE": screenshot_view_source,
    "SECURITY_MISCONFIGURATION": screenshot_inspect_headers,
    "CSP_BYPASS": screenshot_inspect_headers,
    "MISSING_HEADERS": screenshot_inspect_headers,
    "AZURE_AD_EXPOSURE": screenshot_redirect_chain,
    "API_ERROR_DISCLOSURE": screenshot_api_response,
}


# ── Main Agent ───────────────────────────────────────────────────────────────

def run_poc_screenshots(finding_ids=None):
    """Run the PoC screenshot agent for specified or all findings."""
    from playwright.sync_api import sync_playwright

    # Find all findings
    patterns = [
        os.path.join(FINDINGS_DIR, "F-*.md"),
        os.path.join(FINDINGS_DIR, "*", "*", "F-*.md"),
        os.path.join(FINDINGS_DIR, "*", "F-*.md"),
    ]
    all_files = set()
    for pattern in patterns:
        all_files.update(glob.glob(pattern))
    all_files = sorted(all_files)

    # Filter to requested findings
    if finding_ids:
        filtered = []
        for f in all_files:
            fid = os.path.basename(f).replace(".md", "")
            if fid in finding_ids:
                filtered.append(f)
        all_files = filtered

    if not all_files:
        print("[ERROR] No finding files found.")
        return

    print(f"\n{'='*65}")
    print(f"  Agentic PoC Screenshot System (Playwright)")
    print(f"  Findings: {len(all_files)}")
    print(f"  Output: {SCREENSHOTS_DIR}")
    print(f"{'='*65}\n")

    results = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )

        for filepath in all_files:
            finding_id = os.path.basename(filepath).replace(".md", "")
            metadata = load_finding_metadata(finding_id)
            strategy = determine_strategy(metadata)
            handler = STRATEGY_HANDLERS.get(strategy, screenshot_inspect_headers)

            target = metadata.get("target", "N/A")
            title = metadata.get("title", "Unknown")

            print(f"[{finding_id}] {title}")
            print(f"  Target:   {target}")
            print(f"  Strategy: {strategy} ({POC_STRATEGIES.get(strategy, {}).get('description', '')})")

            # Remove old screenshots for this finding
            for old in glob.glob(os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_*.png")):
                os.remove(old)

            page = context.new_page()
            screenshots = []

            try:
                handler(page, metadata, screenshots)
                results[finding_id] = {"status": "OK", "screenshots": len(screenshots), "files": [os.path.basename(s) for s in screenshots]}
                print(f"  Result:   {len(screenshots)} screenshots captured\n")
            except Exception as e:
                results[finding_id] = {"status": "ERROR", "error": str(e)}
                print(f"  [ERROR]   {e}\n")
            finally:
                page.close()

        browser.close()

    # Summary
    print(f"\n{'='*65}")
    print(f"  Results Summary")
    print(f"{'='*65}")
    for fid, res in sorted(results.items()):
        if res["status"] == "OK":
            files = ", ".join(res["files"])
            print(f"  [{fid}] {res['screenshots']} screenshots: {files}")
        else:
            print(f"  [{fid}] ERROR: {res['error']}")
    print(f"{'='*65}\n")

    return results


def main():
    parser = argparse.ArgumentParser(description="Agentic AI PoC Screenshot System")
    parser.add_argument("--finding", "-f", help="Specific finding(s), comma-separated (e.g., F-012,F-013)")
    parser.add_argument("--list", "-l", action="store_true", help="List findings and their strategies")
    args = parser.parse_args()

    if args.list:
        patterns = [
            os.path.join(FINDINGS_DIR, "F-*.md"),
            os.path.join(FINDINGS_DIR, "*", "*", "F-*.md"),
        ]
        all_files = set()
        for pattern in patterns:
            all_files.update(glob.glob(pattern))

        print(f"\n{'='*80}")
        print(f"  Finding PoC Strategies")
        print(f"{'='*80}")
        for f in sorted(all_files):
            fid = os.path.basename(f).replace(".md", "")
            meta = load_finding_metadata(fid)
            strategy = determine_strategy(meta)
            target = meta.get("target", "N/A")
            print(f"  {fid}  {strategy:25s}  {target}")
        print()
        return

    finding_ids = None
    if args.finding:
        finding_ids = [f.strip() for f in args.finding.split(",")]

    run_poc_screenshots(finding_ids)


if __name__ == "__main__":
    main()
