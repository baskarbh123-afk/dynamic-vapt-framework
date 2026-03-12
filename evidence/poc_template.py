#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
  POC Screenshot Generator Template — Penetration Testing Framework
═══════════════════════════════════════════════════════════════════

Reusable template for generating 3 POC screenshots per finding.
Each finding gets:
  POC-1: Discovery / Initial Evidence
  POC-2: Exploitation / Detailed Proof
  POC-3: Impact / Data Extraction

Usage:
  python3 poc_template.py                    # Run all findings
  python3 poc_template.py --finding F-001    # Run specific finding
  python3 poc_template.py --list             # List all findings

Configure findings in the FINDINGS dict at bottom of file.
"""

import subprocess
import textwrap
import os
import sys
import json
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

TESTER = "Baskar"
ENGAGEMENT = "Multi-Target Penetration Test"
CLASSIFICATION = "CONFIDENTIAL"

EVIDENCE_DIR = os.path.dirname(os.path.abspath(__file__))
SCREENSHOTS_DIR = os.path.join(EVIDENCE_DIR, "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════════
# THEME — Terminal style
# ═══════════════════════════════════════════════════════════════

THEME = {
    "bg": (24, 24, 28),
    "header_bg": (40, 40, 44),
    "text": (200, 200, 200),
    "green": (78, 201, 176),
    "red": (255, 85, 85),
    "yellow": (229, 192, 123),
    "cyan": (86, 182, 194),
    "blue": (97, 175, 239),
    "magenta": (198, 120, 221),
    "white": (255, 255, 255),
    "dim": (100, 100, 100),
    "separator": (60, 60, 64),
    "badge_critical": (200, 30, 30),
    "badge_high": (220, 80, 20),
    "badge_medium": (200, 150, 0),
    "badge_low": (60, 140, 200),
}

SEVERITY_COLORS = {
    "Critical": THEME["badge_critical"],
    "High": THEME["badge_high"],
    "Medium": THEME["badge_medium"],
    "Low": THEME["badge_low"],
}

# ═══════════════════════════════════════════════════════════════
# FONT HELPERS
# ═══════════════════════════════════════════════════════════════

def get_font(size=13):
    for fp in [
        "/System/Library/Fonts/SFMono-Regular.otf",
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/Monaco.ttf",
        "/Library/Fonts/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    ]:
        try:
            return ImageFont.truetype(fp, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()

def get_bold_font(size=13):
    for fp in [
        "/System/Library/Fonts/SFMono-Bold.otf",
        "/System/Library/Fonts/SFMono-Semibold.otf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    ]:
        try:
            return ImageFont.truetype(fp, size)
        except (OSError, IOError):
            continue
    return get_font(size)

# ═══════════════════════════════════════════════════════════════
# CURL RUNNER
# ═══════════════════════════════════════════════════════════════

def run_curl(cmd, max_lines=40):
    """Run a shell command and return trimmed output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        output = (result.stdout + result.stderr).strip()
        lines = output.split('\n')
        if len(lines) > max_lines:
            lines = lines[:max_lines] + [f"  ... ({len(lines) - max_lines} more lines truncated)"]
        return '\n'.join(lines)
    except subprocess.TimeoutExpired:
        return "[TIMEOUT — target did not respond within 20s]"
    except Exception as e:
        return f"[ERROR: {e}]"

# ═══════════════════════════════════════════════════════════════
# SCREENSHOT RENDERER
# ═══════════════════════════════════════════════════════════════

def render_screenshot(
    finding_id, title, severity, cvss, target, poc_number, poc_label,
    curl_cmd, curl_output, annotation, filename
):
    """Render a terminal-style POC screenshot with metadata."""
    font = get_font(13)
    bold_font = get_bold_font(13)
    title_font = get_bold_font(15)
    small_font = get_font(11)
    sev_color = SEVERITY_COLORS.get(severity, THEME["yellow"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    # ── Header block ──
    lines.append(("green_bold", f"  ╔══════════════════════════════════════════════════════════════════════╗"))
    lines.append(("green_bold", f"  ║  PROOF OF CONCEPT — {poc_label.upper():50s}║"))
    lines.append(("green_bold", f"  ╚══════════════════════════════════════════════════════════════════════╝"))
    lines.append(("blank", ""))

    # ── Metadata ──
    lines.append(("cyan", f"  Finding:    {finding_id} — {title}"))
    lines.append(("cyan", f"  Target:     {target}"))
    lines.append(("severity", f"  Severity:   {severity} (CVSS {cvss})"))
    lines.append(("cyan", f"  POC:        {poc_number} of 3 — {poc_label}"))
    lines.append(("dim", f"  Captured:   {now}"))
    lines.append(("dim", f"  Tester:     {TESTER}"))
    lines.append(("blank", ""))
    lines.append(("separator", "  " + "─" * 72))
    lines.append(("blank", ""))

    # ── Command ──
    lines.append(("dim", "  Command:"))
    # Wrap long commands
    if len(curl_cmd) > 90:
        cmd_lines = textwrap.wrap(curl_cmd, width=88)
        for i, cl in enumerate(cmd_lines):
            prefix = "  $ " if i == 0 else "    "
            lines.append(("green", f"{prefix}{cl}"))
    else:
        lines.append(("green", f"  $ {curl_cmd}"))
    lines.append(("blank", ""))
    lines.append(("dim", "  Response:"))

    # ── Output ──
    for line in curl_output.split('\n'):
        if len(line) > 105:
            for w in textwrap.wrap(line, width=105):
                lines.append(("text", f"  {w}"))
        else:
            lines.append(("text", f"  {line}"))

    # ── Annotation ──
    lines.append(("blank", ""))
    lines.append(("separator", "  " + "─" * 72))
    lines.append(("blank", ""))
    for ann_line in annotation.split('\n'):
        lines.append(("red_bold", f"  ⚠ {ann_line}"))
    lines.append(("blank", ""))
    lines.append(("separator", "  " + "─" * 72))
    lines.append(("dim", f"  Evidence: {filename} | {CLASSIFICATION} | {ENGAGEMENT}"))

    # ── Calculate image dimensions ──
    line_height = 19
    padding = 16
    header_h = 36
    width = 980
    height = header_h + padding * 2 + len(lines) * line_height + 10
    height = max(height, 300)

    # ── Draw ──
    img = Image.new('RGB', (width, height), THEME["bg"])
    draw = ImageDraw.Draw(img)

    # Window chrome
    draw.rectangle([0, 0, width, header_h], fill=THEME["header_bg"])
    draw.ellipse([12, 10, 24, 22], fill=(255, 95, 87))
    draw.ellipse([30, 10, 42, 22], fill=(254, 188, 46))
    draw.ellipse([48, 10, 60, 22], fill=(40, 201, 64))
    tab_text = f"{finding_id} — POC-{poc_number} — {target}"
    draw.text((72, 9), tab_text, fill=THEME["text"], font=bold_font)

    # Severity badge
    badge_text = f" {severity.upper()} "
    bbox = draw.textbbox((0, 0), badge_text, font=bold_font)
    bw = bbox[2] - bbox[0] + 12
    bx = width - bw - 16
    draw.rounded_rectangle([bx, 7, bx + bw, 29], radius=4, fill=sev_color)
    draw.text((bx + 6, 9), badge_text, fill=THEME["white"], font=bold_font)

    # Lines
    y = header_h + padding
    color_map = {
        "text": THEME["text"],
        "green": THEME["green"],
        "green_bold": THEME["green"],
        "cyan": THEME["cyan"],
        "blue": THEME["blue"],
        "dim": THEME["dim"],
        "separator": THEME["separator"],
        "red_bold": THEME["red"],
        "severity": sev_color,
    }
    font_map = {
        "green_bold": bold_font,
        "red_bold": bold_font,
        "severity": bold_font,
    }

    for line_type, text in lines:
        if line_type == "blank":
            y += line_height
            continue
        color = color_map.get(line_type, THEME["text"])
        f = font_map.get(line_type, font)
        draw.text((8, y), text, fill=color, font=f)
        y += line_height

    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    img.save(filepath, "PNG", optimize=True)
    print(f"    ✓ {filename} ({os.path.getsize(filepath) // 1024}K)")
    return filepath


# ═══════════════════════════════════════════════════════════════
# FINDING DEFINITIONS — 3 POCs PER FINDING
# ═══════════════════════════════════════════════════════════════
# Template for adding new findings:
#
# "F-XXX": {
#     "title": "Vulnerability Name",
#     "severity": "Medium",
#     "cvss": "5.3",
#     "target": "example.com",
#     "pocs": [
#         {
#             "label": "Discovery",
#             "cmd": "curl command here",
#             "annotation": "What this proves",
#         },
#         {
#             "label": "Exploitation",
#             "cmd": "curl command here",
#             "annotation": "What this proves",
#         },
#         {
#             "label": "Impact",
#             "cmd": "curl command here",
#             "annotation": "What this proves",
#         },
#     ]
# }
# ═══════════════════════════════════════════════════════════════

FINDINGS = {

    "F-001": {
        "title": "Swagger API Documentation Publicly Exposed",
        "severity": "Medium",
        "cvss": "5.3",
        "target": "gopps.global.com",
        "pocs": [
            {
                "label": "Discovery — Swagger UI Accessible",
                "cmd": 'curl -sI "https://gopps.global.com/swagger/ui/index" | head -15',
                "annotation": "Swagger UI is publicly accessible without authentication.\nHTTP 200 confirms full interactive API documentation is exposed.",
            },
            {
                "label": "Exploitation — Full API Spec Extracted",
                "cmd": 'curl -s "https://gopps.global.com/swagger/docs/v1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({\'info\':d[\'info\'],\'host\':d[\'host\'],\'paths_count\':len(d[\'paths\']),\'definitions_count\':len(d[\'definitions\']),\'paths_sample\':list(d[\'paths\'].keys())[:12],\'securityDefinitions\':d.get(\'securityDefinitions\',{})},indent=2))"',
                "annotation": "Full API specification extracted: 45 endpoints, 96 data models.\nIncludes auth endpoints, order management, data export, and search APIs.",
            },
            {
                "label": "Impact — Sensitive Endpoint Enumeration",
                "cmd": 'curl -s "https://gopps.global.com/swagger/docs/v1" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f\'  {m.upper():7s} {p}\') for p,v in list(d[\'paths\'].items())[:20] for m in v.keys() if m in (\'get\',\'post\',\'put\',\'delete\',\'patch\')]"',
                "annotation": "Complete API route map with HTTP methods exposed.\nAttacker can craft targeted requests against order, property, and data endpoints.",
            },
        ]
    },

    "F-002": {
        "title": "API Status Endpoint Exposes Internal Details",
        "severity": "Medium",
        "cvss": "5.3",
        "target": "gopps.global.com",
        "pocs": [
            {
                "label": "Discovery — Status Endpoint Accessible",
                "cmd": 'curl -s "https://gopps.global.com/api/status" | python3 -m json.tool | head -25',
                "annotation": "Status endpoint returns internal application details without authentication.\nExposes version, config field names, and permission model.",
            },
            {
                "label": "Exploitation — Permission Model Extracted",
                "cmd": 'curl -s "https://gopps.global.com/api/status" | python3 -c "import sys,json; d=json.load(sys.stdin); print(\'Application:\',d.get(\'applicationName\')); print(\'Version:\',d.get(\'version\')); print(\'\\nConfig fields:\'); [print(f\'  {k}: {v}\') for k,v in d.items() if \'Configuration\' in k or \'Connection\' in k]; print(\'\\nPermission model:\'); [print(f\'  {k}: {v}\') for k,v in d.get(\'userDetails\',{}).get(\'userPrivileges\',{}).items()]"',
                "annotation": "Full authorization model extracted: 9 privilege flags revealed.\nAttacker knows exact permission escalation targets.",
            },
            {
                "label": "Impact — Debug Configuration Confirmed",
                "cmd": 'curl -s "https://gopps.global.com/api/about" | python3 -m json.tool',
                "annotation": "/api/about confirms debug mode: local=\"true\".\nTest/debug fields present in production — indicates dev config deployed to prod.",
            },
        ]
    },

    "F-003": {
        "title": "Internal Environment URLs Leaked in JS Bundle",
        "severity": "Medium",
        "cvss": "5.3",
        "target": "gopps.global.com",
        "pocs": [
            {
                "label": "Discovery — URLs Extracted from JS Bundle",
                "cmd": 'curl -s "https://gopps.global.com/static/js/main.dd4b9293.js" | grep -oE \'https?://[a-zA-Z0-9._/-]+\' | sort -u',
                "annotation": "Production JS bundle contains hardcoded internal environment URLs.\nDev, Int, Test, UAT environments and ADFS OAuth endpoint exposed.",
            },
            {
                "label": "Exploitation — UAT Environment Publicly Accessible",
                "cmd": 'curl -sI "https://goppsuat.global.com" | head -10',
                "annotation": "UAT environment is publicly accessible from the internet (HTTP 200).\nSame application deployed with potentially weaker security controls.",
            },
            {
                "label": "Impact — UAT Swagger Also Exposed",
                "cmd": 'curl -sI "https://goppsuat.global.com/swagger/ui/index" | head -10',
                "annotation": "UAT environment also exposes Swagger API documentation.\nAttacker has full API docs for both production AND UAT environments.",
            },
        ]
    },

    "F-004": {
        "title": "WordPress REST API User Enumeration",
        "severity": "Low",
        "cvss": "3.7",
        "target": "Multiple WordPress Sites",
        "pocs": [
            {
                "label": "Discovery — User List via REST API (globalbuitenreclame.nl)",
                "cmd": 'curl -s "https://globalbuitenreclame.nl/wp-json/wp/v2/users" | python3 -c "import sys,json; [print(f\'  ID:{u[\\\"id\\\"]}  Name:{u[\\\"name\\\"]}  Slug:{u[\\\"slug\\\"]}  URL:{u.get(\\\"url\\\",\\\"-\\\")}\') for u in json.load(sys.stdin)]"',
                "annotation": "3 WordPress users enumerated including admin account.\nInternal dev URL (global-webshop.test/wp) leaked in admin profile.",
            },
            {
                "label": "Exploitation — Admin Username Exposed (fellasstudios.com)",
                "cmd": 'curl -s "https://fellasstudios.com/wp-json/wp/v2/users" | python3 -c "import sys,json; [print(f\'  ID:{u[\\\"id\\\"]}  Name:{u[\\\"name\\\"]}  Slug:{u[\\\"slug\\\"]}  Gravatar:{u[\\\"avatar_urls\\\"][\\\"96\\\"][:60]}...\') for u in json.load(sys.stdin)]"',
                "annotation": "Admin username \"admin3456\" exposed on fellasstudios.com.\nGravatar hash can be reversed to discover admin email address.",
            },
            {
                "label": "Impact — Author Enumeration (production.victoriousfestival.co.uk)",
                "cmd": 'for i in 1 2 3 4 5 6 7 8 9 10; do loc=$(curl -sI --max-time 5 "https://production.victoriousfestival.co.uk/?author=$i" 2>&1 | grep -i "^location:" | head -1); [ -n "$loc" ] && echo "  author=$i → $loc"; done',
                "annotation": "5 usernames discovered via ?author=N parameter enumeration.\nUsernames: rmartin, mbishop, rob-jordan, bmiles, pcaruana.",
            },
        ]
    },

    "F-005": {
        "title": "XMLRPC Enabled with system.multicall",
        "severity": "Low",
        "cvss": "3.7",
        "target": "production.victoriousfestival.co.uk",
        "pocs": [
            {
                "label": "Discovery — XMLRPC Methods Listing",
                "cmd": 'curl -s -X POST "https://production.victoriousfestival.co.uk/xmlrpc.php" -H "Content-Type: text/xml" -d \'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>\' | grep "<string>" | head -15',
                "annotation": "XMLRPC is enabled and responds to system.listMethods.\nsystem.multicall present — allows brute-force amplification.",
            },
            {
                "label": "Exploitation — Multicall Confirmation",
                "cmd": 'curl -s -X POST "https://production.victoriousfestival.co.uk/xmlrpc.php" -H "Content-Type: text/xml" -d \'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>\' | grep -c "<string>"',
                "annotation": "Total number of exposed XMLRPC methods.\nIncludes wp.getUsersBlogs, metaWeblog.*, blogger.* — all authentication targets.",
            },
            {
                "label": "Impact — wp-cron.php Also Accessible",
                "cmd": 'for site in "https://fellasstudios.com" "https://production.victoriousfestival.co.uk" "https://www.victoriousfestival.co.uk"; do code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$site/wp-cron.php"); echo "  $site/wp-cron.php → HTTP $code"; done',
                "annotation": "wp-cron.php publicly accessible on 3 WordPress sites.\nCombined with XMLRPC, increases attack surface for resource exhaustion.",
            },
        ]
    },

    "F-006": {
        "title": "ADFS OAuth Configuration Leaked",
        "severity": "Medium",
        "cvss": "5.3",
        "target": "gopps.global.com",
        "pocs": [
            {
                "label": "Discovery — Auth Redirect Exposes ADFS Config",
                "cmd": 'curl -sI "https://gopps.global.com/api/security/authentication/login?redirectUri=https://gopps.global.com" | head -15',
                "annotation": "Authentication redirect reveals full ADFS OAuth2 configuration.\nADFS server, client_id, resource, and redirect_uri all exposed.",
            },
            {
                "label": "Exploitation — ADFS Server Identification",
                "cmd": 'curl -sI "https://gopps.global.com/api/security/authentication/login?redirectUri=https://gopps.global.com" | grep -i location | sed "s/.*adfs/\\nADFS Server: adfs/" | tr "&" "\\n" | head -10',
                "annotation": "Extracted: ADFS Server = adfs2.thisisglobal.com\nClient ID = gOpps.Prod | Resource = urn:gOpps.Prod",
            },
            {
                "label": "Impact — Swagger Confirms Auth Architecture",
                "cmd": 'curl -s "https://gopps.global.com/swagger/ui/index" | grep -i "apiKey\\|oauth\\|rootUrl\\|discovery" | head -10',
                "annotation": "Swagger UI confirms: apiKeyName=Authorization, apiKeyIn=header.\nCombined with ADFS details, full auth architecture is mapped.",
            },
        ]
    },

    "F-007": {
        "title": "Sanity.io CMS Project ID and Dataset Exposed",
        "severity": "Low",
        "cvss": "3.7",
        "target": "www.makesomenoise.com",
        "pocs": [
            {
                "label": "Discovery — Sanity Config in HTML Source",
                "cmd": 'curl -s "https://www.makesomenoise.com" | grep -o \'lvz0au6x\\|api\\.sanity\\.io\\|"production"\' | sort -u',
                "annotation": "Sanity.io project ID and dataset name found in client-side HTML.\nProject: lvz0au6x | Dataset: production | Host: api.sanity.io",
            },
            {
                "label": "Exploitation — Sanity API Preconnect Confirmed",
                "cmd": 'curl -s "https://www.makesomenoise.com" | grep -i "preconnect\\|sanity" | head -5',
                "annotation": "HTML includes <link rel=preconnect> to Sanity API endpoint.\nConfirms active client-side API connection to lvz0au6x.api.sanity.io.",
            },
            {
                "label": "Impact — Vercel Deployment Details Exposed",
                "cmd": 'curl -sI "https://www.makesomenoise.com" | grep -i "x-vercel\\|x-nextjs\\|x-powered\\|x-matched"',
                "annotation": "Additional info disclosure: Vercel deployment ID, Next.js version.\nCombined with Sanity project ID, full stack architecture is mapped.",
            },
        ]
    },
}


# ═══════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════

def generate_finding(finding_id, finding):
    """Generate 3 POC screenshots for a single finding."""
    print(f"\n  [{finding_id}] {finding['title']}")
    for i, poc in enumerate(finding["pocs"], 1):
        output = run_curl(poc["cmd"])
        if not output.strip():
            output = "(No output — target may be unreachable or response empty)"
        fname = f"{finding_id}_POC-{i}_{poc['label'].split('—')[0].strip().lower().replace(' ', '_')}.png"
        render_screenshot(
            finding_id=finding_id,
            title=finding["title"],
            severity=finding["severity"],
            cvss=finding["cvss"],
            target=finding["target"],
            poc_number=i,
            poc_label=poc["label"],
            curl_cmd=poc["cmd"],
            curl_output=output,
            annotation=poc["annotation"],
            filename=fname,
        )


def main():
    print("═" * 60)
    print("  POC Screenshot Generator — Penetration Testing Framework")
    print("═" * 60)

    # Parse args
    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            for fid, f in FINDINGS.items():
                print(f"  {fid}: {f['title']} ({f['severity']}) — {f['target']}")
            return
        elif sys.argv[1] == "--finding" and len(sys.argv) > 2:
            fid = sys.argv[2].upper()
            if fid in FINDINGS:
                generate_finding(fid, FINDINGS[fid])
                print(f"\n✅ 3 POC screenshots for {fid} saved to: {SCREENSHOTS_DIR}")
                return
            else:
                print(f"  ✗ Finding {fid} not found. Use --list to see available findings.")
                return
        elif sys.argv[1] == "--help":
            print(__doc__)
            return

    # Generate all
    total = 0
    for fid, finding in FINDINGS.items():
        generate_finding(fid, finding)
        total += 3

    print(f"\n{'═' * 60}")
    print(f"  ✅ {total} POC screenshots generated for {len(FINDINGS)} findings")
    print(f"  📂 {SCREENSHOTS_DIR}")
    print(f"{'═' * 60}")


if __name__ == "__main__":
    main()
