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

TESTER = ""                # e.g., "John Doe"
ENGAGEMENT = ""            # e.g., "Acme Corp Penetration Test"
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
    # ═══════════════════════════════════════════════════════════════
    # Add your findings here. Example:
    #
    # "F-001": {
    #     "title": "Swagger API Documentation Publicly Exposed",
    #     "severity": "Medium",
    #     "cvss": "5.3",
    #     "target": "api.example.com",
    #     "pocs": [
    #         {
    #             "label": "Discovery — Swagger UI Accessible",
    #             "cmd": 'curl -sI "https://api.example.com/swagger/ui/index" | head -15',
    #             "annotation": "Swagger UI is publicly accessible without authentication.",
    #         },
    #         {
    #             "label": "Exploitation — Full API Spec Extracted",
    #             "cmd": 'curl -s "https://api.example.com/swagger/docs/v1" | python3 -m json.tool | head -30',
    #             "annotation": "Full API specification extracted.",
    #         },
    #         {
    #             "label": "Impact — Sensitive Endpoint Enumeration",
    #             "cmd": 'curl -s "https://api.example.com/swagger/docs/v1" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get(\'paths\',{})))"',
    #             "annotation": "Complete API route map exposed.",
    #         },
    #     ]
    # },
    # ═══════════════════════════════════════════════════════════════
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
