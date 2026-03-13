#!/usr/bin/env python3
"""
Generate POC screenshot images from curl output for penetration test findings.

Usage:
    python3 poc_screenshot.py

This script is a simple one-off screenshot generator that runs curl commands
against target endpoints and renders the output as terminal-style images.

For more advanced browser-based screenshots, use:
    python3 agents/poc_screenshot_agent.py
"""

from PIL import Image, ImageDraw, ImageFont
import subprocess
import textwrap
import os

EVIDENCE_DIR = os.path.dirname(os.path.abspath(__file__))
SCREENSHOTS_DIR = os.path.join(EVIDENCE_DIR, "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# Terminal-style colors
BG_COLOR = (30, 30, 30)
TEXT_COLOR = (204, 204, 204)
GREEN = (78, 201, 176)
RED = (255, 85, 85)
YELLOW = (229, 192, 123)
CYAN = (86, 182, 194)
WHITE = (255, 255, 255)
HEADER_BG = (45, 45, 45)

def get_font(size=14):
    """Try to load a monospace font."""
    font_paths = [
        "/System/Library/Fonts/SFMono-Regular.otf",
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/Monaco.ttf",
        "/Library/Fonts/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    for fp in font_paths:
        try:
            return ImageFont.truetype(fp, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()

def get_bold_font(size=14):
    font_paths = [
        "/System/Library/Fonts/SFMono-Bold.otf",
        "/System/Library/Fonts/Menlo.ttc",
    ]
    for fp in font_paths:
        try:
            return ImageFont.truetype(fp, size)
        except (OSError, IOError):
            continue
    return get_font(size)

def run_curl(cmd):
    """Run a curl command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"

def create_screenshot(title, finding_id, severity, target, curl_cmd, curl_output, filename, annotation=""):
    """Create a terminal-style screenshot image."""
    font = get_font(13)
    bold_font = get_bold_font(14)
    small_font = get_font(11)

    lines = []
    lines.append(("header", f"  PENETRATION TEST — PROOF OF CONCEPT"))
    lines.append(("blank", ""))
    lines.append(("label", f"  Finding:  {finding_id} — {title}"))
    lines.append(("label", f"  Target:   {target}"))
    lines.append(("severity", f"  Severity: {severity}"))
    lines.append(("blank", ""))
    lines.append(("separator", "─" * 90))
    lines.append(("blank", ""))
    lines.append(("prompt", f"  $ {curl_cmd}"))
    lines.append(("blank", ""))

    for line in curl_output.split('\n'):
        if len(line) > 100:
            wrapped = textwrap.wrap(line, width=100)
            for w in wrapped:
                lines.append(("output", f"  {w}"))
        else:
            lines.append(("output", f"  {line}"))

    if annotation:
        lines.append(("blank", ""))
        lines.append(("separator", "─" * 90))
        lines.append(("annotation", f"  ⚠ {annotation}"))

    lines.append(("blank", ""))
    lines.append(("separator", "─" * 90))
    lines.append(("footer", f"  VAPT Framework PoC Evidence"))

    line_height = 20
    padding = 20
    header_height = 40
    width = 950
    height = header_height + padding * 2 + len(lines) * line_height + 20

    img = Image.new('RGB', (width, height), BG_COLOR)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, width, header_height], fill=HEADER_BG)
    draw.ellipse([12, 12, 24, 24], fill=(255, 95, 87))
    draw.ellipse([32, 12, 44, 24], fill=(254, 188, 46))
    draw.ellipse([52, 12, 64, 24], fill=(40, 201, 64))
    draw.text((80, 10), f"Terminal — {finding_id} PoC — {target}", fill=TEXT_COLOR, font=bold_font)

    y = header_height + padding
    for line_type, text in lines:
        if line_type == "header":
            draw.text((10, y), text, fill=GREEN, font=bold_font)
        elif line_type == "label":
            draw.text((10, y), text, fill=CYAN, font=font)
        elif line_type == "severity":
            sev_color = RED if "Medium" in text or "High" in text or "Critical" in text else YELLOW
            draw.text((10, y), text, fill=sev_color, font=font)
        elif line_type == "prompt":
            draw.text((10, y), text, fill=GREEN, font=font)
        elif line_type == "output":
            draw.text((10, y), text, fill=TEXT_COLOR, font=font)
        elif line_type == "separator":
            draw.text((10, y), text, fill=(80, 80, 80), font=font)
        elif line_type == "annotation":
            draw.text((10, y), text, fill=RED, font=bold_font)
        elif line_type == "footer":
            draw.text((10, y), text, fill=(120, 120, 120), font=small_font)
        elif line_type == "blank":
            pass
        y += line_height

    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    img.save(filepath, "PNG")
    print(f"  Saved: {filepath}")
    return filepath


# ── Add your findings below ──────────────────────────────────────
# Example:
#
# output = run_curl('curl -s "https://api.example.com/swagger/docs/v1" | python3 -m json.tool | head -30')
# create_screenshot(
#     "Swagger API Documentation Publicly Exposed",
#     "F-001", "Medium (CVSS 5.3)", "api.example.com",
#     'curl -s "https://api.example.com/swagger/docs/v1"',
#     output, "F-001_swagger_exposed.png",
#     "FINDING: Full API spec exposed without authentication"
# )

print("[INFO] No findings configured. Add curl commands and create_screenshot() calls above.")
