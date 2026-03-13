#!/usr/bin/env python3
"""Generate terminal-style PoC evidence screenshots from HTTP log files.

This script reads HTTP evidence logs from evidence/http_logs/ and renders
terminal-style screenshot images for each finding.

Usage:
    python3 generate_screenshots.py
"""

import os
import textwrap
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTTP_LOGS_DIR = os.path.join(BASE_DIR, "evidence", "http_logs")
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "evidence", "screenshots")

# Finding metadata — populated during engagement
# Example:
# FINDINGS = {
#     "F-001": {
#         "title": "Swagger API Documentation Publicly Exposed",
#         "target": "api.example.com",
#         "severity": "MEDIUM",
#     },
# }
FINDINGS = {}

# Colors
BG_COLOR = (30, 30, 30)
TITLE_BG = (40, 40, 60)
WHITE = (220, 220, 220)
GREEN = (80, 220, 100)
YELLOW = (255, 220, 80)
RED = (255, 100, 100)
CYAN = (100, 200, 255)
DIM = (130, 130, 130)
BORDER_COLOR = (60, 60, 80)

# Image settings
IMG_WIDTH = 1200
PADDING_X = 30
PADDING_Y = 20
LINE_HEIGHT = 18
MAX_CHARS_PER_LINE = 120
MAX_LINES = 45


def get_font(size=14):
    """Try to load a monospace font, fall back to default."""
    font_paths = [
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFMono-Regular.otf",
        "/System/Library/Fonts/Monaco.ttf",
        "/Library/Fonts/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    for fp in font_paths:
        if os.path.exists(fp):
            try:
                return ImageFont.truetype(fp, size)
            except Exception:
                continue
    return ImageFont.load_default()


def extract_key_lines(content, finding_id):
    """Extract the most important lines from an HTTP log, max ~40 lines."""
    lines = content.split("\n")
    result = []
    skip_patterns = [
        "% Total", "Dload", "bytes data", "CAfile", "CApath",
        "TLS handshake", "(304)", "ALPN: curl",
    ]

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if result and not result[-1].strip():
                continue
            result.append("")
            continue
        if any(p in stripped for p in skip_patterns):
            continue
        if stripped.startswith("0 ") and len(stripped.split()) > 5:
            continue
        if stripped.startswith("100 ") and len(stripped.split()) > 5:
            continue
        if len(stripped) > 300 and ("<" in stripped or "require(" in stripped):
            continue

        result.append(line[:MAX_CHARS_PER_LINE * 2])
        if len(result) >= MAX_LINES:
            break

    return result[:MAX_LINES]


def classify_line(line):
    """Determine the color for a line based on its content."""
    stripped = line.strip()

    if stripped.startswith("## ") or stripped.startswith("=== ") or stripped.startswith("--- "):
        return GREEN
    if stripped.startswith("# ") or stripped.startswith("Timestamp:") or stripped.startswith("Target:"):
        return CYAN
    if stripped.startswith("GET ") or stripped.startswith("POST ") or stripped.startswith("> "):
        return CYAN
    if stripped.startswith("< HTTP/") or stripped.startswith("HTTP/"):
        if " 200" in stripped or " 301" in stripped or " 302" in stripped:
            return GREEN
        elif " 4" in stripped or " 5" in stripped:
            return RED
        return YELLOW
    if "[MISSING]" in stripped or "VULNERABLE" in stripped:
        return RED
    if "[PRESENT]" in stripped:
        return GREEN
    if stripped.startswith("* "):
        return DIM

    return WHITE


def render_screenshot(finding_id, info, lines):
    """Render lines onto a terminal-style image."""
    font = get_font(14)
    title_font = get_font(16)
    small_font = get_font(12)

    header_height = 70
    content_height = len(lines) * LINE_HEIGHT + PADDING_Y * 2
    footer_height = 35
    total_height = header_height + content_height + footer_height

    img = Image.new("RGB", (IMG_WIDTH, total_height), BG_COLOR)
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (IMG_WIDTH, header_height)], fill=TITLE_BG)
    draw.rectangle([(0, header_height - 1), (IMG_WIDTH, header_height)], fill=BORDER_COLOR)

    for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([(15 + i * 25, 12), (27 + i * 25, 24)], fill=color)

    severity_colors = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}
    sev_color = severity_colors.get(info["severity"], WHITE)

    title_text = f"  PoC Evidence  |  {finding_id}  |  {info['title']}"
    draw.text((90, 10), title_text, fill=WHITE, font=title_font)

    meta_text = f"  Target: {info['target']}  |  Severity: {info['severity']}  |  Mode: Terminal (curl)"
    draw.text((90, 38), meta_text, fill=sev_color, font=small_font)

    y = header_height + PADDING_Y
    for line in lines:
        color = classify_line(line)
        display_line = line[:MAX_CHARS_PER_LINE]
        if len(line) > MAX_CHARS_PER_LINE:
            display_line += "..."
        draw.text((PADDING_X, y), display_line, fill=color, font=font)
        y += LINE_HEIGHT

    footer_y = total_height - footer_height
    draw.rectangle([(0, footer_y), (IMG_WIDTH, total_height)], fill=TITLE_BG)
    draw.rectangle([(0, footer_y), (IMG_WIDTH, footer_y + 1)], fill=BORDER_COLOR)
    footer_text = f"  VAPT Framework  |  {finding_id} PoC Evidence  |  Penetration Test"
    draw.text((PADDING_X, footer_y + 10), footer_text, fill=DIM, font=small_font)

    return img


def main():
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

    if not FINDINGS:
        print("[INFO] No findings defined in FINDINGS dict. Add finding metadata to generate screenshots.")
        return

    for finding_id, info in FINDINGS.items():
        log_file = os.path.join(HTTP_LOGS_DIR, f"{finding_id}_attempt1_http.txt")
        if not os.path.exists(log_file):
            print(f"[SKIP] {finding_id}: log file not found at {log_file}")
            continue

        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        lines = extract_key_lines(content, finding_id)
        img = render_screenshot(finding_id, info, lines)

        output_path = os.path.join(SCREENSHOTS_DIR, f"{finding_id}_POC_evidence.png")
        img.save(output_path, "PNG")
        print(f"[OK] {finding_id}: saved {output_path} ({img.width}x{img.height})")

    print("\nDone. All screenshots generated.")


if __name__ == "__main__":
    main()
