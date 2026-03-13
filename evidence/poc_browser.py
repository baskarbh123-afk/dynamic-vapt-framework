#!/usr/bin/env python3
"""
Browser-Style POC Screenshot Generator for Penetration Test Findings.
Generates realistic browser-based screenshots instead of terminal-style.

Usage:
  python3 poc_browser.py                    # Generate all findings
  python3 poc_browser.py --finding F-008    # Generate specific finding
  python3 poc_browser.py --list             # List all findings
"""

import subprocess
import textwrap
import os
import sys
import json
import re
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont

# ── Configuration ──────────────────────────────────────────────
TESTER = ""                # e.g., "John Doe"
ENGAGEMENT = ""            # e.g., "Acme Corp Penetration Test"

EVIDENCE_DIR = os.path.dirname(os.path.abspath(__file__))
SCREENSHOTS_DIR = os.path.join(EVIDENCE_DIR, "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# ── Browser Chrome Colors ─────────────────────────────────────
CHROME = {
    "toolbar_bg": (242, 242, 242),
    "toolbar_border": (218, 218, 218),
    "tab_bg": (255, 255, 255),
    "tab_inactive": (232, 232, 232),
    "tab_text": (60, 60, 60),
    "tab_text_inactive": (140, 140, 140),
    "url_bar_bg": (255, 255, 255),
    "url_bar_border": (200, 200, 200),
    "url_text": (60, 60, 60),
    "url_protocol": (30, 130, 60),
    "close_red": (255, 95, 87),
    "minimize_yellow": (254, 188, 46),
    "maximize_green": (40, 201, 64),
    "lock_green": (30, 130, 60),
}

# ── Page Content Colors ───────────────────────────────────────
PAGE = {
    "bg": (255, 255, 255),
    "text": (36, 41, 47),
    "heading": (36, 41, 47),
    "subheading": (87, 96, 106),
    "link": (9, 105, 218),
    "code_bg": (246, 248, 250),
    "code_border": (216, 222, 228),
    "code_text": (36, 41, 47),
    "json_key": (0, 92, 197),
    "json_string": (3, 47, 98),
    "json_value": (227, 98, 9),
    "json_bracket": (36, 41, 47),
    "xml_tag": (0, 92, 197),
    "xml_attr": (111, 66, 193),
    "xml_value": (3, 47, 98),
    "badge_red_bg": (255, 235, 233),
    "badge_red_text": (207, 34, 46),
    "badge_yellow_bg": (255, 248, 197),
    "badge_yellow_text": (154, 103, 0),
    "badge_green_bg": (218, 251, 225),
    "badge_green_text": (17, 109, 55),
    "badge_blue_bg": (221, 244, 255),
    "badge_blue_text": (9, 105, 218),
    "separator": (216, 222, 228),
    "finding_bg": (255, 251, 235),
    "finding_border": (212, 167, 44),
    "highlight_bg": (255, 245, 196),
    "error_bg": (255, 235, 233),
    "error_border": (255, 129, 130),
}


def get_font(size=14):
    paths = [
        "/System/Library/Fonts/SFMono-Regular.otf",
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/Monaco.ttf",
        "/Library/Fonts/Courier New.ttf",
    ]
    for fp in paths:
        try:
            return ImageFont.truetype(fp, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()


def get_sans_font(size=14):
    paths = [
        "/System/Library/Fonts/SFNSText.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/SFNS.ttf",
        "/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/SFCompact.ttf",
    ]
    for fp in paths:
        try:
            return ImageFont.truetype(fp, size)
        except (OSError, IOError):
            continue
    return get_font(size)


def get_bold_font(size=14):
    paths = [
        "/System/Library/Fonts/SFNSTextBold.ttf",
        "/System/Library/Fonts/SFMono-Bold.otf",
        "/System/Library/Fonts/Menlo.ttc",
    ]
    for fp in paths:
        try:
            return ImageFont.truetype(fp, size)
        except (OSError, IOError):
            continue
    return get_sans_font(size)


def run_curl(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        return output.strip()
    except subprocess.TimeoutExpired:
        return "[Request timed out]"
    except Exception as e:
        return f"[Error: {e}]"


def draw_browser_chrome(draw, width, url, tab_title, y_start=0):
    """Draw realistic macOS browser chrome (toolbar + tab + address bar)."""
    toolbar_h = 38
    tab_h = 32
    urlbar_h = 30
    total_h = toolbar_h + tab_h + urlbar_h + 4

    # Main toolbar background
    draw.rectangle([0, y_start, width, y_start + total_h], fill=CHROME["toolbar_bg"])
    draw.line([0, y_start + total_h, width, y_start + total_h], fill=CHROME["toolbar_border"], width=1)

    # Window control buttons
    btn_y = y_start + 14
    draw.ellipse([14, btn_y, 26, btn_y + 12], fill=CHROME["close_red"])
    draw.ellipse([34, btn_y, 46, btn_y + 12], fill=CHROME["minimize_yellow"])
    draw.ellipse([54, btn_y, 66, btn_y + 12], fill=CHROME["maximize_green"])

    # Tab bar
    tab_y = y_start + toolbar_h
    # Active tab
    tab_font = get_sans_font(12)
    tab_title_short = tab_title[:50] + "..." if len(tab_title) > 50 else tab_title

    # Active tab shape (rounded top)
    draw.rounded_rectangle([8, tab_y, 280, tab_y + tab_h], radius=8, fill=CHROME["tab_bg"])
    draw.rectangle([8, tab_y + 16, 280, tab_y + tab_h], fill=CHROME["tab_bg"])

    # Tab favicon placeholder (small colored square)
    draw.rounded_rectangle([18, tab_y + 9, 30, tab_y + 21], radius=2, fill=(9, 105, 218))

    # Tab title
    draw.text((36, tab_y + 8), tab_title_short, fill=CHROME["tab_text"], font=tab_font)

    # Tab close X
    x_font = get_sans_font(11)
    draw.text((262, tab_y + 8), "×", fill=CHROME["tab_text_inactive"], font=x_font)

    # Inactive tab
    draw.rounded_rectangle([284, tab_y, 320, tab_y + tab_h], radius=8, fill=CHROME["tab_inactive"])
    draw.text((296, tab_y + 8), "+", fill=CHROME["tab_text_inactive"], font=tab_font)

    # URL bar
    url_y = tab_y + tab_h + 2
    bar_x = 80
    bar_w = width - 100
    draw.rounded_rectangle([bar_x, url_y, bar_x + bar_w, url_y + urlbar_h], radius=15, fill=CHROME["url_bar_bg"], outline=CHROME["url_bar_border"])

    # Navigation buttons (back, forward, reload)
    nav_font = get_sans_font(16)
    draw.text((16, url_y + 4), "‹", fill=CHROME["tab_text_inactive"], font=nav_font)
    draw.text((34, url_y + 4), "›", fill=CHROME["tab_text_inactive"], font=nav_font)
    draw.text((54, url_y + 5), "↻", fill=CHROME["tab_text"], font=get_sans_font(14))

    # Lock icon + URL
    url_font = get_sans_font(12)
    lock_x = bar_x + 12
    draw.text((lock_x, url_y + 8), "🔒", fill=CHROME["lock_green"], font=get_sans_font(11))

    # Split URL into protocol + domain + path
    url_display = url
    if url.startswith("https://"):
        draw.text((lock_x + 18, url_y + 9), url[8:], fill=CHROME["url_text"], font=url_font)
    else:
        draw.text((lock_x + 18, url_y + 9), url, fill=CHROME["url_text"], font=url_font)

    return total_h + 1


def draw_severity_badge(draw, x, y, severity, font):
    """Draw a colored severity badge."""
    sev = severity.upper()
    if "CRITICAL" in sev:
        bg, text = PAGE["badge_red_bg"], PAGE["badge_red_text"]
    elif "HIGH" in sev:
        bg, text = (255, 240, 235), (190, 60, 30)
    elif "MEDIUM" in sev:
        bg, text = PAGE["badge_yellow_bg"], PAGE["badge_yellow_text"]
    else:
        bg, text = PAGE["badge_blue_bg"], PAGE["badge_blue_text"]

    bbox = font.getbbox(severity)
    w = bbox[2] - bbox[0] + 16
    h = bbox[3] - bbox[1] + 8
    draw.rounded_rectangle([x, y, x + w, y + h], radius=4, fill=bg)
    draw.text((x + 8, y + 3), severity, fill=text, font=font)
    return w


def colorize_json(draw, text, x, y, font, line_height, max_width):
    """Draw JSON with syntax highlighting."""
    lines = text.split("\n")
    for line in lines:
        if y > 2000:
            break
        cx = x
        remaining = line

        # Indent
        indent = len(line) - len(line.lstrip())
        if indent > 0:
            cx += indent * 7

        stripped = line.strip()

        if stripped in ("{", "}", "[", "]", "},", "],"):
            draw.text((cx, y), stripped, fill=PAGE["json_bracket"], font=font)
        elif ":" in stripped:
            parts = stripped.split(":", 1)
            key_part = parts[0].strip()
            val_part = parts[1].strip() if len(parts) > 1 else ""
            draw.text((cx, y), key_part, fill=PAGE["json_key"], font=font)
            key_w = font.getbbox(key_part)[2]
            draw.text((cx + key_w, y), ": ", fill=PAGE["json_bracket"], font=font)
            colon_w = font.getbbox(": ")[2]
            if val_part.startswith('"'):
                draw.text((cx + key_w + colon_w, y), val_part, fill=PAGE["json_string"], font=font)
            elif val_part in ("true,", "false,", "true", "false", "null,", "null"):
                draw.text((cx + key_w + colon_w, y), val_part, fill=PAGE["json_value"], font=font)
            else:
                draw.text((cx + key_w + colon_w, y), val_part, fill=PAGE["json_value"], font=font)
        else:
            draw.text((cx, y), stripped, fill=PAGE["code_text"], font=font)

        y += line_height
    return y


def colorize_xml(draw, text, x, y, font, line_height):
    """Draw XML with syntax highlighting."""
    lines = text.split("\n")
    for line in lines:
        if y > 2000:
            break
        cx = x
        indent = len(line) - len(line.lstrip())
        cx += indent * 7
        stripped = line.strip()

        # Simple XML colorization
        if stripped.startswith("<?"):
            draw.text((cx, y), stripped, fill=PAGE["xml_attr"], font=font)
        elif stripped.startswith("<"):
            # Color the tag name
            draw.text((cx, y), stripped, fill=PAGE["xml_tag"], font=font)
        else:
            draw.text((cx, y), stripped, fill=PAGE["code_text"], font=font)
        y += line_height
    return y


def create_browser_screenshot(finding_id, poc_num, poc_type, title, url, severity,
                               target, curl_cmd, curl_output, annotation, filename):
    """Create a browser-style POC screenshot."""
    mono_font = get_font(12)
    sans_font = get_sans_font(13)
    sans_bold = get_bold_font(14)
    heading_font = get_bold_font(16)
    small_font = get_sans_font(11)
    code_font = get_font(11)
    badge_font = get_sans_font(11)

    width = 1100
    line_height = 18
    padding = 24

    # Pre-calculate content height
    output_lines = curl_output.split("\n") if curl_output else []
    content_lines = 0
    for line in output_lines:
        if len(line) > 120:
            content_lines += (len(line) // 120) + 1
        else:
            content_lines += 1

    # Height: chrome + finding header + command box + output box + annotation + footer
    chrome_height = 105
    header_height = 120
    cmd_height = 60
    output_height = min(content_lines * line_height + 30, 800)
    annotation_height = 70 if annotation else 0
    footer_height = 50
    total_height = chrome_height + header_height + cmd_height + output_height + annotation_height + footer_height + 60

    img = Image.new("RGB", (width, total_height), PAGE["bg"])
    draw = ImageDraw.Draw(img)

    # ── Browser Chrome ──
    tab_title = f"{finding_id} POC-{poc_num} — {target}"
    chrome_h = draw_browser_chrome(draw, width, url, tab_title)
    y = chrome_h + 12

    # ── Page Content Area ──

    # Finding header bar
    header_y = y
    draw.rectangle([0, header_y, width, header_y + 4], fill=(9, 105, 218))
    y += 12

    # POC badge + Finding ID
    poc_labels = {"discovery": "Discovery", "exploitation": "Exploitation", "impact": "Impact Assessment"}
    poc_label = poc_labels.get(poc_type, poc_type.title())

    draw.text((padding, y), f"{finding_id}", fill=PAGE["heading"], font=heading_font)
    id_w = heading_font.getbbox(finding_id)[2]
    draw.text((padding + id_w + 8, y + 2), f"POC-{poc_num}: {poc_label}", fill=PAGE["subheading"], font=sans_font)

    # Severity badge on the right
    sev_text = severity
    badge_w = draw_severity_badge(draw, width - 160, y, sev_text, badge_font)
    y += 28

    # Title
    draw.text((padding, y), title, fill=PAGE["heading"], font=sans_bold)
    y += 24

    # Metadata line
    meta_text = f"Target: {target}  |  Date: {datetime.now().strftime('%Y-%m-%d')}  |  Tester: {TESTER}"
    draw.text((padding, y), meta_text, fill=PAGE["subheading"], font=small_font)
    y += 20

    # Separator
    draw.line([padding, y, width - padding, y], fill=PAGE["separator"], width=1)
    y += 16

    # ── Request Box ──
    draw.text((padding, y), "Request", fill=PAGE["heading"], font=sans_bold)
    y += 22

    # Command in a styled code box
    cmd_box_y = y
    cmd_display = curl_cmd
    if len(cmd_display) > 130:
        cmd_display = cmd_display[:127] + "..."

    cmd_lines = textwrap.wrap(cmd_display, width=130)
    cmd_box_h = len(cmd_lines) * line_height + 20
    draw.rounded_rectangle([padding, cmd_box_y, width - padding, cmd_box_y + cmd_box_h],
                           radius=6, fill=PAGE["code_bg"], outline=PAGE["code_border"])

    # Dollar prompt
    cmd_y = cmd_box_y + 10
    for cl in cmd_lines:
        if cl == cmd_lines[0]:
            draw.text((padding + 12, cmd_y), "$ ", fill=(110, 110, 110), font=code_font)
            draw.text((padding + 28, cmd_y), cl, fill=PAGE["code_text"], font=code_font)
        else:
            draw.text((padding + 28, cmd_y), cl, fill=PAGE["code_text"], font=code_font)
        cmd_y += line_height
    y = cmd_box_y + cmd_box_h + 16

    # ── Response Box ──
    draw.text((padding, y), "Response", fill=PAGE["heading"], font=sans_bold)

    # Status indicator
    status_text = "200 OK"
    if "403" in curl_output[:100]:
        status_text = "403 Forbidden"
    elif "404" in curl_output[:100]:
        status_text = "404 Not Found"
    elif "302" in curl_output[:100]:
        status_text = "302 Redirect"
    elif "401" in curl_output[:100]:
        status_text = "401 Unauthorized"

    resp_label_w = sans_bold.getbbox("Response")[2]
    draw.text((padding + resp_label_w + 12, y + 2), status_text, fill=PAGE["badge_green_text"], font=small_font)
    y += 22

    # Response content box
    resp_box_y = y
    wrapped_output = []
    for line in output_lines:
        if len(line) > 120:
            wrapped_output.extend(textwrap.wrap(line, width=120))
        else:
            wrapped_output.append(line)

    # Limit output lines
    if len(wrapped_output) > 40:
        wrapped_output = wrapped_output[:38]
        wrapped_output.append("  ...")
        wrapped_output.append(f"  [{len(output_lines) - 38} more lines]")

    resp_box_h = len(wrapped_output) * line_height + 24
    draw.rounded_rectangle([padding, resp_box_y, width - padding, resp_box_y + resp_box_h],
                           radius=6, fill=PAGE["code_bg"], outline=PAGE["code_border"])

    # Detect content type for syntax highlighting
    output_text = curl_output.strip()
    is_json = output_text.startswith("{") or output_text.startswith("[")
    is_xml = output_text.startswith("<?xml") or output_text.startswith("<method")

    ry = resp_box_y + 12
    if is_json:
        ry = colorize_json(draw, "\n".join(wrapped_output), padding + 14, ry, code_font, line_height, width - padding * 2 - 28)
    elif is_xml:
        ry = colorize_xml(draw, "\n".join(wrapped_output), padding + 14, ry, code_font, line_height)
    else:
        for rline in wrapped_output:
            draw.text((padding + 14, ry), rline, fill=PAGE["code_text"], font=code_font)
            ry += line_height

    y = resp_box_y + resp_box_h + 16

    # ── Annotation / Finding Box ──
    if annotation:
        ann_box_y = y
        ann_lines = textwrap.wrap(annotation, width=110)
        ann_box_h = len(ann_lines) * 20 + 20
        draw.rounded_rectangle([padding, ann_box_y, width - padding, ann_box_y + ann_box_h],
                               radius=6, fill=PAGE["finding_bg"], outline=PAGE["finding_border"])

        # Warning icon + text
        ann_y = ann_box_y + 10
        draw.text((padding + 12, ann_y), "⚠", fill=PAGE["badge_yellow_text"], font=sans_bold)
        for i, al in enumerate(ann_lines):
            x_off = padding + 32 if i == 0 else padding + 12
            draw.text((x_off, ann_y), al, fill=PAGE["badge_yellow_text"], font=sans_font)
            ann_y += 20
        y = ann_box_y + ann_box_h + 12

    # ── Footer ──
    draw.line([padding, y, width - padding, y], fill=PAGE["separator"], width=1)
    y += 8
    footer_text = f"Evidence: {filename}  |  {ENGAGEMENT}  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    draw.text((padding, y), footer_text, fill=(160, 160, 160), font=small_font)

    # Crop to actual content
    final_height = y + 30
    img = img.crop((0, 0, width, min(final_height, total_height)))

    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    img.save(filepath, "PNG", quality=95)
    print(f"  ✓ {filepath}")
    return filepath


# ── Findings Definition ─────────────────────────────────────────

FINDINGS = {
    # Add your findings here. Example:
    #
    # "F-001": {
    #     "title": "WordPress REST API User Enumeration",
    #     "severity": "MEDIUM",
    #     "target": "blog.example.com",
    #     "pocs": [
    #         {
    #             "type": "discovery",
    #             "url": "https://blog.example.com/wp-json/wp/v2/users",
    #             "cmd": 'curl -s "https://blog.example.com/wp-json/wp/v2/users" | python3 -m json.tool',
    #             "annotation": "FINDING: User accounts enumerated without authentication",
    #         },
    #         {
    #             "type": "exploitation",
    #             "url": "https://blog.example.com/wp-json/wp/v2/users",
    #             "cmd": 'curl -s "https://blog.example.com/wp-json/wp/v2/users?per_page=100"',
    #             "annotation": "FINDING: Full user list with names and slugs exposed",
    #         },
    #         {
    #             "type": "impact",
    #             "url": "https://blog.example.com/wp-cron.php",
    #             "cmd": 'curl -sI "https://blog.example.com/wp-cron.php"',
    #             "annotation": "IMPACT: wp-cron.php publicly accessible",
    #         },
    #     ],
    # },
}


def generate_finding(finding_id):
    """Generate all 3 POC screenshots for a finding."""
    if finding_id not in FINDINGS:
        print(f"[ERROR] Finding {finding_id} not found")
        return

    f = FINDINGS[finding_id]
    print(f"\n[{finding_id}] {f['title']}")

    for i, poc in enumerate(f["pocs"], 1):
        print(f"  POC-{i} ({poc['type']})...")

        # Run the curl command
        output = run_curl(poc["cmd"])

        # Truncate long output
        lines = output.split("\n")
        if len(lines) > 35:
            output = "\n".join(lines[:35]) + f"\n  ... [{len(lines) - 35} more lines]"

        filename = f"{finding_id}_POC-{i}_{poc['type']}.png"

        create_browser_screenshot(
            finding_id=finding_id,
            poc_num=i,
            poc_type=poc["type"],
            title=f["title"],
            url=poc["url"],
            severity=f["severity"],
            target=f["target"],
            curl_cmd=poc["cmd"],
            curl_output=output,
            annotation=poc["annotation"],
            filename=filename,
        )


def main():
    if "--list" in sys.argv:
        print(f"\nAvailable findings ({len(FINDINGS)}):\n")
        for fid, f in sorted(FINDINGS.items()):
            print(f"  {fid}  [{f['severity']}]  {f['title']}  ({f['target']})")
        print()
        return

    if "--finding" in sys.argv:
        idx = sys.argv.index("--finding")
        if idx + 1 < len(sys.argv):
            fid = sys.argv[idx + 1].upper()
            generate_finding(fid)
            return

    # Generate all
    print(f"\n{'='*60}")
    print(f"  Browser-Style POC Screenshot Generator")
    print(f"  Engagement: {ENGAGEMENT}")
    print(f"  Findings: {len(FINDINGS)}")
    print(f"{'='*60}")

    for fid in sorted(FINDINGS.keys()):
        generate_finding(fid)

    print(f"\n✅ All screenshots saved to: {SCREENSHOTS_DIR}\n")


if __name__ == "__main__":
    main()
