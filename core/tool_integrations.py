#!/usr/bin/env python3
"""
Tool Integrations — Wrapper Layer for Security Testing Tools
=============================================================
Provides safe, rate-limited wrappers around allowed testing tools.
All tool invocations are logged and respect engagement constraints.

Supported tools:
  curl, nuclei, ffuf, dirsearch, subfinder, subjack, sslyze,
  sqlmap (safe mode), jwt_tool, interactsh, nmap (if available)
"""

import subprocess
import shlex
import shutil
import logging
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tool_integrations")

BASE_DIR = Path(__file__).parent.parent.resolve()
HTTP_LOG_DIR = BASE_DIR / "evidence" / "http-logs"
HTTP_LOG_DIR.mkdir(parents=True, exist_ok=True)


class ToolResult:
    """Standardized result from a tool execution."""

    def __init__(self, tool: str, command: str, returncode: int,
                 stdout: str, stderr: str, duration: float):
        self.tool = tool
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration
        self.timestamp = datetime.now().isoformat()
        self.success = returncode == 0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "command": self.command,
            "returncode": self.returncode,
            "stdout_lines": len(self.stdout.splitlines()),
            "stderr_lines": len(self.stderr.splitlines()),
            "duration_seconds": round(self.duration, 2),
            "success": self.success,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        status = "OK" if self.success else f"FAIL(rc={self.returncode})"
        return f"<ToolResult {self.tool} {status} {self.duration:.1f}s>"


class ToolIntegrations:
    """Manages security tool execution with safety controls."""

    # Tools that are allowed per engagement rules
    ALLOWED_TOOLS = {
        "curl", "nuclei", "ffuf", "dirsearch", "subfinder", "subjack",
        "sslyze", "sqlmap", "jwt_tool", "interactsh-client", "nmap",
        "httpx", "katana", "gau", "waybackurls", "python3",
    }

    def __init__(self, config: dict):
        self.config = config
        self.constraints = config.get("scope", {}).get("constraints", {})
        self.tool_settings = config.get("preferences", {}).get("tool_settings", {})
        self.max_rps = self.constraints.get("max_requests_per_second", 10)
        self._last_request_time = 0.0
        self._available_tools: Dict[str, str] = {}
        self._discover_tools()

    def _discover_tools(self):
        """Check which allowed tools are installed."""
        for tool in self.ALLOWED_TOOLS:
            path = shutil.which(tool)
            if path:
                self._available_tools[tool] = path
                logger.debug(f"[TOOLS] Found: {tool} -> {path}")
            else:
                logger.debug(f"[TOOLS] Not found: {tool}")
        logger.info(f"[TOOLS] Available: {len(self._available_tools)}/{len(self.ALLOWED_TOOLS)} tools")

    def available(self) -> Dict[str, str]:
        """Return dict of available tool names to their paths."""
        return dict(self._available_tools)

    def is_available(self, tool: str) -> bool:
        return tool in self._available_tools

    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        if self.max_rps <= 0:
            return
        min_interval = 1.0 / self.max_rps
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    def _run(self, tool: str, args: List[str], timeout: int = 120,
             log_output: bool = True) -> ToolResult:
        """Execute a tool with safety checks."""
        if tool not in self.ALLOWED_TOOLS:
            raise ValueError(f"Tool '{tool}' is not in the allowed tools list")

        if tool not in self._available_tools:
            raise RuntimeError(f"Tool '{tool}' is not installed on this system")

        # Safety: block dangerous flags
        args_str = " ".join(args)
        if tool == "sqlmap":
            if "--dump" in args_str:
                raise ValueError("sqlmap --dump is forbidden by engagement rules")
            if "--os-shell" in args_str or "--os-cmd" in args_str:
                raise ValueError("sqlmap OS command execution is forbidden")

        self._rate_limit()

        full_cmd = [self._available_tools[tool]] + args
        cmd_str = " ".join(shlex.quote(c) for c in full_cmd)
        logger.info(f"[TOOLS] Running: {cmd_str}")

        start = time.time()
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(BASE_DIR),
            )
            duration = time.time() - start

            tr = ToolResult(tool, cmd_str, result.returncode,
                            result.stdout, result.stderr, duration)

            if log_output:
                self._log_execution(tr)

            return tr

        except subprocess.TimeoutExpired:
            duration = time.time() - start
            logger.warning(f"[TOOLS] Timeout after {timeout}s: {tool}")
            return ToolResult(tool, cmd_str, -1, "", f"Timeout after {timeout}s", duration)

        except Exception as e:
            duration = time.time() - start
            logger.error(f"[TOOLS] Error running {tool}: {e}")
            return ToolResult(tool, cmd_str, -1, "", str(e), duration)

    def _log_execution(self, result: ToolResult):
        """Log tool execution to evidence/http-logs."""
        log_file = HTTP_LOG_DIR / f"tool_log_{datetime.now().strftime('%Y%m%d')}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(result.to_dict()) + "\n")

    # ------------------------------------------------------------------
    # Convenience wrappers for common tools
    # ------------------------------------------------------------------
    def curl(self, url: str, method: str = "GET", headers: Optional[dict] = None,
             data: Optional[str] = None, timeout: int = 30, extra_args: Optional[List[str]] = None) -> ToolResult:
        """Execute a curl request."""
        args = ["-s", "-S", "-o", "-", "-w", "\n%{http_code}", "-X", method]
        if headers:
            for k, v in headers.items():
                args += ["-H", f"{k}: {v}"]
        if data:
            args += ["-d", data]
        args += ["-m", str(timeout)]
        if extra_args:
            args += extra_args
        args.append(url)
        return self._run("curl", args, timeout=timeout + 10)

    def nuclei(self, target: str, templates: Optional[str] = None,
               severity: Optional[str] = None, extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run nuclei scanner against a target."""
        rate = self.tool_settings.get("nuclei_rate_limit", 5)
        args = ["-u", target, "-rl", str(rate), "-silent", "-json"]
        if templates:
            args += ["-t", templates]
        if severity:
            args += ["-severity", severity]
        if extra_args:
            args += extra_args
        return self._run("nuclei", args, timeout=300)

    def ffuf(self, url: str, wordlist: str, extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run ffuf for directory/parameter fuzzing."""
        rate = self.tool_settings.get("ffuf_rate", 10)
        args = ["-u", url, "-w", wordlist, "-rate", str(rate), "-o", "-", "-of", "json", "-s"]
        if extra_args:
            args += extra_args
        return self._run("ffuf", args, timeout=300)

    def subfinder(self, domain: str, extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run subfinder for subdomain enumeration."""
        args = ["-d", domain, "-silent"]
        if extra_args:
            args += extra_args
        return self._run("subfinder", args, timeout=120)

    def sslyze(self, target: str, extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run sslyze for SSL/TLS analysis."""
        args = [target, "--json_out=-"]
        if extra_args:
            args += extra_args
        return self._run("sslyze", args, timeout=120)

    def sqlmap(self, url: str, extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run sqlmap in safe mode only."""
        level = self.tool_settings.get("sqlmap_level", 2)
        risk = self.tool_settings.get("sqlmap_risk", 1)
        technique = self.tool_settings.get("sqlmap_technique", "BT")
        args = [
            "-u", url,
            "--level", str(level),
            "--risk", str(risk),
            "--technique", technique,
            "--batch",
            "--output-dir", str(BASE_DIR / "evidence" / "sqlmap-output"),
        ]
        if extra_args:
            args += extra_args
        return self._run("sqlmap", args, timeout=300)

    def nmap(self, target: str, ports: str = "80,443,8080,8443",
             extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run nmap for service enumeration (non-intrusive)."""
        args = ["-sV", "-sC", "--top-ports", "100", "-T3", target]
        if extra_args:
            args += extra_args
        return self._run("nmap", args, timeout=300)

    def httpx(self, targets: List[str], extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run httpx for HTTP probing."""
        # httpx reads from stdin
        input_str = "\n".join(targets)
        args = ["-silent", "-json", "-status-code", "-title", "-tech-detect"]
        if extra_args:
            args += extra_args

        if "httpx" not in self._available_tools:
            raise RuntimeError("httpx is not installed")

        full_cmd = [self._available_tools["httpx"]] + args
        cmd_str = " ".join(shlex.quote(c) for c in full_cmd)
        self._rate_limit()

        start = time.time()
        result = subprocess.run(full_cmd, input=input_str, capture_output=True,
                                text=True, timeout=120)
        duration = time.time() - start
        tr = ToolResult("httpx", cmd_str, result.returncode,
                        result.stdout, result.stderr, duration)
        self._log_execution(tr)
        return tr

    def jwt_tool(self, token: str, extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run jwt_tool for JWT analysis."""
        args = [token]
        if extra_args:
            args += extra_args
        return self._run("jwt_tool", args, timeout=60)
