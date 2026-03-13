#!/usr/bin/env python3
"""
Enumeration Agent — Phase 4: Enumeration
==========================================
Scans discovered assets, discovers endpoints, maps API routes,
identifies authentication mechanisms, detects parameters,
and stores results into the endpoint database.
"""

import json
import re
import logging
from urllib.parse import urljoin, urlparse

from agents.base_agent import BaseAgent
from typing import Any, List

logger = logging.getLogger("agent.enumeration")


class EnumerationAgent(BaseAgent):
    name = "EnumerationAgent"
    description = "Endpoint discovery, API route mapping, auth mechanism identification, parameter detection"
    phase = "enumeration"

    def plan(self) -> List[dict]:
        """Build enumeration plan from discovered assets + config targets."""
        actions = []
        target = self.config.get("target", {})
        base_url = target.get("base_url", target.get("primary_domain", ""))

        # Collect all HTTP-accessible targets
        http_targets = set()
        if base_url:
            http_targets.add(base_url)

        for sd in target.get("subdomains", []):
            if isinstance(sd, dict) and sd.get("in_scope"):
                domain = sd["subdomain"]
                if not domain.startswith("http"):
                    http_targets.add(f"https://{domain}")
                else:
                    http_targets.add(domain)

        # Also pull from KB assets
        for asset in self.kb.get_assets("subdomain"):
            domain = asset.get("domain", "")
            if domain and not domain.startswith("*."):
                http_targets.add(f"https://{domain}")

        for url in sorted(http_targets):
            # 1. HTTP probe — check if alive, get response headers
            actions.append({
                "action": "http_probe",
                "target": url,
                "description": f"HTTP probe: {url}",
            })

            # 2. Common endpoint discovery
            actions.append({
                "action": "endpoint_discovery",
                "target": url,
                "description": f"Common endpoint brute-force: {url}",
            })

            # 3. API route discovery
            actions.append({
                "action": "api_discovery",
                "target": url,
                "description": f"API route discovery: {url}",
            })

            # 4. Auth mechanism detection
            actions.append({
                "action": "auth_detection",
                "target": url,
                "description": f"Auth mechanism detection: {url}",
            })

        return actions

    def execute(self, plan: List[dict]) -> List[dict]:
        results = []
        for action in plan:
            act = action["action"]
            target = action["target"]
            self._log(f"Executing: {action['description']}")

            if act == "http_probe":
                result = self._http_probe(target)
            elif act == "endpoint_discovery":
                result = self._endpoint_discovery(target)
            elif act == "api_discovery":
                result = self._api_discovery(target)
            elif act == "auth_detection":
                result = self._auth_detection(target)
            else:
                result = {"status": "skipped", "reason": f"Unknown action: {act}"}

            result["action"] = act
            result["target"] = target
            results.append(result)
        return results

    def _http_probe(self, url: str) -> dict:
        """Check if a target is alive and collect response metadata."""
        tr = self.tools.curl(url, extra_args=["-I", "-L", "--connect-timeout", "10"])
        if tr.success:
            lines = tr.stdout.strip().splitlines()
            # Extract status code from curl -w output
            status_code = lines[-1].strip() if lines else "unknown"
            headers = "\n".join(lines[:-1]) if len(lines) > 1 else ""

            self.kb.add_endpoint(url, method="HEAD", status_code=status_code,
                                 headers_summary=headers[:500], source="http_probe")
            return {"status": "ok", "http_status": status_code}
        return {"status": "error", "error": tr.stderr[:200]}

    def _endpoint_discovery(self, base_url: str) -> dict:
        """Discover common endpoints by probing known paths."""
        common_paths = [
            "/", "/login", "/register", "/api", "/api/v1", "/api/v2",
            "/health", "/healthz", "/status", "/version", "/info",
            "/docs", "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
            "/graphql", "/graphiql", "/admin", "/dashboard",
            "/.well-known/openid-configuration", "/.well-known/security.txt",
            "/robots.txt", "/sitemap.xml", "/.env", "/config",
            "/wp-admin", "/wp-login.php",  # CMS checks
            "/.git/HEAD", "/.svn/entries",  # Source control leak checks
        ]

        found = []
        for path in common_paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            tr = self.tools.curl(url, extra_args=["--connect-timeout", "5", "-L"])
            if tr.success:
                lines = tr.stdout.strip().splitlines()
                status = lines[-1].strip() if lines else "0"
                if status and status not in ("000", "0") and int(status) < 500:
                    found.append({"path": path, "status": status, "url": url})
                    self.kb.add_endpoint(url, method="GET", status_code=status,
                                         path=path, source="endpoint_discovery")

        return {"status": "ok", "endpoints_found": len(found), "data": found}

    def _api_discovery(self, base_url: str) -> dict:
        """Discover API routes from config + common patterns."""
        api_endpoints = self.config.get("scope", {}).get("in_scope", {}).get("api_endpoints", [])
        found = []

        for ep in api_endpoints:
            if isinstance(ep, dict) and ep.get("path"):
                method = ep.get("method", "GET")
                path = ep["path"]
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                tr = self.tools.curl(url, method=method,
                                     extra_args=["--connect-timeout", "5"])
                if tr.success:
                    lines = tr.stdout.strip().splitlines()
                    status = lines[-1].strip() if lines else "0"
                    found.append({"method": method, "path": path, "status": status})
                    self.kb.add_endpoint(url, method=method, status_code=status,
                                         path=path, auth=ep.get("auth", ""),
                                         source="api_config")

        # Check for OpenAPI/Swagger spec
        for spec_path in ["/openapi.json", "/swagger.json", "/api-docs"]:
            url = urljoin(base_url.rstrip("/") + "/", spec_path.lstrip("/"))
            tr = self.tools.curl(url, extra_args=["--connect-timeout", "5"])
            if tr.success:
                lines = tr.stdout.strip().splitlines()
                status = lines[-1].strip() if lines else "0"
                if status == "200":
                    body = "\n".join(lines[:-1])
                    found.append({"path": spec_path, "status": status, "type": "api_spec"})
                    self.kb.add_endpoint(url, method="GET", status_code=status,
                                         path=spec_path, source="api_spec_discovery",
                                         content_type="openapi")

        return {"status": "ok", "api_routes_found": len(found), "data": found}

    def _auth_detection(self, url: str) -> dict:
        """Detect authentication mechanisms from response headers."""
        tr = self.tools.curl(url, extra_args=["-I", "-L", "--connect-timeout", "5"])
        if not tr.success:
            return {"status": "error", "error": tr.stderr[:200]}

        headers = tr.stdout.lower()
        mechanisms = []

        # Check WWW-Authenticate header
        auth_match = re.search(r"www-authenticate:\s*(.+)", headers)
        if auth_match:
            mechanisms.append({"type": "www-authenticate", "value": auth_match.group(1).strip()})

        # Check for cookie-based auth
        if "set-cookie" in headers:
            cookies = re.findall(r"set-cookie:\s*([^;]+)", headers)
            for c in cookies:
                if any(k in c.lower() for k in ["session", "token", "auth", "jwt"]):
                    mechanisms.append({"type": "cookie", "name": c.split("=")[0].strip()})

        # Check for JWT in response
        if "authorization" in headers or "bearer" in headers:
            mechanisms.append({"type": "bearer_token", "note": "Bearer auth detected"})

        # Check for OAuth
        if "oauth" in headers or "openid" in headers:
            mechanisms.append({"type": "oauth", "note": "OAuth/OpenID detected"})

        # Check for CORS
        if "access-control-allow-origin" in headers:
            cors_match = re.search(r"access-control-allow-origin:\s*(.+)", headers)
            if cors_match:
                mechanisms.append({"type": "cors", "value": cors_match.group(1).strip()})

        if mechanisms:
            self.kb.add_endpoint(url, method="AUTH_CHECK",
                                 auth_mechanisms=mechanisms, source="auth_detection")

        return {"status": "ok", "mechanisms_found": len(mechanisms), "data": mechanisms}

    def report(self) -> dict:
        endpoints = self.kb.get_endpoints()
        return {
            "agent": self.name,
            "phase": self.phase,
            "state": self.state,
            "total_endpoints": len(endpoints),
            "actions_executed": len(self.results),
            "successful": sum(1 for r in self.results if r.get("status") == "ok"),
            "errors": [r for r in self.results if r.get("status") == "error"],
        }
