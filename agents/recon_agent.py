#!/usr/bin/env python3
"""
Recon Agent — Phase 3: Reconnaissance
=======================================
Discovers subdomains, analyzes DNS records, queries certificate
transparency logs, identifies technologies, and stores results
into the assets database.
"""

import json
import re
import logging
from typing import Any, Dict, List

from agents.base_agent import BaseAgent

logger = logging.getLogger("agent.recon")


class ReconAgent(BaseAgent):
    name = "ReconAgent"
    description = "Passive & active reconnaissance — subdomain discovery, DNS, CT logs, tech fingerprinting"
    phase = "recon"

    def plan(self) -> List[dict]:
        """Build recon action plan from config targets."""
        actions = []
        scope = self.config.get("scope", {}).get("in_scope", {})
        target = self.config.get("target", {})
        domains = [d["domain"] for d in scope.get("domains", []) if isinstance(d, dict) and d.get("domain")]

        # Extract root domains for subdomain enumeration
        root_domains = set()
        for d in domains:
            parts = d.replace("*.", "").split(".")
            if len(parts) >= 2:
                root_domains.add(".".join(parts[-2:]))

        # 1. Subdomain discovery for each root domain
        for rd in sorted(root_domains):
            actions.append({
                "action": "subdomain_enum",
                "target": rd,
                "description": f"Enumerate subdomains for {rd}",
                "tool": "subfinder",
            })

        # 2. DNS analysis for each in-scope domain
        for d in domains:
            if d.startswith("*."):
                continue
            actions.append({
                "action": "dns_analysis",
                "target": d,
                "description": f"DNS records for {d}",
                "tool": "curl",
            })

        # 3. Certificate transparency log query
        for rd in sorted(root_domains):
            actions.append({
                "action": "ct_logs",
                "target": rd,
                "description": f"CT log query for {rd}",
                "tool": "curl",
            })

        # 4. Technology fingerprinting for each HTTP target
        primary = target.get("primary_domain", "")
        subdomains = [s["subdomain"] for s in target.get("subdomains", [])
                      if isinstance(s, dict) and s.get("in_scope")]
        http_targets = []
        if primary:
            http_targets.append(primary)
        for sd in subdomains:
            if not sd.startswith("http"):
                http_targets.append(f"https://{sd}")
            else:
                http_targets.append(sd)

        for t in http_targets:
            actions.append({
                "action": "tech_fingerprint",
                "target": t,
                "description": f"Technology fingerprinting for {t}",
                "tool": "curl",
            })

        # 5. SSL/TLS analysis
        for d in domains:
            if d.startswith("*."):
                continue
            actions.append({
                "action": "ssl_analysis",
                "target": d,
                "description": f"SSL/TLS analysis for {d}",
                "tool": "sslyze",
            })

        return actions

    def execute(self, plan: List[dict]) -> List[dict]:
        """Execute each recon action."""
        results = []

        for action in plan:
            act = action["action"]
            target = action["target"]
            tool = action.get("tool", "")

            self._log(f"Executing: {action['description']}")

            if act == "subdomain_enum":
                result = self._subdomain_enum(target)
            elif act == "dns_analysis":
                result = self._dns_analysis(target)
            elif act == "ct_logs":
                result = self._ct_logs(target)
            elif act == "tech_fingerprint":
                result = self._tech_fingerprint(target)
            elif act == "ssl_analysis":
                result = self._ssl_analysis(target)
            else:
                result = {"status": "skipped", "reason": f"Unknown action: {act}"}

            result["action"] = act
            result["target"] = target
            results.append(result)

        return results

    def _subdomain_enum(self, domain: str) -> dict:
        """Enumerate subdomains using subfinder."""
        if self.tools.is_available("subfinder"):
            tr = self.tools.subfinder(domain)
            if tr.success:
                subs = [s.strip() for s in tr.stdout.splitlines() if s.strip()]
                for sub in subs:
                    self.kb.add_asset(sub, asset_type="subdomain", source="subfinder",
                                      parent_domain=domain)
                return {"status": "ok", "subdomains_found": len(subs), "data": subs}
            return {"status": "error", "error": tr.stderr}
        return {"status": "skipped", "reason": "subfinder not available"}

    def _dns_analysis(self, domain: str) -> dict:
        """Query DNS records via dig or curl to DNS-over-HTTPS."""
        tr = self.tools.curl(
            f"https://dns.google/resolve?name={domain}&type=ANY",
            headers={"Accept": "application/dns-json"},
        )
        if tr.success:
            try:
                # Parse HTTP status from curl output (last line)
                lines = tr.stdout.strip().splitlines()
                body = "\n".join(lines[:-1]) if lines else ""
                data = json.loads(body) if body else {}
                records = data.get("Answer", [])
                self.kb.add_asset(domain, asset_type="dns",
                                  records=records, source="dns.google")
                return {"status": "ok", "records": len(records), "data": records}
            except json.JSONDecodeError:
                return {"status": "ok", "raw": tr.stdout[:500]}
        return {"status": "error", "error": tr.stderr}

    def _ct_logs(self, domain: str) -> dict:
        """Query certificate transparency logs via crt.sh."""
        tr = self.tools.curl(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30,
        )
        if tr.success:
            try:
                lines = tr.stdout.strip().splitlines()
                body = "\n".join(lines[:-1]) if lines else ""
                certs = json.loads(body) if body else []
                names = set()
                for cert in certs if isinstance(certs, list) else []:
                    name_value = cert.get("name_value", "")
                    for n in name_value.split("\n"):
                        n = n.strip()
                        if n and domain in n:
                            names.add(n)
                for n in names:
                    self.kb.add_asset(n, asset_type="ct_subdomain",
                                      source="crt.sh", parent_domain=domain)
                return {"status": "ok", "unique_names": len(names), "data": sorted(names)}
            except json.JSONDecodeError:
                return {"status": "ok", "raw": tr.stdout[:500]}
        return {"status": "error", "error": tr.stderr}

    def _tech_fingerprint(self, target: str) -> dict:
        """Fingerprint technologies via HTTP headers and response analysis."""
        tr = self.tools.curl(target, extra_args=["-I", "-L"])
        if tr.success:
            headers_raw = tr.stdout
            techs = []

            # Parse Server header
            server_match = re.search(r"(?i)^server:\s*(.+)$", headers_raw, re.MULTILINE)
            if server_match:
                techs.append({"type": "web_server", "name": server_match.group(1).strip()})

            # X-Powered-By
            powered_match = re.search(r"(?i)^x-powered-by:\s*(.+)$", headers_raw, re.MULTILINE)
            if powered_match:
                techs.append({"type": "framework", "name": powered_match.group(1).strip()})

            # Content-Type hints
            if "application/json" in headers_raw.lower():
                techs.append({"type": "api_format", "name": "JSON API"})

            # Security headers
            for hdr in ["strict-transport-security", "content-security-policy",
                        "x-frame-options", "x-content-type-options", "x-xss-protection"]:
                if hdr.lower() in headers_raw.lower():
                    techs.append({"type": "security_header", "name": hdr})

            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            for t in techs:
                self.kb.add_technology(domain, t["name"], t["type"])

            return {"status": "ok", "technologies": len(techs), "data": techs}
        return {"status": "error", "error": tr.stderr}

    def _ssl_analysis(self, domain: str) -> dict:
        """Analyze SSL/TLS configuration."""
        if self.tools.is_available("sslyze"):
            tr = self.tools.sslyze(domain)
            if tr.success:
                self.kb.add_asset(domain, asset_type="ssl_scan",
                                  source="sslyze", raw_length=len(tr.stdout))
                return {"status": "ok", "raw_length": len(tr.stdout)}
            return {"status": "error", "error": tr.stderr}

        # Fallback: use curl to check basic SSL info
        tr = self.tools.curl(f"https://{domain}", extra_args=["-vI", "--connect-timeout", "5"])
        ssl_info = [l for l in tr.stderr.splitlines() if "SSL" in l or "TLS" in l or "certificate" in l.lower()]
        if ssl_info:
            self.kb.add_asset(domain, asset_type="ssl_basic",
                              source="curl", info=ssl_info[:10])
            return {"status": "ok", "ssl_lines": len(ssl_info), "data": ssl_info[:10]}
        return {"status": "partial", "note": "No SSL info extracted"}

    def report(self) -> dict:
        """Summarize recon findings."""
        assets = self.kb.get_assets()
        by_type: Dict[str, int] = {}
        for a in assets:
            t = a.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        return {
            "agent": self.name,
            "phase": self.phase,
            "state": self.state,
            "total_assets": len(assets),
            "assets_by_type": by_type,
            "actions_executed": len(self.results),
            "successful": sum(1 for r in self.results if r.get("status") == "ok"),
            "errors": [r for r in self.results if r.get("status") == "error"],
        }
