#!/usr/bin/env python3
"""
Attack Chain Agent — Phase 7: Attack Chain Analysis
=====================================================
Analyzes discovered vulnerabilities, identifies privilege escalation
paths, builds attack graphs, and stores results in attack_paths database.
"""

import logging
from itertools import combinations

from agents.base_agent import BaseAgent
from typing import Any, List

logger = logging.getLogger("agent.attack_chain")

# Vulnerability chaining rules: (vuln_type_A, vuln_type_B) -> chain description
CHAIN_RULES = [
    ({"XSS"}, {"CSRF"}, "XSS → CSRF: Inject script that triggers cross-site actions"),
    ({"XSS"}, {"SESSION_HIJACK"}, "XSS → Session Hijack: Steal session tokens via injected script"),
    ({"SQL_INJECTION"}, {"SENSITIVE_DATA_EXPOSURE"}, "SQLi → Data Exfil: Extract sensitive data via injection"),
    ({"SSRF"}, {"SENSITIVE_DATA_EXPOSURE"}, "SSRF → Internal Data: Access internal services/metadata"),
    ({"IDOR"}, {"SENSITIVE_DATA_EXPOSURE"}, "IDOR → Cross-tenant Data: Access other users' data"),
    ({"CORS"}, {"XSS"}, "CORS + XSS: Cross-origin data theft via reflected XSS"),
    ({"AUTHENTICATION"}, {"IDOR"}, "Auth Bypass → IDOR: Unauthenticated access to user resources"),
    ({"JWT_SECURITY"}, {"AUTHORIZATION"}, "JWT Forge → Privilege Escalation: Forge admin tokens"),
    ({"FILE_UPLOAD"}, {"COMMAND_INJECTION"}, "Upload → RCE: Upload webshell, execute commands"),
    ({"OPEN_REDIRECT"}, {"OAUTH"}, "Open Redirect → OAuth Theft: Redirect OAuth tokens to attacker"),
    ({"RATE_LIMITING"}, {"AUTHENTICATION"}, "No Rate Limit → Brute Force: Credential stuffing"),
    ({"SECURITY_MISCONFIG"}, {"SENSITIVE_DATA_EXPOSURE"}, "Misconfig → Info Leak: Debug endpoints expose data"),
]

# Severity escalation when chains are found
CHAIN_SEVERITY = {
    "Low+Low": "Medium",
    "Low+Medium": "Medium",
    "Medium+Medium": "High",
    "Medium+High": "High",
    "High+High": "Critical",
    "Low+High": "High",
    "Low+Critical": "Critical",
    "Medium+Critical": "Critical",
    "High+Critical": "Critical",
}


class AttackChainAgent(BaseAgent):
    name = "AttackChainAgent"
    description = "Attack chain analysis — privilege escalation paths, vulnerability chaining, attack graphs"
    phase = "attack_chain"

    def plan(self) -> List[dict]:
        """Plan attack chain analysis."""
        vulns = self.kb.get_vulnerabilities()
        actions = []

        if len(vulns) >= 2:
            actions.append({
                "action": "chain_analysis",
                "target": "all_vulnerabilities",
                "description": f"Analyze {len(vulns)} vulnerabilities for chaining opportunities",
            })

        actions.append({
            "action": "privilege_escalation",
            "target": "all_vulnerabilities",
            "description": "Identify privilege escalation paths",
        })

        actions.append({
            "action": "impact_assessment",
            "target": "all_vulnerabilities",
            "description": "Assess combined impact of vulnerability chains",
        })

        return actions

    def execute(self, plan: List[dict]) -> List[dict]:
        results = []
        for action in plan:
            self._log(f"Executing: {action['description']}")

            if action["action"] == "chain_analysis":
                result = self._chain_analysis()
            elif action["action"] == "privilege_escalation":
                result = self._privilege_escalation()
            elif action["action"] == "impact_assessment":
                result = self._impact_assessment()
            else:
                result = {"status": "skipped"}

            result["action"] = action["action"]
            results.append(result)
        return results

    def _chain_analysis(self) -> dict:
        """Identify vulnerability chains."""
        vulns = self.kb.get_vulnerabilities()
        chains_found = []

        vuln_types = {}
        for v in vulns:
            vt = v.get("vuln_type", "")
            if vt not in vuln_types:
                vuln_types[vt] = []
            vuln_types[vt].append(v)

        present_types = set(vuln_types.keys())

        for type_set_a, type_set_b, chain_desc in CHAIN_RULES:
            if type_set_a & present_types and type_set_b & present_types:
                # Get representative vulns
                vuln_a_type = (type_set_a & present_types).pop()
                vuln_b_type = (type_set_b & present_types).pop()
                vuln_a = vuln_types[vuln_a_type][0]
                vuln_b = vuln_types[vuln_b_type][0]

                # Determine combined severity
                sev_a = vuln_a.get("severity", "Medium")
                sev_b = vuln_b.get("severity", "Medium")
                combined_key = f"{sev_a}+{sev_b}"
                combined_sev = CHAIN_SEVERITY.get(combined_key,
                               CHAIN_SEVERITY.get(f"{sev_b}+{sev_a}", "High"))

                chain = {
                    "name": chain_desc.split(":")[0].strip(),
                    "description": chain_desc,
                    "vulnerability_a": vuln_a.get("finding_id", ""),
                    "vulnerability_b": vuln_b.get("finding_id", ""),
                    "combined_severity": combined_sev,
                    "steps": [
                        {"step": 1, "action": f"Exploit {vuln_a_type}", "finding": vuln_a.get("finding_id", ""),
                         "endpoint": vuln_a.get("endpoint", "")},
                        {"step": 2, "action": f"Chain to {vuln_b_type}", "finding": vuln_b.get("finding_id", ""),
                         "endpoint": vuln_b.get("endpoint", "")},
                    ],
                    "impact": f"Combined {vuln_a_type} + {vuln_b_type} escalates to {combined_sev} severity",
                }
                chains_found.append(chain)

                self.kb.add_attack_path(
                    name=chain["name"],
                    steps=chain["steps"],
                    impact=chain["impact"],
                    combined_severity=combined_sev,
                    vulnerabilities=[vuln_a.get("finding_id"), vuln_b.get("finding_id")],
                )

        return {"status": "ok", "chains_found": len(chains_found), "data": chains_found}

    def _privilege_escalation(self) -> dict:
        """Identify privilege escalation paths."""
        vulns = self.kb.get_vulnerabilities()
        priv_esc_paths = []

        # Check for auth-related vulnerabilities that enable escalation
        auth_vulns = [v for v in vulns if v.get("vuln_type") in
                      ("AUTHENTICATION", "AUTHORIZATION", "JWT_SECURITY", "IDOR", "OAUTH")]
        access_vulns = [v for v in vulns if v.get("vuln_type") in
                        ("SENSITIVE_DATA_EXPOSURE", "SECURITY_MISCONFIG")]

        if auth_vulns:
            for av in auth_vulns:
                path = {
                    "type": "vertical_escalation",
                    "entry_point": av.get("endpoint", ""),
                    "finding": av.get("finding_id", ""),
                    "vuln_type": av.get("vuln_type", ""),
                    "description": f"{av.get('vuln_type', '')} enables potential privilege escalation",
                    "risk": "High" if av.get("severity") in ("Critical", "High") else "Medium",
                }
                priv_esc_paths.append(path)

        # Horizontal escalation via IDOR
        idor_vulns = [v for v in vulns if v.get("vuln_type") == "IDOR"]
        for iv in idor_vulns:
            priv_esc_paths.append({
                "type": "horizontal_escalation",
                "entry_point": iv.get("endpoint", ""),
                "finding": iv.get("finding_id", ""),
                "description": "IDOR enables cross-tenant data access",
                "risk": "High",
            })

        return {"status": "ok", "escalation_paths": len(priv_esc_paths), "data": priv_esc_paths}

    def _impact_assessment(self) -> dict:
        """Assess overall impact of all findings + chains."""
        vulns = self.kb.get_vulnerabilities()
        chains = self.kb.get_attack_paths()

        severity_counts = {}
        for v in vulns:
            sev = v.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Determine overall risk rating
        if severity_counts.get("Critical", 0) > 0 or len(chains) >= 3:
            overall_risk = "CRITICAL"
        elif severity_counts.get("High", 0) > 0 or len(chains) >= 1:
            overall_risk = "HIGH"
        elif severity_counts.get("Medium", 0) > 0:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        return {
            "status": "ok",
            "overall_risk": overall_risk,
            "total_vulnerabilities": len(vulns),
            "severity_distribution": severity_counts,
            "attack_chains": len(chains),
            "max_chain_severity": max(
                (c.get("combined_severity", "Low") for c in chains),
                key=lambda s: ["Low", "Medium", "High", "Critical"].index(s) if s in ["Low", "Medium", "High", "Critical"] else 0,
                default="N/A",
            ),
        }

    def report(self) -> dict:
        chains = self.kb.get_attack_paths()
        vulns = self.kb.get_vulnerabilities()

        return {
            "agent": self.name,
            "phase": self.phase,
            "state": self.state,
            "attack_chains": len(chains),
            "total_vulnerabilities_analyzed": len(vulns),
            "chains": [{"name": c.get("name", ""), "severity": c.get("combined_severity", "")}
                       for c in chains],
            "actions_executed": len(self.results),
        }
