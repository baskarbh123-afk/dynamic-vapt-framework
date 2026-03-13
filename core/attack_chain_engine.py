"""
core/attack_chain_engine.py

Attack chain detection and analysis engine.
Implements 10 predefined chain templates from ARCHITECTURE.md § 10,
plus a graph-based dynamic chain discovery algorithm.

Architecture reference: ARCHITECTURE.md § 10 "Attack Chain Intelligence"
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Chain templates
# ------------------------------------------------------------------

@dataclass
class ChainTemplate:
    """
    A known attack chain pattern.
    `required_vuln_types` must all be present (in order or co-present).
    `prerequisite_pairs` are (A, B) meaning A enables B (A must come before B).
    """
    chain_id: str
    name: str
    description: str
    required_vuln_types: list[str]
    prerequisite_pairs: list[tuple[str, str]]   # (source_type, target_type)
    combined_impact: str
    severity: str                               # critical | high | medium
    likelihood: str                             # high | medium | low
    owasp_categories: list[str]


CHAIN_TEMPLATES: list[ChainTemplate] = [
    ChainTemplate(
        chain_id="AC-001",
        name="IDOR → Account Takeover",
        description=(
            "An IDOR vulnerability exposes another user's session token or credentials, "
            "enabling full account takeover without brute force."
        ),
        required_vuln_types=["IDOR", "AUTH_BYPASS"],
        prerequisite_pairs=[("IDOR", "AUTH_BYPASS")],
        combined_impact="Full account takeover — attacker gains access to victim's account and data.",
        severity="critical",
        likelihood="high",
        owasp_categories=["A01", "A07"],
    ),
    ChainTemplate(
        chain_id="AC-002",
        name="SSRF → Cloud Metadata Access",
        description=(
            "SSRF vulnerability is used to reach the cloud instance metadata endpoint "
            "(169.254.169.254), leaking IAM credentials and enabling lateral cloud movement."
        ),
        required_vuln_types=["SSRF"],
        prerequisite_pairs=[],
        combined_impact="Cloud credential exfiltration, potential privilege escalation within cloud account.",
        severity="critical",
        likelihood="high",
        owasp_categories=["A10"],
    ),
    ChainTemplate(
        chain_id="AC-003",
        name="Stored XSS → Session Hijacking",
        description=(
            "A stored XSS payload exfiltrates the victim's HttpOnly-unprotected session cookie "
            "to an attacker-controlled server, achieving account takeover."
        ),
        required_vuln_types=["XSS_STORED", "SESSION_MANAGEMENT"],
        prerequisite_pairs=[("XSS_STORED", "SESSION_MANAGEMENT")],
        combined_impact="Session hijacking — attacker impersonates victim in the application.",
        severity="critical",
        likelihood="medium",
        owasp_categories=["A03", "A07"],
    ),
    ChainTemplate(
        chain_id="AC-004",
        name="SQLi → Authentication Bypass",
        description=(
            "SQL injection in the login form allows the attacker to bypass authentication "
            "by manipulating the WHERE clause, gaining admin access directly."
        ),
        required_vuln_types=["SQLI", "AUTH_BYPASS"],
        prerequisite_pairs=[("SQLI", "AUTH_BYPASS")],
        combined_impact="Admin account access without valid credentials.",
        severity="critical",
        likelihood="high",
        owasp_categories=["A03", "A07"],
    ),
    ChainTemplate(
        chain_id="AC-005",
        name="Open Redirect → SSRF",
        description=(
            "An open redirect vulnerability on the target is chained to bypass SSRF "
            "allowlists — the server follows the redirect to an internal resource."
        ),
        required_vuln_types=["OPEN_REDIRECT", "SSRF"],
        prerequisite_pairs=[("OPEN_REDIRECT", "SSRF")],
        combined_impact="Bypass of SSRF filters; access to internal services/cloud metadata.",
        severity="high",
        likelihood="medium",
        owasp_categories=["A01", "A10"],
    ),
    ChainTemplate(
        chain_id="AC-006",
        name="CORS Misconfiguration → CSRF Amplification",
        description=(
            "An overly permissive CORS policy combined with a CSRF vulnerability allows "
            "an attacker to make credentialed cross-origin requests, performing state-changing actions."
        ),
        required_vuln_types=["CORS", "CSRF"],
        prerequisite_pairs=[("CORS", "CSRF")],
        combined_impact="Unauthorized state-changing actions performed on behalf of authenticated users.",
        severity="high",
        likelihood="medium",
        owasp_categories=["A05", "A01"],
    ),
    ChainTemplate(
        chain_id="AC-007",
        name="Subdomain Takeover → Cookie Theft",
        description=(
            "A dangling DNS CNAME allows the attacker to claim a subdomain under the target's "
            "domain. Because cookies are scoped to parent domain, session cookies are readable "
            "from the claimed subdomain."
        ),
        required_vuln_types=["SUBDOMAIN_TAKEOVER"],
        prerequisite_pairs=[],
        combined_impact="Session cookie theft via same-origin subdomain; account takeover.",
        severity="high",
        likelihood="medium",
        owasp_categories=["A05", "A07"],
    ),
    ChainTemplate(
        chain_id="AC-008",
        name="JWT None Algorithm → IDOR Privilege Escalation",
        description=(
            "The JWT implementation accepts the 'none' signing algorithm. Attacker forges a token "
            "with an elevated role claim (e.g., admin=true), then accesses IDOR-vulnerable admin endpoints."
        ),
        required_vuln_types=["JWT", "IDOR"],
        prerequisite_pairs=[("JWT", "IDOR")],
        combined_impact="Vertical privilege escalation to administrator role.",
        severity="critical",
        likelihood="high",
        owasp_categories=["A02", "A07", "A01"],
    ),
    ChainTemplate(
        chain_id="AC-009",
        name="XXE → SSRF → Internal Port Scan",
        description=(
            "An XML External Entity vulnerability is leveraged to perform SSRF, "
            "scanning internal network ports and extracting internal service banners."
        ),
        required_vuln_types=["XXE", "SSRF"],
        prerequisite_pairs=[("XXE", "SSRF")],
        combined_impact="Internal network reconnaissance, potential further exploitation of internal services.",
        severity="high",
        likelihood="medium",
        owasp_categories=["A03", "A10"],
    ),
    ChainTemplate(
        chain_id="AC-010",
        name="Mass Assignment → Privilege Escalation",
        description=(
            "A mass assignment vulnerability allows the attacker to set the 'role' or 'is_admin' "
            "field during account creation or update, gaining administrator privileges."
        ),
        required_vuln_types=["MASS_ASSIGNMENT"],
        prerequisite_pairs=[],
        combined_impact="Admin privilege escalation via parameter pollution on user profile/registration.",
        severity="high",
        likelihood="high",
        owasp_categories=["A04", "A01"],
    ),
]


# ------------------------------------------------------------------
# Detected chain
# ------------------------------------------------------------------

@dataclass
class DetectedChain:
    """A chain matched against real verified vulnerabilities."""
    template: ChainTemplate
    matched_vulns: list[dict]       # The actual finding records that matched
    chain_score: float
    steps: list[dict] = field(default_factory=list)
    narrative: str = ""
    remediation: str = ""
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict:
        return {
            "chain_id": self.template.chain_id,
            "name": self.template.name,
            "description": self.template.description,
            "severity": self.template.severity,
            "likelihood": self.template.likelihood,
            "chain_score": round(self.chain_score, 2),
            "combined_impact": self.template.combined_impact,
            "owasp_categories": self.template.owasp_categories,
            "matched_vulnerabilities": [
                {
                    "finding_id": v.get("id", ""),
                    "title": v.get("title", ""),
                    "type": v.get("type", ""),
                    "severity": v.get("severity", ""),
                    "endpoint": v.get("endpoint", ""),
                }
                for v in self.matched_vulns
            ],
            "steps": self.steps,
            "narrative": self.narrative,
            "remediation": self.remediation,
            "detected_at": self.detected_at,
        }


# ------------------------------------------------------------------
# Chain engine
# ------------------------------------------------------------------

class AttackChainEngine:
    """
    Detects attack chains by matching verified vulnerabilities against
    the 10 chain templates. Also performs dynamic chain discovery for
    novel combinations not in the template library.

    Usage:
        engine = AttackChainEngine()
        verified_vulns = kb.get_vulnerabilities(status="POC_VERIFIED")
        chains = engine.detect(verified_vulns)
        for chain in chains:
            print(chain.template.name, chain.chain_score)
    """

    def __init__(self, output_dir: str = "data"):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._templates = CHAIN_TEMPLATES
        self._detected: list[DetectedChain] = []

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect(self, vulnerabilities: list[dict]) -> list[DetectedChain]:
        """
        Match verified vulnerabilities against all chain templates.

        Args:
            vulnerabilities: List of vulnerability records (from knowledge base).

        Returns:
            List of DetectedChain objects, sorted by chain_score descending.
        """
        # Build type lookup
        vuln_by_type: dict[str, list[dict]] = {}
        for vuln in vulnerabilities:
            vuln_type = self._normalize_type(vuln.get("type", ""))
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)

        detected: list[DetectedChain] = []

        for template in self._templates:
            chain = self._match_template(template, vuln_by_type)
            if chain:
                detected.append(chain)

        # Also run dynamic discovery
        dynamic = self._dynamic_discovery(vulnerabilities)
        detected.extend(dynamic)

        # Deduplicate by chain_id
        seen_ids: set[str] = set()
        unique: list[DetectedChain] = []
        for chain in detected:
            if chain.template.chain_id not in seen_ids:
                seen_ids.add(chain.template.chain_id)
                unique.append(chain)

        # Sort by score descending
        unique.sort(key=lambda c: c.chain_score, reverse=True)
        self._detected = unique

        logger.info(f"[AttackChainEngine] Detected {len(unique)} attack chains.")
        return unique

    def _match_template(
        self,
        template: ChainTemplate,
        vuln_by_type: dict[str, list[dict]],
    ) -> Optional[DetectedChain]:
        """Check if a template's required vulnerability types are all present."""
        # Normalize required types and check coverage
        matched: dict[str, dict] = {}

        for req_type in template.required_vuln_types:
            # Try exact match
            normalized = req_type.upper()
            matching_vulns = []

            for vtype, vulns in vuln_by_type.items():
                if normalized in vtype or vtype in normalized:
                    matching_vulns.extend(vulns)

            if not matching_vulns:
                return None  # Required type not found — chain cannot form

            # Pick highest-severity matching vuln
            matching_vulns.sort(
                key=lambda v: self._severity_rank(v.get("severity", "low")),
                reverse=True,
            )
            matched[req_type] = matching_vulns[0]

        if not matched:
            return None

        matched_list = list(matched.values())
        score = self._compute_chain_score(template, matched_list)
        steps = self._build_steps(template, matched_list)
        narrative = self._generate_narrative(template, matched_list)
        remediation = self._generate_remediation(template)

        return DetectedChain(
            template=template,
            matched_vulns=matched_list,
            chain_score=score,
            steps=steps,
            narrative=narrative,
            remediation=remediation,
        )

    def _dynamic_discovery(self, vulnerabilities: list[dict]) -> list[DetectedChain]:
        """
        Discover novel chains not in the template library.
        Groups vulnerabilities by endpoint host to find co-located attack paths.
        """
        chains: list[DetectedChain] = []
        from urllib.parse import urlparse

        # Group by host
        by_host: dict[str, list[dict]] = {}
        for vuln in vulnerabilities:
            try:
                host = urlparse(vuln.get("endpoint", "")).netloc
            except Exception:
                host = "unknown"
            if host not in by_host:
                by_host[host] = []
            by_host[host].append(vuln)

        # Any host with 3+ verified vulns gets a dynamic chain entry
        for host, vulns in by_host.items():
            if len(vulns) < 3:
                continue
            highest_severity = sorted(
                vulns,
                key=lambda v: self._severity_rank(v.get("severity", "low")),
                reverse=True,
            )
            score = self._compute_dynamic_score(vulns)

            # Build synthetic template
            synthetic = ChainTemplate(
                chain_id=f"AC-DYN-{host[:20]}",
                name=f"Multi-vector attack on {host}",
                description=(
                    f"Multiple verified vulnerabilities on {host} form a multi-step attack path."
                ),
                required_vuln_types=[v.get("type", "") for v in highest_severity[:3]],
                prerequisite_pairs=[],
                combined_impact=f"Comprehensive compromise of {host} via {len(vulns)} distinct vulnerabilities.",
                severity=highest_severity[0].get("severity", "high"),
                likelihood="high",
                owasp_categories=list({v.get("owasp_category", "A01") for v in vulns}),
            )

            chains.append(DetectedChain(
                template=synthetic,
                matched_vulns=highest_severity[:5],
                chain_score=score,
                narrative=self._generate_dynamic_narrative(host, highest_severity),
                remediation="Remediate all identified vulnerabilities. Prioritize authentication and injection issues.",
            ))

        return chains

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _compute_chain_score(self, template: ChainTemplate, vulns: list[dict]) -> float:
        """
        Score = max_severity × length_multiplier + avg_cvss × 0.4 + likelihood × 0.2
        """
        if not vulns:
            return 0.0

        max_sev_rank = max(self._severity_rank(v.get("severity", "low")) for v in vulns)
        avg_cvss = sum(float(v.get("cvss", 0)) for v in vulns) / len(vulns)
        length = len(template.required_vuln_types)

        length_mult = {1: 1.0, 2: 1.3, 3: 1.6}.get(length, 2.0)
        likelihood_score = {"high": 1.0, "medium": 0.6, "low": 0.3}.get(template.likelihood, 0.5)

        score = (max_sev_rank / 4.0) * 10 * length_mult
        score += avg_cvss * 0.4
        score += likelihood_score * 2.0
        return round(min(score, 10.0), 2)

    def _compute_dynamic_score(self, vulns: list[dict]) -> float:
        avg_cvss = sum(float(v.get("cvss", 5.0)) for v in vulns) / len(vulns)
        multiplier = min(len(vulns) / 3 + 1.0, 2.0)
        return round(min(avg_cvss * multiplier, 10.0), 2)

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
            severity.lower(), 1
        )

    @staticmethod
    def _normalize_type(vuln_type: str) -> str:
        type_map = {
            "xss": "XSS_STORED",
            "reflected_xss": "XSS",
            "stored_xss": "XSS_STORED",
            "sql_injection": "SQLI",
            "sqli": "SQLI",
            "open_redirect": "OPEN_REDIRECT",
            "idor": "IDOR",
            "ssrf": "SSRF",
            "cors": "CORS",
            "csrf": "CSRF",
            "jwt": "JWT",
            "xxe": "XXE",
            "mass_assignment": "MASS_ASSIGNMENT",
            "subdomain_takeover": "SUBDOMAIN_TAKEOVER",
            "auth_bypass": "AUTH_BYPASS",
            "session": "SESSION_MANAGEMENT",
        }
        normalized = vuln_type.upper().replace("-", "_")
        return type_map.get(vuln_type.lower(), normalized)

    # ------------------------------------------------------------------
    # Step / narrative generation
    # ------------------------------------------------------------------

    def _build_steps(self, template: ChainTemplate, vulns: list[dict]) -> list[dict]:
        steps = []
        for i, (req_type, vuln) in enumerate(
            zip(template.required_vuln_types, vulns), start=1
        ):
            steps.append({
                "step": i,
                "vulnerability_type": req_type,
                "finding_id": vuln.get("id", ""),
                "endpoint": vuln.get("endpoint", ""),
                "action": f"Exploit {req_type} at {vuln.get('endpoint', 'target')}",
                "result": f"Attacker gains: {self._step_result(req_type)}",
            })
        return steps

    @staticmethod
    def _step_result(vuln_type: str) -> str:
        results = {
            "IDOR": "access to another user's data/session",
            "SSRF": "access to internal network / cloud metadata",
            "XSS_STORED": "persistent JavaScript execution in victim browsers",
            "SQLI": "database access or authentication bypass",
            "JWT": "forged authentication token with elevated privileges",
            "XXE": "local file read and SSRF capability",
            "OPEN_REDIRECT": "bypass of URL allowlist / SSRF filter",
            "CORS": "cross-origin credentialed request capability",
            "CSRF": "unauthorized state-changing action on behalf of victim",
            "MASS_ASSIGNMENT": "unauthorized role/privilege field modification",
            "SUBDOMAIN_TAKEOVER": "control of subdomain under target's domain",
        }
        return results.get(vuln_type.upper(), "access to restricted resource")

    def _generate_narrative(self, template: ChainTemplate, vulns: list[dict]) -> str:
        vuln_list = ", ".join(
            f"{v.get('type', 'unknown')} on {v.get('endpoint', 'target')}"
            for v in vulns
        )
        return (
            f"The attacker begins with {template.required_vuln_types[0]} at the identified endpoint. "
            f"{template.description} "
            f"In this engagement, the chain was formed by: {vuln_list}. "
            f"Ultimate impact: {template.combined_impact}"
        )

    def _generate_dynamic_narrative(self, host: str, vulns: list[dict]) -> str:
        types = ", ".join(v.get("type", "unknown") for v in vulns[:5])
        return (
            f"The host {host} has multiple verified vulnerabilities ({types}), "
            f"which together form a multi-vector attack path. "
            f"An attacker could combine these issues to achieve a more severe impact "
            f"than any single vulnerability in isolation."
        )

    @staticmethod
    def _generate_remediation(template: ChainTemplate) -> str:
        remediation_map = {
            "AC-001": "Fix the IDOR vulnerability first — enforce ownership checks on all object references.",
            "AC-002": "Implement SSRF allowlisting. Block access to 169.254.169.254 at the network layer.",
            "AC-003": "Set HttpOnly flag on all session cookies. Fix the stored XSS injection point.",
            "AC-004": "Use parameterized queries. The SQL injection fix will also break this chain.",
            "AC-005": "Fix the open redirect by validating redirect destinations against an allowlist.",
            "AC-006": "Restrict CORS to explicit trusted origins. Add anti-CSRF tokens to state-changing endpoints.",
            "AC-007": "Remove or update the dangling DNS CNAME record. Monitor DNS records for new dangles.",
            "AC-008": "Enforce JWT signature validation. Reject tokens with alg=none. Fix IDOR checks.",
            "AC-009": "Disable external entity processing in the XML parser. Apply SSRF mitigations.",
            "AC-010": "Implement an allowlist of fields that can be mass-assigned. Never expose role fields.",
        }
        return remediation_map.get(
            template.chain_id,
            "Remediate all component vulnerabilities. Prioritize the first step in the chain.",
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> str:
        """Save detected chains to data/attack_paths.json."""
        output_file = self._output_dir / "attack_paths.json"
        data = [chain.to_dict() for chain in self._detected]
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"[AttackChainEngine] Saved {len(data)} chains to {output_file}")
        return str(output_file)

    def summary(self) -> dict:
        return {
            "total_chains": len(self._detected),
            "critical": sum(1 for c in self._detected if c.template.severity == "critical"),
            "high": sum(1 for c in self._detected if c.template.severity == "high"),
            "medium": sum(1 for c in self._detected if c.template.severity == "medium"),
            "chains": [
                {
                    "id": c.template.chain_id,
                    "name": c.template.name,
                    "severity": c.template.severity,
                    "score": c.chain_score,
                }
                for c in self._detected
            ],
        }
