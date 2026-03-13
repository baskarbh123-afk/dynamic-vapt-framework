"""
core/authorization_guard.py

Centralized scope enforcement for the Autonomous AI Pentesting Platform.
Every asset, endpoint, or domain discovered during testing must pass through
this guard before being processed. Assets outside scope are dropped and logged.

Architecture reference: ARCHITECTURE.md § 2 "Autonomous Recon Engine"
"""

import ipaddress
import logging
import re
import fnmatch
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ScopeDecision:
    """Result of a scope validation check."""
    asset: str
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class AuthorizationGuard:
    """
    Central gate that validates every discovered asset against the authorized scope.

    Priority order:
      1. Exclusions are checked first — if excluded, always DENY.
      2. Inclusions are checked next — if included, ALLOW.
      3. Default policy applied (default: DENY anything not explicitly allowed).

    Supported scope formats:
      - Exact domain:       example.com
      - Wildcard domain:    *.example.com
      - IP address:         192.168.1.1
      - CIDR range:         192.168.0.0/24
      - URL prefix:         https://api.example.com/v1/
    """

    def __init__(self, config: dict, log_dir: str = "logs"):
        self.config = config
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self._allowed_domains: list[str] = []
        self._allowed_ips: list[str] = []
        self._allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_domains: list[str] = []
        self._excluded_ips: list[str] = []
        self._excluded_paths: list[str] = []
        self._excluded_patterns: list[str] = []

        self._decisions: list[ScopeDecision] = []
        self._roe_verified: bool = False

        self._load_scope()
        self._verify_roe()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _load_scope(self):
        """Parse scope from config.yaml."""
        scope = self.config.get("scope", {})
        engagement = self.config.get("engagement", {})

        # Primary target
        target = self.config.get("target", {})
        primary_domain = target.get("domain", "")
        if primary_domain:
            self._allowed_domains.append(primary_domain)
            self._allowed_domains.append(f"*.{primary_domain}")

        # Additional in-scope targets
        for entry in scope.get("in_scope", []):
            self._parse_scope_entry(entry, allow=True)

        # Explicit exclusions
        for entry in scope.get("out_of_scope", []):
            self._parse_scope_entry(entry, allow=False)

        # Additional exclusion patterns
        for pattern in scope.get("excluded_paths", []):
            self._excluded_paths.append(pattern)

        for pattern in scope.get("excluded_patterns", []):
            self._excluded_patterns.append(pattern)

        logger.info(
            f"[AuthorizationGuard] Loaded scope: "
            f"{len(self._allowed_domains)} domains, "
            f"{len(self._allowed_ips)} IPs, "
            f"{len(self._allowed_cidrs)} CIDRs, "
            f"{len(self._excluded_domains)} exclusions"
        )

    def _parse_scope_entry(self, entry: str, allow: bool):
        """Route a scope entry to the appropriate list."""
        entry = entry.strip()
        if not entry:
            return

        # CIDR notation
        if "/" in entry and not entry.startswith("http"):
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if allow:
                    self._allowed_cidrs.append(network)
                else:
                    self._excluded_ips.append(entry)
                return
            except ValueError:
                pass

        # Plain IP address
        try:
            ipaddress.ip_address(entry)
            if allow:
                self._allowed_ips.append(entry)
            else:
                self._excluded_ips.append(entry)
            return
        except ValueError:
            pass

        # URL — extract hostname
        if entry.startswith("http://") or entry.startswith("https://"):
            parsed = urlparse(entry)
            entry = parsed.netloc or entry

        # Domain / wildcard
        if allow:
            self._allowed_domains.append(entry)
        else:
            self._excluded_domains.append(entry)

    def _verify_roe(self):
        """
        Enforce that authorization/ROE is signed before any testing.
        Raises RuntimeError if authorization is missing.
        """
        auth = self.config.get("authorization", {})
        roe_signed = auth.get("roe_signed", False)

        if not roe_signed:
            raise RuntimeError(
                "[AuthorizationGuard] FATAL: authorization.roe_signed is not true in config.yaml. "
                "Testing requires prior written authorization. Refusing to proceed."
            )

        self._roe_verified = True
        logger.info("[AuthorizationGuard] ROE verified — authorized to proceed.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_allowed(self, asset: str) -> ScopeDecision:
        """
        Validate a single asset (domain, IP, or URL) against the scope.

        Args:
            asset: Domain name, IP address, CIDR, or full URL.

        Returns:
            ScopeDecision with allowed=True/False and reason.
        """
        normalized = self._normalize(asset)

        # Step 1: Check exclusions first (exclusions win)
        exclusion_hit = self._check_exclusions(normalized)
        if exclusion_hit:
            decision = ScopeDecision(
                asset=asset,
                allowed=False,
                reason=f"Excluded by rule: {exclusion_hit}",
                matched_rule=exclusion_hit,
            )
            self._record(decision)
            return decision

        # Step 2: Check inclusions
        inclusion_hit = self._check_inclusions(normalized)
        if inclusion_hit:
            decision = ScopeDecision(
                asset=asset,
                allowed=True,
                reason=f"Allowed by rule: {inclusion_hit}",
                matched_rule=inclusion_hit,
            )
            self._record(decision)
            return decision

        # Step 3: Default deny
        decision = ScopeDecision(
            asset=asset,
            allowed=False,
            reason="Not in scope (default deny — no matching allow rule)",
        )
        self._record(decision)
        return decision

    def validate_asset(self, asset: str) -> bool:
        """Convenience method — returns True if asset is in scope."""
        return self.is_allowed(asset).allowed

    def filter_assets(self, assets: list[str]) -> list[str]:
        """
        Filter a list of assets, returning only those in scope.
        Logs each dropped asset.
        """
        allowed = []
        for asset in assets:
            decision = self.is_allowed(asset)
            if decision.allowed:
                allowed.append(asset)
            else:
                logger.debug(f"[AuthorizationGuard] DROPPED: {asset} — {decision.reason}")
        return allowed

    def validate_url(self, url: str) -> bool:
        """Validate a full URL — checks hostname, path exclusions, and patterns."""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            path = parsed.path
        except Exception:
            return False

        # Check hostname scope
        decision = self.is_allowed(hostname)
        if not decision.allowed:
            return False

        # Check path exclusions
        for excluded_path in self._excluded_paths:
            if path.startswith(excluded_path):
                logger.debug(f"[AuthorizationGuard] URL path excluded: {url} (rule: {excluded_path})")
                return False

        # Check pattern exclusions
        for pattern in self._excluded_patterns:
            if re.search(pattern, url):
                logger.debug(f"[AuthorizationGuard] URL pattern excluded: {url} (pattern: {pattern})")
                return False

        return True

    def get_stats(self) -> dict:
        """Return decision statistics."""
        total = len(self._decisions)
        allowed = sum(1 for d in self._decisions if d.allowed)
        denied = total - allowed
        return {
            "total_decisions": total,
            "allowed": allowed,
            "denied": denied,
            "allow_rate": round(allowed / total * 100, 1) if total else 0,
            "scope_domains": len(self._allowed_domains),
            "scope_ips": len(self._allowed_ips),
            "scope_cidrs": len(self._allowed_cidrs),
            "exclusions": len(self._excluded_domains) + len(self._excluded_ips),
        }

    # ------------------------------------------------------------------
    # Internal matching logic
    # ------------------------------------------------------------------

    def _normalize(self, asset: str) -> str:
        """Strip protocol, port, and trailing slashes for comparison."""
        asset = asset.strip().lower()
        if asset.startswith("http://") or asset.startswith("https://"):
            parsed = urlparse(asset)
            asset = parsed.netloc
        # Remove port
        if ":" in asset and not asset.startswith("["):
            asset = asset.rsplit(":", 1)[0]
        return asset

    def _check_exclusions(self, normalized: str) -> Optional[str]:
        """Return the matching exclusion rule, or None."""
        # IP exclusion
        try:
            ip = ipaddress.ip_address(normalized)
            if normalized in self._excluded_ips:
                return f"IP {normalized}"
            # CIDR exclusion for IPs
            for excluded_cidr in self._excluded_ips:
                if "/" in excluded_cidr:
                    try:
                        if ip in ipaddress.ip_network(excluded_cidr, strict=False):
                            return f"CIDR {excluded_cidr}"
                    except ValueError:
                        pass
        except ValueError:
            pass

        # Domain exclusion (exact + wildcard)
        for excl in self._excluded_domains:
            if self._domain_matches(normalized, excl):
                return f"domain {excl}"

        return None

    def _check_inclusions(self, normalized: str) -> Optional[str]:
        """Return the matching inclusion rule, or None."""
        # IP inclusion
        try:
            ip = ipaddress.ip_address(normalized)
            if normalized in self._allowed_ips:
                return f"IP {normalized}"
            for network in self._allowed_cidrs:
                if ip in network:
                    return f"CIDR {network}"
        except ValueError:
            pass

        # Domain inclusion (exact + wildcard)
        for allowed in self._allowed_domains:
            if self._domain_matches(normalized, allowed):
                return f"domain {allowed}"

        return None

    @staticmethod
    def _domain_matches(domain: str, pattern: str) -> bool:
        """
        Match a domain against a rule.
        Supports exact match and wildcard (*.example.com).
        """
        pattern = pattern.lower().strip()
        domain = domain.lower().strip()

        if pattern.startswith("*."):
            # Wildcard: *.example.com matches sub.example.com and example.com
            base = pattern[2:]
            return domain == base or domain.endswith("." + base)
        else:
            return domain == pattern or domain.endswith("." + pattern)

    def _record(self, decision: ScopeDecision):
        """Store decision in memory and write denied assets to log."""
        self._decisions.append(decision)
        if not decision.allowed:
            with open(self.log_dir / "scope_denials.log", "a") as f:
                f.write(
                    f"{decision.timestamp} DENIED {decision.asset} — {decision.reason}\n"
                )
