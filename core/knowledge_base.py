#!/usr/bin/env python3
"""
Knowledge Base — Persistent Storage for VAPT Framework
=======================================================
Provides structured JSON-based databases for:
  - assets       → discovered subdomains, IPs, technologies
  - endpoints    → URLs, API routes, parameters, auth requirements
  - vulnerabilities → confirmed findings with severity, CVSS, evidence
  - evidence     → screenshots, HTTP logs, PoC artifacts
  - attack_paths → privilege escalation chains, lateral movement graphs

All databases are stored in data/ as JSON files with append/query support.
"""

import json
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("knowledge_base")

BASE_DIR = Path(__file__).parent.parent.resolve()
DATA_DIR = BASE_DIR / "data"

# Database file mapping
DATABASES = {
    "assets": DATA_DIR / "assets.json",
    "endpoints": DATA_DIR / "endpoints.json",
    "vulnerabilities": DATA_DIR / "vulnerabilities.json",
    "evidence": DATA_DIR / "evidence.json",
    "poc_results": DATA_DIR / "poc_results.json",
    "attack_paths": DATA_DIR / "attack_paths.json",
}


class KnowledgeBase:
    """Centralized knowledge store for all pentest data."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, List[dict]] = {}
        self._load_all()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_all(self):
        for name, path in DATABASES.items():
            if path.exists():
                with open(path) as f:
                    self._cache[name] = json.load(f)
            else:
                self._cache[name] = []

    def _save(self, db_name: str):
        path = DATABASES[db_name]
        with open(path, "w") as f:
            json.dump(self._cache[db_name], f, indent=2, default=str)

    def _timestamp(self) -> str:
        return datetime.now().isoformat()

    # ------------------------------------------------------------------
    # Generic CRUD
    # ------------------------------------------------------------------
    def add(self, db_name: str, record: dict) -> dict:
        """Add a record to a database. Returns the record with metadata."""
        if db_name not in DATABASES:
            raise ValueError(f"Unknown database: {db_name}. Valid: {list(DATABASES.keys())}")
        record["_id"] = len(self._cache[db_name]) + 1
        record["_created"] = self._timestamp()
        record["_updated"] = self._timestamp()
        self._cache[db_name].append(record)
        self._save(db_name)
        logger.info(f"[KB] Added to {db_name}: {record.get('_id')}")
        return record

    def query(self, db_name: str, **filters) -> List[dict]:
        """Query records matching all key=value filters."""
        if db_name not in DATABASES:
            raise ValueError(f"Unknown database: {db_name}")
        results = self._cache.get(db_name, [])
        for key, value in filters.items():
            results = [r for r in results if r.get(key) == value]
        return results

    def get_all(self, db_name: str) -> List[dict]:
        """Return all records from a database."""
        return list(self._cache.get(db_name, []))

    def update(self, db_name: str, record_id: int, updates: dict) -> Optional[dict]:
        """Update a record by _id."""
        for record in self._cache.get(db_name, []):
            if record.get("_id") == record_id:
                record.update(updates)
                record["_updated"] = self._timestamp()
                self._save(db_name)
                return record
        return None

    def count(self, db_name: str, **filters) -> int:
        """Count records matching filters."""
        return len(self.query(db_name, **filters))

    def clear(self, db_name: str):
        """Clear all records from a database."""
        self._cache[db_name] = []
        self._save(db_name)

    # ------------------------------------------------------------------
    # Asset-specific methods
    # ------------------------------------------------------------------
    def add_asset(self, domain: str, asset_type: str = "subdomain", **kwargs) -> dict:
        return self.add("assets", {"domain": domain, "type": asset_type, **kwargs})

    def add_technology(self, domain: str, tech_name: str, tech_type: str, version: str = "") -> dict:
        return self.add("assets", {
            "domain": domain,
            "type": "technology",
            "tech_name": tech_name,
            "tech_type": tech_type,
            "version": version,
        })

    def get_assets(self, asset_type: Optional[str] = None) -> List[dict]:
        if asset_type:
            return self.query("assets", type=asset_type)
        return self.get_all("assets")

    # ------------------------------------------------------------------
    # Endpoint-specific methods
    # ------------------------------------------------------------------
    def add_endpoint(self, url: str, method: str = "GET", **kwargs) -> dict:
        return self.add("endpoints", {"url": url, "method": method, **kwargs})

    def get_endpoints(self, auth_required: Optional[bool] = None) -> List[dict]:
        if auth_required is not None:
            return self.query("endpoints", auth_required=auth_required)
        return self.get_all("endpoints")

    # ------------------------------------------------------------------
    # Domain extraction helper
    # ------------------------------------------------------------------
    @staticmethod
    def extract_domain_info(url_or_domain: str) -> Tuple[str, str]:
        """Extract (root_domain, subdomain_host) from a URL or domain string.

        Examples:
            "https://www.example.com/path"     → ("example.com", "www.example.com")
            "https://blog.example.at/api"      → ("example.at", "blog.example.at")
            "https://app.example.com/swagger"  → ("example.com", "app.example.com")
            "example.com"                      → ("example.com", "example.com")
        """
        # Parse URL to get hostname
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            host = parsed.hostname or url_or_domain
        else:
            host = url_or_domain.split("/")[0].split(":")[0]

        host = host.lower().strip(".")

        # Extract root domain (last 2 parts, or 3 for co.uk etc.)
        parts = host.split(".")
        # Common two-part TLDs
        two_part_tlds = {"co.uk", "co.in", "com.au", "co.jp", "co.nz", "com.br",
                         "co.za", "org.uk", "net.au", "ac.uk", "gov.uk"}
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
            root_domain = ".".join(parts[-3:])
        elif len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
        else:
            root_domain = host

        return root_domain, host

    # ------------------------------------------------------------------
    # Vulnerability-specific methods
    # ------------------------------------------------------------------
    def add_vulnerability(self, title: str, severity: str, cvss: float,
                          endpoint: str, vuln_type: str, **kwargs) -> dict:
        finding_id = f"F-{self.count('vulnerabilities') + 1:03d}"
        root_domain, subdomain = self.extract_domain_info(endpoint)
        return self.add("vulnerabilities", {
            "finding_id": finding_id,
            "title": title,
            "severity": severity,
            "cvss": cvss,
            "endpoint": endpoint,
            "vuln_type": vuln_type,
            "status": "DRAFT",
            "domain": kwargs.get("domain", root_domain),
            "subdomain": kwargs.get("subdomain", subdomain),
            "owasp_category": kwargs.get("owasp_category", ""),
            "cwe": kwargs.get("cwe", ""),
            "description": kwargs.get("description", ""),
            "steps_to_reproduce": kwargs.get("steps_to_reproduce", []),
            "impact": kwargs.get("impact", ""),
            "remediation": kwargs.get("remediation", ""),
            **{k: v for k, v in kwargs.items() if k not in
               ("owasp_category", "cwe", "description", "steps_to_reproduce",
                "impact", "remediation", "domain", "subdomain")},
        })

    def get_vulnerabilities(self, severity: Optional[str] = None, status: Optional[str] = None) -> List[dict]:
        filters: Dict[str, Any] = {}
        if severity:
            filters["severity"] = severity
        if status:
            filters["status"] = status
        return self.query("vulnerabilities", **filters)

    def validate_finding(self, finding_id: str, status: str, notes: str = "") -> Optional[dict]:
        """Update finding status during validation step."""
        for record in self._cache.get("vulnerabilities", []):
            if record.get("finding_id") == finding_id:
                record["status"] = status
                record["validation_notes"] = notes
                record["_updated"] = self._timestamp()
                self._save("vulnerabilities")
                return record
        return None

    # ------------------------------------------------------------------
    # Evidence-specific methods
    # ------------------------------------------------------------------
    def add_evidence(self, finding_id: str, evidence_type: str, path: str, **kwargs) -> dict:
        # Auto-populate domain/subdomain from the linked vulnerability
        domain = kwargs.pop("domain", "")
        subdomain = kwargs.pop("subdomain", "")
        if not domain:
            vuln_records = self.query("vulnerabilities", finding_id=finding_id)
            if vuln_records:
                domain = vuln_records[0].get("domain", "unknown")
                subdomain = vuln_records[0].get("subdomain", domain)
        return self.add("evidence", {
            "finding_id": finding_id,
            "type": evidence_type,
            "path": path,
            "domain": domain,
            "subdomain": subdomain,
            **kwargs,
        })

    def get_evidence(self, finding_id: str) -> List[dict]:
        return self.query("evidence", finding_id=finding_id)

    # ------------------------------------------------------------------
    # PoC result methods
    # ------------------------------------------------------------------
    def add_poc_result(self, finding_id: str, poc_mode: str, verified: bool,
                       payload: str, **kwargs) -> dict:
        return self.add("poc_results", {
            "finding_id": finding_id,
            "poc_mode": poc_mode,
            "verified_poc": verified,
            "payload": payload,
            **kwargs,
        })

    def get_poc_results(self, verified: Optional[bool] = None) -> List[dict]:
        if verified is not None:
            return self.query("poc_results", verified_poc=verified)
        return self.get_all("poc_results")

    # ------------------------------------------------------------------
    # Attack path methods
    # ------------------------------------------------------------------
    def add_attack_path(self, name: str, steps: List[dict], impact: str, **kwargs) -> dict:
        return self.add("attack_paths", {
            "name": name,
            "steps": steps,
            "impact": impact,
            **kwargs,
        })

    def get_attack_paths(self) -> List[dict]:
        return self.get_all("attack_paths")

    # ------------------------------------------------------------------
    # Summary / stats
    # ------------------------------------------------------------------
    def summary(self) -> dict:
        vuln_by_sev = {}
        for v in self.get_all("vulnerabilities"):
            sev = v.get("severity", "unknown")
            vuln_by_sev[sev] = vuln_by_sev.get(sev, 0) + 1

        return {
            "assets": self.count("assets"),
            "endpoints": self.count("endpoints"),
            "vulnerabilities": self.count("vulnerabilities"),
            "vulnerabilities_by_severity": vuln_by_sev,
            "poc_results": self.count("poc_results"),
            "poc_verified": self.count("poc_results", verified_poc=True),
            "evidence": self.count("evidence"),
            "attack_paths": self.count("attack_paths"),
        }
