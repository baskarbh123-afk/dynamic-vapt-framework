"""
core/evidence_store.py

Evidence management system for the AI Pentesting Platform.
Handles structured storage of: screenshots, HTTP request/response logs,
HAR files, payload results, and auto-generated PoC scripts.

Supports local filesystem storage with optional S3/MinIO backend.
Evidence is organized by: tenant → engagement → finding → evidence type.

Architecture reference: ARCHITECTURE.md § 9 "Evidence Collection System"
"""

import base64
import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class HttpCapture:
    """Raw HTTP request + response pair."""
    request_method: str
    request_url: str
    request_headers: dict[str, str]
    request_body: str
    response_status: int
    response_headers: dict[str, str]
    response_body: str
    duration_ms: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_text(self) -> str:
        """Format as readable HTTP log."""
        lines = [
            f"=== REQUEST [{self.timestamp}] ===",
            f"{self.request_method} {self.request_url}",
        ]
        for k, v in self.request_headers.items():
            lines.append(f"{k}: {v}")
        if self.request_body:
            lines.extend(["", self.request_body])

        lines.extend([
            "",
            f"=== RESPONSE [{self.response_status}] ({self.duration_ms}ms) ===",
        ])
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {v}")
        if self.response_body:
            lines.extend(["", self.response_body[:5000]])  # Cap body at 5KB
        return "\n".join(lines)


@dataclass
class ValidationAttempt:
    """Single PoC validation attempt record."""
    attempt_number: int
    success: bool
    duration_ms: int
    request_hash: str = ""
    response_hash: str = ""
    evidence_files: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class EvidencePackage:
    """
    Complete evidence package for one finding.
    Contains all artifacts needed to reproduce and prove the vulnerability.
    """
    finding_id: str
    engagement_id: str
    tenant_id: str
    vuln_type: str
    endpoint: str
    payload_used: str
    validation_mode: str  # "terminal" or "browser"
    attempts: list[ValidationAttempt] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)  # file paths
    http_logs: list[str] = field(default_factory=list)    # file paths
    har_file: Optional[str] = None
    poc_script: Optional[str] = None
    annotations: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    @property
    def success_rate(self) -> float:
        if not self.attempts:
            return 0.0
        successes = sum(1 for a in self.attempts if a.success)
        return successes / len(self.attempts)

    @property
    def confidence(self) -> float:
        """Compute confidence score from evidence richness."""
        score = self.success_rate * 0.5
        evidence_types = sum([
            bool(self.screenshots),
            bool(self.http_logs),
            bool(self.har_file),
            bool(self.poc_script),
        ])
        score += (evidence_types / 4) * 0.3
        reproducibility = min(len(self.attempts) / 3, 1.0) * 0.2
        score += reproducibility
        return round(score, 3)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "engagement_id": self.engagement_id,
            "tenant_id": self.tenant_id,
            "vulnerability_type": self.vuln_type,
            "endpoint": self.endpoint,
            "payload_used": self.payload_used,
            "validation_mode": self.validation_mode,
            "validation_timestamp": self.created_at,
            "attempts": [
                {
                    "attempt_number": a.attempt_number,
                    "success": a.success,
                    "duration_ms": a.duration_ms,
                    "request_hash": a.request_hash,
                    "response_hash": a.response_hash,
                    "evidence_files": a.evidence_files,
                    "error": a.error,
                }
                for a in self.attempts
            ],
            "success_rate": self.success_rate,
            "confidence": self.confidence,
            "screenshots": self.screenshots,
            "http_logs": self.http_logs,
            "har_file": self.har_file,
            "poc_script": self.poc_script,
            "annotations": self.annotations,
        }


# ------------------------------------------------------------------
# Storage backend
# ------------------------------------------------------------------

class LocalStorage:
    """Local filesystem evidence storage."""

    def __init__(self, base_dir: str):
        self.base = Path(base_dir)

    def path(self, *parts: str) -> Path:
        p = self.base.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write(self, rel_path: str, content: Union[str, bytes]) -> str:
        """Write content to rel_path, return absolute path string."""
        target = self.path(rel_path)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(target, mode) as f:
            f.write(content)
        return str(target)

    def read(self, rel_path: str) -> Optional[str]:
        target = self.base / rel_path
        if not target.exists():
            return None
        return target.read_text()

    def exists(self, rel_path: str) -> bool:
        return (self.base / rel_path).exists()

    def list(self, rel_dir: str) -> list[str]:
        d = self.base / rel_dir
        if not d.exists():
            return []
        return [str(p.relative_to(self.base)) for p in d.iterdir() if p.is_file()]


# ------------------------------------------------------------------
# Main evidence store
# ------------------------------------------------------------------

class EvidenceStore:
    """
    Central evidence management system.

    Directory layout:
        evidence/
        └── {tenant_id}/
            └── {engagement_id}/
                └── {finding_id}/
                    ├── screenshots/
                    │   ├── initial_state.png
                    │   ├── exploitation.png
                    ├── http_logs/
                    │   ├── attempt_1/
                    │   │   ├── request.txt
                    │   │   └── response.txt
                    ├── har/
                    │   └── session.har
                    ├── payload_results/
                    │   └── validation.json
                    └── poc_script/
                        └── reproduce.sh
    """

    def __init__(
        self,
        base_dir: str = "evidence",
        tenant_id: str = "default",
        engagement_id: str = "engagement-001",
    ):
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id
        self._storage = LocalStorage(base_dir)
        self._packages: dict[str, EvidencePackage] = {}
        self._index_file = f"{tenant_id}/{engagement_id}/evidence_index.json"
        self._load_index()

    # ------------------------------------------------------------------
    # Package management
    # ------------------------------------------------------------------

    def create_package(
        self,
        finding_id: str,
        vuln_type: str,
        endpoint: str,
        payload_used: str,
        validation_mode: str = "terminal",
    ) -> EvidencePackage:
        """Create and register a new evidence package for a finding."""
        package = EvidencePackage(
            finding_id=finding_id,
            engagement_id=self.engagement_id,
            tenant_id=self.tenant_id,
            vuln_type=vuln_type,
            endpoint=endpoint,
            payload_used=payload_used,
            validation_mode=validation_mode,
        )
        self._packages[finding_id] = package
        return package

    def get_package(self, finding_id: str) -> Optional[EvidencePackage]:
        return self._packages.get(finding_id)

    # ------------------------------------------------------------------
    # Evidence writing
    # ------------------------------------------------------------------

    def save_screenshot(
        self,
        finding_id: str,
        image_data: bytes,
        label: str = "screenshot",
        annotate: bool = True,
    ) -> str:
        """
        Save a PNG screenshot. Returns the relative file path.
        """
        filename = f"{label}_{int(time.time())}.png"
        rel_path = self._rel(finding_id, "screenshots", filename)
        saved_path = self._storage.write(rel_path, image_data)

        package = self._packages.get(finding_id)
        if package:
            package.screenshots.append(saved_path)
            self._save_index()

        logger.debug(f"[EvidenceStore] Screenshot saved: {saved_path}")
        return saved_path

    def save_http_log(
        self,
        finding_id: str,
        capture: HttpCapture,
        attempt_number: int = 1,
    ) -> tuple[str, str]:
        """
        Save HTTP request and response as separate text files.
        Returns (request_path, response_path).
        """
        base = f"http_logs/attempt_{attempt_number}"
        req_path = self._storage.write(
            self._rel(finding_id, base, "request.txt"),
            self._format_request(capture),
        )
        resp_path = self._storage.write(
            self._rel(finding_id, base, "response.txt"),
            self._format_response(capture),
        )

        package = self._packages.get(finding_id)
        if package:
            package.http_logs.extend([req_path, resp_path])
            self._save_index()

        return req_path, resp_path

    def save_har(self, finding_id: str, har_data: dict) -> str:
        """Save a HAR (HTTP Archive) JSON file."""
        rel_path = self._rel(finding_id, "har", "session.har")
        saved_path = self._storage.write(rel_path, json.dumps(har_data, indent=2))

        package = self._packages.get(finding_id)
        if package:
            package.har_file = saved_path
            self._save_index()

        return saved_path

    def save_validation_result(
        self,
        finding_id: str,
        result: dict,
    ) -> str:
        """Save structured JSON validation result."""
        rel_path = self._rel(finding_id, "payload_results", "validation.json")
        return self._storage.write(rel_path, json.dumps(result, indent=2))

    def save_poc_script(
        self,
        finding_id: str,
        vuln_type: str,
        endpoint: str,
        payload: str,
        http_capture: Optional[HttpCapture] = None,
        notes: str = "",
    ) -> str:
        """
        Auto-generate and save a self-contained PoC shell script.
        The script uses only curl — no tool dependencies.
        """
        script = self._generate_poc_script(
            finding_id, vuln_type, endpoint, payload, http_capture, notes
        )
        rel_path = self._rel(finding_id, "poc_script", "reproduce.sh")
        saved_path = self._storage.write(rel_path, script)

        package = self._packages.get(finding_id)
        if package:
            package.poc_script = saved_path
            self._save_index()

        return saved_path

    def record_attempt(
        self,
        finding_id: str,
        attempt: ValidationAttempt,
    ):
        """Record a validation attempt in the package."""
        package = self._packages.get(finding_id)
        if package:
            package.attempts.append(attempt)
            self._save_index()

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_evidence_summary(self, finding_id: str) -> dict:
        """Return a compact evidence summary for inclusion in reports."""
        package = self._packages.get(finding_id)
        if not package:
            return {}
        return {
            "finding_id": finding_id,
            "confidence": package.confidence,
            "success_rate": package.success_rate,
            "screenshot_count": len(package.screenshots),
            "http_log_count": len(package.http_logs) // 2,
            "has_har": bool(package.har_file),
            "has_poc_script": bool(package.poc_script),
            "primary_screenshot": package.screenshots[0] if package.screenshots else None,
            "poc_script": package.poc_script,
        }

    def list_all_packages(self) -> list[EvidencePackage]:
        return list(self._packages.values())

    # ------------------------------------------------------------------
    # PoC Script generation
    # ------------------------------------------------------------------

    def _generate_poc_script(
        self,
        finding_id: str,
        vuln_type: str,
        endpoint: str,
        payload: str,
        capture: Optional[HttpCapture],
        notes: str,
    ) -> str:
        method = capture.request_method if capture else "GET"
        headers = capture.request_headers if capture else {}
        body = capture.request_body if capture else ""

        header_flags = " ".join(
            f'-H "{k}: {v}"'
            for k, v in headers.items()
            if k.lower() not in ("host", "content-length")
        )
        data_flag = f"--data '{body}'" if body else ""

        script = f"""#!/usr/bin/env bash
# ================================================================
# Proof of Concept: {vuln_type}
# Finding ID: {finding_id}
# Endpoint: {endpoint}
# Generated: {datetime.utcnow().isoformat()}Z
# ================================================================
#
# DESCRIPTION:
# This script reproduces the {vuln_type} vulnerability.
# Run it to verify the finding.
#
# PREREQUISITES:
# - curl installed
# - Replace <AUTH_TOKEN> with a valid session token
# - Target must be in authorized scope
#
# EXPECTED RESULT:
# {self._expected_result(vuln_type)}
#
{notes}
# ================================================================

set -euo pipefail

TARGET="{endpoint}"
PAYLOAD='{payload}'

echo "[*] Testing {vuln_type} on $TARGET"
echo "[*] Payload: $PAYLOAD"
echo ""

# Step 1: Baseline request
echo "[1/2] Sending baseline request..."
curl -sk -o /dev/null -w "Status: %{{http_code}} | Time: %{{time_total}}s\\n" \\
  {header_flags} \\
  "{endpoint}"

echo ""

# Step 2: Exploit request with payload
echo "[2/2] Sending exploit request..."
curl -sk -i \\
  {header_flags} \\
  {data_flag} \\
  "{endpoint}"

echo ""
echo "[*] Compare the two responses above."
echo "[*] {self._expected_result(vuln_type)}"
"""
        return script

    @staticmethod
    def _expected_result(vuln_type: str) -> str:
        mapping = {
            "IDOR": "Step 2 should return another user's data.",
            "XSS": "Step 2 should show the payload reflected/executed.",
            "SQLi": "Step 2 should show a DB error or time delay.",
            "SSRF": "Check your OOB listener for an incoming request.",
            "CORS": "Response should include Access-Control-Allow-Origin: attacker.com",
            "PATH_TRAVERSAL": "Response body should contain /etc/passwd content.",
            "COMMAND_INJECTION": "Check OOB listener or look for time delay.",
        }
        return mapping.get(vuln_type, "Verify the vulnerability is present in the response.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _rel(self, finding_id: str, *sub: str) -> str:
        parts = [self.tenant_id, self.engagement_id, finding_id] + list(sub)
        return "/".join(parts)

    @staticmethod
    def _format_request(capture: HttpCapture) -> str:
        lines = [f"{capture.request_method} {capture.request_url} HTTP/1.1"]
        for k, v in capture.request_headers.items():
            lines.append(f"{k}: {v}")
        if capture.request_body:
            lines.extend(["", capture.request_body])
        return "\n".join(lines)

    @staticmethod
    def _format_response(capture: HttpCapture) -> str:
        lines = [f"HTTP/1.1 {capture.response_status}"]
        for k, v in capture.response_headers.items():
            lines.append(f"{k}: {v}")
        if capture.response_body:
            lines.extend(["", capture.response_body[:10000]])
        return "\n".join(lines)

    def _load_index(self):
        raw = self._storage.read(self._index_file)
        if raw:
            try:
                data = json.loads(raw)
                for pkg_data in data.get("packages", []):
                    fid = pkg_data.get("finding_id", "")
                    attempts = [ValidationAttempt(**a) for a in pkg_data.pop("attempts", [])]
                    pkg = EvidencePackage(**{
                        k: v for k, v in pkg_data.items()
                        if k in EvidencePackage.__dataclass_fields__
                    })
                    pkg.attempts = attempts
                    self._packages[fid] = pkg
            except Exception as e:
                logger.debug(f"[EvidenceStore] Index load error: {e}")

    def _save_index(self):
        data = {
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "packages": [p.to_dict() for p in self._packages.values()],
        }
        self._storage.write(self._index_file, json.dumps(data, indent=2))
