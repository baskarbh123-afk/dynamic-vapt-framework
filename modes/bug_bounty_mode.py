"""
modes/bug_bounty_mode.py

Bug Bounty Hunter Mode — optimized scan configuration for bug bounty programs.
Differs from enterprise pentesting in: scope handling, target prioritization,
vulnerability focus, deduplication logic, and output format.

Architecture reference: ARCHITECTURE.md § 13 "Bug Bounty Hunter Mode"
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Mode configuration
# ------------------------------------------------------------------

@dataclass
class BugBountyConfig:
    """
    Bug Bounty mode parameters. Loaded from config.yaml or instantiated directly.
    """
    program_name: str
    platform: str = "hackerone"          # hackerone | bugcrowd | intigriti | self-hosted
    program_url: str = ""

    # Scan strategy
    scan_strategy: str = "high_value_first"  # high_value_first | comprehensive | stealth
    max_subdomains: int = 50_000
    js_analysis_depth: str = "deep"          # deep | standard | quick
    parameter_mining: str = "aggressive"     # aggressive | standard | passive

    # Vulnerability priorities (what to look for first)
    priority_vuln_types: list[str] = field(default_factory=lambda: [
        "IDOR", "SSRF", "RCE", "AUTH_BYPASS", "ACCOUNT_TAKEOVER",
        "SQLI", "STORED_XSS", "JWT", "MASS_ASSIGNMENT", "OPEN_REDIRECT",
    ])

    # Deprioritized (low reward, often out of scope on most programs)
    deprioritized_vuln_types: list[str] = field(default_factory=lambda: [
        "MISSING_SECURITY_HEADERS",
        "SELF_XSS",
        "RATE_LIMITING_COSMETIC",
        "SSL_WEAK_CIPHER",
        "CLICKJACKING_NO_SENSITIVE_ACTION",
        "INFORMATION_DISCLOSURE_PUBLIC",
    ])

    # Deduplication
    dedup_enabled: bool = True
    dedup_sources: list[str] = field(default_factory=lambda: [
        "hackerone_disclosed", "local_history",
    ])

    # Continuous monitoring
    monitor_enabled: bool = True
    monitor_interval_hours: float = 6.0

    @classmethod
    def from_config(cls, config: dict) -> "BugBountyConfig":
        bb = config.get("bug_bounty", {})
        return cls(
            program_name=bb.get("program", "unknown"),
            platform=bb.get("platform", "hackerone"),
            program_url=bb.get("program_url", ""),
            scan_strategy=bb.get("scan_strategy", "high_value_first"),
            max_subdomains=bb.get("max_subdomains", 50_000),
            js_analysis_depth=bb.get("js_analysis", "deep"),
            parameter_mining=bb.get("parameter_mining", "aggressive"),
            priority_vuln_types=bb.get("priority_findings", [
                "IDOR", "SSRF", "RCE", "AUTH_BYPASS", "ACCOUNT_TAKEOVER",
                "SQLI", "STORED_XSS",
            ]),
            deprioritized_vuln_types=bb.get("deprioritized", []),
            dedup_enabled=bb.get("dedup_check", {}).get("enabled", True),
            monitor_interval_hours=float(bb.get("monitor_interval_hours", 6)),
        )


# ------------------------------------------------------------------
# High-value target scorer
# ------------------------------------------------------------------

class TargetScorer:
    """
    Scores and ranks discovered endpoints by their bug bounty value.
    High-value targets get deeper scanning first.
    """

    # Path patterns that tend to have high-reward vulnerabilities
    HIGH_VALUE_PATHS: list[tuple[str, int]] = [
        (r"/admin", 100),
        (r"/api/v\d", 90),
        (r"/internal", 90),
        (r"/payment|/checkout|/billing|/subscription", 95),
        (r"/account|/user|/profile|/me", 85),
        (r"/upload|/import|/export", 80),
        (r"/webhook|/callback|/notify|/hook", 80),
        (r"/oauth|/auth|/sso|/login", 85),
        (r"/graphql|/gql", 85),
        (r"/debug|/console|/metrics|/health", 70),
        (r"/reset|/forgot|/recover", 75),
        (r"\?.*id=|\?.*uid=|\?.*user_id=", 90),
        (r"\?.*url=|\?.*redirect=|\?.*callback=", 85),
        (r"\?.*file=|\?.*path=|\?.*template=", 80),
        (r"\?.*token=|\?.*jwt=|\?.*session=", 85),
    ]

    LOW_VALUE_PATHS: list[str] = [
        r"/static/", r"/assets/", r"/images/", r"/fonts/",
        r"/css/", r"/js/vendor/", r"/node_modules/",
        r"\.min\.", r"/cdn-cgi/", r"/wp-admin/", r"/wp-content/",
    ]

    def score(self, url: str, is_new_asset: bool = False) -> int:
        """
        Score an endpoint from 0-100. Higher = more likely to have high-reward bug.
        New assets get a bonus (+20) in bug bounty mode.
        """
        score = 50  # Baseline

        # Low-value path penalty
        for pattern in self.LOW_VALUE_PATHS:
            if re.search(pattern, url, re.IGNORECASE):
                score -= 30
                break

        # High-value path bonuses
        for pattern, points in self.HIGH_VALUE_PATHS:
            if re.search(pattern, url, re.IGNORECASE):
                score = max(score, points)
                break

        # New asset bonus (unexplored = higher chance of bugs)
        if is_new_asset:
            score = min(score + 20, 100)

        return max(0, min(score, 100))

    def rank_endpoints(
        self,
        endpoints: list[str],
        new_endpoints: set[str] = None,
    ) -> list[tuple[str, int]]:
        """
        Rank endpoints by bug bounty value.
        Returns list of (url, score) sorted descending.
        """
        new = new_endpoints or set()
        scored = [(ep, self.score(ep, is_new_asset=(ep in new))) for ep in endpoints]
        return sorted(scored, key=lambda x: x[1], reverse=True)


# ------------------------------------------------------------------
# Deduplication engine
# ------------------------------------------------------------------

@dataclass
class DuplicateCheckResult:
    is_duplicate: bool
    similarity: float           # 0.0-1.0
    matched_report: Optional[str] = None
    source: Optional[str] = None


class DeduplicationEngine:
    """
    Checks findings against:
    1. Local submission history (previous reports in this session)
    2. HackerOne disclosed reports (cached)
    3. CVE/NVD database references
    4. Fuzzy text matching
    """

    SIMILARITY_THRESHOLD = 0.80  # 80% similarity = duplicate

    def __init__(self, data_dir: str = "data"):
        self._data_dir = Path(data_dir)
        self._local_history_file = self._data_dir / "bb_submission_history.json"
        self._local_history: list[dict] = self._load_local_history()
        self._disclosed_cache: list[dict] = []  # Populated from HackerOne API

    def check(self, finding: dict) -> DuplicateCheckResult:
        """
        Check if a finding is a duplicate.
        Returns DuplicateCheckResult.
        """
        # Check local history first (fast)
        local_result = self._check_local(finding)
        if local_result.is_duplicate:
            return local_result

        # Check disclosed cache
        disclosed_result = self._check_disclosed(finding)
        if disclosed_result.is_duplicate:
            return disclosed_result

        return DuplicateCheckResult(is_duplicate=False, similarity=0.0)

    def record_submission(self, finding: dict):
        """Record a submitted finding to local history."""
        record = {
            "finding_id": finding.get("id", ""),
            "title": finding.get("title", ""),
            "vuln_type": finding.get("type", ""),
            "endpoint": finding.get("endpoint", ""),
            "fingerprint": self._fingerprint(finding),
            "submitted_at": datetime.utcnow().isoformat() + "Z",
        }
        self._local_history.append(record)
        self._save_local_history()

    def _check_local(self, finding: dict) -> DuplicateCheckResult:
        fp = self._fingerprint(finding)
        for record in self._local_history:
            if record.get("fingerprint") == fp:
                return DuplicateCheckResult(
                    is_duplicate=True,
                    similarity=1.0,
                    matched_report=record.get("finding_id"),
                    source="local_history",
                )
        # Fuzzy check
        title = finding.get("title", "").lower()
        endpoint = finding.get("endpoint", "").lower()
        for record in self._local_history:
            sim = self._similarity(
                title + " " + endpoint,
                record.get("title", "").lower() + " " + record.get("endpoint", "").lower(),
            )
            if sim >= self.SIMILARITY_THRESHOLD:
                return DuplicateCheckResult(
                    is_duplicate=True,
                    similarity=sim,
                    matched_report=record.get("finding_id"),
                    source="local_history_fuzzy",
                )
        return DuplicateCheckResult(is_duplicate=False, similarity=0.0)

    def _check_disclosed(self, finding: dict) -> DuplicateCheckResult:
        if not self._disclosed_cache:
            return DuplicateCheckResult(is_duplicate=False, similarity=0.0)

        title = finding.get("title", "").lower()
        for report in self._disclosed_cache:
            sim = self._similarity(title, report.get("title", "").lower())
            if sim >= self.SIMILARITY_THRESHOLD:
                return DuplicateCheckResult(
                    is_duplicate=True,
                    similarity=sim,
                    matched_report=report.get("id"),
                    source="hackerone_disclosed",
                )
        return DuplicateCheckResult(is_duplicate=False, similarity=0.0)

    @staticmethod
    def _fingerprint(finding: dict) -> str:
        """Generate a stable fingerprint for deduplication."""
        key = (
            finding.get("type", "") + "|"
            + finding.get("endpoint", "").split("?")[0] + "|"
            + finding.get("parameter", "")
        )
        return hashlib.md5(key.lower().encode()).hexdigest()

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        """
        Simple token-based Jaccard similarity.
        Fast enough for local dedup without external libraries.
        """
        if not a or not b:
            return 0.0
        tokens_a = set(re.findall(r'\w+', a.lower()))
        tokens_b = set(re.findall(r'\w+', b.lower()))
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)

    def _load_local_history(self) -> list[dict]:
        if self._local_history_file.exists():
            try:
                with open(self._local_history_file) as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_local_history(self):
        with open(self._local_history_file, "w") as f:
            json.dump(self._local_history, f, indent=2)


# ------------------------------------------------------------------
# Bug Bounty submission queue
# ------------------------------------------------------------------

@dataclass
class SubmissionItem:
    """A finding ready for bug bounty platform submission."""
    finding: dict
    platform: str
    formatted_report: str
    priority_score: int
    is_duplicate: bool = False
    duplicate_info: Optional[DuplicateCheckResult] = None
    submitted: bool = False
    submitted_at: Optional[str] = None
    platform_id: Optional[str] = None


class SubmissionQueue:
    """
    Manages bug bounty findings ready for submission.
    Applies deduplication and priority ordering.
    """

    def __init__(self, bb_config: BugBountyConfig, data_dir: str = "data"):
        self.bb_config = bb_config
        self._scorer = TargetScorer()
        self._dedup = DeduplicationEngine(data_dir)
        self._queue: list[SubmissionItem] = []
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(exist_ok=True)

    def add_finding(self, finding: dict, formatted_report: str) -> SubmissionItem:
        """Add a finding to the submission queue after dedup check."""
        dedup_result = self._dedup.check(finding)
        priority_score = self._scorer.score(finding.get("endpoint", ""))

        # Apply vuln type priority bonus
        vuln_type = finding.get("type", "")
        if vuln_type in self.bb_config.priority_vuln_types:
            priority_score = min(priority_score + 20, 100)
        elif vuln_type in self.bb_config.deprioritized_vuln_types:
            priority_score = max(priority_score - 30, 0)

        item = SubmissionItem(
            finding=finding,
            platform=self.bb_config.platform,
            formatted_report=formatted_report,
            priority_score=priority_score,
            is_duplicate=dedup_result.is_duplicate,
            duplicate_info=dedup_result,
        )

        self._queue.append(item)

        if dedup_result.is_duplicate:
            logger.warning(
                f"[SubmissionQueue] DUPLICATE detected: {finding.get('title', '')} "
                f"(similarity={dedup_result.similarity:.0%}, source={dedup_result.source})"
            )
        else:
            logger.info(
                f"[SubmissionQueue] Added: {finding.get('title', '')} "
                f"(priority={priority_score})"
            )

        return item

    def get_submission_order(self, exclude_duplicates: bool = True) -> list[SubmissionItem]:
        """Return findings sorted by priority, optionally excluding duplicates."""
        items = self._queue
        if exclude_duplicates:
            items = [i for i in items if not i.is_duplicate]
        return sorted(items, key=lambda x: x.priority_score, reverse=True)

    def mark_submitted(self, item: SubmissionItem, platform_id: str):
        """Record a successful platform submission."""
        item.submitted = True
        item.submitted_at = datetime.utcnow().isoformat() + "Z"
        item.platform_id = platform_id
        self._dedup.record_submission(item.finding)
        self._save()
        logger.info(
            f"[SubmissionQueue] Submitted {item.finding.get('title', '')} "
            f"→ {self.bb_config.platform} ID: {platform_id}"
        )

    def summary(self) -> dict:
        total = len(self._queue)
        duplicates = sum(1 for i in self._queue if i.is_duplicate)
        submitted = sum(1 for i in self._queue if i.submitted)
        pending = total - duplicates - submitted
        return {
            "total_findings": total,
            "duplicates_excluded": duplicates,
            "submitted": submitted,
            "pending_submission": pending,
            "platform": self.bb_config.platform,
            "program": self.bb_config.program_name,
        }

    def _save(self):
        output = self._data_dir / "bb_submission_queue.json"
        data = [
            {
                "finding_id": i.finding.get("id", ""),
                "title": i.finding.get("title", ""),
                "priority_score": i.priority_score,
                "is_duplicate": i.is_duplicate,
                "submitted": i.submitted,
                "platform_id": i.platform_id,
            }
            for i in self._queue
        ]
        with open(output, "w") as f:
            json.dump(data, f, indent=2)


# ------------------------------------------------------------------
# Mode activator
# ------------------------------------------------------------------

class BugBountyMode:
    """
    Entry point for Bug Bounty Hunter Mode.
    Configures the platform for bug bounty operation and returns
    the configured components.
    """

    def __init__(self, config: dict, data_dir: str = "data"):
        if config.get("mode") != "bug_bounty" and not config.get("bug_bounty"):
            logger.warning(
                "[BugBountyMode] Config mode is not 'bug_bounty'. "
                "Using default bug bounty settings."
            )
        self.bb_config = BugBountyConfig.from_config(config)
        self._data_dir = data_dir
        logger.info(
            f"[BugBountyMode] Activated for program: {self.bb_config.program_name} "
            f"on {self.bb_config.platform}"
        )

    def create_submission_queue(self) -> SubmissionQueue:
        return SubmissionQueue(self.bb_config, self._data_dir)

    def create_target_scorer(self) -> TargetScorer:
        return TargetScorer()

    def get_scan_config_overrides(self) -> dict:
        """
        Returns config overrides that adapt the main scan pipeline
        for bug bounty mode.
        """
        return {
            "scanning": {
                "max_subdomains": self.bb_config.max_subdomains,
                "js_analysis": self.bb_config.js_analysis_depth,
                "parameter_mining": self.bb_config.parameter_mining,
                "priority_vulns": self.bb_config.priority_vuln_types,
                "skip_vulns": self.bb_config.deprioritized_vuln_types,
            },
            "monitoring": {
                "enabled": self.bb_config.monitor_enabled,
                "interval_hours": self.bb_config.monitor_interval_hours,
                "alert_on_new_subdomain": True,
                "alert_on_new_endpoint": True,
                "alert_on_js_change": True,
            },
            "reporting": {
                "format": self.bb_config.platform,
                "dedup_enabled": self.bb_config.dedup_enabled,
            },
        }

    def is_priority_finding(self, vuln_type: str) -> bool:
        return vuln_type.upper() in [v.upper() for v in self.bb_config.priority_vuln_types]

    def is_deprioritized(self, vuln_type: str) -> bool:
        return vuln_type.upper() in [v.upper() for v in self.bb_config.deprioritized_vuln_types]
