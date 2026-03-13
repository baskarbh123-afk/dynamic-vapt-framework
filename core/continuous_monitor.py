"""
core/continuous_monitor.py

Continuous attack surface monitoring with delta detection.
Runs in a background loop, rescanning targets every N hours and
alerting on: new subdomains, new endpoints, changed content hashes,
new JS files, and parameter changes.

Architecture reference: ARCHITECTURE.md § 13 "Bug Bounty Hunter Mode"
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Snapshot structures
# ------------------------------------------------------------------

@dataclass
class AssetSnapshot:
    """Point-in-time snapshot of a discovered asset."""
    domain: str
    subdomains: set[str] = field(default_factory=set)
    endpoints: dict[str, str] = field(default_factory=dict)   # url → content_hash
    js_files: dict[str, str] = field(default_factory=dict)    # url → content_hash
    parameters: dict[str, list[str]] = field(default_factory=dict)  # url → [params]
    technologies: set[str] = field(default_factory=set)
    captured_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": list(self.subdomains),
            "endpoints": self.endpoints,
            "js_files": self.js_files,
            "parameters": self.parameters,
            "technologies": list(self.technologies),
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AssetSnapshot":
        snap = cls(domain=data.get("domain", ""))
        snap.subdomains = set(data.get("subdomains", []))
        snap.endpoints = data.get("endpoints", {})
        snap.js_files = data.get("js_files", {})
        snap.parameters = data.get("parameters", {})
        snap.technologies = set(data.get("technologies", []))
        snap.captured_at = data.get("captured_at", "")
        return snap


@dataclass
class DeltaEvent:
    """A change detected between two snapshots."""
    event_type: str          # new_subdomain | new_endpoint | changed_endpoint | new_js | new_param
    domain: str
    asset: str               # The specific asset that changed
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    priority: str = "medium" # high | medium | low
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "domain": self.domain,
            "asset": self.asset,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "priority": self.priority,
            "detected_at": self.detected_at,
        }

    def __str__(self) -> str:
        return f"[{self.priority.upper()}] {self.event_type}: {self.asset}"


# ------------------------------------------------------------------
# Delta detector
# ------------------------------------------------------------------

class DeltaDetector:
    """
    Compares two AssetSnapshots and returns all detected changes.
    New assets always get HIGH priority in bug bounty mode.
    """

    HIGH_VALUE_PATH_PATTERNS = [
        "/admin", "/api/", "/internal", "/debug", "/console",
        "/payment", "/checkout", "/billing", "/account", "/profile",
        "/webhook", "/callback", "/oauth", "/auth", "/graphql",
        "/upload", "/download", "/export", "/import",
    ]

    def diff(
        self,
        old: Optional[AssetSnapshot],
        new: AssetSnapshot,
        bug_bounty_mode: bool = False,
    ) -> list[DeltaEvent]:
        """
        Compare old and new snapshots.

        Args:
            old: Previous snapshot (None on first scan).
            new: Current snapshot.
            bug_bounty_mode: If True, new assets get highest priority.

        Returns:
            List of DeltaEvent objects sorted by priority.
        """
        events: list[DeltaEvent] = []

        if old is None:
            # First scan — everything is "new" but don't flood
            return events

        # New subdomains
        new_subs = new.subdomains - old.subdomains
        for sub in new_subs:
            priority = "high" if bug_bounty_mode else "medium"
            events.append(DeltaEvent(
                event_type="new_subdomain",
                domain=new.domain,
                asset=sub,
                priority=priority,
            ))

        # New endpoints
        new_eps = set(new.endpoints.keys()) - set(old.endpoints.keys())
        for ep in new_eps:
            priority = self._endpoint_priority(ep, bug_bounty_mode)
            events.append(DeltaEvent(
                event_type="new_endpoint",
                domain=new.domain,
                asset=ep,
                priority=priority,
            ))

        # Changed endpoint content hashes (updated pages)
        for url in set(new.endpoints.keys()) & set(old.endpoints.keys()):
            if new.endpoints[url] != old.endpoints[url]:
                events.append(DeltaEvent(
                    event_type="changed_endpoint",
                    domain=new.domain,
                    asset=url,
                    old_value=old.endpoints[url],
                    new_value=new.endpoints[url],
                    priority="medium",
                ))

        # New JS files (always HIGH priority — may expose new endpoints/secrets)
        new_js = set(new.js_files.keys()) - set(old.js_files.keys())
        for js_url in new_js:
            events.append(DeltaEvent(
                event_type="new_js_file",
                domain=new.domain,
                asset=js_url,
                priority="high" if bug_bounty_mode else "medium",
            ))

        # Changed JS files
        for js_url in set(new.js_files.keys()) & set(old.js_files.keys()):
            if new.js_files[js_url] != old.js_files[js_url]:
                events.append(DeltaEvent(
                    event_type="changed_js_file",
                    domain=new.domain,
                    asset=js_url,
                    priority="high",
                ))

        # New parameters on existing endpoints
        for url, params in new.parameters.items():
            old_params = set(old.parameters.get(url, []))
            new_params = set(params) - old_params
            for param in new_params:
                events.append(DeltaEvent(
                    event_type="new_parameter",
                    domain=new.domain,
                    asset=f"{url}?{param}=",
                    priority="high" if self._is_high_value_param(param) else "low",
                ))

        # Sort: high first
        priority_order = {"high": 0, "medium": 1, "low": 2}
        events.sort(key=lambda e: priority_order.get(e.priority, 2))
        return events

    def _endpoint_priority(self, url: str, bug_bounty_mode: bool) -> str:
        if bug_bounty_mode:
            for pattern in self.HIGH_VALUE_PATH_PATTERNS:
                if pattern in url.lower():
                    return "high"
        return "medium"

    @staticmethod
    def _is_high_value_param(param: str) -> bool:
        high_value = {
            "id", "user_id", "uid", "account_id", "customer_id",
            "url", "redirect", "callback", "next", "return",
            "file", "path", "template", "page",
            "cmd", "exec", "command",
            "token", "jwt", "session", "key",
        }
        return param.lower() in high_value or any(
            kw in param.lower() for kw in ["id", "url", "file", "cmd", "token"]
        )


# ------------------------------------------------------------------
# Snapshot store
# ------------------------------------------------------------------

class SnapshotStore:
    """Persists asset snapshots to disk for delta comparison."""

    def __init__(self, data_dir: str = "data/monitor"):
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, domain: str, snapshot: AssetSnapshot):
        path = self._dir / f"{self._safe(domain)}_latest.json"
        with open(path, "w") as f:
            json.dump(snapshot.to_dict(), f, indent=2)

    def load(self, domain: str) -> Optional[AssetSnapshot]:
        path = self._dir / f"{self._safe(domain)}_latest.json"
        if not path.exists():
            return None
        try:
            with open(path) as f:
                return AssetSnapshot.from_dict(json.load(f))
        except Exception as e:
            logger.warning(f"[SnapshotStore] Load failed for {domain}: {e}")
            return None

    def archive(self, domain: str, snapshot: AssetSnapshot):
        """Archive snapshot with timestamp (historical record)."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = self._dir / f"{self._safe(domain)}_{ts}.json"
        with open(path, "w") as f:
            json.dump(snapshot.to_dict(), f, indent=2)

    @staticmethod
    def _safe(domain: str) -> str:
        return domain.replace(".", "_").replace("*", "wildcard")


# ------------------------------------------------------------------
# Continuous monitor
# ------------------------------------------------------------------

class ContinuousMonitor:
    """
    Runs the recon pipeline on a schedule and emits delta events
    when new attack surface is discovered.

    Usage:
        monitor = ContinuousMonitor(
            config=config,
            scan_fn=run_recon_stage,
            interval_hours=6,
            bug_bounty_mode=True,
            on_delta=handle_delta,
        )
        await monitor.start()       # runs forever (call stop() to halt)
    """

    def __init__(
        self,
        config: dict,
        scan_fn: Callable[[str], "Coroutine[AssetSnapshot]"],
        interval_hours: float = 6.0,
        bug_bounty_mode: bool = False,
        on_delta: Optional[Callable[[list[DeltaEvent]], None]] = None,
        data_dir: str = "data/monitor",
    ):
        self.config = config
        self._scan_fn = scan_fn
        self._interval = interval_hours * 3600
        self._bug_bounty = bug_bounty_mode
        self._on_delta = on_delta
        self._store = SnapshotStore(data_dir)
        self._detector = DeltaDetector()
        self._targets = self._load_targets()
        self._running = False
        self._cycle_count = 0
        self._log_dir = Path("logs")
        self._log_dir.mkdir(exist_ok=True)

    def _load_targets(self) -> list[str]:
        target = self.config.get("target", {})
        targets = [target.get("domain", "")]
        additional = self.config.get("scope", {}).get("in_scope", [])
        targets.extend([t for t in additional if "." in t and not t.startswith("http")])
        return [t for t in targets if t]

    async def start(self):
        """Start the continuous monitoring loop."""
        self._running = True
        logger.info(
            f"[ContinuousMonitor] Starting — targets={self._targets}, "
            f"interval={self._interval/3600:.1f}h, bug_bounty={self._bug_bounty}"
        )
        while self._running:
            await self._run_cycle()
            if self._running:
                logger.info(
                    f"[ContinuousMonitor] Cycle {self._cycle_count} complete. "
                    f"Sleeping {self._interval/3600:.1f}h..."
                )
                await asyncio.sleep(self._interval)

    def stop(self):
        """Stop the monitoring loop."""
        self._running = False
        logger.info("[ContinuousMonitor] Stop requested.")

    async def run_once(self) -> list[DeltaEvent]:
        """Run a single monitoring cycle and return all deltas."""
        return await self._run_cycle()

    async def _run_cycle(self) -> list[DeltaEvent]:
        self._cycle_count += 1
        all_deltas: list[DeltaEvent] = []
        cycle_start = datetime.utcnow().isoformat() + "Z"

        logger.info(f"[ContinuousMonitor] Cycle {self._cycle_count} starting at {cycle_start}")

        for domain in self._targets:
            try:
                logger.info(f"[ContinuousMonitor] Scanning {domain}...")
                new_snapshot: AssetSnapshot = await self._scan_fn(domain)

                old_snapshot = self._store.load(domain)
                deltas = self._detector.diff(old_snapshot, new_snapshot, self._bug_bounty)

                if deltas:
                    logger.info(
                        f"[ContinuousMonitor] {len(deltas)} delta(s) on {domain}: "
                        + ", ".join(str(d) for d in deltas[:5])
                    )
                    all_deltas.extend(deltas)
                    self._log_deltas(domain, deltas)
                    if self._on_delta:
                        self._on_delta(deltas)

                # Archive old snapshot, save new
                if old_snapshot:
                    self._store.archive(domain, old_snapshot)
                self._store.save(domain, new_snapshot)

            except Exception as e:
                logger.error(f"[ContinuousMonitor] Error scanning {domain}: {e}")

        return all_deltas

    def _log_deltas(self, domain: str, deltas: list[DeltaEvent]):
        """Append delta events to log file."""
        log_file = self._log_dir / "monitor_deltas.jsonl"
        with open(log_file, "a") as f:
            for delta in deltas:
                f.write(json.dumps(delta.to_dict()) + "\n")

    def get_stats(self) -> dict:
        return {
            "cycles_completed": self._cycle_count,
            "targets": self._targets,
            "interval_hours": self._interval / 3600,
            "bug_bounty_mode": self._bug_bounty,
            "running": self._running,
        }


# ------------------------------------------------------------------
# Content hashing utilities
# ------------------------------------------------------------------

def hash_content(content: str) -> str:
    """SHA-256 hash of normalized content for delta comparison."""
    normalized = " ".join(content.split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def build_snapshot_from_kb(kb, domain: str) -> AssetSnapshot:
    """
    Build an AssetSnapshot from the current knowledge base state.
    Used to compare KB state between monitoring cycles.
    """
    snapshot = AssetSnapshot(domain=domain)

    for asset in kb.get_all("assets"):
        sub = asset.get("subdomain") or asset.get("domain", "")
        if sub and domain in sub:
            snapshot.subdomains.add(sub)
        if asset.get("type") == "technology":
            snapshot.technologies.add(asset.get("technology", ""))

    for endpoint in kb.get_all("endpoints"):
        url = endpoint.get("url", "")
        content_hash = hash_content(
            str(endpoint.get("status_code", "")) + str(endpoint.get("title", ""))
        )
        snapshot.endpoints[url] = content_hash

        if url.endswith(".js"):
            snapshot.js_files[url] = content_hash

        params = endpoint.get("parameters", [])
        if params:
            snapshot.parameters[url] = params

    return snapshot
