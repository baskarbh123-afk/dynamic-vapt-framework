"""
core/rate_limiter.py

Adaptive per-host rate limiter with token bucket algorithm.
Automatically backs off when WAF/rate-limit responses are detected (429, 503).
Tracks per-domain request windows and enforces engagement-level caps.

Architecture reference: ARCHITECTURE.md § 4 "Parallel Scanning Engine"
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

DEFAULT_RPS = 10.0       # Requests per second per host
BURST_MULTIPLIER = 2.0   # Allow 2× RPS in bursts
BACKOFF_FACTOR = 0.5     # Reduce RPS by 50% on 429
RECOVER_FACTOR = 1.1     # Increase RPS by 10% after 60s clean window
RECOVER_WINDOW = 60.0    # Seconds before attempting rate recovery
MIN_RPS = 0.5            # Never go below 1 req/2s
MAX_RPS = 100.0          # Hard cap


WAF_RESPONSE_CODES = {429, 503, 403, 503}
WAF_BACKOFF_CODES = {429, 503}   # Codes that trigger rate reduction


# ------------------------------------------------------------------
# Per-host token bucket
# ------------------------------------------------------------------

@dataclass
class HostBucket:
    """
    Token bucket for one host.
    Tokens refill at `rate` tokens/second, capped at `burst`.
    """
    host: str
    rate: float = DEFAULT_RPS           # tokens per second
    burst: float = field(init=False)    # max tokens
    tokens: float = field(init=False)
    last_refill: float = field(default_factory=time.monotonic)
    last_429: float = 0.0
    last_recovery_check: float = field(default_factory=time.monotonic)
    total_requests: int = 0
    total_429s: int = 0

    def __post_init__(self):
        self.burst = self.rate * BURST_MULTIPLIER
        self.tokens = self.burst

    def consume(self) -> float:
        """
        Consume one token, blocking until available.
        Returns the wait time in seconds (0 if immediate).
        """
        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            self.total_requests += 1
            return 0.0
        else:
            wait = (1.0 - self.tokens) / self.rate
            self.tokens = 0.0
            self.total_requests += 1
            return wait

    def on_rate_limited(self):
        """Called when a 429/503 response is received. Back off."""
        self.last_429 = time.monotonic()
        self.total_429s += 1
        old_rate = self.rate
        self.rate = max(MIN_RPS, self.rate * BACKOFF_FACTOR)
        self.burst = self.rate * BURST_MULTIPLIER
        self.tokens = min(self.tokens, self.burst)
        logger.warning(
            f"[RateLimiter] Rate limited on {self.host}: "
            f"{old_rate:.1f} → {self.rate:.1f} rps"
        )

    def maybe_recover(self):
        """Gradually recover rate after a clean window."""
        now = time.monotonic()
        if now - self.last_recovery_check < RECOVER_WINDOW:
            return
        if now - self.last_429 < RECOVER_WINDOW:
            return
        self.last_recovery_check = now
        old_rate = self.rate
        self.rate = min(MAX_RPS, self.rate * RECOVER_FACTOR)
        self.burst = self.rate * BURST_MULTIPLIER
        if self.rate > old_rate:
            logger.debug(
                f"[RateLimiter] Recovery on {self.host}: "
                f"{old_rate:.2f} → {self.rate:.2f} rps"
            )

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.last_refill = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)


# ------------------------------------------------------------------
# Main rate limiter
# ------------------------------------------------------------------

class RateLimiter:
    """
    Thread-safe adaptive rate limiter.

    Usage (sync):
        limiter = RateLimiter(default_rps=10)
        limiter.wait("example.com")           # blocks if needed
        limiter.on_response("example.com", 429)  # record WAF hit

    Usage (async):
        await limiter.async_wait("example.com")
    """

    def __init__(
        self,
        default_rps: float = DEFAULT_RPS,
        per_host_overrides: Optional[dict[str, float]] = None,
    ):
        self.default_rps = default_rps
        self._per_host_overrides = per_host_overrides or {}
        self._buckets: dict[str, HostBucket] = {}
        self._lock = Lock()

    def _get_bucket(self, host: str) -> HostBucket:
        """Get or create a token bucket for the given host."""
        with self._lock:
            if host not in self._buckets:
                rate = self._per_host_overrides.get(host, self.default_rps)
                self._buckets[host] = HostBucket(host=host, rate=rate)
            return self._buckets[host]

    def wait(self, host: str) -> float:
        """
        Synchronously enforce rate limit for host.
        Returns actual wait time in seconds.
        """
        bucket = self._get_bucket(host)
        bucket.maybe_recover()
        wait_time = bucket.consume()
        if wait_time > 0:
            logger.debug(f"[RateLimiter] Waiting {wait_time:.2f}s for {host}")
            time.sleep(wait_time)
        return wait_time

    async def async_wait(self, host: str) -> float:
        """
        Asynchronously enforce rate limit for host.
        Returns actual wait time in seconds.
        """
        bucket = self._get_bucket(host)
        bucket.maybe_recover()
        wait_time = bucket.consume()
        if wait_time > 0:
            logger.debug(f"[RateLimiter] Async waiting {wait_time:.2f}s for {host}")
            await asyncio.sleep(wait_time)
        return wait_time

    def on_response(self, host: str, status_code: int):
        """
        Record an HTTP response for adaptive adjustment.
        Call this after every HTTP request.
        """
        bucket = self._get_bucket(host)
        if status_code in WAF_BACKOFF_CODES:
            bucket.on_rate_limited()

    def set_rate(self, host: str, rps: float):
        """Manually set rate for a specific host."""
        bucket = self._get_bucket(host)
        with self._lock:
            bucket.rate = max(MIN_RPS, min(MAX_RPS, rps))
            bucket.burst = bucket.rate * BURST_MULTIPLIER

    def stats(self) -> dict:
        """Return per-host statistics."""
        return {
            host: {
                "current_rps": round(bucket.rate, 2),
                "total_requests": bucket.total_requests,
                "total_429s": bucket.total_429s,
                "tokens_available": round(bucket.tokens, 2),
            }
            for host, bucket in self._buckets.items()
        }

    def reset(self, host: Optional[str] = None):
        """Reset rate limit state for a host or all hosts."""
        with self._lock:
            if host:
                self._buckets.pop(host, None)
            else:
                self._buckets.clear()


# ------------------------------------------------------------------
# Engagement-level rate cap (global guard)
# ------------------------------------------------------------------

class EngagementRateCap:
    """
    Global rate cap across all hosts in an engagement.
    Prevents the platform from overwhelming targets even if
    per-host limits haven't been hit.
    """

    def __init__(self, max_total_rps: float = 100.0):
        self.max_total_rps = max_total_rps
        self._global_bucket = HostBucket(host="__global__", rate=max_total_rps)
        self._lock = Lock()

    def wait(self):
        """Enforce global rate cap."""
        with self._lock:
            wait_time = self._global_bucket.consume()
        if wait_time > 0:
            time.sleep(wait_time)

    async def async_wait(self):
        with self._lock:
            wait_time = self._global_bucket.consume()
        if wait_time > 0:
            await asyncio.sleep(wait_time)
