"""
core/token_optimizer.py

LLM token consumption optimization strategies.
Reduces token usage by ~90% through context slicing, memory compression,
structured output formatting, and response caching.

Architecture reference: ARCHITECTURE.md § 5 "Token Optimization Strategy"

Token budget targets:
  Recon:           ~500 tokens  (1-2 LLM calls)
  Enumeration:     ~2,000       (5-10 calls)
  Vulnerability:   ~5,000       (20-40 calls)
  PoC Validation:  ~1,000       (2-5 calls)
  Attack Chain:    ~3,000       (10-15 calls)
  Report:          ~8,000       (3-5 calls)
  Total per engagement: ~20,000 tokens
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

MAX_CONTEXT_CHARS = 2000       # Max chars from an HTTP response for AI context
MAX_MEMORY_ENTRIES = 20        # Max agent memory entries before compression
CACHE_FILE = "data/llm_cache.json"
RELEVANT_HEADERS = {
    "content-type", "server", "x-frame-options", "x-content-type-options",
    "access-control-allow-origin", "access-control-allow-credentials",
    "authorization", "www-authenticate", "set-cookie",
    "x-powered-by", "cf-ray", "x-amz-cf-id", "x-ratelimit-limit",
    "strict-transport-security", "content-security-policy",
}


# ------------------------------------------------------------------
# Context Slicing
# ------------------------------------------------------------------

class ContextSlicer:
    """
    Reduces large HTTP responses/documents to minimal AI-relevant slices.
    Extracts only the signals relevant to the current analysis task.
    """

    @staticmethod
    def slice_http_response(
        status_code: int,
        headers: dict[str, str],
        body: str,
        task: str = "general",
        reflection_param: Optional[str] = None,
    ) -> dict:
        """
        Slice an HTTP response for AI context.

        Args:
            status_code: HTTP response code.
            headers: Response headers dict.
            body: Response body text.
            task: Analysis task hint (xss, sqli, ssrf, auth, general).
            reflection_param: If set, find where this string appears in body.

        Returns:
            Compact dict suitable for LLM context (~200 tokens typical).
        """
        slice_data: dict[str, Any] = {
            "status": status_code,
            "relevant_headers": ContextSlicer._filter_headers(headers),
        }

        # Body slice: first 500 chars + reflection location
        body_slice = body[:500] if body else ""
        if reflection_param and reflection_param in body:
            idx = body.index(reflection_param)
            start = max(0, idx - 100)
            end = min(len(body), idx + len(reflection_param) + 200)
            slice_data["reflection_context"] = body[start:end]
        else:
            slice_data["body_preview"] = body_slice

        # Task-specific extraction
        if task == "xss":
            slice_data["js_contexts"] = ContextSlicer._extract_js_contexts(body)
        elif task == "sqli":
            slice_data["db_error_hints"] = ContextSlicer._find_db_errors(body)
        elif task == "ssrf":
            slice_data["internal_references"] = ContextSlicer._find_internal_refs(body)
        elif task == "auth":
            slice_data["auth_tokens"] = ContextSlicer._find_auth_tokens(headers, body)

        return slice_data

    @staticmethod
    def slice_js_file(content: str, max_chars: int = 1000) -> dict:
        """Extract security-relevant signals from a JS file."""
        signals: dict[str, list[str]] = {
            "api_endpoints": [],
            "sinks": [],
            "secrets_hint": [],
        }

        # API endpoint patterns
        url_patterns = re.findall(
            r'(?:fetch|axios|xhr\.open)\s*\(\s*["\']([^"\']+)["\']', content
        )
        signals["api_endpoints"] = url_patterns[:20]

        # XSS sinks
        sink_patterns = re.findall(
            r'(innerHTML|outerHTML|document\.write|eval|location\.href|'
            r'setTimeout|setInterval|insertAdjacentHTML)\s*[=(]',
            content,
        )
        signals["sinks"] = list(set(sink_patterns))[:10]

        # Secret hints (patterns, not values)
        secret_types = []
        if re.search(r'(?i)(api[_-]?key|apikey)\s*[:=]', content):
            secret_types.append("api_key_pattern")
        if re.search(r'(?i)(secret|password|passwd|token)\s*[:=]', content):
            secret_types.append("credential_pattern")
        if re.search(r'(?i)(aws|gcp|azure).*?(key|secret|token)', content):
            secret_types.append("cloud_credential_pattern")
        signals["secrets_hint"] = secret_types

        return {
            "signals": signals,
            "file_size_chars": len(content),
            "preview": content[:200],
        }

    @staticmethod
    def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
        return {
            k.lower(): v for k, v in headers.items()
            if k.lower() in RELEVANT_HEADERS
        }

    @staticmethod
    def _extract_js_contexts(body: str) -> list[str]:
        """Find inline script contexts in HTML."""
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
        return [s[:100] for s in scripts[:3]]

    @staticmethod
    def _find_db_errors(body: str) -> list[str]:
        """Find database error message signatures in response body."""
        patterns = [
            r"You have an error in your SQL syntax",
            r"ORA-\d{5}",
            r"Microsoft OLE DB Provider",
            r"PostgreSQL.*ERROR",
            r"SQLite.*Error",
            r"mysql_fetch",
            r"Unclosed quotation mark",
            r"ODBC SQL Server Driver",
        ]
        found = []
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                # Return the surrounding context, not the full body
                start = max(0, match.start() - 30)
                end = min(len(body), match.end() + 100)
                found.append(body[start:end])
        return found[:3]

    @staticmethod
    def _find_internal_refs(body: str) -> list[str]:
        """Find internal hostnames or cloud metadata references."""
        patterns = [
            r'169\.254\.169\.254',
            r'metadata\.google\.internal',
            r'100\.100\.100\.200',
            r'(?:10|172|192)\.\d+\.\d+\.\d+',
            r'localhost:\d+',
        ]
        found = []
        for p in patterns:
            if re.search(p, body):
                found.append(p)
        return found

    @staticmethod
    def _find_auth_tokens(headers: dict[str, str], body: str) -> list[str]:
        """Note the presence (not value) of auth tokens."""
        tokens = []
        combined = " ".join(headers.values()) + body[:500]
        if re.search(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', combined):
            tokens.append("JWT_detected")
        if re.search(r'Bearer\s+\S+', combined, re.IGNORECASE):
            tokens.append("Bearer_token_detected")
        if re.search(r'session[_-]?id\s*=', combined, re.IGNORECASE):
            tokens.append("session_cookie_detected")
        return tokens


# ------------------------------------------------------------------
# Memory Compression
# ------------------------------------------------------------------

@dataclass
class AgentMemory:
    """
    Rolling window memory for an AI agent.
    Compresses old entries when the window exceeds max_entries.
    """
    agent_name: str
    max_entries: int = MAX_MEMORY_ENTRIES
    _entries: list[dict] = field(default_factory=list)
    _summaries: list[str] = field(default_factory=list)

    def add(self, entry: dict):
        """Add a memory entry (action result, finding, etc.)."""
        self._entries.append(entry)
        if len(self._entries) > self.max_entries:
            self._compress()

    def get_context(self) -> str:
        """Return compact memory context string for LLM prompt."""
        parts = []
        if self._summaries:
            parts.append("Previous actions summary:\n" + "\n".join(self._summaries))
        if self._entries:
            recent = self._entries[-5:]  # Only last 5 in full
            parts.append("Recent actions:\n" + json.dumps(recent, indent=2)[:800])
        return "\n\n".join(parts)

    def _compress(self):
        """Compress oldest half of entries into a summary."""
        half = len(self._entries) // 2
        to_compress = self._entries[:half]
        self._entries = self._entries[half:]

        # Simple rule-based summary (no LLM call for compression)
        counts: dict[str, int] = {}
        for entry in to_compress:
            action = entry.get("action", "unknown")
            counts[action] = counts.get(action, 0) + 1

        summary_parts = [f"Ran {count}× {action}" for action, count in counts.items()]
        self._summaries.append("; ".join(summary_parts))

        # Keep summaries manageable
        if len(self._summaries) > 5:
            self._summaries = self._summaries[-3:]

        logger.debug(f"[AgentMemory:{self.agent_name}] Compressed {half} entries")

    def clear(self):
        self._entries.clear()
        self._summaries.clear()


# ------------------------------------------------------------------
# Response Cache
# ------------------------------------------------------------------

class LLMResponseCache:
    """
    Caches LLM responses by prompt hash.
    Achieves >40% cache hit rate for repeated patterns within an engagement.
    """

    def __init__(self, cache_file: str = CACHE_FILE):
        self._cache_file = Path(cache_file)
        self._cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._store: dict[str, str] = {}
        self._hits = 0
        self._misses = 0
        self._load()

    def get(self, prompt: str) -> Optional[str]:
        """Return cached response or None."""
        key = self._hash(prompt)
        result = self._store.get(key)
        if result:
            self._hits += 1
            logger.debug(f"[LLMCache] HIT (total hits={self._hits})")
        else:
            self._misses += 1
        return result

    def set(self, prompt: str, response: str):
        """Cache an LLM response."""
        key = self._hash(prompt)
        self._store[key] = response
        self._save()

    def stats(self) -> dict:
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total else 0
        return {
            "cache_size": len(self._store),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate_pct": round(hit_rate, 1),
        }

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def _load(self):
        if self._cache_file.exists():
            try:
                with open(self._cache_file) as f:
                    self._store = json.load(f)
            except Exception:
                self._store = {}

    def _save(self):
        try:
            with open(self._cache_file, "w") as f:
                json.dump(self._store, f)
        except Exception as e:
            logger.debug(f"[LLMCache] Save failed: {e}")


# ------------------------------------------------------------------
# Structured output templates
# ------------------------------------------------------------------

STRUCTURED_PROMPTS = {
    "triage_finding": """
Analyze this potential vulnerability finding and return ONLY valid JSON.

Finding:
{finding_json}

HTTP Response Slice:
{response_slice}

Return JSON with this exact schema:
{{
  "is_real_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "severity": "critical|high|medium|low|info",
  "reasoning": "one sentence explanation",
  "false_positive_reason": "if false positive, why"
}}
""",

    "auth_flow_analysis": """
Analyze this authentication flow and return ONLY valid JSON.

Endpoints observed:
{endpoints_json}

Headers:
{headers_json}

Return JSON:
{{
  "auth_mechanism": "jwt|session|api_key|basic|oauth|none",
  "rbac_present": true/false,
  "attack_vectors": ["list", "of", "potential", "issues"],
  "recommended_tests": ["test1", "test2"]
}}
""",

    "attack_chain_narrative": """
Given these verified vulnerabilities, construct an attack chain narrative.
Return ONLY valid JSON.

Vulnerabilities:
{vulns_json}

Return JSON:
{{
  "chain_name": "descriptive name",
  "steps": [
    {{"step": 1, "action": "...", "vulnerability": "...", "result": "..."}}
  ],
  "combined_impact": "what attacker achieves",
  "severity": "critical|high|medium",
  "likelihood": "high|medium|low"
}}
""",
}


def build_prompt(template_name: str, **kwargs) -> str:
    """Build a structured prompt from a template."""
    template = STRUCTURED_PROMPTS.get(template_name, "")
    for key, value in kwargs.items():
        if isinstance(value, (dict, list)):
            value = json.dumps(value, indent=2)[:MAX_CONTEXT_CHARS]
        template = template.replace("{" + key + "}", str(value))
    return template.strip()


# ------------------------------------------------------------------
# Token counter (rough estimate without tiktoken dependency)
# ------------------------------------------------------------------

def estimate_tokens(text: str) -> int:
    """
    Rough token count estimate: ~4 chars per token for English text.
    Accurate enough for budget planning without requiring tiktoken.
    """
    return max(1, len(text) // 4)


@dataclass
class TokenBudget:
    """Track token consumption per engagement phase."""
    phase: str
    budget: int
    consumed: int = 0

    def spend(self, tokens: int) -> bool:
        """
        Record token spend. Returns False if over budget.
        """
        self.consumed += tokens
        if self.consumed > self.budget:
            logger.warning(
                f"[TokenBudget] {self.phase} over budget: "
                f"{self.consumed}/{self.budget} tokens"
            )
            return False
        return True

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.consumed)

    @property
    def pct_used(self) -> float:
        return (self.consumed / self.budget * 100) if self.budget else 0


PHASE_BUDGETS = {
    "recon":         TokenBudget("recon", 500),
    "enumeration":   TokenBudget("enumeration", 2000),
    "vulnerability": TokenBudget("vulnerability", 5000),
    "poc_validation":TokenBudget("poc_validation", 1000),
    "attack_chain":  TokenBudget("attack_chain", 3000),
    "report":        TokenBudget("report", 8000),
}
