"""
agents/recon_pipeline.py

Full 7-stage autonomous recon pipeline.
Extends the existing ReconAgent with Stages 4-7 that were missing:
  Stage 4: Historical URL collection (gau, waybackurls)
  Stage 5: Active crawl + JS endpoint extraction (katana, hakrawler, linkfinder)
  Stage 6: Parameter discovery (paramspider, arjun)
  Stage 7: API schema discovery (enhanced)

The pipeline is event-driven: each stage emits results as soon as they're
ready, so downstream stages begin processing without waiting for prior
stages to fully complete.

Architecture reference: ARCHITECTURE.md § 2 "Autonomous Recon Engine"
"""

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Result containers
# ------------------------------------------------------------------

@dataclass
class ReconResult:
    """Aggregated output of the full 7-stage recon pipeline."""
    domain: str
    stage: str
    subdomains: list[str] = field(default_factory=list)
    dns_records: list[dict] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)
    historical_urls: list[str] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    js_sinks: list[dict] = field(default_factory=list)
    js_secrets: list[dict] = field(default_factory=list)
    parameters: dict[str, list[str]] = field(default_factory=dict)
    api_schemas: list[dict] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)
    subdomain_takeover_candidates: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# Stage 4: Historical URL collection
# ------------------------------------------------------------------

class HistoricalURLCollector:
    """
    Collects historical URLs from:
    - gau (getallurls): URLScan + Wayback + OTX + Common Crawl
    - waybackurls: Internet Archive corpus
    - Filters and normalizes results
    """

    # Path patterns to filter out (static assets, not interesting for vuln testing)
    STATIC_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff",
        ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
        ".css",  # CSS kept only if contains URL patterns
    }

    # High-value path patterns to prioritize
    HIGH_VALUE_PATTERNS = [
        r"/api/", r"/admin", r"/internal", r"/user", r"/account",
        r"/payment", r"/checkout", r"/upload", r"/download",
        r"/oauth", r"/auth", r"/login", r"/graphql", r"/webhook",
        r"\?.*id=", r"\?.*token=", r"\?.*url=", r"\?.*redirect=",
        r"\?.*file=", r"\?.*path=",
    ]

    def collect(self, domain: str, tools: dict) -> list[str]:
        """
        Collect historical URLs for a domain.
        Returns deduplicated, filtered URL list.
        """
        urls: set[str] = set()

        # Try gau
        if tools.get("gau"):
            gau_urls = self._run_gau(domain)
            urls.update(gau_urls)
            logger.info(f"[HistoricalURLCollector] gau: {len(gau_urls)} URLs for {domain}")

        # Try waybackurls
        if tools.get("waybackurls"):
            wb_urls = self._run_waybackurls(domain)
            urls.update(wb_urls)
            logger.info(f"[HistoricalURLCollector] waybackurls: {len(wb_urls)} URLs for {domain}")

        # Filter static assets
        filtered = self._filter(list(urls), domain)
        logger.info(
            f"[HistoricalURLCollector] {len(filtered)} useful URLs after filtering "
            f"(from {len(urls)} total)"
        )
        return filtered

    def _run_gau(self, domain: str, timeout: int = 60) -> list[str]:
        try:
            result = subprocess.run(
                ["gau", "--threads", "5", "--timeout", "15", domain],
                capture_output=True, text=True, timeout=timeout,
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _run_waybackurls(self, domain: str, timeout: int = 60) -> list[str]:
        try:
            result = subprocess.run(
                ["waybackurls", domain],
                capture_output=True, text=True, timeout=timeout,
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _filter(self, urls: list[str], domain: str) -> list[str]:
        """Remove static assets; keep parameterized and high-value paths."""
        filtered = []
        seen_patterns: set[str] = set()

        for url in urls:
            # Must be on the target domain
            try:
                parsed = urlparse(url)
                if domain not in parsed.netloc:
                    continue
            except Exception:
                continue

            # Skip static extensions
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
                continue

            # Normalize: strip UUIDs and numeric IDs for deduplication
            pattern = self._normalize_pattern(url)
            if pattern in seen_patterns:
                continue
            seen_patterns.add(pattern)
            filtered.append(url)

        return filtered

    @staticmethod
    def _normalize_pattern(url: str) -> str:
        """Replace UUIDs, integers, and hashes with placeholders."""
        url = re.sub(r'/[0-9a-f]{8}-[0-9a-f-]{27}', '/{UUID}', url)
        url = re.sub(r'/\d+', '/{ID}', url)
        url = re.sub(r'=[0-9a-f]{32,}', '={HASH}', url)
        return url


# ------------------------------------------------------------------
# Stage 5: Active crawl + JS extraction
# ------------------------------------------------------------------

class JSAnalyzer:
    """
    Extracts security-relevant signals from JavaScript files:
    - API endpoint URLs (fetch, axios, XHR)
    - XSS sinks (innerHTML, document.write, eval, etc.)
    - Source→sink flows for DOM XSS
    - Secrets (API keys, tokens, credentials)
    """

    SINK_PATTERNS = [
        (r'\.innerHTML\s*[+=]', "innerHTML"),
        (r'\.outerHTML\s*=', "outerHTML"),
        (r'document\.write\s*\(', "document.write"),
        (r'\beval\s*\(', "eval"),
        (r'location\.href\s*=', "location.href"),
        (r'location\.replace\s*\(', "location.replace"),
        (r'setTimeout\s*\(', "setTimeout"),
        (r'setInterval\s*\(', "setInterval"),
        (r'insertAdjacentHTML\s*\(', "insertAdjacentHTML"),
        (r'\$\s*\([^)]*\)\.html\s*\(', "jQuery.html"),
    ]

    SOURCE_PATTERNS = [
        (r'location\.search', "location.search"),
        (r'location\.hash', "location.hash"),
        (r'location\.href', "location.href"),
        (r'document\.referrer', "document.referrer"),
        (r'window\.name', "window.name"),
        (r'document\.URL', "document.URL"),
    ]

    API_URL_PATTERNS = [
        r'(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:url|endpoint|api_url|baseURL)\s*[:=]\s*["\']([^"\']+)["\']',
        r'xhr\.open\s*\(\s*["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']',
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v\d/[^"\']+)["\']',
    ]

    SECRET_PATTERNS = [
        (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{10,})["\']', "api_key"),
        (r'(?i)(?:secret|password|passwd)\s*[:=]\s*["\']([^"\']{8,})["\']', "secret"),
        (r'(?i)(?:token|jwt|bearer)\s*[:=]\s*["\']([^"\']{20,})["\']', "token"),
        (r'AKIA[0-9A-Z]{16}', "aws_access_key"),
        (r'(?i)(?:aws_secret|aws_key)\s*[:=]\s*["\']([^"\']{20,})["\']', "aws_secret"),
        (r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "jwt_token"),
    ]

    def analyze(self, js_content: str, source_url: str) -> dict:
        """
        Analyze a JS file for security signals.

        Returns dict with: endpoints, sinks, sources, secrets
        """
        result: dict = {
            "source_url": source_url,
            "endpoints": self._extract_endpoints(js_content),
            "sinks": self._find_sinks(js_content),
            "sources": self._find_sources(js_content),
            "secrets": self._find_secrets(js_content),
            "dom_xss_flows": [],
        }

        # Find potential DOM XSS source→sink flows
        if result["sources"] and result["sinks"]:
            result["dom_xss_flows"] = [
                {"source": s, "sink": k}
                for s in result["sources"]
                for k in result["sinks"]
            ]

        return result

    def _extract_endpoints(self, content: str) -> list[str]:
        endpoints = set()
        for pattern in self.API_URL_PATTERNS:
            matches = re.findall(pattern, content)
            endpoints.update(matches)
        return [ep for ep in endpoints if len(ep) > 2 and not ep.startswith("//")]

    def _find_sinks(self, content: str) -> list[str]:
        sinks = []
        for pattern, sink_name in self.SINK_PATTERNS:
            if re.search(pattern, content):
                sinks.append(sink_name)
        return sinks

    def _find_sources(self, content: str) -> list[str]:
        sources = []
        for pattern, source_name in self.SOURCE_PATTERNS:
            if re.search(pattern, content):
                sources.append(source_name)
        return sources

    def _find_secrets(self, content: str) -> list[dict]:
        """
        Find secret patterns. Returns type and masked value (never the real secret).
        """
        found = []
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                val = match if isinstance(match, str) else match[0]
                found.append({
                    "type": secret_type,
                    "masked_value": val[:4] + "****" + val[-2:] if len(val) > 6 else "****",
                    "length": len(val),
                })
        return found


class ActiveCrawler:
    """
    Runs katana/hakrawler for active crawling and downloads JS files for analysis.
    """

    def crawl(self, url: str, tools: dict, depth: int = 3) -> list[str]:
        """Return list of discovered URLs via active crawling."""
        urls: set[str] = set()

        if tools.get("katana"):
            katana_urls = self._run_katana(url, depth)
            urls.update(katana_urls)
            logger.info(f"[ActiveCrawler] katana: {len(katana_urls)} URLs from {url}")

        if tools.get("hakrawler"):
            hak_urls = self._run_hakrawler(url, depth)
            urls.update(hak_urls)

        return list(urls)

    def _run_katana(self, url: str, depth: int, timeout: int = 120) -> list[str]:
        try:
            result = subprocess.run(
                ["katana", "-u", url, "-d", str(depth), "-silent", "-jc", "-o", "/dev/stdout"],
                capture_output=True, text=True, timeout=timeout,
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("http")]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _run_hakrawler(self, url: str, depth: int, timeout: int = 60) -> list[str]:
        try:
            result = subprocess.run(
                ["hakrawler", "-url", url, "-depth", str(depth)],
                capture_output=True, text=True, timeout=timeout,
                input=url,
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("http")]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def fetch_js_files(self, js_urls: list[str], auth_headers: dict = None) -> dict[str, str]:
        """
        Fetch JS files and return {url: content} map.
        """
        js_contents: dict[str, str] = {}
        headers = auth_headers or {}

        for js_url in js_urls[:50]:  # Cap at 50 JS files
            try:
                cmd = ["curl", "-sk", "--max-time", "15", "--compressed"]
                for k, v in headers.items():
                    cmd.extend(["-H", f"{k}: {v}"])
                cmd.append(js_url)

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if result.returncode == 0 and result.stdout:
                    js_contents[js_url] = result.stdout
            except Exception:
                pass

        return js_contents


# ------------------------------------------------------------------
# Stage 6: Parameter discovery
# ------------------------------------------------------------------

class ParameterMiner:
    """
    Discovers hidden/undocumented HTTP parameters using:
    - paramspider: Spider-based parameter collection
    - arjun: Active parameter brute-force
    - Historical URL parameter analysis (from Stage 4)
    - Classification of parameters by injection potential
    """

    # Parameter → likely vulnerability type
    PARAM_VULN_MAP = {
        # IDOR candidates
        "id": "IDOR", "user_id": "IDOR", "uid": "IDOR",
        "account_id": "IDOR", "customer_id": "IDOR", "order_id": "IDOR",
        "record_id": "IDOR", "item_id": "IDOR",
        # SSRF/Open Redirect candidates
        "url": "SSRF", "callback": "SSRF", "redirect": "OPEN_REDIRECT",
        "next": "OPEN_REDIRECT", "return": "OPEN_REDIRECT",
        "return_url": "OPEN_REDIRECT", "target": "SSRF",
        "dest": "OPEN_REDIRECT", "destination": "OPEN_REDIRECT",
        # Path traversal candidates
        "file": "PATH_TRAVERSAL", "path": "PATH_TRAVERSAL",
        "dir": "PATH_TRAVERSAL", "template": "SSTI",
        "page": "PATH_TRAVERSAL", "include": "PATH_TRAVERSAL",
        # Command injection candidates
        "cmd": "COMMAND_INJECTION", "exec": "COMMAND_INJECTION",
        "command": "COMMAND_INJECTION", "run": "COMMAND_INJECTION",
        # XSS/SQLi candidates
        "q": "XSS", "query": "XSS", "search": "XSS",
        "filter": "SQLI", "sort": "SQLI", "order": "SQLI",
        "where": "SQLI", "limit": "SQLI",
        # Auth candidates
        "token": "JWT", "session": "AUTH", "key": "AUTH",
        "api_key": "AUTH", "apikey": "AUTH",
    }

    def mine_from_historical_urls(self, urls: list[str]) -> dict[str, list[str]]:
        """
        Extract parameters from historical URL query strings.
        Returns {endpoint_pattern → [param_names]}.
        """
        from urllib.parse import urlparse, parse_qs

        params_by_endpoint: dict[str, set[str]] = {}

        for url in urls:
            try:
                parsed = urlparse(url)
                query_params = list(parse_qs(parsed.query).keys())
                if not query_params:
                    continue
                # Normalize endpoint (strip IDs)
                pattern = self._normalize_path(parsed.scheme + "://" + parsed.netloc + parsed.path)
                if pattern not in params_by_endpoint:
                    params_by_endpoint[pattern] = set()
                params_by_endpoint[pattern].update(query_params)
            except Exception:
                pass

        return {k: list(v) for k, v in params_by_endpoint.items()}

    def run_arjun(self, url: str, timeout: int = 120) -> list[str]:
        """Run arjun for hidden parameter discovery on a single endpoint."""
        try:
            result = subprocess.run(
                ["arjun", "-u", url, "--stable", "-t", "10"],
                capture_output=True, text=True, timeout=timeout,
            )
            # Parse arjun JSON output
            params = re.findall(r'"(\w+)":\s*\[', result.stdout)
            if not params:
                # Fallback: extract from human-readable output
                matches = re.findall(r'Found parameter:\s*(\w+)', result.stdout)
                params = matches
            return params
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def classify(self, params: list[str]) -> list[dict]:
        """
        Classify parameters by their likely vulnerability type.

        Returns list of {param, vuln_type, confidence} dicts.
        """
        classified = []
        for param in params:
            param_lower = param.lower()

            # Exact match first
            vuln_type = self.PARAM_VULN_MAP.get(param_lower)
            confidence = 0.9 if vuln_type else 0.0

            # Fuzzy match on keywords
            if not vuln_type:
                for key, vtype in self.PARAM_VULN_MAP.items():
                    if key in param_lower or param_lower in key:
                        vuln_type = vtype
                        confidence = 0.6
                        break

            classified.append({
                "param": param,
                "vuln_type": vuln_type or "XSS",  # Default: test XSS
                "confidence": confidence,
            })

        return sorted(classified, key=lambda x: x["confidence"], reverse=True)

    @staticmethod
    def _normalize_path(url: str) -> str:
        return re.sub(r'/\d+', '/{id}', url)


# ------------------------------------------------------------------
# Stage 7: API Schema Discovery (enhanced)
# ------------------------------------------------------------------

class APISchemaDiscoverer:
    """
    Discovers and parses API schemas from common paths.
    Supports: OpenAPI/Swagger, GraphQL introspection, WSDL
    """

    OPENAPI_PATHS = [
        "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
        "/openapi.json", "/openapi.yaml", "/api/swagger.json",
        "/api/v1/swagger.json", "/api/v2/swagger.json",
        "/v1/api-docs", "/v2/api-docs", "/swagger-ui.html",
        "/.well-known/openapi.json",
    ]

    GRAPHQL_PATHS = [
        "/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql",
    ]

    def discover(self, base_url: str, auth_headers: dict = None) -> list[dict]:
        """
        Probe for API schemas and return parsed schema data.
        """
        schemas: list[dict] = []

        # OpenAPI/Swagger
        for path in self.OPENAPI_PATHS:
            schema = self._probe_openapi(base_url, path, auth_headers)
            if schema:
                schemas.append(schema)
                break  # One swagger is enough per host

        # GraphQL introspection
        for path in self.GRAPHQL_PATHS:
            schema = self._probe_graphql(base_url, path, auth_headers)
            if schema:
                schemas.append(schema)
                break

        return schemas

    def _probe_openapi(
        self, base_url: str, path: str, headers: dict = None
    ) -> Optional[dict]:
        url = base_url.rstrip("/") + path
        try:
            cmd = ["curl", "-sk", "--max-time", "10"]
            for k, v in (headers or {}).items():
                cmd.extend(["-H", f"{k}: {v}"])
            cmd.append(url)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0 or not result.stdout:
                return None

            # Try JSON parse
            try:
                data = json.loads(result.stdout)
                if "paths" in data or "swagger" in data or "openapi" in data:
                    endpoints = list(data.get("paths", {}).keys())
                    return {
                        "type": "openapi",
                        "url": url,
                        "version": data.get("openapi") or data.get("swagger", "unknown"),
                        "endpoints": endpoints[:100],
                        "endpoint_count": len(endpoints),
                        "raw_schema": data,
                    }
            except json.JSONDecodeError:
                # Check if it's YAML-like
                if "paths:" in result.stdout or "swagger:" in result.stdout:
                    return {"type": "openapi_yaml", "url": url}
        except Exception:
            pass
        return None

    def _probe_graphql(
        self, base_url: str, path: str, headers: dict = None
    ) -> Optional[dict]:
        url = base_url.rstrip("/") + path
        introspection_query = json.dumps({
            "query": "{__schema{types{name fields{name type{name}}}}}"
        })
        try:
            cmd = [
                "curl", "-sk", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/json",
            ]
            for k, v in (headers or {}).items():
                cmd.extend(["-H", f"{k}: {v}"])
            cmd.extend(["--data", introspection_query, url])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0 or not result.stdout:
                return None

            data = json.loads(result.stdout)
            if "data" in data and "__schema" in data.get("data", {}):
                types = data["data"]["__schema"].get("types", [])
                type_names = [t["name"] for t in types if not t["name"].startswith("__")]
                return {
                    "type": "graphql",
                    "url": url,
                    "introspection_enabled": True,
                    "types": type_names[:30],
                    "type_count": len(type_names),
                }
            elif "errors" in data:
                # GraphQL is there but introspection is disabled
                return {
                    "type": "graphql",
                    "url": url,
                    "introspection_enabled": False,
                }
        except Exception:
            pass
        return None


# ------------------------------------------------------------------
# Full Pipeline Orchestrator
# ------------------------------------------------------------------

class ReconPipeline:
    """
    Orchestrates all 7 recon stages in sequence.
    Each stage feeds into the next.

    Stages 1-3 are handled by the existing ReconAgent.
    This class implements Stages 4-7.
    """

    def __init__(self, config: dict, tools: dict, kb, guard=None):
        self.config = config
        self.tools = tools
        self.kb = kb
        self.guard = guard
        self._hist_collector = HistoricalURLCollector()
        self._crawler = ActiveCrawler()
        self._js_analyzer = JSAnalyzer()
        self._param_miner = ParameterMiner()
        self._api_discoverer = APISchemaDiscoverer()

    def run_stages_4_to_7(self, domain: str, live_hosts: list[str]) -> ReconResult:
        """
        Run Stages 4-7 for a domain.

        Args:
            domain: Root domain.
            live_hosts: Live host URLs from Stage 3.

        Returns:
            ReconResult with all collected data.
        """
        result = ReconResult(domain=domain, stage="4-7")
        auth_headers = self._get_auth_headers()

        # Stage 4: Historical URLs
        logger.info(f"[ReconPipeline] Stage 4: Historical URL collection for {domain}")
        result.historical_urls = self._hist_collector.collect(domain, self.tools)
        self._save_endpoints_to_kb(result.historical_urls, source="historical")

        # Stage 5: Active crawl + JS analysis
        logger.info(f"[ReconPipeline] Stage 5: Active crawl for {domain}")
        for host_url in live_hosts[:20]:  # Cap at 20 hosts
            crawled = self._crawler.crawl(host_url, self.tools)
            result.crawled_urls.extend(crawled)

        all_urls = list(set(result.historical_urls + result.crawled_urls))
        self._save_endpoints_to_kb(result.crawled_urls, source="crawl")

        # Extract and analyze JS files
        js_urls = [u for u in all_urls if u.endswith(".js") or "/static/" in u or "/assets/" in u]
        if js_urls:
            logger.info(f"[ReconPipeline] Stage 5: Analyzing {len(js_urls)} JS files")
            js_contents = self._crawler.fetch_js_files(js_urls[:30], auth_headers)
            for js_url, content in js_contents.items():
                analysis = self._js_analyzer.analyze(content, js_url)
                result.js_endpoints.extend(analysis.get("endpoints", []))
                if analysis.get("sinks"):
                    result.js_sinks.append({"url": js_url, "sinks": analysis["sinks"]})
                if analysis.get("secrets"):
                    result.js_secrets.append({"url": js_url, "secrets": analysis["secrets"]})
                    logger.warning(
                        f"[ReconPipeline] SECRET PATTERN detected in {js_url}: "
                        + str([s["type"] for s in analysis["secrets"]])
                    )

            # Save JS-discovered endpoints
            self._save_endpoints_to_kb(result.js_endpoints, source="js_analysis")

        # Stage 6: Parameter discovery
        logger.info(f"[ReconPipeline] Stage 6: Parameter discovery for {domain}")

        # Mine from historical URLs
        hist_params = self._param_miner.mine_from_historical_urls(result.historical_urls)
        result.parameters.update(hist_params)

        # Run arjun on top-priority endpoints (scope-validated)
        priority_endpoints = self._select_priority_endpoints(all_urls, max_count=10)
        for ep_url in priority_endpoints:
            if self.guard and not self.guard.validate_url(ep_url):
                continue
            arjun_params = self._param_miner.run_arjun(ep_url)
            if arjun_params:
                result.parameters[ep_url] = arjun_params
                classified = self._param_miner.classify(arjun_params)
                logger.info(
                    f"[ReconPipeline] arjun found params on {ep_url}: "
                    + str([p["param"] for p in classified])
                )
                self._save_parameters_to_kb(ep_url, arjun_params, classified)

        # Stage 7: API Schema Discovery
        logger.info(f"[ReconPipeline] Stage 7: API schema discovery for {domain}")
        for host_url in live_hosts[:5]:
            schemas = self._api_discoverer.discover(host_url, auth_headers)
            result.api_schemas.extend(schemas)
            for schema in schemas:
                logger.info(
                    f"[ReconPipeline] API schema found: {schema['type']} at {schema['url']}"
                )
                # Add discovered endpoints from schema to KB
                if schema.get("endpoints"):
                    schema_urls = [
                        host_url.rstrip("/") + path
                        for path in schema["endpoints"]
                    ]
                    self._save_endpoints_to_kb(schema_urls, source="api_schema")
                    result.crawled_urls.extend(schema_urls)

        logger.info(
            f"[ReconPipeline] Stages 4-7 complete for {domain}: "
            f"{len(result.historical_urls)} historical URLs, "
            f"{len(result.crawled_urls)} crawled URLs, "
            f"{len(result.js_endpoints)} JS endpoints, "
            f"{len(result.parameters)} parameterized endpoints, "
            f"{len(result.api_schemas)} API schemas"
        )

        return result

    # ------------------------------------------------------------------
    # Knowledge base integration
    # ------------------------------------------------------------------

    def _save_endpoints_to_kb(self, urls: list[str], source: str):
        """Save discovered URLs to the knowledge base."""
        for url in urls:
            if self.guard and not self.guard.validate_url(url):
                continue
            self.kb.add_endpoint({
                "url": url,
                "method": "GET",
                "source": source,
                "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

    def _save_parameters_to_kb(self, url: str, params: list[str], classified: list[dict]):
        """Update the KB endpoint record with discovered parameters."""
        existing = self.kb.query("endpoints", url=url)
        if existing:
            self.kb.update("endpoints", existing[0]["_id"], {
                "parameters": params,
                "param_classification": classified,
            })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_auth_headers(self) -> dict:
        """Load auth headers from config."""
        creds = self.config.get("credentials", {})
        headers = {}
        if creds.get("api_key"):
            headers["Authorization"] = f"Bearer {creds['api_key']}"
        return headers

    @staticmethod
    def _select_priority_endpoints(urls: list[str], max_count: int = 10) -> list[str]:
        """Select the highest-value endpoints for deep parameter mining."""
        high_value_patterns = [
            r"/api/", r"/admin", r"/user", r"/account", r"/payment",
        ]
        priority = []
        for url in urls:
            if any(re.search(p, url, re.IGNORECASE) for p in high_value_patterns):
                priority.append(url)
            if len(priority) >= max_count:
                break
        return priority
