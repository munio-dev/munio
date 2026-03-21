"""L2 Heuristic Analysis: text content inspection of MCP tool definitions.

Scans all text fields (descriptions, parameter descriptions, defaults, enum
values) for injection patterns, exfiltration indicators, and suspicious
language that L1 structural checks cannot detect.

Checks:
  L2_001  Directive/markup tag injection
  L2_002  Sensitive file path references
  L2_003  External destination references (URL, email, phone)
  L2_004  Cross-server tool shadowing
  L2_005  Enum/default value poisoning
  L2_006  Suspicious justification patterns
  L2_007  Imperative instruction patterns
  L2_008  Path traversal patterns
  L2_009  Command injection patterns
  L2_010  Combination escalation (multi-signal correlation)
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import TYPE_CHECKING, Any, NamedTuple

from munio.scan.models import (
    AttackType,
    Finding,
    FindingSeverity,
    Layer,
    ToolDefinition,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────

_MAX_RECURSION_DEPTH = 10
_MIN_TOOL_NAME_LEN = 4  # Skip cross-ref matching for very short tool names

# ── Pattern type: (compiled regex, human description, confidence 0-1) ────


class _Pattern(NamedTuple):
    regex: re.Pattern[str]
    desc: str
    confidence: float


# L2_001: Directive / markup tag injection
_DIRECTIVE_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        re.compile(r"<IMPORTANT\b", re.IGNORECASE), "HTML-style <IMPORTANT> directive tag", 0.95
    ),
    _Pattern(re.compile(r"</IMPORTANT>", re.IGNORECASE), "closing </IMPORTANT> tag", 0.95),
    _Pattern(
        re.compile(r"\[SYSTEM\s+OVERRIDE\b", re.IGNORECASE),
        "fake [SYSTEM OVERRIDE] directive",
        0.95,
    ),
    _Pattern(re.compile(r"\[ADMIN\s+MODE\b", re.IGNORECASE), "fake [ADMIN MODE] directive", 0.95),
    _Pattern(re.compile(r"<!--.{1,500}?-->"), "HTML comment with hidden content", 0.85),
    _Pattern(
        re.compile(r"\bNOTE_TO_ASSISTANT\s*:", re.IGNORECASE), "NOTE_TO_ASSISTANT directive", 0.90
    ),
    _Pattern(re.compile(r"\bNOTE_TO_AI\s*:", re.IGNORECASE), "NOTE_TO_AI directive", 0.90),
    _Pattern(re.compile(r"\bNOTE_TO_LLM\s*:", re.IGNORECASE), "NOTE_TO_LLM directive", 0.90),
    _Pattern(re.compile(r"\[INST\]", re.IGNORECASE), "[INST] model instruction tag", 0.90),
    _Pattern(
        re.compile(r"```system\b", re.IGNORECASE), "fenced code block impersonating system", 0.85
    ),
    # Model-specific injection tags
    _Pattern(re.compile(r"<\|im_start\|>", re.IGNORECASE), "ChatML injection tag", 0.95),
    _Pattern(re.compile(r"<\|im_end\|>", re.IGNORECASE), "ChatML closing tag", 0.90),
    _Pattern(re.compile(r"<system>", re.IGNORECASE), "XML system tag injection", 0.90),
    _Pattern(re.compile(r"<<SYS>>", re.IGNORECASE), "Llama2 system tag injection", 0.90),
    _Pattern(
        re.compile(r"\bHuman\s*:\s*\S", re.IGNORECASE), "Anthropic turn delimiter injection", 0.85
    ),
    _Pattern(
        re.compile(r"\bAssistant\s*:\s*\S", re.IGNORECASE),
        "Anthropic turn delimiter injection",
        0.85,
    ),
    _Pattern(
        re.compile(r">\s*\[!IMPORTANT\]", re.IGNORECASE),
        "Markdown alert directive injection",
        0.85,
    ),
)

# L2_002: Sensitive file path references
_SENSITIVE_PATH_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(re.compile(r"~/\.ssh/", re.IGNORECASE), "SSH directory reference", 0.90),
    _Pattern(re.compile(r"/\.ssh/", re.IGNORECASE), "SSH directory reference (absolute)", 0.90),
    _Pattern(re.compile(r"\bid_rsa\b", re.IGNORECASE), "SSH private key file", 0.90),
    _Pattern(re.compile(r"\bid_ed25519\b", re.IGNORECASE), "SSH private key file", 0.90),
    _Pattern(re.compile(r"~/\.aws/credentials", re.IGNORECASE), "AWS credentials file", 0.95),
    _Pattern(re.compile(r"~/\.aws/config", re.IGNORECASE), "AWS config file", 0.80),
    _Pattern(re.compile(r"\.env\b"), ".env file reference", 0.70),
    _Pattern(re.compile(r"\bapi_keys?\.json\b", re.IGNORECASE), "API keys file", 0.85),
    _Pattern(re.compile(r"/etc/passwd\b", re.IGNORECASE), "/etc/passwd reference", 0.85),
    _Pattern(re.compile(r"/etc/shadow\b", re.IGNORECASE), "/etc/shadow reference", 0.90),
    _Pattern(re.compile(r"~/\.cursor/", re.IGNORECASE), "Cursor IDE config reference", 0.80),
    _Pattern(re.compile(r"~/\.kube/config", re.IGNORECASE), "Kubernetes config reference", 0.85),
    _Pattern(re.compile(r"~/\.gnupg/", re.IGNORECASE), "GPG key directory reference", 0.85),
)

# L2_003: External destination references
_URL_RE = re.compile(r"https?://[^\s\"'<>]{5,200}", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_PHONE_RE = re.compile(r"\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{0,4}")
_SAFE_URL_RE = re.compile(
    r"https?://(?:"
    # Exact trusted domains (no prefix-only wildcards — docs.evil.com was a bypass)
    r"(?:[^/]*\.)?(?:json-schema\.org|schema\.org|w3\.org|wikipedia\.org|localhost)\b"
    r"|(?:[^/]*\.)?github\.com/(?:[^/]+/[^/]+/(?:blob|tree|wiki|docs|README)|docs/)"
    r"|(?:[^/]*\.)?(?:docs\.python\.org|docs\.github\.com|developer\.mozilla\.org)\b"
    r"|(?:www\.)?example\.(?:com|org|net)\b"
    r")",
    re.IGNORECASE,
)
_EXFIL_URL_WORDS: frozenset[str] = frozenset(
    {
        "exfil",
        "steal",
        "leak",
        "dump",
        "upload",
        "collect",
        "harvest",
    }
)

# L2_004: Cross-server tool shadowing
_SHADOWING_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        re.compile(r"\bside\s+effect\s+on\b", re.IGNORECASE), "side effect on another tool", 0.90
    ),
    _Pattern(
        re.compile(r"\bwhen\s+this\s+tool\s+is\s+available\b", re.IGNORECASE),
        "conditional on own presence",
        0.90,
    ),
    _Pattern(
        re.compile(r"\boverride\s+(?:the\s+)?(?:behavior|behaviour)\b", re.IGNORECASE),
        "behavior override",
        0.95,
    ),
    _Pattern(
        re.compile(r"\binstead\s+of\s+(?:the\s+)?(?:normal|default|original)\b", re.IGNORECASE),
        "behavior replacement",
        0.85,
    ),
    _Pattern(
        re.compile(r"\breplace\s+(?:the\s+)?(?:default|normal)\b", re.IGNORECASE),
        "behavior replacement",
        0.85,
    ),
)

# L2_005: Enum/default value poisoning
_POISONED_VALUE_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        re.compile(
            r"\b(?:first|also|before|after)\s+(?:read|retrieve|fetch|get|include|send|forward|upload)",
            re.IGNORECASE,
        ),
        "imperative instruction in value",
        0.90,
    ),
    _Pattern(
        re.compile(
            r"\b(?:read|retrieve|access|include|send|forward)\s+(?:all|the|your|user)",
            re.IGNORECASE,
        ),
        "data access instruction in value",
        0.85,
    ),
    _Pattern(
        re.compile(r";\s*(?:Also|And|Then|First|Before)\b", re.IGNORECASE),
        "semicolon-separated hidden instruction",
        0.90,
    ),
)

# L2_006: Suspicious justification patterns
_JUSTIFICATION_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        re.compile(
            r"\b(?:security|compliance|verification)\s+(?:check|requirement|protocol|measure)",
            re.IGNORECASE,
        ),
        "fake security justification",
        0.75,
    ),
    _Pattern(
        re.compile(r"\brequired\s+for\s+(?:API\s+)?authentication\b", re.IGNORECASE),
        "fake authentication requirement",
        0.80,
    ),
    _Pattern(
        re.compile(r"\bstandard\s+(?:security\s+)?protocol\b", re.IGNORECASE),
        "fake standard protocol claim",
        0.80,
    ),
    _Pattern(
        re.compile(
            r"\bdo\s+not\s+(?:inform|tell|mention|alert)\s+(?:the\s+)?user\b", re.IGNORECASE
        ),
        "instruction to hide from user",
        0.95,
    ),
    _Pattern(
        re.compile(r"\bshould\s+not\s+be\s+mentioned\b", re.IGNORECASE),
        "instruction to suppress disclosure",
        0.90,
    ),
    _Pattern(
        re.compile(r"\bauto[\s-]?populated\b", re.IGNORECASE),
        "auto-populated parameter claim",
        0.70,
    ),
)

# L2_007: Imperative instruction patterns
_IMPERATIVE_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        re.compile(
            r"\b(?:before|after)\s+(?:using|calling|running|performing|executing)\s+this\s+tool\b",
            re.IGNORECASE,
        ),
        "pre/post-execution instruction",
        0.85,
    ),
    _Pattern(
        re.compile(
            r"\b(?:before|after)\s+\w+(?:ing|ion)\b[^.]{0,40}\b(?:read|retrieve|fetch|include|send|access)\b",
            re.IGNORECASE,
        ),
        "pre/post-action data access instruction",
        0.80,
    ),
    _Pattern(
        re.compile(
            r"\byou\s+(?:must|should|need\s+to|have\s+to)\s+(?:first\s+)?(?:read|retrieve|fetch|get|access|include|send|forward)",
            re.IGNORECASE,
        ),
        "imperative data access instruction",
        0.90,
    ),
    _Pattern(
        re.compile(r"\bthe\s+assistant\s+must\b", re.IGNORECASE),
        "explicit assistant instruction",
        0.90,
    ),
    _Pattern(
        re.compile(r"\byour\s+(?:new\s+)?task\s+is\b", re.IGNORECASE),
        "task override instruction",
        0.95,
    ),
    _Pattern(
        re.compile(
            r"\bplease\s+(?:first\s+)?(?:read|retrieve|include|send|forward|access)\b",
            re.IGNORECASE,
        ),
        "polite imperative data access",
        0.80,
    ),
    _Pattern(
        re.compile(
            r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", re.IGNORECASE
        ),
        "instruction override",
        0.95,
    ),
    _Pattern(
        re.compile(r"\bdisregard\s+(?:all\s+)?(?:previous|prior)\b", re.IGNORECASE),
        "instruction override",
        0.95,
    ),
    _Pattern(
        re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
        "role/persona override",
        0.85,
    ),
    _Pattern(
        re.compile(r"\bpass\s+(?:its?\s+)?contents?\s+as\b", re.IGNORECASE),
        "instruction to pass data as parameter",
        0.90,
    ),
)

# L2_008: Path traversal patterns
_PATH_TRAVERSAL_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(re.compile(r"\.\.[/\\]"), "directory traversal (../)", 0.80),
    _Pattern(re.compile(r"%2[eE]%2[eE]"), "encoded directory traversal (%2e%2e)", 0.90),
    _Pattern(re.compile(r"\\\\[a-zA-Z0-9]"), "UNC path (\\\\server)", 0.80),
)

# L2_009: Command injection patterns
_COMMAND_INJECTION_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(re.compile(r"\$\("), "command substitution $()", 0.85),
    _Pattern(
        re.compile(
            r"`(?:rm|cat|curl|wget|nc|bash|sh|python|perl|ruby|exec|eval|whoami|id|env|"
            r"ls|cp|mv|chmod|chown|kill|pkill|nohup|sudo)\b[^`]*`",
            re.IGNORECASE,
        ),
        "backtick command execution",
        0.85,
    ),
    _Pattern(
        re.compile(
            r"\|\s*(?:grep|awk|sed|sort|tee|xargs|bash|sh|python|perl|ruby|cat|curl|wget|nc)\b",
            re.IGNORECASE,
        ),
        "pipe to dangerous command",
        0.80,
    ),
    _Pattern(re.compile(r"&&\s*\w"), "chained command (&&)", 0.80),
    _Pattern(re.compile(r"\|\|\s*\w"), "fallback command (||)", 0.75),
    _Pattern(
        re.compile(
            r";\s*(?:rm|cat|curl|wget|nc|bash|sh|python|perl|ruby|exec|eval)\b", re.IGNORECASE
        ),
        "semicolon before dangerous command",
        0.90,
    ),
)


# ── Text field types ─────────────────────────────────────────────────────


class _TextField(NamedTuple):
    text: str
    location: str
    field_type: str  # "description", "param_description", "default", "enum"


# ── Helper functions ─────────────────────────────────────────────────────


# Common Latin confusables (Cyrillic, Greek) -- shared with L1
_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic U+0430 -> a
    "\u0435": "e",  # Cyrillic U+0435 -> e
    "\u043e": "o",  # Cyrillic U+043E -> o
    "\u0440": "p",  # Cyrillic U+0440 -> p
    "\u0441": "c",  # Cyrillic U+0441 -> c
    "\u0443": "y",  # Cyrillic U+0443 -> y
    "\u0445": "x",  # Cyrillic U+0445 -> x
    "\u0455": "s",  # Cyrillic U+0455 -> s
    "\u0456": "i",  # Cyrillic U+0456 -> i
    "\u03bf": "o",  # Greek U+03BF -> o
}


def _normalize_text(text: str) -> str:
    """Strip Unicode format chars, replace confusables, and NFKC-normalize."""
    stripped = "".join(c for c in text if unicodedata.category(c) != "Cf")
    normalized = unicodedata.normalize("NFKC", stripped)
    return "".join(_CONFUSABLES.get(c, c) for c in normalized)


def _is_safe_url(url: str) -> bool:
    """Check if URL points to a known-safe documentation host."""
    return _SAFE_URL_RE.match(url) is not None


def _url_has_exfil_words(url: str) -> bool:
    """Check if URL path contains exfiltration-related words."""
    lower = url.lower()
    return any(word in lower for word in _EXFIL_URL_WORDS)


def _extract_text_fields(
    tool: ToolDefinition,
) -> Iterator[_TextField]:
    """Extract all text fields from a tool definition for analysis."""
    # Tool title
    if tool.title.strip():
        yield _TextField(tool.title, "title", "description")

    # Tool description
    if tool.description.strip():
        yield _TextField(tool.description, "description", "description")

    # Schema-level description/title
    schema = tool.input_schema
    schema_desc = schema.get("description", "")
    if isinstance(schema_desc, str) and schema_desc.strip():
        yield _TextField(schema_desc, "inputSchema.description", "description")
    schema_title = schema.get("title", "")
    if isinstance(schema_title, str) and schema_title.strip():
        yield _TextField(schema_title, "inputSchema.title", "description")

    # Parameter-level text fields
    properties = schema.get("properties")
    if isinstance(properties, dict):
        yield from _extract_param_fields(properties, "inputSchema.properties", 0)

    # Annotations — recursively extract string values
    if tool.annotations:
        yield from _extract_annotation_fields(tool.annotations, "annotations", 0)


def _extract_param_fields(
    properties: dict[str, Any],
    parent_path: str,
    depth: int,
) -> Iterator[_TextField]:
    """Recursively extract text from parameter definitions."""
    if depth > _MAX_RECURSION_DEPTH:
        return

    for param_name, param_def in properties.items():
        if not isinstance(param_def, dict):
            continue

        location = f"{parent_path}.{param_name}"

        # Parameter description
        desc = param_def.get("description", "")
        if isinstance(desc, str) and desc.strip():
            yield _TextField(desc, f"{location}.description", "param_description")

        # Default value
        default = param_def.get("default")
        if isinstance(default, str) and default.strip():
            yield _TextField(default, f"{location}.default", "default")
        elif isinstance(default, list):
            for i, item in enumerate(default):
                if isinstance(item, str) and item.strip():
                    yield _TextField(item, f"{location}.default[{i}]", "default")

        # Enum values
        enum_vals = param_def.get("enum")
        if isinstance(enum_vals, list):
            for i, val in enumerate(enum_vals):
                if isinstance(val, str) and val.strip():
                    yield _TextField(val, f"{location}.enum[{i}]", "enum")

        # Recurse into nested object properties
        if param_def.get("type") == "object":
            nested = param_def.get("properties")
            if isinstance(nested, dict):
                yield from _extract_param_fields(
                    nested,
                    f"{location}.properties",
                    depth + 1,
                )

        # Recurse into array items
        if param_def.get("type") == "array":
            items = param_def.get("items")
            if isinstance(items, dict):
                # items-level description
                items_desc = items.get("description", "")
                if isinstance(items_desc, str) and items_desc.strip():
                    yield _TextField(
                        items_desc, f"{location}.items.description", "param_description"
                    )
                # items with object properties
                items_props = items.get("properties")
                if isinstance(items_props, dict):
                    yield from _extract_param_fields(
                        items_props,
                        f"{location}.items.properties",
                        depth + 1,
                    )


def _extract_annotation_fields(
    data: dict[str, Any],
    parent_path: str,
    depth: int,
) -> Iterator[_TextField]:
    """Recursively extract string values from annotations dict."""
    if depth > _MAX_RECURSION_DEPTH:
        return

    for key, value in data.items():
        location = f"{parent_path}.{key}"
        if isinstance(value, str) and value.strip():
            yield _TextField(value, location, "description")
        elif isinstance(value, dict):
            yield from _extract_annotation_fields(value, location, depth + 1)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, str) and item.strip():
                    yield _TextField(item, f"{location}[{i}]", "description")


# ── Main analyzer ────────────────────────────────────────────────────────


class L2HeuristicAnalyzer:
    """L2 Heuristic Analysis: text content inspection of tool definitions."""

    __slots__ = ("_tool_name_patterns", "_tool_names")

    @property
    def layer(self) -> Layer:
        return Layer.L2_HEURISTIC

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]:
        """Run all L2 heuristic checks on tool definitions."""
        self._tool_names: frozenset[str] = frozenset(t.name for t in tools)
        # Pre-compile tool name patterns once (avoids O(N²) re.compile in cross-server check)
        self._tool_name_patterns: dict[str, re.Pattern[str]] = {
            name: re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE)
            for name in self._tool_names
            if len(name) >= _MIN_TOOL_NAME_LEN
        }

        findings: list[Finding] = []
        for tool in tools:
            try:
                tool_findings = self._analyze_tool(tool)
                tool_findings.extend(self._check_combinations(tool.name, tool_findings))
                findings.extend(tool_findings)
            except Exception:  # noqa: PERF203 — fail-closed per tool
                logger.warning("L2 analysis failed for tool '%s', skipping", tool.name)
        return findings

    def _analyze_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        text_fields = list(_extract_text_fields(tool))

        for tf in text_fields:
            normalized = _normalize_text(tf.text)
            if not normalized.strip():
                continue

            findings.extend(self._check_directives(tool.name, normalized, tf.location))
            findings.extend(self._check_sensitive_paths(tool.name, normalized, tf.location))
            findings.extend(self._check_exfil_destinations(tool.name, normalized, tf.location))
            findings.extend(self._check_justifications(tool.name, normalized, tf.location))
            findings.extend(self._check_imperatives(tool.name, normalized, tf.location))
            findings.extend(self._check_path_traversal(tool.name, normalized, tf.location))

            if tf.field_type in ("default", "enum"):
                findings.extend(self._check_poisoned_values(tool.name, normalized, tf.location))
                findings.extend(self._check_command_injection(tool.name, normalized, tf.location))
            elif tf.field_type == "description":
                # In descriptions, only flag command injection with dangerous commands
                findings.extend(self._check_command_injection(tool.name, normalized, tf.location))

        # Cross-server shadowing requires full description + tool name set
        findings.extend(self._check_cross_server(tool))

        return findings

    # ── Individual checks ────────────────────────────────────────────

    def _check_directives(
        self,
        tool_name: str,
        text: str,
        location: str,
    ) -> list[Finding]:
        """L2_001: Detect directive/markup tag injection."""
        findings: list[Finding] = []
        for pat in _DIRECTIVE_PATTERNS:
            if pat.regex.search(text):
                findings.append(
                    self._finding(
                        "L2_001",
                        tool_name,
                        _severity_from_confidence(pat.confidence),
                        f"Directive injection detected: {pat.desc}",
                        location=location,
                        attack_type=AttackType.PROMPT_INJECTION,
                        cwe="CWE-74",
                        confidence=pat.confidence,
                    )
                )
                break  # One finding per check per text field
        return findings

    def _check_sensitive_paths(
        self,
        tool_name: str,
        text: str,
        location: str,
    ) -> list[Finding]:
        """L2_002: Detect sensitive file path references."""
        findings: list[Finding] = []
        for pat in _SENSITIVE_PATH_PATTERNS:
            if pat.regex.search(text):
                attack = (
                    AttackType.CREDENTIAL_EXPOSURE
                    if "ssh" in pat.desc.lower() or "aws" in pat.desc.lower()
                    else AttackType.DATA_EXFILTRATION
                )
                findings.append(
                    self._finding(
                        "L2_002",
                        tool_name,
                        _severity_from_confidence(pat.confidence),
                        f"Sensitive file path in text: {pat.desc}",
                        location=location,
                        attack_type=attack,
                        cwe="CWE-200",
                        confidence=pat.confidence,
                    )
                )
                break
        return findings

    def _check_exfil_destinations(
        self,
        tool_name: str,
        text: str,
        location: str,
    ) -> list[Finding]:
        """L2_003: Detect external destination references (URLs, emails, phones)."""
        findings: list[Finding] = []

        # Email addresses
        if _EMAIL_RE.search(text):
            findings.append(
                self._finding(
                    "L2_003",
                    tool_name,
                    FindingSeverity.HIGH,
                    "Email address found in text content — potential exfiltration target",
                    location=location,
                    attack_type=AttackType.DATA_EXFILTRATION,
                    cwe="CWE-200",
                    confidence=0.85,
                )
            )

        # Phone numbers
        if _PHONE_RE.search(text):
            findings.append(
                self._finding(
                    "L2_003",
                    tool_name,
                    FindingSeverity.MEDIUM,
                    "Phone number found in text content — potential exfiltration target",
                    location=location,
                    attack_type=AttackType.DATA_EXFILTRATION,
                    cwe="CWE-200",
                    confidence=0.70,
                )
            )

        # URLs (skip safe documentation URLs)
        for m in _URL_RE.finditer(text):
            url = m.group(0)
            if _is_safe_url(url):
                continue
            severity = FindingSeverity.HIGH if _url_has_exfil_words(url) else FindingSeverity.MEDIUM
            conf = 0.85 if _url_has_exfil_words(url) else 0.65
            findings.append(
                self._finding(
                    "L2_003",
                    tool_name,
                    severity,
                    "URL found in text content — potential exfiltration destination",
                    location=location,
                    attack_type=AttackType.DATA_EXFILTRATION,
                    cwe="CWE-200",
                    confidence=conf,
                )
            )
            break  # One URL finding per field

        return findings

    def _check_cross_server(self, tool: ToolDefinition) -> list[Finding]:
        """L2_004: Detect cross-server tool shadowing references."""
        findings: list[Finding] = []
        desc = tool.description
        if not desc.strip():
            return findings

        normalized = _normalize_text(desc).lower()

        # Check for shadowing language patterns (use normalized to defeat ZWS bypass)
        has_shadowing_language = False
        for pat in _SHADOWING_PATTERNS:
            if pat.regex.search(normalized):
                findings.append(
                    self._finding(
                        "L2_004",
                        tool.name,
                        _severity_from_confidence(pat.confidence),
                        f"Cross-server shadowing language: {pat.desc}",
                        location="description",
                        attack_type=AttackType.CROSS_SERVER_SHADOWING,
                        cwe="CWE-441",
                        confidence=pat.confidence,
                    )
                )
                break

        # Check if description references OTHER tool names (pre-compiled patterns)
        for other_name, pattern in self._tool_name_patterns.items():
            if other_name == tool.name:
                continue
            if pattern.search(normalized):
                severity = (
                    FindingSeverity.CRITICAL if has_shadowing_language else FindingSeverity.HIGH
                )
                conf = 0.90 if has_shadowing_language else 0.75
                findings.append(
                    self._finding(
                        "L2_004",
                        tool.name,
                        severity,
                        f"Description references another tool: '{other_name}'",
                        location="description",
                        attack_type=AttackType.CROSS_SERVER_SHADOWING,
                        cwe="CWE-441",
                        confidence=conf,
                    )
                )
                break  # One cross-reference finding per tool

        return findings

    def _check_poisoned_values(
        self,
        tool_name: str,
        text: str,
        location: str,
    ) -> list[Finding]:
        """L2_005: Detect hidden instructions in enum/default values."""
        findings: list[Finding] = []
        for pat in _POISONED_VALUE_PATTERNS:
            if pat.regex.search(text):
                findings.append(
                    self._finding(
                        "L2_005",
                        tool_name,
                        FindingSeverity.HIGH,
                        f"Enum/default value poisoning: {pat.desc}",
                        location=location,
                        attack_type=AttackType.PROMPT_INJECTION,
                        cwe="CWE-74",
                        confidence=pat.confidence,
                    )
                )
                break
        return findings

    def _check_justifications(
        self,
        tool_name: str,
        text: str,
        location: str,
    ) -> list[Finding]:
        """L2_006: Detect suspicious justification patterns."""
        findings: list[Finding] = []
        for pat in _JUSTIFICATION_PATTERNS:
            if pat.regex.search(text):
                findings.append(
                    self._finding(
                        "L2_006",
                        tool_name,
                        _severity_from_confidence(pat.confidence),
                        f"Suspicious justification: {pat.desc}",
                        location=location,
                        attack_type=AttackType.PROMPT_INJECTION,
                        cwe="CWE-74",
                        confidence=pat.confidence,
                    )
                )
                break
        return findings

    def _check_imperatives(
        self,
        tool_name: str,
        text: str,
        location: str,
    ) -> list[Finding]:
        """L2_007: Detect imperative instruction patterns."""
        findings: list[Finding] = []
        for pat in _IMPERATIVE_PATTERNS:
            if pat.regex.search(text):
                findings.append(
                    self._finding(
                        "L2_007",
                        tool_name,
                        _severity_from_confidence(pat.confidence),
                        f"Imperative instruction: {pat.desc}",
                        location=location,
                        attack_type=AttackType.PROMPT_INJECTION,
                        cwe="CWE-74",
                        confidence=pat.confidence,
                    )
                )
                break
        return findings

    def _check_path_traversal(
        self,
        tool_name: str,
        text: str,
        location: str,
    ) -> list[Finding]:
        """L2_008: Detect path traversal patterns."""
        findings: list[Finding] = []
        for pat in _PATH_TRAVERSAL_PATTERNS:
            if pat.regex.search(text):
                findings.append(
                    self._finding(
                        "L2_008",
                        tool_name,
                        _severity_from_confidence(pat.confidence),
                        f"Path traversal pattern: {pat.desc}",
                        location=location,
                        attack_type=AttackType.PATH_TRAVERSAL,
                        cwe="CWE-22",
                        confidence=pat.confidence,
                    )
                )
                break
        return findings

    def _check_command_injection(
        self,
        tool_name: str,
        text: str,
        location: str,
    ) -> list[Finding]:
        """L2_009: Detect command injection patterns."""
        findings: list[Finding] = []
        for pat in _COMMAND_INJECTION_PATTERNS:
            if pat.regex.search(text):
                findings.append(
                    self._finding(
                        "L2_009",
                        tool_name,
                        _severity_from_confidence(pat.confidence),
                        f"Command injection pattern: {pat.desc}",
                        location=location,
                        attack_type=AttackType.COMMAND_INJECTION,
                        cwe="CWE-78",
                        confidence=pat.confidence,
                    )
                )
                break
        return findings

    def _check_combinations(
        self,
        tool_name: str,
        findings: list[Finding],
    ) -> list[Finding]:
        """L2_010: Escalate when multiple check types co-occur on same tool."""
        if not findings:
            return []

        # Collect unique check IDs that produced findings
        check_ids = {f.id for f in findings}

        # Dangerous combinations that warrant escalation (always report, even with CRITICAL)
        escalation_pairs: tuple[tuple[frozenset[str], str], ...] = (
            (frozenset({"L2_001", "L2_002"}), "directive injection + sensitive file path"),
            (frozenset({"L2_001", "L2_007"}), "directive injection + imperative instruction"),
            (frozenset({"L2_002", "L2_006"}), "sensitive file path + fake justification"),
            (frozenset({"L2_003", "L2_007"}), "exfiltration target + imperative instruction"),
            (frozenset({"L2_002", "L2_007"}), "sensitive file path + imperative instruction"),
            (frozenset({"L2_002", "L2_003"}), "sensitive file path + exfiltration target"),
        )

        for pair, desc in escalation_pairs:
            if pair.issubset(check_ids):
                return [
                    self._finding(
                        "L2_010",
                        tool_name,
                        FindingSeverity.CRITICAL,
                        f"Multi-signal compound finding: {desc}",
                        attack_type=AttackType.PROMPT_INJECTION,
                        cwe="CWE-74",
                        confidence=0.95,
                    )
                ]

        return []

    # ── Helper ───────────────────────────────────────────────────────

    @staticmethod
    def _finding(
        finding_id: str,
        tool_name: str,
        severity: FindingSeverity,
        message: str,
        *,
        location: str = "",
        attack_type: AttackType | None = None,
        cwe: str | None = None,
        confidence: float = 1.0,
    ) -> Finding:
        return Finding(
            id=finding_id,
            layer=Layer.L2_HEURISTIC,
            severity=severity,
            tool_name=tool_name,
            message=message,
            location=location,
            attack_type=attack_type,
            cwe=cwe,
            confidence=confidence,
        )


# ── Severity helper ──────────────────────────────────────────────────────


def _severity_from_confidence(confidence: float) -> FindingSeverity:
    """Map confidence score to finding severity."""
    if confidence >= 0.90:
        return FindingSeverity.CRITICAL
    if confidence >= 0.75:
        return FindingSeverity.HIGH
    if confidence >= 0.55:
        return FindingSeverity.MEDIUM
    return FindingSeverity.LOW
