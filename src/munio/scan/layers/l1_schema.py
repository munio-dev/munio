"""L1 Schema Analysis: structural checks on MCP tool definitions.

Checks:
  L1_001  Missing tool description
  L1_002  Empty/missing inputSchema
  L1_003  additionalProperties not false
  L1_004  Untyped parameter
  L1_005  Missing string bounds (maxLength/pattern)
  L1_006  Missing numeric bounds (maximum/minimum)
  L1_007  Dangerous parameter name
  L1_008  Missing required array
  L1_009  Missing parameter description
  L1_010  Excessive parameter count
  L1_011  Suspicious default value
  L1_012  Overly broad object type
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import TYPE_CHECKING, Any

from munio.scan.models import (
    AttackType,
    Finding,
    FindingSeverity,
    Layer,
    ToolDefinition,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

_DANGEROUS_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "system_prompt",
        "conversation_history",
        "model_name",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "api_secret",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "auth_token",
        "ssh_key",
        "private_key",
        "credential",
        "credentials",
        "sidenote",
    }
)

_SUSPICIOUS_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"~/\.ssh", re.IGNORECASE),
    re.compile(r"~/\.aws", re.IGNORECASE),
    re.compile(r"~/\.config", re.IGNORECASE),
    re.compile(r"\.env\b", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"/etc/shadow", re.IGNORECASE),
    re.compile(r"id_rsa", re.IGNORECASE),
    re.compile(r"api_keys?\.json", re.IGNORECASE),
)

_SUSPICIOUS_URL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"169\.254\.169\.254"),
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
)

_MAX_PARAMS = 20
_MAX_RECURSION_DEPTH = 10
_VACUOUS_PATTERNS: frozenset[str] = frozenset({".*", "^.*$", ".+", "^.+$"})
_MAX_STRING_LENGTH_BOUND = 10_000

# Common Latin confusables (Cyrillic, Greek) for homoglyph attack detection
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


def _normalize_param_name(name: str) -> str:
    """Strip zero-width / format chars, replace confusables, and normalize.

    Defends against homoglyph (e.g. Cyrillic U+043E) and zero-width char injection.
    """
    # 1. Strip Unicode category Cf (zero-width, format chars)
    stripped = "".join(c for c in name if unicodedata.category(c) != "Cf")
    # 2. NFKC normalize (compatibility decomposition + composition)
    normalized = unicodedata.normalize("NFKC", stripped)
    # 3. Replace confusable chars (Cyrillic/Greek → Latin)
    deconfused = "".join(_CONFUSABLES.get(c, c) for c in normalized)
    # 4. Casefold for case-insensitive match
    return deconfused.casefold()


class L1SchemaAnalyzer:
    """L1 Schema Analysis layer."""

    @property
    def layer(self) -> Layer:
        return Layer.L1_SCHEMA

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]:
        """Run all L1 checks on a sequence of tool definitions."""
        findings: list[Finding] = []
        for tool in tools:
            try:
                findings.extend(self._analyze_tool(tool))
            except Exception:  # noqa: PERF203 — fail-closed per tool
                logger.warning("L1 analysis failed for tool '%s', skipping", tool.name)
        return findings

    def _analyze_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        schema = tool.input_schema
        properties: dict[str, Any] = schema.get("properties", {})

        # L1_001: Missing tool description
        if not tool.description.strip():
            findings.append(
                self._finding(
                    "L1_001",
                    tool.name,
                    FindingSeverity.LOW,
                    "Tool has no description",
                )
            )

        # L1_002: Empty/missing inputSchema
        if not schema or not properties:
            findings.append(
                self._finding(
                    "L1_002",
                    tool.name,
                    FindingSeverity.MEDIUM,
                    "No inputSchema properties defined — no input validation possible",
                    attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                    cwe="CWE-20",
                )
            )

        # L1_003: additionalProperties not false
        if properties and schema.get("additionalProperties") is not False:
            findings.append(
                self._finding(
                    "L1_003",
                    tool.name,
                    FindingSeverity.LOW,
                    "additionalProperties is not false — accepts arbitrary extra parameters",
                    attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                    cwe="CWE-20",
                )
            )

        # L1_008: Missing required array
        if properties and "required" not in schema:
            findings.append(
                self._finding(
                    "L1_008",
                    tool.name,
                    FindingSeverity.LOW,
                    "No 'required' array in schema",
                )
            )

        # L1_010: Excessive parameter count
        if len(properties) > _MAX_PARAMS:
            findings.append(
                self._finding(
                    "L1_010",
                    tool.name,
                    FindingSeverity.MEDIUM,
                    f"Excessive parameter count: {len(properties)} (max {_MAX_PARAMS})",
                    attack_type=AttackType.TOKEN_STUFFING,
                    cwe="CWE-400",
                )
            )

        # Per-parameter checks (recursive into nested objects)
        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue
            findings.extend(self._check_parameter(tool.name, param_name, param_def))

        return findings

    def _check_parameter(
        self,
        tool_name: str,
        param_name: str,
        param_def: dict[str, Any],
        parent_path: str = "inputSchema.properties",
        depth: int = 0,
    ) -> list[Finding]:
        if depth > _MAX_RECURSION_DEPTH:
            return []

        findings: list[Finding] = []
        param_type = param_def.get("type")
        location = f"{parent_path}.{param_name}"

        # L1_004: Untyped parameter
        if param_type is None:
            findings.append(
                self._finding(
                    "L1_004",
                    tool_name,
                    FindingSeverity.MEDIUM,
                    f"Untyped parameter: '{param_name}'",
                    location=location,
                    attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                    cwe="CWE-1287",
                )
            )

        # L1_005: Missing string bounds (with vacuous detection)
        if param_type == "string":
            bounded = "enum" in param_def or "const" in param_def
            if not bounded:
                ml = param_def.get("maxLength")
                if isinstance(ml, int) and 0 < ml <= _MAX_STRING_LENGTH_BOUND:
                    bounded = True
                pat = param_def.get("pattern")
                if isinstance(pat, str) and pat not in _VACUOUS_PATTERNS:
                    bounded = True
            if not bounded:
                findings.append(
                    self._finding(
                        "L1_005",
                        tool_name,
                        FindingSeverity.LOW,
                        f"String parameter '{param_name}' has no effective "
                        f"maxLength, pattern, or enum constraint",
                        location=location,
                    )
                )

        # L1_006: Missing numeric bounds
        if param_type in ("integer", "number"):
            has_bounds = any(
                k in param_def
                for k in ("maximum", "minimum", "exclusiveMaximum", "exclusiveMinimum", "enum")
            )
            if not has_bounds:
                findings.append(
                    self._finding(
                        "L1_006",
                        tool_name,
                        FindingSeverity.LOW,
                        f"Numeric parameter '{param_name}' has no maximum/minimum bounds",
                        location=location,
                    )
                )

        # L1_007: Dangerous parameter name (NFKC-normalized, zero-width stripped)
        if _normalize_param_name(param_name) in _DANGEROUS_PARAM_NAMES:
            findings.append(
                self._finding(
                    "L1_007",
                    tool_name,
                    FindingSeverity.HIGH,
                    f"Dangerous parameter name: '{param_name}' — may cause LLM to auto-populate "
                    f"with sensitive system data",
                    location=location,
                    attack_type=AttackType.SYSTEM_PROMPT_EXTRACTION,
                    cwe="CWE-497",
                )
            )

        # L1_009: Missing parameter description
        if not param_def.get("description", "").strip():
            findings.append(
                self._finding(
                    "L1_009",
                    tool_name,
                    FindingSeverity.INFO,
                    f"Parameter '{param_name}' has no description",
                    location=location,
                )
            )

        # L1_011: Suspicious default value
        default = param_def.get("default")
        if default is not None:
            findings.extend(
                self._check_suspicious_default(tool_name, param_name, default, location)
            )

        # Also check enum defaults for poisoning
        if "enum" in param_def and isinstance(param_def["enum"], list):
            for enum_val in param_def["enum"]:
                if isinstance(enum_val, str):
                    findings.extend(
                        self._check_suspicious_default(tool_name, param_name, enum_val, location)
                    )

        # L1_012: Overly broad object type
        if param_type == "object" and "properties" not in param_def:
            findings.append(
                self._finding(
                    "L1_012",
                    tool_name,
                    FindingSeverity.MEDIUM,
                    f"Parameter '{param_name}' is type 'object' with no properties defined",
                    location=location,
                    attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                    cwe="CWE-20",
                )
            )

        # Recurse into nested object properties (C3 fix)
        if param_type == "object" and "properties" in param_def:
            nested_props = param_def["properties"]
            if isinstance(nested_props, dict):
                for nested_name, nested_def in nested_props.items():
                    if isinstance(nested_def, dict):
                        findings.extend(
                            self._check_parameter(
                                tool_name,
                                nested_name,
                                nested_def,
                                parent_path=f"{parent_path}.{param_name}.properties",
                                depth=depth + 1,
                            )
                        )

        # Recurse into array items
        if param_type == "array":
            items = param_def.get("items")
            if isinstance(items, dict):
                items_props = items.get("properties")
                if isinstance(items_props, dict):
                    for nested_name, nested_def in items_props.items():
                        if isinstance(nested_def, dict):
                            findings.extend(
                                self._check_parameter(
                                    tool_name,
                                    nested_name,
                                    nested_def,
                                    parent_path=f"{parent_path}.{param_name}.items.properties",
                                    depth=depth + 1,
                                )
                            )

        return findings

    def _check_suspicious_default(
        self,
        tool_name: str,
        param_name: str,
        default: Any,
        location: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if isinstance(default, str):
            # Check for suspicious file paths
            for pattern in _SUSPICIOUS_PATH_PATTERNS:
                if pattern.search(default):
                    findings.append(
                        self._finding(
                            "L1_011",
                            tool_name,
                            FindingSeverity.HIGH,
                            f"Suspicious file path in default value of '{param_name}': "
                            f"may indicate data exfiltration attempt",
                            location=location,
                            attack_type=AttackType.DATA_EXFILTRATION,
                            cwe="CWE-200",
                        )
                    )
                    break

            # Check for suspicious URLs (SSRF)
            for pattern in _SUSPICIOUS_URL_PATTERNS:
                if pattern.search(default):
                    findings.append(
                        self._finding(
                            "L1_011",
                            tool_name,
                            FindingSeverity.HIGH,
                            f"Suspicious URL pattern in default value of '{param_name}': "
                            f"may indicate SSRF attempt",
                            location=location,
                            attack_type=AttackType.SSRF,
                            cwe="CWE-918",
                        )
                    )
                    break

        elif isinstance(default, list):
            for item in default:
                if isinstance(item, str):
                    findings.extend(
                        self._check_suspicious_default(tool_name, param_name, item, location)
                    )

        return findings

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
    ) -> Finding:
        return Finding(
            id=finding_id,
            layer=Layer.L1_SCHEMA,
            severity=severity,
            tool_name=tool_name,
            message=message,
            location=location,
            attack_type=attack_type,
            cwe=cwe,
        )


def schema_completeness_score(tool: ToolDefinition) -> float:
    """Calculate a schema completeness score (0-100) for a tool definition."""
    score = 0.0
    schema = tool.input_schema
    properties: dict[str, Any] = schema.get("properties", {})

    # 20 points: has description
    if tool.description.strip():
        score += 20.0

    # 15 points: has inputSchema with properties
    if properties:
        score += 15.0

    # 10 points: has required array
    if "required" in schema:
        score += 10.0

    if properties:
        typed_count = 0
        described_count = 0
        string_bounded = 0
        numeric_bounded = 0
        string_count = 0
        numeric_count = 0

        for param_def in properties.values():
            if not isinstance(param_def, dict):
                continue

            param_type = param_def.get("type")
            if param_type is not None:
                typed_count += 1
            if param_def.get("description", "").strip():
                described_count += 1

            if param_type == "string":
                string_count += 1
                if any(k in param_def for k in ("maxLength", "pattern", "enum", "const")):
                    string_bounded += 1
            elif param_type in ("integer", "number"):
                numeric_count += 1
                if any(
                    k in param_def
                    for k in ("maximum", "minimum", "exclusiveMaximum", "exclusiveMinimum", "enum")
                ):
                    numeric_bounded += 1

        n = len(properties)

        # 15 points: all params typed
        if typed_count == n:
            score += 15.0

        # 10 points: all params described
        if described_count == n:
            score += 10.0

        # 10 points: string bounds (proportional)
        if string_count > 0:
            score += 10.0 * (string_bounded / string_count)

        # 5 points: numeric bounds (proportional)
        if numeric_count > 0:
            score += 5.0 * (numeric_bounded / numeric_count)

    # 10 points: additionalProperties false
    if schema.get("additionalProperties") is False:
        score += 10.0

    # 5 points: has outputSchema
    if tool.output_schema is not None:
        score += 5.0

    return round(score, 1)
