"""Constraint matching infrastructure: sanitization, field extraction, value matching.

This module contains the security-critical foundation layer used by all solver
tiers.  Every string value passes through ``_sanitize_string()`` before matching
against constraint entries.

Functions are ordered by the evaluation pipeline:
1. Sanitize input (strip invisible chars, NFKC normalize)
2. Extract field value from action args
3. Match value against constraint entries
4. Create violation on match
"""

from __future__ import annotations

import fnmatch
import functools
import logging
import re
import unicodedata
import urllib.parse
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Sequence

    from munio.models import ConstraintCondition

from munio.models import (
    Constraint,
    MatchMode,
    MunioError,
    Tier,
    Violation,
    ViolationSeverity,
    ViolationSource,
)

__all__ = [
    "_MISSING",
    "_STRIP_CHARS",
    "InputTooLargeError",
    "_FieldValue",
    "_MissingSentinel",
    "_any_match",
    "_check_conditions",
    "_collect_string_values",
    "_compile_regex",
    "_extract_field",
    "_make_system_violation",
    "_make_violation",
    "_match_value",
    "_sanitize_string",
    "_strict_eq",
]

logger = logging.getLogger(__name__)

_MAX_LEAF_COUNT = 10_000
_MAX_FIELD_DEPTH = 32
_MAX_NODE_COUNT = 100_000

# Characters to strip from input values before matching.
# Zero-width chars, soft hyphen, combining grapheme joiner, BOM.
_ZERO_WIDTH_CHARS = frozenset(
    "\u200b"  # ZERO WIDTH SPACE
    "\u200c"  # ZERO WIDTH NON-JOINER
    "\u200d"  # ZERO WIDTH JOINER
    "\ufeff"  # BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
    "\u00ad"  # SOFT HYPHEN
    "\u034f"  # COMBINING GRAPHEME JOINER
    "\u2060"  # WORD JOINER
    "\u2061"  # FUNCTION APPLICATION (invisible math operator)
    "\u2062"  # INVISIBLE TIMES
    "\u2063"  # INVISIBLE SEPARATOR
    "\u2064"  # INVISIBLE PLUS
    "\u180e"  # MONGOLIAN VOWEL SEPARATOR
)

# Variation selectors: invisible chars that modify preceding character rendering.
# NFKC does NOT remove these — must strip explicitly to prevent bypass.
_VARIATION_SELECTORS = frozenset(chr(c) for c in range(0xFE00, 0xFE10))

# Bidi control characters.
_BIDI_CONTROLS = frozenset(
    "\u200e"  # LEFT-TO-RIGHT MARK
    "\u200f"  # RIGHT-TO-LEFT MARK
    "\u202a"  # LEFT-TO-RIGHT EMBEDDING
    "\u202b"  # RIGHT-TO-LEFT EMBEDDING
    "\u202c"  # POP DIRECTIONAL FORMATTING
    "\u202d"  # LEFT-TO-RIGHT OVERRIDE
    "\u202e"  # RIGHT-TO-LEFT OVERRIDE
    "\u2066"  # LEFT-TO-RIGHT ISOLATE
    "\u2067"  # RIGHT-TO-LEFT ISOLATE
    "\u2068"  # FIRST STRONG ISOLATE
    "\u2069"  # POP DIRECTIONAL ISOLATE
)

# Surrogate code points (U+D800-U+DFFF): invalid in well-formed UTF-8,
# can bypass denylist matching if injected via programmatic API.
_SURROGATES = frozenset(chr(c) for c in range(0xD800, 0xE000))

# C0 control chars (U+0000-U+001F) — null, ESC, and all other non-printable
# C0 controls that can break denylist matching.
_C0_CONTROLS = frozenset(chr(c) for c in range(0x20))

# DEL (U+007F) and C1 controls (U+0080-U+009F).
_C1_CONTROLS = frozenset(chr(c) for c in range(0x80, 0xA0)) | {"\x7f"}

# Tag characters (U+E0001-U+E007F): invisible format markers that survive NFKC.
_TAG_CHARS = frozenset(chr(c) for c in range(0xE0001, 0xE0080))

# Variation Selectors Supplement (U+E0100-U+E01EF): 240 additional invisible marks.
_VARIATION_SELECTORS_SUPP = frozenset(chr(c) for c in range(0xE0100, 0xE01F0))

# Interlinear Annotation characters (U+FFF9-U+FFFB): invisible format markers.
_INTERLINEAR_ANNOTATION = frozenset("\ufff9\ufffa\ufffb")

# Line/paragraph separators (U+2028-U+2029): can break regex . matching.
_LINE_SEPARATORS = frozenset("\u2028\u2029")

_STRIP_CHARS = (
    _ZERO_WIDTH_CHARS
    | _VARIATION_SELECTORS
    | _VARIATION_SELECTORS_SUPP
    | _BIDI_CONTROLS
    | _SURROGATES
    | _C0_CONTROLS
    | _C1_CONTROLS
    | _TAG_CHARS
    | _INTERLINEAR_ANNOTATION
    | _LINE_SEPARATORS
)


# ── String preprocessing pipeline (security-critical) ───────────────────


def _sanitize_string(value: str) -> str:
    """Normalize and sanitize a string value before matching.

    Pipeline (loops until stable, max 5 iterations):
    1. URL percent-decoding — decodes ``%2F`` → ``/``, ``%69`` → ``i``, etc.
    2. NFKC normalization — collapses fullwidth chars (e.g. ``evil`` → ``evil``).
       NOTE: NFKC does NOT handle cross-script homoglyphs (Cyrillic U+0430 vs Latin ``a``).
       Confusables support is planned for Phase 2.
    3. Strip null bytes, zero-width characters, and bidi controls.

    NFKC is applied inside the loop because it can create new percent-encoding
    sequences (e.g. superscript ``¹`` (U+00B9) → ``1`` turns ``%0¹`` into ``%01``).

    This function is idempotent: applying it twice produces the same result.
    """
    # Loop decode+normalize until stable to handle multi-layer encoding
    # and NFKC-created percent sequences.
    # Max 5 iterations prevents infinite loop on adversarial input
    # while catching 4x encoding like %25252569 → %252569 → %2569 → %69 → i.
    for _ in range(5):
        prev = value
        if "%" in value:
            value = urllib.parse.unquote(value)
        value = unicodedata.normalize("NFKC", value)
        if any(ch in _STRIP_CHARS for ch in value):
            value = "".join(ch for ch in value if ch not in _STRIP_CHARS)
        if value == prev:
            break
    return value


# ── Field extraction ─────────────────────────────────────────────────────


class _MissingSentinel:
    """Sentinel for missing field values. Distinguishes 'missing' from None."""

    __slots__ = ()

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "_MISSING"


_MISSING = _MissingSentinel()


def _extract_field(args: dict[str, Any], field_path: str) -> Any:
    """Extract a value from nested args dict using dot-separated path.

    Always splits on ``.`` and traverses nested dicts. Never does flat key lookup.
    Keys containing dots (e.g. ``"db.host"``) are not addressable; use nested dicts.

    Args:
        args: The arguments dict to extract from.
        field_path: Dot-separated path (e.g. ``"headers.authorization"``).

    Returns:
        The extracted value, or ``_MISSING`` if any segment is missing.
    """
    if not field_path:
        return _MISSING

    segments = field_path.split(".")
    if len(segments) > _MAX_FIELD_DEPTH:
        return _MISSING

    current: Any = args
    for segment in segments:
        if not isinstance(current, dict):
            return _MISSING
        if segment not in current:
            return _MISSING
        current = current[segment]

    return current


# ── Value collection (field="*") ─────────────────────────────────────────


class _FieldValue(NamedTuple):
    """A field path and its sanitized string value."""

    path: str
    value: str


class InputTooLargeError(MunioError):
    """Raised when input exceeds safety limits (e.g. >10K leaf values).

    This triggers a fail-closed CRITICAL violation in Tier1Solver.
    """


def _collect_string_values(
    args: dict[str, Any], max_depth: int = _MAX_FIELD_DEPTH
) -> list[_FieldValue]:
    """Collect all leaf values from a nested args dict as sanitized strings.

    Uses iterative traversal (not recursive) to prevent stack overflow.
    ALL leaves are converted via ``_sanitize_string(str(value))``.

    Args:
        args: The arguments dict to traverse.
        max_depth: Maximum nesting depth.

    Returns:
        List of (path, sanitized_value) tuples.

    Raises:
        InputTooLargeError: If more than 10,000 leaves are found.
    """
    result: list[_FieldValue] = []
    # Stack items: (current_value, current_path, current_depth)
    stack: list[tuple[str, Any, int]] = [("", args, 0)]
    node_count = 0

    while stack:
        path_prefix, current, depth = stack.pop()
        node_count += 1
        if node_count > _MAX_NODE_COUNT:
            msg = f"Action arguments exceed {_MAX_NODE_COUNT} nodes; cannot fully verify"
            raise InputTooLargeError(msg)

        if depth > max_depth:
            msg = f"Action arguments exceed depth {max_depth}; cannot fully verify"
            raise InputTooLargeError(msg)

        if isinstance(current, dict):
            for key, val in current.items():
                child_path = f"{path_prefix}.{key}" if path_prefix else key
                stack.append((child_path, val, depth + 1))
        elif isinstance(current, list):
            for i, val in enumerate(current):
                child_path = f"{path_prefix}[{i}]"
                stack.append((child_path, val, depth + 1))
        else:
            # Leaf value — sanitize and collect.
            # None = missing/absent — skip to prevent str(None) → "None" bypass.
            if current is None:
                continue
            sanitized = _sanitize_string(str(current))
            result.append(_FieldValue(path=path_prefix, value=sanitized))
            if len(result) > _MAX_LEAF_COUNT:
                msg = f"Action arguments exceed {_MAX_LEAF_COUNT} leaf values; cannot fully verify"
                raise InputTooLargeError(msg)

    return result


# ── Regex compilation cache ──────────────────────────────────────────────


@functools.lru_cache(maxsize=256)
def _compile_regex(pattern: str, case_sensitive: bool = True) -> re.Pattern[str]:
    """Compile a regex pattern with caching.

    Cache key includes ``case_sensitive`` flag to produce correct
    ``re.IGNORECASE`` variant when needed.
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(pattern, flags)


# ── Value matching ───────────────────────────────────────────────────────


def _match_value(
    value: str,
    entry: str,
    mode: MatchMode,
    case_sensitive: bool,
    *,
    fullmatch: bool = False,
) -> bool:
    """Check if a pre-sanitized value matches a constraint entry.

    The ``value`` is expected to be already sanitized by the caller.
    The ``entry`` (from constraint values/patterns) is sanitized here as
    defense-in-depth against YAML copy-paste with zero-width chars.

    For REGEX mode, ``re.IGNORECASE`` is used instead of casefolding the pattern
    (casefolding destroys regex semantics: ``\\S`` → ``\\s``, ``\\W`` → ``\\w``).

    Args:
        fullmatch: If True, use ``re.fullmatch`` instead of ``re.search`` for
            REGEX mode. Used for allowlists where the entire value must match
            (prevents substring bypass: ``evil.com?r=safe.com`` matching ``safe.com``).
    """
    # Sanitize the constraint entry (defense-in-depth)
    if mode != MatchMode.REGEX:
        entry = _sanitize_string(entry)

    if mode == MatchMode.REGEX:
        compiled = _compile_regex(entry, case_sensitive)
        if fullmatch:
            return compiled.fullmatch(value) is not None
        return compiled.search(value) is not None

    # Apply case normalization for non-regex modes
    if not case_sensitive:
        value = value.casefold()
        entry = entry.casefold()

    if mode == MatchMode.EXACT:
        return value == entry
    if mode == MatchMode.CONTAINS:
        return entry in value
    if mode == MatchMode.PREFIX:
        return value.startswith(entry)
    if mode == MatchMode.SUFFIX:
        return value.endswith(entry)
    if mode == MatchMode.GLOB:
        return fnmatch.fnmatchcase(value, entry)

    return False  # pragma: no cover — all MatchMode values handled above


def _any_match(
    value: str,
    entries: Sequence[str],
    mode: MatchMode,
    case_sensitive: bool,
    *,
    fullmatch: bool = False,
) -> bool:
    """Check if a value matches ANY entry in the list."""
    return any(
        _match_value(value, entry, mode, case_sensitive, fullmatch=fullmatch) for entry in entries
    )


# ── Type-safe comparison ─────────────────────────────────────────────────


def _strict_eq(a: object, b: object) -> bool:
    """Equality check that prevents bool/int type confusion.

    In Python ``1 == True`` and ``0 == False``. A condition ``equals: true``
    should NOT match integer ``1``.  We guard against this by requiring
    matching types when either operand is ``bool``.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


# ── Condition checking ───────────────────────────────────────────────────


def _check_conditions(
    args: dict[str, Any],
    conditions: Sequence[ConstraintCondition],
) -> bool:
    """Check if all conditions are met (AND logic).

    Uses the same ``_extract_field`` as check fields for uniform dot-path semantics.

    Args:
        args: The action's args dict.
        conditions: List of ConstraintCondition objects.

    Returns:
        True if all conditions pass, False if any fails.
    """
    for condition in conditions:
        field_value = _extract_field(args, condition.field)
        is_present = field_value is not _MISSING

        if condition.exists is not None:
            if condition.exists and not is_present:
                return False
            if not condition.exists and is_present:
                return False

        if condition.equals is not None and (
            not is_present or not _strict_eq(field_value, condition.equals)
        ):
            return False

        if condition.not_equals is not None and (
            is_present and _strict_eq(field_value, condition.not_equals)
        ):
            return False

    return True


# ── Violation factories ──────────────────────────────────────────────────


def _make_violation(
    constraint: Constraint,
    message: str,
    field: str = "",
    actual_value: str = "",
    source: ViolationSource = ViolationSource.SECURITY,
) -> Violation:
    """Create a Violation from a constraint and context.

    Truncation of actual_value is handled by Verifier._postprocess_violations,
    not here — single truncation point controlled by config.
    """
    return Violation(
        constraint_name=constraint.name,
        constraint_category=constraint.category,
        severity=constraint.severity,
        message=message,
        field=field,
        actual_value=actual_value,
        tier=constraint.tier,
        source=source,
    )


def _make_system_violation(
    message: str,
    *,
    field: str = "",
    tier: Tier = Tier.TIER_1,
    source: ViolationSource = ViolationSource.SYSTEM,
) -> Violation:
    """Create a system-level violation (not tied to a specific constraint)."""
    return Violation(
        constraint_name="__system__",
        constraint_category="",
        severity=ViolationSeverity.CRITICAL,
        message=message,
        field=field,
        tier=tier,
        source=source,
    )
