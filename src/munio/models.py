"""Core Pydantic models, enums, and configuration for munio.

These models are shared across all modules:
- constraints.py uses Constraint, ConstraintCheck, ConstraintConfig
- solver.py uses Action, Constraint, PolicyVerificationResult
- verifier.py uses VerificationResult, Violation
- guard.py uses Action, VerificationResult
- cli.py uses all of the above

Design principles:
- Pydantic v2 for validation + serialization
- Frozen models where possible (immutability)
- YAML constraint format mirrors these models exactly
- Same models reused in future Platform API (FastAPI)
"""

from __future__ import annotations

import ast
import enum
import keyword
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

# ── Constants ─────────────────────────────────────────────────────────────

_MAX_VALUES_PER_CHECK = 10_000
_MAX_PATTERNS_PER_CHECK = 1_000
_MAX_COMPOSITE_VARS = 20
_MAX_EXPRESSION_LEN = 500
_MAX_AST_DEPTH = 10
_MIN_WINDOW_SECONDS = 1.0  # sub-second windows effectively disable rate limiting
_MAX_WINDOW_SECONDS = 86_400  # 24 hours
_MAX_RATE_LIMIT_COUNT = 1_000_000
_MAX_SEQUENCE_STEPS = 10
_MAX_STEP_LENGTH = 256

# Detect regex patterns with nested quantifiers or alternation in quantified
# groups (ReDoS risk).  Catches: (x+)+, (x*)+, (x+)*, (x+){n} — AND
# alternation-based ambiguity: (a|a)+, (a|aa)+, ([x-z]|[x-z])+ etc.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*(?:[+*]|\|)[^)]*\)[+*{]")

# Detect 5+ consecutive quantified atoms WITHOUT separating fixed-text tokens.
# Causes polynomial O(n^k) or exponential backtracking.
# Examples: [a-z]+[a-z]+[a-z]+[a-z]+[a-z]+, a*a*a*a*a*a*
# Conservative: may flag non-overlapping sequences (safe direction).
_POLY_REDOS_RE = re.compile(
    r"(?:"
    r"(?:\[[^\]]*\]|\\[dDsSwW.]|\\.|\.|\w)"  # atom: class, escape, dot, char
    r"[+*{]"  # quantifier
    r"){5,}"  # 5+ consecutive quantified atoms
)

# ── Base exception ────────────────────────────────────────────────────────


class MunioError(Exception):
    """Base exception for all munio errors.

    Allows users to catch all library errors with a single
    ``except MunioError`` clause.
    """


# Backward compatibility alias
ProofAgentError = MunioError


# ── Enums ──────────────────────────────────────────────────────────────────


class VerificationMode(str, enum.Enum):
    """How the guard behaves on violation."""

    ENFORCE = "enforce"  # Block the action, raise error
    SHADOW = "shadow"  # Log violation but allow action
    DISABLED = "disabled"  # Skip verification entirely


class ViolationSeverity(str, enum.Enum):
    """Severity of a constraint violation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckType(str, enum.Enum):
    """Type of constraint check — determines Tier auto-detection."""

    DENYLIST = "denylist"
    ALLOWLIST = "allowlist"
    THRESHOLD = "threshold"
    REGEX_DENY = "regex_deny"
    REGEX_ALLOW = "regex_allow"
    COMPOSITE = "composite"  # Multiple checks combined
    RATE_LIMIT = "rate_limit"  # Sliding window call counting
    SEQUENCE_DENY = "sequence_deny"  # Multi-step attack chain detection


class MatchMode(str, enum.Enum):
    """How string matching is performed."""

    EXACT = "exact"
    CONTAINS = "contains"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    REGEX = "regex"
    GLOB = "glob"


class OnViolation(str, enum.Enum):
    """What to do when a constraint is violated."""

    BLOCK = "block"
    WARN = "warn"
    SHADOW = "shadow"


class FailBehavior(str, enum.Enum):
    """What to do when verification itself fails (Z3 timeout, error)."""

    FAIL_CLOSED = "fail_closed"  # Treat as violation (safe default)
    FAIL_OPEN = "fail_open"  # Treat as allowed (dangerous)


class ViolationSource(str, enum.Enum):
    """Origin of a violation — for observability and alerting.

    NOT configurable for enforcement policy: all sources are always enforced
    the same way.  This enum exists solely for structured logging, dashboards,
    and on-call triage (distinguishing infra issues from real attacks).
    """

    SECURITY = "security"  # Constraint-matched violation (denylist, threshold, etc.)
    PARSE = "parse"  # Malformed input or type mismatch
    INFRA = "infra"  # Z3 timeout, subprocess crash, queue error
    SYSTEM = "system"  # Internal system violation (__system__ constraints)


class Tier(int, enum.Enum):
    """Verification tier — determines which backend handles the check."""

    TIER_1 = 1  # Pure Python: set lookup, regex, thresholds. <0.01ms
    TIER_2 = 2  # Z3 QF_LIA subprocess: arithmetic interactions. 5-100ms
    TIER_3 = 3  # Z3 full + portfolio: complex multi-variable. 100ms-5s
    TIER_4 = 4  # Z3 deploy-time: policy verification. seconds-minutes


class DeployCheckType(str, enum.Enum):
    """Type of deploy-time (Tier 4) Z3 verification."""

    CONSISTENCY = "consistency"  # No contradictions in constraint set
    NO_NEW_ACCESS = "no_new_access"  # CheckNoNewAccess pattern
    DATA_FLOW = "data_flow"  # Transitive reachability / exfiltration
    FILTER_COMPLETENESS = "filter_completeness"  # Denylist covers all variants


class PolicyResult(str, enum.Enum):
    """Outcome of a Tier 4 Z3 policy verification."""

    SAFE = "safe"  # Policy verified safe (e.g. SAT for consistency, UNSAT for no_new_access)
    UNSAFE = "unsafe"  # Policy violation found (e.g. contradiction or counterexample)
    TIMEOUT = "timeout"  # Z3 solver timeout
    UNKNOWN = "unknown"  # Z3 returned unknown
    ERROR = "error"  # Exception during verification


# ── Core Models ────────────────────────────────────────────────────────────


class Action(BaseModel):
    """An agent tool call to be verified.

    This is the input to the verification pipeline. Every framework adapter
    (LangChain, CrewAI, ADK, MCP) normalizes its tool call into this model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str = Field(description="Tool/function name being called")
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the tool",
    )
    agent_id: str | None = Field(
        default=None,
        description="Identifier of the agent making the call",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context (session_id, user_id, etc.)",
    )


class ConstraintCondition(BaseModel):
    """Optional condition on a constraint check (e.g., 'only if auth header exists')."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Field(description="Dot-separated path in Action.args")
    exists: bool | None = Field(default=None, description="Field must exist")
    equals: str | int | float | bool | None = Field(
        default=None, description="Field must equal value"
    )
    not_equals: str | int | float | bool | None = Field(
        default=None, description="Field must not equal value"
    )

    @model_validator(mode="after")
    def _validate_condition(self) -> Self:
        if self.exists is None and self.equals is None and self.not_equals is None:
            msg = "ConstraintCondition must specify at least one of: exists, equals, not_equals"
            raise ValueError(msg)
        if self.exists is False and (self.equals is not None or self.not_equals is not None):
            msg = (
                "exists=False cannot be combined with equals/not_equals "
                "(field must not exist, so there is no value to compare)"
            )
            raise ValueError(msg)
        return self


# ── COMPOSITE expression validation ───────────────────────────────────────

# Positive whitelist of allowed AST nodes (future-proof: new Python AST nodes
# are auto-rejected).  No Call, Attribute, Subscript, Lambda, IfExp, NamedExpr.
_ALLOWED_AST_NODES: frozenset[type] = frozenset(
    {
        ast.Expression,
        ast.BoolOp,
        ast.BinOp,
        ast.UnaryOp,
        ast.Compare,
        ast.Name,
        ast.Constant,
        ast.Load,
        ast.And,
        ast.Or,
        ast.Not,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        # FloorDiv (//) and Mod (%) deliberately excluded: Python semantics
        # differ from Z3 for negative numbers (Python floors, Z3 truncates).
        # This creates false SAFE in Z3 path. Reject at validation time.
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Eq,
        ast.NotEq,
        ast.UAdd,
        ast.USub,
    }
)

# Only int/float constants allowed.  bool is rejected (isinstance(True, int) is
# True — allowing bool would cause `True + x` to silently evaluate as `1 + x`).
_ALLOWED_CONSTANT_TYPES: tuple[type, ...] = (int, float)

_VAR_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,49}$")


def _get_python_builtins() -> frozenset[str]:
    """Return frozenset of Python builtin names (lazy, import-safe)."""
    import builtins as _builtins_mod

    return frozenset(dir(_builtins_mod))


def _validate_variable_name(name: str) -> None:
    """Validate a COMPOSITE variable name for safety.

    Rejects dunder names, Python keywords, builtins, and invalid identifiers.
    Defense-in-depth: prevents eval() namespace pollution.
    """
    if not _VAR_NAME_RE.match(name):
        msg = f"Invalid variable name {name!r}: must match [a-zA-Z][a-zA-Z0-9_]{{0,49}}"
        raise ValueError(msg)
    if name.startswith("__") and name.endswith("__"):
        msg = f"Dunder variable name {name!r} is not allowed (security)"
        raise ValueError(msg)
    if keyword.iskeyword(name) or keyword.issoftkeyword(name):
        msg = f"Python keyword {name!r} cannot be used as variable name"
        raise ValueError(msg)
    builtins_set = _get_python_builtins()
    if name in builtins_set:
        msg = f"Python builtin {name!r} cannot be used as variable name"
        raise ValueError(msg)


def _check_ast_depth(node: ast.AST, max_depth: int, current: int = 0) -> None:
    """Raise ValueError if AST exceeds max depth."""
    if current > max_depth:
        msg = f"Expression AST depth exceeds {max_depth}"
        raise ValueError(msg)
    for child in ast.iter_child_nodes(node):
        _check_ast_depth(child, max_depth, current + 1)


def _validate_expression_ast(expression: str, variable_names: frozenset[str]) -> None:
    """Validate a COMPOSITE expression against a strict AST whitelist.

    Parses ``expression`` as a Python eval-mode expression and walks the AST,
    rejecting any node type not in ``_ALLOWED_AST_NODES``.  Also validates
    that all names reference declared variables and all constants are numeric.

    This function uses only stdlib ``ast`` — no Z3 dependency.
    """
    if not expression or not expression.strip():
        msg = "composite check requires non-empty 'expression'"
        raise ValueError(msg)
    if len(expression) > _MAX_EXPRESSION_LEN:
        msg = f"expression length {len(expression)} exceeds max {_MAX_EXPRESSION_LEN}"
        raise ValueError(msg)

    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        msg = f"Invalid expression syntax: {exc}"
        raise ValueError(msg) from exc

    _check_ast_depth(tree, _MAX_AST_DEPTH)

    has_variable = False
    for node in ast.walk(tree):
        if type(node) not in _ALLOWED_AST_NODES:
            msg = f"Disallowed AST node {type(node).__name__} in expression"
            raise ValueError(msg)
        if isinstance(node, ast.Name):
            if node.id not in variable_names:
                msg = f"Undeclared variable {node.id!r} in expression"
                raise ValueError(msg)
            has_variable = True
        if isinstance(node, ast.Constant):
            # bool check MUST be before int check (isinstance(True, int) is True)
            if isinstance(node.value, bool):
                msg = f"Boolean constant {node.value!r} not allowed in expression (use 1/0 instead)"
                raise ValueError(msg)
            if not isinstance(node.value, _ALLOWED_CONSTANT_TYPES):
                msg = f"Disallowed constant type {type(node.value).__name__} in expression"
                raise ValueError(msg)

    if not has_variable:
        msg = "expression must reference at least one variable"
        raise ValueError(msg)


# ── CompositeVariable ────────────────────────────────────────────────────


class CompositeVariable(BaseModel):
    """Variable declaration for a COMPOSITE constraint expression.

    Maps a named variable to a field path in Action.args, with optional
    type, bounds, and default value.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Field(description="Dot-separated path in Action.args")
    type: Literal["int", "real"] = Field(
        default="int", description="Variable type (maps to Z3 Int or Real)"
    )
    min: float | None = Field(default=None, description="Lower bound")
    max: float | None = Field(default=None, description="Upper bound")
    default: float | None = Field(
        default=None, description="Default value when field is missing from action.args"
    )

    @model_validator(mode="after")
    def _validate_composite_variable(self) -> Self:
        for attr in ("min", "max", "default"):
            v = getattr(self, attr)
            if v is not None and (math.isnan(v) or math.isinf(v)):
                msg = f"CompositeVariable.{attr} must be finite, got {v}"
                raise ValueError(msg)
        if self.min is not None and self.max is not None and self.min > self.max:
            msg = f"min ({self.min}) > max ({self.max})"
            raise ValueError(msg)
        if self.default is not None:
            if self.min is not None and self.default < self.min:
                msg = f"default ({self.default}) < min ({self.min})"
                raise ValueError(msg)
            if self.max is not None and self.default > self.max:
                msg = f"default ({self.default}) > max ({self.max})"
                raise ValueError(msg)
        return self


# ── ConstraintCheck helpers ──────────────────────────────────────────────


def _reject_temporal_fields(check_type: CheckType, check: Any) -> None:
    """Reject temporal fields (window_seconds, max_count, steps, scope) in non-temporal checks."""
    if check.window_seconds is not None:
        msg = f"{check_type} check must not have 'window_seconds'"
        raise ValueError(msg)
    if check.max_count is not None:
        msg = f"{check_type} check must not have 'max_count'"
        raise ValueError(msg)
    if check.steps:
        msg = f"{check_type} check must not have 'steps'"
        raise ValueError(msg)
    if check.scope != "global":
        msg = f"{check_type} check must not have non-default 'scope'"
        raise ValueError(msg)


def _reject_non_temporal_fields(check_type: CheckType, check: Any) -> None:
    """Reject non-temporal fields (values, patterns, min/max, variables, expression) in temporal checks."""
    if check.values:
        msg = f"{check_type} check must not have 'values'"
        raise ValueError(msg)
    if check.patterns:
        msg = f"{check_type} check must not have 'patterns'"
        raise ValueError(msg)
    if check.min is not None or check.max is not None:
        msg = f"{check_type} check must not have 'min'/'max'"
        raise ValueError(msg)
    if check.variables:
        msg = f"{check_type} check must not have 'variables'"
        raise ValueError(msg)
    if check.expression:
        msg = f"{check_type} check must not have 'expression'"
        raise ValueError(msg)


# ── ConstraintCheck ──────────────────────────────────────────────────────


class ConstraintCheck(BaseModel):
    """The check definition inside a constraint.

    Determines WHAT to check and HOW.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: CheckType = Field(description="Type of check")
    field: str = Field(description="Dot-separated path in Action.args to check")
    values: list[str] = Field(default_factory=list, description="For denylist/allowlist")
    patterns: list[str] = Field(default_factory=list, description="For regex checks")
    match: MatchMode = Field(default=MatchMode.EXACT, description="String matching mode")
    case_sensitive: bool = Field(
        default=True,
        description="Case-sensitive matching (set false for URLs, domains)",
    )
    min: float | None = Field(default=None, description="Minimum threshold")
    max: float | None = Field(default=None, description="Maximum threshold")
    unit: str | None = Field(
        default=None, description="Unit for thresholds (informational, not enforced)"
    )
    # COMPOSITE check fields (multi-variable arithmetic expressions)
    variables: dict[str, CompositeVariable] = Field(
        default_factory=dict,
        description="Variable declarations for composite checks",
    )
    expression: str = Field(
        default="",
        description="Arithmetic/boolean expression over declared variables",
    )
    # TEMPORAL check fields (rate limiting and sequence detection)
    window_seconds: float | None = Field(
        default=None,
        description="Sliding window duration in seconds (for rate_limit and sequence_deny)",
    )
    max_count: int | None = Field(
        default=None,
        description="Maximum calls allowed per window (for rate_limit)",
    )
    steps: list[str] = Field(
        default_factory=list,
        description="Ordered tool name patterns for sequence detection (fnmatch globs)",
    )
    scope: Literal["global", "agent"] = Field(
        default="global",
        description="Temporal state scope: 'global' or per 'agent' (uses Action.agent_id)",
    )

    @model_validator(mode="after")
    def _validate_fields_for_type(self) -> Self:
        """Ensure fields are consistent with check type."""
        t = self.type
        if t in (CheckType.DENYLIST, CheckType.ALLOWLIST):
            if not self.values:
                msg = f"{t} check requires non-empty 'values'"
                raise ValueError(msg)
            if len(self.values) > _MAX_VALUES_PER_CHECK:
                msg = f"{t} check has {len(self.values)} values, max {_MAX_VALUES_PER_CHECK}"
                raise ValueError(msg)
            # When match=regex, values are used as regex patterns at runtime —
            # validate syntax and ReDoS the same way as REGEX_DENY/REGEX_ALLOW.
            if self.match == MatchMode.REGEX:
                if any(v == "" for v in self.values):
                    msg = f"{t} check must not contain empty strings in 'values'"
                    raise ValueError(msg)
                for val in self.values:
                    try:
                        re.compile(val)
                    except re.error as exc:
                        msg = f"Invalid regex in values (match=regex) {val!r}: {exc}"
                        raise ValueError(msg) from exc
                    if _NESTED_QUANTIFIER_RE.search(val):
                        msg = f"Regex {val!r} in values (match=regex) contains nested quantifiers (potential ReDoS)"
                        raise ValueError(msg)
                    if _POLY_REDOS_RE.search(val):
                        msg = f"Regex {val!r} in values (match=regex) has 5+ consecutive quantified atoms (polynomial ReDoS)"
                        raise ValueError(msg)
            else:
                # Pre-sanitize values at load time for non-REGEX match modes.
                # _sanitize_string is idempotent, so runtime defense-in-depth
                # in _match_value() is still safe but now nearly free (no-op).
                from munio._matching import _sanitize_string

                sanitized = [_sanitize_string(v) for v in self.values]
                if sanitized != list(self.values):
                    object.__setattr__(self, "values", sanitized)
                # Check AFTER sanitization — control chars may sanitize to empty
                if any(v == "" for v in self.values):
                    msg = (
                        f"{t} check must not contain empty strings in 'values' (after sanitization)"
                    )
                    raise ValueError(msg)
            if self.patterns:
                msg = f"{t} check must not have 'patterns'"
                raise ValueError(msg)
            if self.min is not None or self.max is not None:
                msg = f"{t} check must not have 'min'/'max'"
                raise ValueError(msg)
        elif t == CheckType.THRESHOLD:
            if self.field == "*":
                msg = "threshold check cannot use field='*' (semantically meaningless)"
                raise ValueError(msg)
            if self.min is None and self.max is None:
                msg = "threshold check requires at least 'min' or 'max'"
                raise ValueError(msg)
            for attr_name in ("min", "max"):
                val = getattr(self, attr_name)
                if val is not None and (math.isnan(val) or math.isinf(val)):
                    msg = f"threshold {attr_name} must be a finite number, got {val}"
                    raise ValueError(msg)
            if self.values:
                msg = "threshold check must not have 'values'"
                raise ValueError(msg)
            if self.patterns:
                msg = "threshold check must not have 'patterns'"
                raise ValueError(msg)
        elif t in (CheckType.REGEX_DENY, CheckType.REGEX_ALLOW):
            if not self.patterns:
                msg = f"{t} check requires non-empty 'patterns'"
                raise ValueError(msg)
            if any(p == "" for p in self.patterns):
                msg = f"{t} check must not contain empty strings in 'patterns' (empty regex matches everything)"
                raise ValueError(msg)
            if len(self.patterns) > _MAX_PATTERNS_PER_CHECK:
                msg = f"{t} check has {len(self.patterns)} patterns, max {_MAX_PATTERNS_PER_CHECK}"
                raise ValueError(msg)
            for pattern in self.patterns:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    msg = f"Invalid regex pattern {pattern!r}: {exc}"
                    raise ValueError(msg) from exc
                if _NESTED_QUANTIFIER_RE.search(pattern):
                    msg = f"Regex pattern {pattern!r} contains nested quantifiers (potential ReDoS)"
                    raise ValueError(msg)
                if _POLY_REDOS_RE.search(pattern):
                    msg = f"Regex pattern {pattern!r} has 5+ consecutive quantified atoms (polynomial ReDoS)"
                    raise ValueError(msg)
            if self.values:
                msg = f"{t} check must not have 'values'"
                raise ValueError(msg)
            if self.min is not None or self.max is not None:
                msg = f"{t} check must not have 'min'/'max'"
                raise ValueError(msg)
        elif t == CheckType.COMPOSITE:
            if not self.variables:
                msg = "composite check requires non-empty 'variables'"
                raise ValueError(msg)
            if len(self.variables) > _MAX_COMPOSITE_VARS:
                msg = f"composite check has {len(self.variables)} variables, max {_MAX_COMPOSITE_VARS}"
                raise ValueError(msg)
            for var_name in self.variables:
                _validate_variable_name(var_name)
            _validate_expression_ast(self.expression, frozenset(self.variables))
            if self.values:
                msg = "composite check must not have 'values'"
                raise ValueError(msg)
            if self.patterns:
                msg = "composite check must not have 'patterns'"
                raise ValueError(msg)
            if self.min is not None or self.max is not None:
                msg = "composite check must not have 'min'/'max'"
                raise ValueError(msg)
        elif t == CheckType.RATE_LIMIT:
            if self.field != "*":
                msg = "rate_limit check must use field='*' (counts calls, not field values)"
                raise ValueError(msg)
            if self.window_seconds is None:
                msg = "rate_limit check requires 'window_seconds'"
                raise ValueError(msg)
            # Note: Pydantic v2 coerces bool→float before validator runs,
            # so False→0.0 is caught by the min check below.
            if self.window_seconds < _MIN_WINDOW_SECONDS:
                msg = f"rate_limit window_seconds must be >= {_MIN_WINDOW_SECONDS}, got {self.window_seconds}"
                raise ValueError(msg)
            if self.window_seconds > _MAX_WINDOW_SECONDS:
                msg = f"rate_limit window_seconds must be <= {_MAX_WINDOW_SECONDS}, got {self.window_seconds}"
                raise ValueError(msg)
            if not math.isfinite(self.window_seconds):
                msg = f"rate_limit window_seconds must be finite, got {self.window_seconds}"
                raise ValueError(msg)
            if self.max_count is None:
                msg = "rate_limit check requires 'max_count'"
                raise ValueError(msg)
            # Note: Pydantic v2 coerces bool→int before validator runs,
            # so False→0 is caught by the min check below.
            if self.max_count < 1:
                msg = f"rate_limit max_count must be >= 1, got {self.max_count}"
                raise ValueError(msg)
            if self.max_count > _MAX_RATE_LIMIT_COUNT:
                msg = (
                    f"rate_limit max_count must be <= {_MAX_RATE_LIMIT_COUNT}, got {self.max_count}"
                )
                raise ValueError(msg)
            _reject_non_temporal_fields(t, self)
            if self.steps:
                msg = "rate_limit check must not have 'steps'"
                raise ValueError(msg)
        elif t == CheckType.SEQUENCE_DENY:
            if self.field != "*":
                msg = "sequence_deny check must use field='*' (checks tool call sequences)"
                raise ValueError(msg)
            if not self.steps:
                msg = "sequence_deny check requires non-empty 'steps'"
                raise ValueError(msg)
            if len(self.steps) < 2:
                msg = f"sequence_deny requires at least 2 steps, got {len(self.steps)}"
                raise ValueError(msg)
            if len(self.steps) > _MAX_SEQUENCE_STEPS:
                msg = f"sequence_deny has {len(self.steps)} steps, max {_MAX_SEQUENCE_STEPS}"
                raise ValueError(msg)
            for step in self.steps:
                if not step or not step.strip():
                    msg = "sequence_deny steps must not contain empty or whitespace-only strings"
                    raise ValueError(msg)
                if len(step) > _MAX_STEP_LENGTH:
                    msg = f"sequence_deny step length {len(step)} exceeds max {_MAX_STEP_LENGTH}"
                    raise ValueError(msg)
            if self.window_seconds is None:
                msg = "sequence_deny check requires 'window_seconds'"
                raise ValueError(msg)
            # Note: Pydantic v2 coerces bool→float before validator,
            # so False→0.0 is caught by the min check below.
            if self.window_seconds < _MIN_WINDOW_SECONDS:
                msg = f"sequence_deny window_seconds must be >= {_MIN_WINDOW_SECONDS}, got {self.window_seconds}"
                raise ValueError(msg)
            if self.window_seconds > _MAX_WINDOW_SECONDS:
                msg = f"sequence_deny window_seconds must be <= {_MAX_WINDOW_SECONDS}, got {self.window_seconds}"
                raise ValueError(msg)
            if not math.isfinite(self.window_seconds):
                msg = f"sequence_deny window_seconds must be finite, got {self.window_seconds}"
                raise ValueError(msg)
            _reject_non_temporal_fields(t, self)
            if self.max_count is not None:
                msg = "sequence_deny check must not have 'max_count'"
                raise ValueError(msg)

        # Reject temporal fields in non-temporal check types.
        # Without this, a constraint author could add window_seconds=60 to a
        # DENYLIST and assume it's enforced — it would be silently ignored.
        if t not in (CheckType.RATE_LIMIT, CheckType.SEQUENCE_DENY):
            _reject_temporal_fields(t, self)

        return self


class DeployCheck(BaseModel):
    """Deploy-time (Tier 4) Z3 verification specification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: DeployCheckType = Field(description="Type of deploy-time check")
    constraints_ref: list[str] = Field(
        default_factory=list,
        description="Names of constraints to check interactions between",
    )
    baseline_constraints_ref: list[str] = Field(
        default_factory=list,
        description="For no_new_access: names of OLD/baseline constraints to compare against",
    )
    source: str | None = Field(default=None, description="For data_flow: source node")
    forbidden_sink: str | None = Field(default=None, description="For data_flow: forbidden sink")
    through: str | None = Field(default=None, description="For data_flow: intermediate filter")
    flow_edges: list[list[str]] = Field(
        default_factory=list,
        description="For data_flow: list of [from_node, to_node] directed edges",
    )
    dangerous_pattern: str | None = Field(
        default=None,
        description="For filter_completeness: semicolon-separated keywords the dangerous input must contain",
    )
    max_string_length: int = Field(
        default=200,
        ge=10,
        le=10_000,
        description="For filter_completeness: max string length for Z3 bounded check (default 200)",
    )
    verify: str | None = Field(default=None, description="Human-readable verification goal")

    @model_validator(mode="after")
    def _validate_fields_for_type(self) -> Self:
        """Ensure required fields are present for each deploy check type."""
        t = self.type
        if t == DeployCheckType.DATA_FLOW:
            if not self.source:
                msg = "data_flow check requires 'source'"
                raise ValueError(msg)
            if not self.forbidden_sink:
                msg = "data_flow check requires 'forbidden_sink'"
                raise ValueError(msg)
            if not self.flow_edges:
                msg = "data_flow check requires non-empty 'flow_edges'"
                raise ValueError(msg)
            for i, edge in enumerate(self.flow_edges):
                if not isinstance(edge, list) or len(edge) != 2:
                    msg = f"flow_edges[{i}] must be [from, to], got {edge!r}"
                    raise ValueError(msg)
                if not all(isinstance(n, str) and n for n in edge):
                    msg = f"flow_edges[{i}] must contain non-empty strings"
                    raise ValueError(msg)
        elif t == DeployCheckType.NO_NEW_ACCESS:
            if not self.constraints_ref:
                msg = "no_new_access check requires non-empty 'constraints_ref'"
                raise ValueError(msg)
            if not self.baseline_constraints_ref:
                msg = "no_new_access check requires non-empty 'baseline_constraints_ref'"
                raise ValueError(msg)
        elif t == DeployCheckType.FILTER_COMPLETENESS:
            if not self.constraints_ref:
                msg = "filter_completeness check requires non-empty 'constraints_ref'"
                raise ValueError(msg)
            if not self.dangerous_pattern:
                msg = "filter_completeness check requires 'dangerous_pattern'"
                raise ValueError(msg)
            keywords = [k.strip() for k in self.dangerous_pattern.split(";") if k.strip()]
            if not keywords:
                msg = "dangerous_pattern must contain at least one non-empty keyword"
                raise ValueError(msg)
        return self


class Constraint(BaseModel):
    """A single safety constraint loaded from YAML.

    Maps to OWASP Agentic Top 10 categories (ASI01-ASI10).
    Tier is auto-detected from check type if not specified.

    Action pattern matching uses fnmatch (glob) syntax:
    - ``"*"`` matches any action (default).
    - ``"http_request"`` matches exactly ``"http_request"``.
    - ``"http_*"`` matches ``"http_request"``, ``"http_get"``, etc.
    - ``"*.read"`` matches ``"db.read"``, ``"file.read"``, etc.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(description="Unique constraint identifier")
    description: str = Field(default="", description="Human-readable description")
    category: str = Field(default="", description="OWASP category: ASI01-ASI10")

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        if not v:
            msg = "constraint name must not be empty"
            raise ValueError(msg)
        if len(v) > 100:
            msg = f"constraint name too long ({len(v)} chars, max 100)"
            raise ValueError(msg)
        # Regex also prevents collision with internal sentinels (__system__, __unmatched__)
        # since they start with underscore.
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", v):
            msg = f"constraint name must be alphanumeric with _.- separators, got {v!r}"
            raise ValueError(msg)
        return v

    tier: Tier = Field(default=Tier.TIER_1, description="Verification tier (auto-detected)")
    action: str = Field(
        default="*",
        description="Tool name pattern this constraint applies to ('*' = all)",
    )
    actions: list[str] | None = Field(
        default=None,
        description="Alternative: list of tool name patterns (OR logic). "
        "If provided, takes precedence over 'action' for matching.",
    )
    check: ConstraintCheck | None = Field(
        default=None,
        description="Runtime check definition (Tier 1-3)",
    )
    deploy_check: DeployCheck | None = Field(
        default=None,
        description="Deploy-time check definition (Tier 4)",
    )
    conditions: list[ConstraintCondition] = Field(
        default_factory=list,
        description="Optional conditions for when the check applies",
    )
    on_violation: OnViolation = Field(
        default=OnViolation.BLOCK,
        description="What to do on violation",
    )
    severity: ViolationSeverity = Field(
        default=ViolationSeverity.HIGH,
        description="Severity level of violations",
    )
    enabled: bool = Field(default=True, description="Whether this constraint is active")

    @field_validator("category")
    @classmethod
    def _validate_category(cls, v: str) -> str:
        if v and not re.match(r"^[A-Z][A-Z0-9_-]{0,19}$", v):
            msg = f"category must be uppercase identifier (e.g. ASI01, PCI_DSS), got {v!r}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def _tier_check_consistency(self) -> Self:
        if self.tier == Tier.TIER_4:
            if self.deploy_check is None:
                msg = "Tier 4 constraint must have deploy_check"
                raise ValueError(msg)
        else:
            if self.deploy_check is not None:
                msg = f"deploy_check is only valid for Tier 4, got tier={self.tier}"
                raise ValueError(msg)
            if self.check is None:
                msg = f"Tier {self.tier.value} constraint must have 'check'"
                raise ValueError(msg)
        return self


# ── Result Models ──────────────────────────────────────────────────────────


class Violation(BaseModel):
    """A single constraint violation found during verification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    constraint_name: str = Field(description="Name of the violated constraint")
    constraint_category: str = Field(default="", description="OWASP category")
    severity: ViolationSeverity = Field(default=ViolationSeverity.HIGH)
    message: str = Field(description="Human-readable violation description")
    field: str = Field(default="", description="Which field caused the violation")
    actual_value: str = Field(default="", description="The value that triggered violation")
    tier: Tier = Field(default=Tier.TIER_1, description="Which tier detected this")
    source: ViolationSource = Field(
        default=ViolationSource.SECURITY,
        description="Origin of the violation (observability only, not enforcement policy)",
    )


class VerificationResult(BaseModel):
    """Result of verifying an action against a constraint set.

    This is the primary output of the verification pipeline.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: bool = Field(description="Whether the action is allowed")
    mode: VerificationMode = Field(
        default=VerificationMode.ENFORCE,
        description="The mode verification ran in",
    )
    violations: list[Violation] = Field(
        default_factory=list,
        description="All violations found (empty if allowed=True in enforce mode)",
    )
    checked_constraints: int = Field(
        default=0,
        description="Number of constraints evaluated",
    )
    elapsed_ms: float = Field(default=0.0, description="Total verification time in ms")
    tier_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Number of checks per tier: {'tier_1': 5, 'tier_4': 1}",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_violations(self) -> bool:
        """Whether any violations were found, regardless of mode."""
        return len(self.violations) > 0

    @field_validator("tier_breakdown")
    @classmethod
    def _validate_tier_keys(cls, v: dict[str, int]) -> dict[str, int]:
        valid_keys = {f"tier_{t.value}" for t in Tier}
        invalid = set(v.keys()) - valid_keys
        if invalid:
            msg = f"Invalid tier_breakdown keys: {invalid}. Valid: {valid_keys}"
            raise ValueError(msg)
        return v


class PolicyVerificationResult(BaseModel):
    """Result of deploy-time (Tier 4) Z3 policy verification.

    Separate from VerificationResult because it operates on
    constraint SETS, not individual actions.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    result: PolicyResult = Field(description="Solver outcome")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def safe(self) -> bool:
        """True only if mathematically proven safe (UNSAT). Derived from result."""
        return self.result == PolicyResult.SAFE

    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Counterexample, unsat core, or error info",
    )
    elapsed_ms: float = Field(default=0.0, description="Solver time in ms")
    check_type: DeployCheckType | None = Field(
        default=None,
        description="Which Tier 4 check was performed",
    )
    constraints_checked: list[str] = Field(
        default_factory=list,
        description="Names of constraints involved",
    )


# ── Configuration ──────────────────────────────────────────────────────────


class SolverConfig(BaseModel):
    """Configuration for the Z3 solver subsystem."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timeout_ms: int = Field(default=5000, description="Z3 solver timeout in ms")
    rlimit: int = Field(
        default=500_000,
        description="Z3 deterministic resource limit (for CI reproducibility)",
    )
    process_timeout_s: int = Field(
        default=10,
        description="External process timeout (must be > Z3 timeout). Hard OS kill.",
    )
    z3_version_required: str = Field(
        default="4.16.0.0",
        description="Required Z3 version (exact match for reproducibility)",
    )
    fail_behavior: FailBehavior = Field(
        default=FailBehavior.FAIL_CLOSED,
        description="Behavior on solver timeout/error",
    )
    max_memory_mb: int = Field(
        default=512,
        description="Worker memory limit in MB (enforced via resource.setrlimit on Linux)",
    )
    max_workers: int = Field(
        default=4,
        ge=1,
        le=32,
        description="Max concurrent Z3 worker processes (prevents fork bomb)",
    )

    @model_validator(mode="after")
    def _process_timeout_exceeds_solver(self) -> Self:
        if self.process_timeout_s * 1000 <= self.timeout_ms:
            msg = (
                f"process_timeout_s ({self.process_timeout_s}s) must be > "
                f"timeout_ms ({self.timeout_ms}ms = {self.timeout_ms / 1000}s)"
            )
            raise ValueError(msg)
        return self


class ConstraintConfig(BaseModel):
    """Top-level configuration for munio.

    Loaded from .munio.yaml or CLI flags.
    Use ``model_copy(update={...})`` to derive modified configs.

    Mode vs on_violation resolution:
    - DISABLED mode: skip all checks, return allowed=True immediately.
    - SHADOW mode: run all checks, always return allowed=True (global override).
    - ENFORCE mode: per-constraint ``on_violation`` applies:
      - BLOCK: violation blocks the action (allowed=False).
      - WARN: violation logged, action allowed (allowed=True).
      - SHADOW: same as WARN for that individual constraint.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: VerificationMode = Field(
        default=VerificationMode.ENFORCE,
        description="Global verification mode",
    )
    constraints_dir: Path = Field(
        default=Path("constraints"),
        description="Directory containing YAML constraint files (relative to project root)",
    )
    constraint_packs: list[str] = Field(
        default_factory=lambda: ["generic"],
        description="Which constraint packs to load",
    )
    default_on_unmatched: OnViolation = Field(
        default=OnViolation.WARN,
        description="Default behavior for actions matching no constraints",
    )
    solver: SolverConfig = Field(
        default_factory=SolverConfig,
        description="Z3 solver configuration",
    )
    include_violation_values: bool = Field(
        default=True,
        description="Include actual values in violation reports (disable to prevent info disclosure)",
    )
    max_violation_value_length: int = Field(
        default=200,
        ge=4,
        description="Maximum total length of actual_value in violations (truncated values get '...' suffix)",
    )
