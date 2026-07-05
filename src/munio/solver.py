"""Runtime solver: pure-Python Tier 1 + in-process COMPOSITE checking (Tier 2-3).

The runtime gate uses no SMT solver — every check is deterministic and
sub-millisecond, and the ``[z3]`` extra is not required to run it.

- Tier 1: set lookup, regex, thresholds (denylist/allowlist/regex/threshold).
- Tier 2-3: COMPOSITE constraints (multi-variable arithmetic). Concrete values
  are evaluated directly; missing variables are decided exactly by the endpoint
  evaluator (``_composite_endpoint``), which answers "could some in-bounds value
  violate this?" without a solver. Expressions outside its grammar are rejected
  at load time, not mis-decided at runtime.

Z3 remains only OFFLINE, where satisfiability is the actual problem and there is
no latency or install-footprint pressure: deploy-time policy verification
(``PolicyVerifier``, Tier 4) and static scanning (``munio.scan`` layer L4).
"""

from __future__ import annotations

import fnmatch
import logging
import math
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence


from munio._composite import (
    _MAX_NUMERIC_MAGNITUDE as _MAX_NUMERIC_MAGNITUDE,
)
from munio._composite import (
    _coerce_numeric as _coerce_numeric,
)
from munio._composite import (
    _eval_composite_expression as _eval_composite_expression,
)
from munio._composite import (
    _eval_composite_python as _eval_composite_python,
)
from munio._composite import (
    _EvalResult as _EvalResult,
)
from munio._composite import (
    _make_worker_violation as _make_worker_violation,
)
from munio._composite import (
    _resolve_composite_variables as _resolve_composite_variables,
)
from munio._composite import (
    _ResolveResult as _ResolveResult,
)
from munio._composite import (
    _VarAccessor as _VarAccessor,
)
from munio._composite_endpoint import (
    UnsupportedCompositeError as UnsupportedCompositeError,
)
from munio._composite_endpoint import (
    decide_violation as decide_violation,
)
from munio._composite_endpoint import (
    parse_comparisons as parse_comparisons,
)
from munio._matching import (
    _MISSING as _MISSING,
)
from munio._matching import (
    _STRIP_CHARS as _STRIP_CHARS,
)
from munio._matching import (
    InputTooLargeError as InputTooLargeError,
)
from munio._matching import (
    _any_match as _any_match,
)
from munio._matching import (
    _check_conditions as _check_conditions,
)
from munio._matching import (
    _collect_string_values as _collect_string_values,
)
from munio._matching import (
    _compile_regex as _compile_regex,
)
from munio._matching import (
    _extract_field as _extract_field,
)
from munio._matching import (
    _FieldValue as _FieldValue,
)
from munio._matching import (
    _make_system_violation as _make_system_violation,
)
from munio._matching import (
    _make_violation as _make_violation,
)
from munio._matching import (
    _match_value as _match_value,
)
from munio._matching import (
    _MissingSentinel as _MissingSentinel,
)
from munio._matching import (
    _sanitize_string as _sanitize_string,
)
from munio._matching import (
    _strict_eq as _strict_eq,
)
from munio._policy_verifier import PolicyVerifier as PolicyVerifier
from munio._temporal import InMemoryTemporalStore as InMemoryTemporalStore
from munio._temporal import TemporalStore as TemporalStore
from munio._z3_regex import _regex_to_z3 as _regex_to_z3
from munio._z3_regex import _sre_category_to_z3 as _sre_category_to_z3
from munio._z3_regex import _sre_charset_to_z3 as _sre_charset_to_z3
from munio._z3_regex import _sre_to_z3 as _sre_to_z3
from munio._z3_regex import _z3_dot as _z3_dot
from munio.models import (
    Action,
    CheckType,
    Constraint,
    ConstraintCheck,
    MatchMode,
    Tier,
    Violation,
    ViolationSource,
)

__all__ = [
    "InMemoryTemporalStore",
    "InputTooLargeError",
    "PolicyVerifier",
    "RuntimeSolver",
    "TemporalStore",
    "Tier1Solver",
    "check_composite_tier23",
]

logger = logging.getLogger(__name__)


# ── Solver protocol ─────────────────────────────────────────────────────


class RuntimeSolver(Protocol):
    """Protocol for runtime constraint solvers (Tier 1-3).

    Implement this to create custom solvers or mock solvers for testing.
    The Verifier dispatches checks to solvers implementing this protocol.
    """

    def check(self, action: Action, constraints: Sequence[Constraint]) -> list[Violation]:
        """Check an action against constraints and return violations found."""
        ...


# ── Tier 1: Pure Python solver ───────────────────────────────────────────


_TEMPORAL_CHECK_TYPES = frozenset({CheckType.RATE_LIMIT, CheckType.SEQUENCE_DENY})


class Tier1Solver:
    """Pure Python solver for Tier 1 checks.

    Handles: denylist, allowlist, threshold, regex_deny, regex_allow,
    rate_limit, sequence_deny.
    Target: <0.01ms per check.
    """

    __slots__ = ("_temporal_store",)

    def __init__(self, temporal_store: TemporalStore | None = None) -> None:
        self._temporal_store = temporal_store

    def check(self, action: Action, constraints: Sequence[Constraint]) -> list[Violation]:
        """Check an action against Tier 1 constraints.

        Constraints are expected to be pre-filtered by the caller (via
        ConstraintRegistry.constraints_for). Defensive re-filtering is
        applied as a safety net.

        Args:
            action: The action to verify.
            constraints: Constraints to check (should be Tier 1, matching action).

        Returns:
            List of violations found (empty if all checks pass).
        """
        violations: list[Violation] = []
        # Sanitize tool name: strip invisible chars, NFKC normalize, casefold.
        # Without this, an attacker can bypass tool-specific constraints via
        # case variants ("Exec"), zero-width chars ("ex\u200bec"), or
        # fullwidth chars ("\uff45\uff58\uff45\uff43").
        sanitized_tool = _sanitize_string(action.tool).casefold()
        logger.debug(
            "Tier1Solver: checking %s against %d constraints", sanitized_tool, len(constraints)
        )

        for constraint in constraints:
            # Defensive re-filtering (safety net)
            if not constraint.enabled:
                continue
            # Tier1Solver defensively handles all check types; Tier 2-3 COMPOSITE
            # constraints are decided by check_composite_tier23 in the Verifier.
            # Tier 4 (deploy-time) constraints have check=None → skipped below.
            action_patterns = (
                [p.casefold() for p in constraint.actions]
                if constraint.actions
                else [constraint.action.casefold()]
            )
            if not any(fnmatch.fnmatchcase(sanitized_tool, p) for p in action_patterns):
                continue
            if constraint.check is None:
                continue

            # Check conditions
            if constraint.conditions and not _check_conditions(action.args, constraint.conditions):
                continue

            logger.debug(
                "Evaluating constraint %r (%s) on field %r",
                constraint.name,
                constraint.check.type,
                constraint.check.field,
            )

            check = constraint.check
            check_type = check.type

            # COMPOSITE: Python fast path for concrete values
            if check_type == CheckType.COMPOSITE:
                result = _eval_composite_python(check, action.args)
                if result is None:
                    # Missing variables without defaults
                    if constraint.tier == Tier.TIER_1:
                        # Tier 1 can't defer to Z3 — fail-closed
                        violations.append(
                            _make_violation(
                                constraint,
                                "COMPOSITE: missing variables without defaults (fail-closed)",
                                field="(composite)",
                            )
                        )
                    # Tier 2-3 are handled in-process by check_composite_tier23
                    continue
                expr_holds, _values = result
                if not expr_holds:
                    violations.append(
                        _make_violation(
                            constraint,
                            "Composite expression violated",
                            field="(composite)",
                        )
                    )
                continue

            # TEMPORAL: rate limiting and sequence detection
            if check_type in _TEMPORAL_CHECK_TYPES:
                self._check_temporal(action, constraint, sanitized_tool, violations)
                continue

            if check.field == "*":
                # Wildcard: check all leaf values
                self._check_wildcard(action, constraint, violations)
            else:
                # Normal field extraction
                self._check_field(action, constraint, violations)

        if violations:
            logger.debug("Tier1Solver: %d violation(s) for %s", len(violations), action.tool)
        return violations

    def _check_wildcard(
        self,
        action: Action,
        constraint: Constraint,
        violations: list[Violation],
    ) -> None:
        """Check all leaf values in args against a constraint."""
        if constraint.check is None:
            return

        try:
            field_values = _collect_string_values(action.args)
        except InputTooLargeError:
            violations.append(
                _make_system_violation(
                    "input too large",
                    field="*",
                    source=ViolationSource.PARSE,
                )
            )
            return

        # Fail-closed for allowlists: if args is non-empty but no leaf values
        # were found (e.g. args={"data": {}, "headers": []}), an allowlist
        # check would silently pass.  Treat as suspicious — downstream tools
        # may interpret empty containers in unexpected ways.
        if (
            not field_values
            and action.args
            and constraint.check.type in (CheckType.ALLOWLIST, CheckType.REGEX_ALLOW)
        ):
            violations.append(
                _make_violation(
                    constraint,
                    "No leaf values found in non-empty args (fail-closed for allowlist)",
                    field="*",
                )
            )
            return

        for fv in field_values:
            self._evaluate_check(constraint, fv.value, fv.path, violations)

    def _check_field(
        self,
        action: Action,
        constraint: Constraint,
        violations: list[Violation],
    ) -> None:
        """Check a specific field value against a constraint."""
        if constraint.check is None:
            return
        check = constraint.check

        raw_value = _extract_field(action.args, check.field)

        # Treat None as missing — str(None)="None" would bypass pattern-based
        # denylists while downstream tools may interpret None as a default value.
        if raw_value is None:
            raw_value = _MISSING

        if raw_value is _MISSING:
            # Missing field handling per check type
            if check.type in (CheckType.ALLOWLIST, CheckType.REGEX_ALLOW):
                violations.append(
                    _make_violation(
                        constraint,
                        f"Required field {check.field!r} is missing (fail-closed)",
                        field=check.field,
                    )
                )
            # DENYLIST/REGEX_DENY/THRESHOLD: nothing to match → skip
            return

        # THRESHOLD shortcut: skip string round-trip for numeric types.
        # bool MUST be excluded (isinstance(True, int) is True, float(True)=1.0).
        if (
            check.type == CheckType.THRESHOLD
            and isinstance(raw_value, int | float)
            and not isinstance(raw_value, bool)
        ):
            try:
                num = float(raw_value)
            except OverflowError:
                violations.append(
                    _make_violation(
                        constraint,
                        f"Value too large for threshold check on {check.field!r}",
                        field=check.field,
                    )
                )
                return
            self._evaluate_threshold(constraint, num, check.field, violations)
            return

        # Reject non-scalar types (lists, dicts, etc.) to prevent str() coercion bypass.
        # E.g., {"url": ["evil.com"]} -> str() = "['evil.com']" bypasses EXACT denylist.
        if not isinstance(raw_value, str | int | float | bool):
            violations.append(
                _make_violation(
                    constraint,
                    f"Field {check.field!r} has non-scalar type {type(raw_value).__name__!r}",
                    field=check.field,
                )
            )
            return

        # Convert to sanitized string
        value = _sanitize_string(str(raw_value))
        self._evaluate_check(constraint, value, check.field, violations)

    def _evaluate_check(
        self,
        constraint: Constraint,
        value: str,
        field: str,
        violations: list[Violation],
    ) -> None:
        """Dispatch to the appropriate check type handler."""
        if constraint.check is None:
            return
        check = constraint.check
        check_type = check.type

        if check_type == CheckType.DENYLIST:
            if _any_match(value, check.values, check.match, check.case_sensitive):
                violations.append(
                    _make_violation(
                        constraint,
                        f"Value matches denylist ({check.match})",
                        field=field,
                        actual_value=value,
                    )
                )

        elif check_type == CheckType.ALLOWLIST:
            if not _any_match(
                value, check.values, check.match, check.case_sensitive, fullmatch=True
            ):
                violations.append(
                    _make_violation(
                        constraint,
                        f"Value does not match allowlist ({check.match})",
                        field=field,
                        actual_value=value,
                    )
                )

        elif check_type == CheckType.THRESHOLD:
            try:
                num_value = float(value)
            except (ValueError, TypeError):
                violations.append(
                    _make_violation(
                        constraint,
                        f"Non-numeric value for threshold check: {value!r}",
                        field=field,
                        actual_value=value,
                    )
                )
                return
            self._evaluate_threshold(constraint, num_value, field, violations)

        elif check_type == CheckType.REGEX_DENY:
            if _any_match(value, check.patterns, MatchMode.REGEX, check.case_sensitive):
                violations.append(
                    _make_violation(
                        constraint,
                        "Value matches denied regex pattern",
                        field=field,
                        actual_value=value,
                    )
                )

        elif check_type == CheckType.REGEX_ALLOW and not _any_match(
            value, check.patterns, MatchMode.REGEX, check.case_sensitive, fullmatch=True
        ):
            violations.append(
                _make_violation(
                    constraint,
                    "Value does not match any allowed regex pattern",
                    field=field,
                    actual_value=value,
                )
            )

    def _evaluate_threshold(
        self,
        constraint: Constraint,
        num_value: float,
        field: str,
        violations: list[Violation],
    ) -> None:
        """Evaluate a numeric value against threshold min/max."""
        if constraint.check is None:
            return
        check = constraint.check

        # NaN/Inf bypass prevention
        if math.isnan(num_value):
            violations.append(
                _make_violation(
                    constraint,
                    "NaN value for threshold check (bypass prevention)",
                    field=field,
                    actual_value="NaN",
                )
            )
            return

        if math.isinf(num_value):
            violations.append(
                _make_violation(
                    constraint,
                    "Infinite value for threshold check (bypass prevention)",
                    field=field,
                    actual_value=str(num_value),
                )
            )
            return

        if check.min is not None and num_value < check.min:
            violations.append(
                _make_violation(
                    constraint,
                    f"Value {num_value} below minimum {check.min}",
                    field=field,
                    actual_value=str(num_value),
                )
            )

        if check.max is not None and num_value > check.max:
            violations.append(
                _make_violation(
                    constraint,
                    f"Value {num_value} exceeds maximum {check.max}",
                    field=field,
                    actual_value=str(num_value),
                )
            )

    def _check_temporal(
        self,
        action: Action,
        constraint: Constraint,
        sanitized_tool: str,
        violations: list[Violation],
    ) -> None:
        """Dispatch temporal checks (rate_limit, sequence_deny) to the store."""
        if self._temporal_store is None:
            # No store provided — fail-closed (defense-in-depth)
            violations.append(
                _make_violation(
                    constraint,
                    "Temporal check requires a TemporalStore (fail-closed)",
                    field="(temporal)",
                )
            )
            return

        if constraint.check is None:
            return
        check = constraint.check
        scope_key = self._resolve_scope(action, check)

        try:
            if check.type == CheckType.RATE_LIMIT:
                # Guaranteed non-None by model validation; defensive guard
                if check.window_seconds is None or check.max_count is None:
                    return
                key = f"{constraint.name}:{scope_key}"
                allowed = self._temporal_store.check_and_record_rate(
                    key,
                    check.window_seconds,
                    check.max_count,
                )
                if not allowed:
                    violations.append(
                        _make_violation(
                            constraint,
                            "Rate limit exceeded",
                            field="(rate_limit)",
                        )
                    )
            elif check.type == CheckType.SEQUENCE_DENY:
                if check.window_seconds is None:
                    return
                steps_lower = [s.casefold() for s in check.steps]
                allowed = self._temporal_store.check_sequence(
                    scope_key,
                    sanitized_tool,
                    steps_lower,
                    check.window_seconds,
                )
                if not allowed:
                    violations.append(
                        _make_violation(
                            constraint,
                            "Denied action sequence detected",
                            field="(sequence)",
                        )
                    )
        except Exception:
            logger.exception("TemporalStore error for %r", constraint.name)
            violations.append(
                _make_violation(
                    constraint,
                    "Temporal check failed (fail-closed)",
                    field="(temporal)",
                    source=ViolationSource.INFRA,
                )
            )

    @staticmethod
    def _resolve_scope(action: Action, check: ConstraintCheck) -> str:
        """Resolve temporal scope key from action and check configuration."""
        if check.scope == "agent":
            agent_id = action.agent_id or "__anonymous__"
            return f"agent:{_sanitize_string(agent_id)[:128]}"
        return "__global__"


# ── Tier 2-3: in-process COMPOSITE checking (no solver) ──────────────────


def check_composite_tier23(action: Action, constraints: Sequence[Constraint]) -> list[Violation]:
    """Decide Tier 2-3 COMPOSITE constraints in-process (replaces the Z3 pool).

    Answers "could some in-bounds assignment of the missing variables violate
    this constraint?" exactly via the endpoint evaluator — deterministic and
    sub-millisecond, no subprocess, no optional Z3 dependency. Non-COMPOSITE
    Tier 2-3 constraints are skipped (as the former worker did). Resolution
    errors, and any expression that slips past load-time classification, are
    fail-closed.
    """
    violations: list[Violation] = []
    for constraint in constraints:
        check = constraint.check
        if check is None or check.type != CheckType.COMPOSITE:
            continue

        resolved = _resolve_composite_variables(check.variables, action.args, allow_unbound=True)
        if resolved.error:
            violations.append(
                _make_violation(
                    constraint,
                    f"COMPOSITE: {resolved.error} (fail-closed)",
                    field="(composite)",
                )
            )
            continue

        try:
            comparisons = parse_comparisons(check.expression)
            bounds = {
                name: (
                    acc.min if acc.min is not None else -math.inf,
                    acc.max if acc.max is not None else math.inf,
                )
                for name, acc in resolved.unbound.items()
            }
            violated = decide_violation(comparisons, resolved.concrete, bounds)
        except UnsupportedCompositeError:
            # Load-time classify should prevent this; fail-closed if it doesn't.
            violations.append(
                _make_violation(
                    constraint,
                    "COMPOSITE: unsupported expression reached runtime (fail-closed)",
                    field="(composite)",
                    source=ViolationSource.INFRA,
                )
            )
            continue

        if violated:
            detail = (
                "Composite expression can be violated (counterexample exists)"
                if resolved.unbound
                else "Composite expression violated"
            )
            violations.append(_make_violation(constraint, detail, field="(composite)"))
    return violations
