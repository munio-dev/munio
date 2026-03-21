"""COMPOSITE expression evaluation: variable resolution, numeric coercion, eval.

This module implements the Python fast-path for COMPOSITE constraint checks.
Shared between Tier1Solver (direct call) and Z3 subprocess worker (via pickle
boundary — hence ``_VarAccessor`` normalises both Pydantic objects and dicts).

Pipeline:
1. Resolve variables from action args (``_resolve_composite_variables``)
2. Coerce to numeric (``_coerce_numeric``) with NaN/Inf/magnitude guards
3. Evaluate expression (``_eval_composite_expression``) with sandboxed ``eval()``

Security invariants:
- ``isinstance(x, bool)`` checked BEFORE ``isinstance(x, int)`` everywhere
- NaN/Inf rejected pre-eval AND post-eval
- Magnitude capped at 10^18 (prevents DoS from huge ints)
- ``eval()`` with ``{"__builtins__": {}}`` (AST-validated expressions only)
- No raw values in worker violation dicts (``actual_value=""`` always)
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from munio.models import ConstraintCheck

from munio._matching import _MISSING, _extract_field

__all__ = [
    "_MAX_NUMERIC_MAGNITUDE",
    "_EvalResult",
    "_ResolveResult",
    "_VarAccessor",
    "_coerce_numeric",
    "_eval_composite_expression",
    "_eval_composite_python",
    "_make_worker_violation",
    "_resolve_composite_variables",
]

# Maximum magnitude for numeric values in COMPOSITE expressions.
# 10^18 fits in 64-bit signed int, covers all practical financial amounts.
# Prevents DoS from huge ints (10**1000000 → 5.7s eval).
_MAX_NUMERIC_MAGNITUDE = 10**18


def _coerce_numeric(value: Any, var_type: str) -> int | float | None:
    """Coerce a value to numeric type for COMPOSITE evaluation.

    Returns the coerced value, or None if the value cannot be safely coerced.
    Rejects NaN, Inf, non-scalar types, and values exceeding magnitude limit.

    Args:
        value: The raw value from action.args.
        var_type: ``"int"`` or ``"real"`` from CompositeVariable.type.

    Returns:
        Coerced numeric value, or None if coercion fails (fail-closed).
    """
    # bool MUST be checked before int (isinstance(True, int) is True)
    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        if abs(value) > _MAX_NUMERIC_MAGNITUDE:
            return None
        return value

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        if abs(value) > _MAX_NUMERIC_MAGNITUDE:
            return None
        return value if var_type == "real" else int(value)

    if isinstance(value, str):
        # Reject excessively long numeric strings BEFORE parsing.
        # int("1"*500000) is O(n*log(n)) and takes 50-200ms.
        # 10^18 has 19 digits; allow 25 for sign, leading zeros, whitespace.
        stripped = value.strip()
        if len(stripped) > 25:
            return None
        # Try int first, then float
        try:
            i = int(stripped)
        except (ValueError, OverflowError):
            pass
        else:
            return i if abs(i) <= _MAX_NUMERIC_MAGNITUDE else None
        try:
            f = float(stripped)
        except (ValueError, OverflowError):
            return None
        if math.isnan(f) or math.isinf(f):
            return None
        if abs(f) > _MAX_NUMERIC_MAGNITUDE:
            return None
        return f if var_type == "real" else int(f)

    # list, dict, None, other non-scalar types → fail-closed
    return None


# ── Shared COMPOSITE helpers (used by both Python fast path and Z3 worker) ──


class _VarAccessor:
    """Unified property access for CompositeVariable objects and raw dicts.

    Tier1Solver passes ``CompositeVariable`` Pydantic objects, but the Z3 worker
    receives ``model_dump()`` dicts (pickle boundary).  This adapter normalises
    both to the same attribute-access API.
    """

    __slots__ = ("_default", "_field", "_max", "_min", "_type")

    def __init__(self, var: Any) -> None:
        if isinstance(var, dict):
            self._field: str = var.get("field", "")
            self._type: str = var.get("type", "int")
            self._default: float | None = var.get("default")
            self._min: float | None = var.get("min")
            self._max: float | None = var.get("max")
        else:
            self._field = var.field
            self._type = var.type
            self._default = var.default
            self._min = var.min
            self._max = var.max

    @property
    def field(self) -> str:
        return self._field

    @property
    def type(self) -> str:
        return self._type

    @property
    def default(self) -> float | None:
        return self._default

    @property
    def min(self) -> float | None:
        return self._min

    @property
    def max(self) -> float | None:
        return self._max


class _ResolveResult(NamedTuple):
    """Result of resolving COMPOSITE variables from action args."""

    concrete: dict[str, int | float]
    unbound: dict[str, _VarAccessor]
    error: str  # Non-empty on resolution failure (fail-closed)


def _resolve_composite_variables(
    variables: dict[str, Any],
    args: dict[str, Any],
    *,
    allow_unbound: bool = False,
) -> _ResolveResult:
    """Resolve COMPOSITE variables from action args.

    For each declared variable, extracts the field value, coerces to numeric,
    and enforces bounds.

    Args:
        variables: Map of var_name -> CompositeVariable (or dict from model_dump).
        args: The action's arguments dict.
        allow_unbound: If True, missing variables go to ``unbound``; if False,
            a missing variable without a default returns an error.

    Returns:
        ``_ResolveResult(concrete, unbound, error)``  where ``error`` is non-empty
        on failure.
    """
    concrete: dict[str, int | float] = {}
    unbound: dict[str, _VarAccessor] = {}

    for var_name, raw_var in variables.items():
        accessor = _VarAccessor(raw_var)
        raw = _extract_field(args, accessor.field)

        if raw is _MISSING or raw is None:
            if accessor.default is not None:
                # Defense-in-depth: validate default even though Pydantic
                # already checks it at model load time.
                coerced_default = _coerce_numeric(accessor.default, accessor.type)
                if coerced_default is None:
                    return _ResolveResult(concrete, unbound, "non-numeric")
                if accessor.min is not None and coerced_default < accessor.min:
                    return _ResolveResult(concrete, unbound, "out-of-bounds")
                if accessor.max is not None and coerced_default > accessor.max:
                    return _ResolveResult(concrete, unbound, "out-of-bounds")
                concrete[var_name] = coerced_default
            elif allow_unbound:
                unbound[var_name] = accessor
            else:
                return _ResolveResult(concrete, unbound, "unbound")
        else:
            coerced = _coerce_numeric(raw, accessor.type)
            if coerced is None:
                return _ResolveResult(concrete, unbound, "non-numeric")
            if accessor.min is not None and coerced < accessor.min:
                return _ResolveResult(concrete, unbound, "out-of-bounds")
            if accessor.max is not None and coerced > accessor.max:
                return _ResolveResult(concrete, unbound, "out-of-bounds")
            concrete[var_name] = coerced

    return _ResolveResult(concrete, unbound, "")


class _EvalResult(NamedTuple):
    """Result of evaluating a COMPOSITE expression."""

    holds: bool  # True = expression satisfied
    error: str  # Non-empty on evaluation failure


def _eval_composite_expression(expression: str, concrete: dict[str, int | float]) -> _EvalResult:
    """Evaluate a COMPOSITE expression against concrete variable values.

    Performs NaN/Inf pre-check, compiles and evals the expression, then
    validates the result (post-eval NaN/Inf, boolean type check).

    Args:
        expression: The boolean expression string (already AST-validated).
        concrete: Map of variable names to numeric values.

    Returns:
        ``_EvalResult(holds, error)`` where ``error`` is non-empty on failure.
    """
    # Pre-eval NaN/Inf check (defense-in-depth: coerce_numeric already rejects)
    if any(isinstance(v, float) and (math.isnan(v) or math.isinf(v)) for v in concrete.values()):
        return _EvalResult(False, "nan-inf")

    try:
        code = compile(expression, "<composite>", "eval")
        result = eval(code, {"__builtins__": {}}, concrete)
    except Exception:
        return _EvalResult(False, "arithmetic")

    # Post-eval NaN/Inf check (can arise from float division)
    if isinstance(result, float) and (math.isnan(result) or math.isinf(result)):
        return _EvalResult(False, "nan-inf-result")

    # Expression must produce a boolean result (comparison/logical).
    if not isinstance(result, bool):
        return _EvalResult(False, "non-boolean")

    return _EvalResult(result, "")


def _make_worker_violation(
    name: str,
    category: str,
    severity: str,
    message: str,
    tier: int,
    source: str = "security",
) -> dict[str, Any]:
    """Create a violation dict for the Z3 worker (subprocess boundary)."""
    return {
        "constraint_name": name,
        "constraint_category": category,
        "severity": severity,
        "message": message,
        "field": "(composite)",
        "actual_value": "",
        "tier": tier,
        "source": source,
    }


def _eval_composite_python(
    check: ConstraintCheck,
    args: dict[str, Any],
) -> tuple[bool, dict[str, Any]] | None:
    """Evaluate a COMPOSITE constraint using Python eval (fast path).

    If all variables can be resolved to concrete numeric values, evaluates the
    expression using Python ``eval()`` with an empty ``__builtins__`` dict.

    Args:
        check: The ConstraintCheck with type=COMPOSITE.
        args: The action's arguments dict.

    Returns:
        ``(expression_holds, concrete_values)`` if all variables resolved,
        or ``None`` if any variable is missing (defer to Z3 for unbound vars).
    """
    resolved = _resolve_composite_variables(check.variables, args)
    if resolved.error == "unbound":
        return None  # Defer to Z3
    if resolved.error:
        return (False, resolved.concrete)

    eval_result = _eval_composite_expression(check.expression, resolved.concrete)
    return (eval_result.holds, resolved.concrete)
