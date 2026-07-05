"""Solver-free existential-violation decision for COMPOSITE constraints.

Replaces the runtime Z3 subprocess path for the hot path. The runtime question
is: *does there exist an in-bounds assignment of the unbound (missing) variables
that VIOLATES the constraint?* — exactly what the Z3 worker decided via
``Not(expr) sat?``.

For the supported grammar this is decided EXACTLY, no solver:

- The expression is a conjunction of inequalities ``<, <=, >, >=`` between two
  multilinear polynomials (each variable appears at most once per product term).
  ``exists x: not(C1 and ... and Cn)`` distributes over the conjunction, so each
  comparison is decided independently: a conjunction is violable iff any one
  comparison is.
- Each comparison reduces to ``f op 0`` with ``f = lhs - rhs`` multilinear;
  violability is the sign of the box extremum of ``f`` (``max f`` for ``<=``/``<``,
  ``min f`` for ``>=``/``>``).
- Multilinear functions attain extrema at box vertices. Unbounded variables are
  admitted only in *linear* terms (enforced by ``classify``), so ``f`` separates
  into independent per-variable linear parts (optimised in isolation — ∞-safe,
  never an indeterminate ``+inf + -inf``) plus a bounded multilinear part
  (finite vertex enumeration). Exact ``Fraction`` arithmetic matches the solver
  on boundary equalities.

Anything outside the grammar (``==``/``!=``, ``or``, division by a variable,
repeated variable in a term, or an unbounded variable inside a product term) is
rejected by ``classify`` with an actionable message — never silently decided.
"""

from __future__ import annotations

import ast
import math
from fractions import Fraction
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

__all__ = [
    "ClassifyResult",
    "UnsupportedCompositeError",
    "classify",
    "decide_violation",
    "parse_comparisons",
]

# A multilinear polynomial: term (frozenset of variable names) -> coefficient.
# The empty frozenset is the constant term. A frozenset key (not a tuple)
# structurally forbids a variable repeating within a term.
_Poly = dict[frozenset[str], Fraction]

_INF = math.inf


class UnsupportedCompositeError(Exception):
    """Raised when an expression/constraint falls outside the exact grammar."""


class _Comparison(NamedTuple):
    poly: _Poly  # f = lhs - rhs
    op: str  # one of: "lt", "le", "gt", "ge"


class ClassifyResult(NamedTuple):
    supported: bool
    reason: str  # empty when supported


# ── Polynomial construction from a validated AST ──────────────────────────


def _add(a: _Poly, b: _Poly, *, sub: bool = False) -> _Poly:
    out: _Poly = dict(a)
    for term, coeff in b.items():
        out[term] = out.get(term, Fraction(0)) + (-coeff if sub else coeff)
    return {t: c for t, c in out.items() if c != 0}


def _mul(a: _Poly, b: _Poly) -> _Poly:
    out: _Poly = {}
    for ta, ca in a.items():
        for tb, cb in b.items():
            if ta & tb:  # shared variable -> would repeat in a term
                msg = "variable repeated in a product term (non-multilinear)"
                raise UnsupportedCompositeError(msg)
            term = ta | tb
            out[term] = out.get(term, Fraction(0)) + ca * cb
    return {t: c for t, c in out.items() if c != 0}


def _poly(node: ast.AST) -> _Poly:
    if isinstance(node, ast.Expression):
        return _poly(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise UnsupportedCompositeError("non-numeric constant")
        return {frozenset(): Fraction(str(node.value))}
    if isinstance(node, ast.Name):
        return {frozenset({node.id}): Fraction(1)}
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.USub):
            return _add({}, _poly(node.operand), sub=True)
        if isinstance(node.op, ast.UAdd):
            return _poly(node.operand)
        raise UnsupportedCompositeError("unsupported unary operator")
    if isinstance(node, ast.BinOp):
        left, right = _poly(node.left), _poly(node.right)
        if isinstance(node.op, ast.Add):
            return _add(left, right)
        if isinstance(node.op, ast.Sub):
            return _add(left, right, sub=True)
        if isinstance(node.op, ast.Mult):
            return _mul(left, right)
        if isinstance(node.op, ast.Div):
            # Division is affine only by a nonzero constant.
            if set(right) != {frozenset()}:
                raise UnsupportedCompositeError("division by a variable (non-polynomial)")
            divisor = right[frozenset()]
            if divisor == 0:
                raise UnsupportedCompositeError("division by zero")
            return {t: c / divisor for t, c in left.items()}
        raise UnsupportedCompositeError("unsupported binary operator")
    raise UnsupportedCompositeError(f"unsupported syntax: {type(node).__name__}")


_OP = {ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt", ast.GtE: "ge"}


def _comparisons_from(node: ast.AST) -> list[_Comparison]:
    """Flatten a conjunction of inequalities into normalized f-vs-0 comparisons."""
    if isinstance(node, ast.Expression):
        return _comparisons_from(node.body)
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.Or):
            raise UnsupportedCompositeError("top-level 'or' (violation region not separable)")
        out: list[_Comparison] = []
        for value in node.values:
            out.extend(_comparisons_from(value))
        return out
    if isinstance(node, ast.Compare):
        out = []
        left = _poly(node.left)
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            if type(op) not in _OP:
                raise UnsupportedCompositeError("only <, <=, >, >= are supported (not ==/!=)")
            right = _poly(comparator)
            out.append(_Comparison(_add(left, right, sub=True), _OP[type(op)]))
            left = right  # chained comparison: 0 <= x <= 100
        return out
    raise UnsupportedCompositeError("expression must be a conjunction of inequalities")


def parse_comparisons(expression: str) -> list[_Comparison]:
    """Parse an expression into normalized comparisons, or raise UnsupportedCompositeError."""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise UnsupportedCompositeError(f"syntax error: {exc.msg}") from None
    return _comparisons_from(tree)


# ── Load-time classification ──────────────────────────────────────────────


def classify(expression: str, unbounded_vars: Iterable[str]) -> ClassifyResult:
    """Decide whether the constraint can be decided exactly without a solver.

    Args:
        expression: the boolean expression.
        unbounded_vars: variable names whose runtime value may be missing AND
            whose bounds are not both finite (so they can range to +/-inf).

    Returns:
        ``ClassifyResult(supported, reason)``.
    """
    try:
        comparisons = parse_comparisons(expression)
    except UnsupportedCompositeError as exc:
        return ClassifyResult(False, str(exc))

    unbounded = set(unbounded_vars)
    for cmp in comparisons:
        for term in cmp.poly:
            if len(term) >= 2 and (term & unbounded):
                bad = sorted(term & unbounded)[0]
                return ClassifyResult(
                    False,
                    f"unbounded variable {bad!r} appears in a product term; "
                    f"add a finite max/min bound or use offline (Tier 4) verification",
                )
    return ClassifyResult(True, "")


# ── Box extremum of a multilinear polynomial ──────────────────────────────


def _substitute(poly: _Poly, concrete: Mapping[str, float]) -> _Poly:
    """Fold concrete variable values into the polynomial; leftover vars are free."""
    out: _Poly = {}
    for term, coeff in poly.items():
        free = frozenset(v for v in term if v not in concrete)
        c = coeff
        for v in term:
            if v in concrete:
                c *= Fraction(str(concrete[v]))
        if c != 0:
            out[free] = out.get(free, Fraction(0)) + c
    return {t: c for t, c in out.items() if c != 0}


def _box_max(
    poly: _Poly,
    bounds: Mapping[str, tuple[float, float]],
    *,
    minimize: bool = False,
) -> float | Fraction:
    """Exact max (or min) of a multilinear poly over the box.

    Unbounded variables appear only linearly (guaranteed by ``classify``), so
    they are optimised independently; bounded variables are enumerated over
    vertices. Returns a ``Fraction`` or ``+/-math.inf``.
    """
    sign = -1 if minimize else 1
    linear_unbounded: list[tuple[str, Fraction]] = []
    bounded_terms: _Poly = {}
    bounded_vars: set[str] = set()

    for term, coeff in poly.items():
        free_unbounded = [v for v in term if not _is_finite_box(bounds.get(v))]
        if not free_unbounded:
            bounded_terms[term] = coeff
            bounded_vars |= term
        elif len(term) == 1:
            linear_unbounded.append((free_unbounded[0], coeff))
        else:  # pragma: no cover - classify() forbids this
            msg = "unbounded variable in a product term reached the evaluator"
            raise UnsupportedCompositeError(msg)

    total: float | Fraction = _vertex_extreme(bounded_terms, bounded_vars, bounds, sign)
    if total in (_INF, -_INF):
        return total

    for var, coeff in linear_unbounded:
        lo, hi = bounds[var]
        pick_hi = (coeff * sign) > 0
        edge = hi if pick_hi else lo
        if math.isinf(edge):
            return _INF * sign  # this variable alone drives the extremum to +/-inf
        total += coeff * Fraction(str(edge))
    return total


def _is_finite_box(box: tuple[float, float] | None) -> bool:
    return box is not None and math.isfinite(box[0]) and math.isfinite(box[1])


def _vertex_extreme(
    terms: _Poly,
    variables: set[str],
    bounds: Mapping[str, tuple[float, float]],
    sign: int,
) -> Fraction:
    """max/min over the finite box of a multilinear poly (all vars bounded)."""
    ordered = sorted(variables)
    best: Fraction | None = None
    for mask in range(1 << len(ordered)):
        assignment: dict[str, Fraction] = {}
        for i, var in enumerate(ordered):
            lo, hi = bounds[var]
            assignment[var] = Fraction(str(hi if (mask >> i) & 1 else lo))
        value = Fraction(0)
        for term, coeff in terms.items():
            prod = coeff
            for v in term:
                prod *= assignment[v]
            value += prod
        signed = value * sign
        if best is None or signed > best:
            best = signed
    return (best if best is not None else Fraction(0)) * sign


# ── The runtime decision ──────────────────────────────────────────────────


def decide_violation(
    comparisons: list[_Comparison],
    concrete: Mapping[str, float],
    unbound_bounds: Mapping[str, tuple[float, float]],
) -> bool:
    """True iff some in-bounds assignment of the unbound vars violates the constraint.

    Mirrors the Z3 worker's ``Not(expr) sat?`` for the supported grammar.
    """
    for poly, op in comparisons:
        f = _substitute(poly, concrete)
        if op in ("le", "lt"):  # f <= 0 / f < 0 ; violated if f can exceed 0
            hi = _box_max(f, unbound_bounds)
            if (op == "le" and hi > 0) or (op == "lt" and hi >= 0):
                return True
        else:  # ge / gt : f >= 0 / f > 0 ; violated if f can drop below 0
            lo = _box_max(f, unbound_bounds, minimize=True)
            if (op == "ge" and lo < 0) or (op == "gt" and lo <= 0):
                return True
    return False
