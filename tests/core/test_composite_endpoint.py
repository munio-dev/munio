"""Tests for the solver-free COMPOSITE endpoint evaluator.

The differential oracle (``TestDifferentialOracle``) is the load-bearing proof:
it cross-checks ``decide_violation`` against Z3's ``Not(expr) sat?`` over random
multilinear constraints and boxes, oversampling unbounded bounds and equality
boundaries. Unit tests below pin specific behaviours and the grammar boundary.
"""

from __future__ import annotations

import ast
import math
import random

import pytest

from munio._composite_endpoint import (
    classify,
    decide_violation,
    parse_comparisons,
)


class TestClassify:
    @pytest.mark.parametrize(
        ("expression", "unbounded"),
        [
            ("cost * quantity <= budget", []),  # all bounded -> vertex enumeration
            ("memory + disk * 2 <= maxr", ["memory", "disk"]),  # linear, unbounded ok
            ("price - discount >= 0 and discount * 2 <= price", ["price", "discount"]),
            ("0 <= x and x <= 100", ["x"]),  # chained / conjunction
            ("x / 2 <= y", ["x"]),  # division by a constant is affine
        ],
    )
    def test_supported(self, expression: str, unbounded: list[str]) -> None:
        result = classify(expression, unbounded)
        assert result.supported, result.reason

    @pytest.mark.parametrize(
        ("expression", "unbounded", "reason_substr"),
        [
            ("x == y", [], "=="),
            ("x != y", [], "=="),
            ("x < 1 or y < 1", [], "or"),
            ("x / y <= 1", [], "division by a variable"),
            ("x * x <= 4", [], "repeated in a product term"),
            ("cost * quantity <= budget", ["cost"], "unbounded variable 'cost'"),
        ],
    )
    def test_unsupported(self, expression: str, unbounded: list[str], reason_substr: str) -> None:
        result = classify(expression, unbounded)
        assert not result.supported
        assert reason_substr in result.reason


class TestDecideViolation:
    """block == True means: some in-bounds assignment violates the constraint."""

    def _decide(
        self,
        expression: str,
        concrete: dict[str, float],
        unbound: dict[str, tuple[float, float]],
    ) -> bool:
        return decide_violation(parse_comparisons(expression), concrete, unbound)

    @pytest.mark.parametrize(
        ("expression", "concrete", "unbound", "block"),
        [
            # spend-limit: cost * quantity <= budget
            ("cost * quantity <= budget", {"cost": 10, "quantity": 2, "budget": 10000}, {}, False),
            ("cost * quantity <= budget", {"cost": 100, "quantity": 200, "budget": 50}, {}, True),
            ("cost * quantity <= budget", {"cost": 10, "budget": 100}, {"quantity": (1, 5)}, False),
            ("cost * quantity <= budget", {"cost": 10, "budget": 40}, {"quantity": (1, 5)}, True),
            # resource-quota: memory + disk*2 <= maxr
            ("memory + disk * 2 <= maxr", {"memory": 10, "disk": 5, "maxr": 100}, {}, False),
            ("memory + disk * 2 <= maxr", {"memory": 10, "maxr": 100}, {"disk": (0, 10000)}, True),
            (
                "memory + disk * 2 <= maxr",
                {"maxr": 100},
                {"memory": (0, 40), "disk": (0, 20)},
                False,
            ),
            # discount-bound: price - discount >= 0 and discount*2 <= price
            (
                "price - discount >= 0 and discount * 2 <= price",
                {"price": 100, "discount": 30},
                {},
                False,
            ),
            (
                "price - discount >= 0 and discount * 2 <= price",
                {"price": 100, "discount": 60},
                {},
                True,
            ),
            # unbounded (infinite box) — the ∞-safe linear path
            (
                "price - discount >= 0 and discount * 2 <= price",
                {"price": 100},
                {"discount": (0, math.inf)},
                True,
            ),
            (
                "price - discount >= 0 and discount * 2 <= price",
                {"discount": 10},
                {"price": (0, math.inf)},
                True,
            ),
        ],
    )
    def test_real_constraints(
        self,
        expression: str,
        concrete: dict[str, float],
        unbound: dict[str, tuple[float, float]],
        block: bool,
    ) -> None:
        assert self._decide(expression, concrete, unbound) is block

    @pytest.mark.parametrize(
        ("expression", "unbound", "block"),
        [
            # strict vs non-strict at the exact boundary (max x == 10)
            ("x <= 10", {"x": (0, 10)}, False),  # 10 <= 10 holds everywhere
            ("x < 10", {"x": (0, 10)}, True),  # x=10 makes 10 < 10 false
            # exact rational arithmetic through division
            ("x / 3 <= 1", {"x": (0, 3)}, False),  # x/3 max is exactly 1
            ("x / 3 < 1", {"x": (0, 3)}, True),  # x=3 -> 1 < 1 false
        ],
    )
    def test_boundary_exactness(
        self, expression: str, unbound: dict[str, tuple[float, float]], block: bool
    ) -> None:
        assert self._decide(expression, {}, unbound) is block


@pytest.mark.z3
class TestDifferentialOracle:
    """Guardrail 2: endpoint evaluator must agree with Z3 on every supported case."""

    def test_matches_z3(self) -> None:
        import z3

        def to_z3(node: ast.AST, zvars: dict) -> object:
            """Minimal AST -> Z3 builder for the generated grammar (+, -, *, comparisons, and)."""
            if isinstance(node, ast.Expression):
                return to_z3(node.body, zvars)
            if isinstance(node, ast.BoolOp):  # only 'and' is generated
                return z3.And(*[to_z3(v, zvars) for v in node.values])
            if isinstance(node, ast.Compare):
                left = to_z3(node.left, zvars)
                op, right = node.ops[0], to_z3(node.comparators[0], zvars)
                return {
                    ast.Lt: left < right,
                    ast.LtE: left <= right,
                    ast.Gt: left > right,
                    ast.GtE: left >= right,
                }[type(op)]
            if isinstance(node, ast.BinOp):
                left, right = to_z3(node.left, zvars), to_z3(node.right, zvars)
                return {ast.Add: left + right, ast.Sub: left - right, ast.Mult: left * right}[
                    type(node.op)
                ]
            if isinstance(node, ast.UnaryOp):  # only USub is generated
                return -to_z3(node.operand, zvars)
            if isinstance(node, ast.Name):
                return zvars[node.id]
            if isinstance(node, ast.Constant):
                return z3.IntVal(int(node.value))
            raise AssertionError(f"unexpected node {type(node).__name__}")

        variables = ["a", "b", "c"]
        rng = random.Random(20260705)  # noqa: S311 — test data, not cryptographic

        def rpoly() -> str:
            parts = []
            for _ in range(rng.choice([1, 1, 2])):
                k = rng.choice([0, 1, 1, 2])
                vs = rng.sample(variables, k)
                coeff = rng.choice([-2, -1, 1, 1, 2])
                if vs:
                    term = (f"{abs(coeff)}*" if abs(coeff) != 1 else "") + "*".join(vs)
                else:
                    term = str(abs(coeff))
                parts.append(("-" if coeff < 0 else "+") + term)
            expr = parts[0].lstrip("+")
            for p in parts[1:]:
                expr += p if p[0] == "-" else "+" + p.lstrip("+")
            return expr

        def rexpr() -> str:
            n = rng.choice([1, 1, 2])
            return " and ".join(
                f"({rpoly()}) {rng.choice(['<', '<=', '>', '>='])} ({rpoly()})" for _ in range(n)
            )

        def rscenario() -> tuple[dict[str, float], dict[str, tuple[float, float]]]:
            concrete: dict[str, float] = {}
            unbound: dict[str, tuple[float, float]] = {}
            for v in variables:
                if rng.random() < 0.55:
                    concrete[v] = rng.choice([0, 0, 1, 2, 3, -1, -2, 4])
                else:
                    lo = rng.choice([-math.inf, 0, 0, -3, 1])
                    hi = rng.choice([math.inf, 0, 5, 3, 10])
                    unbound[v] = (min(lo, hi), max(lo, hi))
            return concrete, unbound

        def z3_violates(
            expr: str, concrete: dict[str, float], unbound: dict[str, tuple[float, float]]
        ) -> bool | None:
            tree = ast.parse(expr, mode="eval")
            solver = z3.Solver()
            zvars = {}
            for v in variables:
                if v in concrete:
                    zvars[v] = z3.IntVal(int(concrete[v]))
                elif v in unbound:
                    zvars[v] = z3.Int(v)
                    lo, hi = unbound[v]
                    if math.isfinite(lo):
                        solver.add(zvars[v] >= int(lo))
                    if math.isfinite(hi):
                        solver.add(zvars[v] <= int(hi))
                else:
                    zvars[v] = z3.IntVal(0)
            solver.add(z3.Not(to_z3(tree, zvars)))
            result = solver.check()
            if result == z3.unknown:
                return None
            return result == z3.sat

        supported = checked = with_unbounded = 0
        for _ in range(3000):
            expr = rexpr()
            concrete, unbound = rscenario()
            unbounded_vars = [
                v
                for v, (lo, hi) in unbound.items()
                if not (math.isfinite(lo) and math.isfinite(hi))
            ]
            if not classify(expr, unbounded_vars).supported:
                continue
            supported += 1
            if unbounded_vars:
                with_unbounded += 1
            mine = decide_violation(parse_comparisons(expr), concrete, unbound)
            theirs = z3_violates(expr, concrete, unbound)
            if theirs is None:
                continue
            checked += 1
            assert mine == theirs, (
                f"divergence: expr={expr!r} concrete={concrete} unbound={unbound} "
                f"endpoint={mine} z3={theirs}"
            )

        # Ensure the run actually exercised the hard regions, not just trivial cases.
        assert checked > 500, f"oracle sample too small: {checked}"
        assert with_unbounded > 100, f"unbounded path under-exercised: {with_unbounded}"
