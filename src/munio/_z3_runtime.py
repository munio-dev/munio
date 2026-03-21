"""Z3 subprocess pool for Tier 2-3 runtime constraint checks.

Process isolation is MANDATORY (from AWS Zelkova/MS SecGuru production lessons):
- Serialize as SMT-LIB2, solve in worker process, kill periodically
- rlimit (deterministic) for CI reproducibility, timeout as safety net
- External process timeout > Z3 internal timeout (Z3 ignores its own in preprocessing)
- Z3 LEAKS MEMORY on timeout — worker processes are disposable

Uses ``multiprocessing.get_context("spawn")`` for macOS fork safety.
"""

from __future__ import annotations

import logging
import multiprocessing
import threading
from queue import Empty as QueueEmpty
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

from munio._composite import (
    _eval_composite_expression,
    _make_worker_violation,
    _resolve_composite_variables,
    _VarAccessor,
)
from munio._matching import _make_system_violation
from munio.models import (
    Action,
    Constraint,
    FailBehavior,
    SolverConfig,
    Tier,
    Violation,
    ViolationSource,
)

__all__ = [
    "Z3SubprocessPool",
    "_ast_to_z3",
    "_collect_divisor_names",
    "_expression_has_div",
    "_z3_worker",
    "check_z3_version",
]

logger = logging.getLogger(__name__)

_spawn_context = multiprocessing.get_context("spawn")


def check_z3_version(required: str | None = None) -> tuple[bool, str]:
    """Check if Z3 solver is available and optionally verify version.

    Args:
        required: Required version string (e.g. ``"4.16.0.0"``).
            If None, just checks availability.

    Returns:
        ``(ok, message)`` tuple. ``ok=False`` if Z3 not installed or version mismatch.
    """
    try:
        import z3  # type: ignore[import-untyped]
    except ImportError:
        return False, "Z3 solver is not installed"

    version = z3.get_version_string()
    if required is not None and version != required:
        return False, f"Z3 version mismatch: installed={version}, required={required}"

    return True, f"Z3 version {version}"


def _expression_has_div(expression: str) -> bool:
    """Check if a COMPOSITE expression contains a division operator.

    Used to determine if Int variables should be promoted to Real for Z3
    encoding, since Python ``/`` is true division (returns float) while Z3
    Int ``/`` is truncating integer division — a semantic mismatch.
    """
    import ast as _ast

    try:
        tree = _ast.parse(expression, mode="eval")
    except SyntaxError:
        return False

    return any(isinstance(node, _ast.Div) for node in _ast.walk(tree))


def _collect_divisor_names(expression: str) -> set[str]:
    """Collect variable names used as divisors in a COMPOSITE expression.

    Z3 treats division-by-zero as an uninterpreted function (returns arbitrary
    value), which can cause false SAFE results.  The caller should add
    ``z3.Not(var == 0)`` for each returned variable name.
    """
    import ast as _ast

    names: set[str] = set()
    try:
        tree = _ast.parse(expression, mode="eval")
    except SyntaxError:
        return names

    for node in _ast.walk(tree):
        if (
            isinstance(node, _ast.BinOp)
            and isinstance(node.op, _ast.Div)
            and isinstance(node.right, _ast.Name)
        ):
            names.add(node.right.id)
    return names


def _ast_to_z3(node: Any, z3_vars: dict[str, Any], z3_mod: Any) -> Any:
    """Convert a validated Python AST node to a Z3 expression.

    The expression has already been validated by ``_validate_expression_ast``,
    so all nodes are in the allowed whitelist. This function runs inside the
    Z3 subprocess worker.

    Args:
        node: An ``ast`` module AST node.
        z3_vars: Mapping of variable name to Z3 ArithRef (Int/Real).
        z3_mod: The ``z3`` module (passed to avoid top-level import).

    Returns:
        A Z3 expression.
    """
    import ast as _ast

    if isinstance(node, _ast.Expression):
        return _ast_to_z3(node.body, z3_vars, z3_mod)

    if isinstance(node, _ast.Name):
        return z3_vars[node.id]

    if isinstance(node, _ast.Constant):
        v = node.value
        if isinstance(v, bool):
            msg = "bool constants should have been rejected by validator"
            raise ValueError(msg)
        if isinstance(v, int):
            return z3_mod.IntVal(v)
        if isinstance(v, float):
            return z3_mod.RealVal(v)
        msg = f"Unsupported constant type: {type(v).__name__}"
        raise ValueError(msg)

    if isinstance(node, _ast.BinOp):
        left = _ast_to_z3(node.left, z3_vars, z3_mod)
        right = _ast_to_z3(node.right, z3_vars, z3_mod)
        op = node.op
        if isinstance(op, _ast.Add):
            return left + right
        if isinstance(op, _ast.Sub):
            return left - right
        if isinstance(op, _ast.Mult):
            return left * right
        if isinstance(op, _ast.Div):
            return left / right
        # FloorDiv and Mod deliberately unsupported: Python //  and %
        # differ from Z3 div/mod for negative numbers.
        msg = f"Unsupported binary op: {type(op).__name__}"
        raise ValueError(msg)

    if isinstance(node, _ast.UnaryOp):
        operand = _ast_to_z3(node.operand, z3_vars, z3_mod)
        if isinstance(node.op, _ast.USub):
            return -operand
        if isinstance(node.op, _ast.UAdd):
            return operand
        if isinstance(node.op, _ast.Not):
            return z3_mod.Not(operand)
        msg = f"Unsupported unary op: {type(node.op).__name__}"
        raise ValueError(msg)

    if isinstance(node, _ast.Compare):
        # Handle chained comparisons: 0 <= x <= 100 → And(0<=x, x<=100)
        parts = []
        left = _ast_to_z3(node.left, z3_vars, z3_mod)
        for cmp_op, comparator_node in zip(node.ops, node.comparators, strict=True):
            right = _ast_to_z3(comparator_node, z3_vars, z3_mod)
            if isinstance(cmp_op, _ast.Lt):
                parts.append(left < right)
            elif isinstance(cmp_op, _ast.LtE):
                parts.append(left <= right)
            elif isinstance(cmp_op, _ast.Gt):
                parts.append(left > right)
            elif isinstance(cmp_op, _ast.GtE):
                parts.append(left >= right)
            elif isinstance(cmp_op, _ast.Eq):
                parts.append(left == right)
            elif isinstance(cmp_op, _ast.NotEq):
                parts.append(left != right)
            else:
                msg = f"Unsupported comparison: {type(cmp_op).__name__}"
                raise ValueError(msg)
            left = right
        if len(parts) == 1:
            return parts[0]
        return z3_mod.And(*parts)

    if isinstance(node, _ast.BoolOp):
        values = [_ast_to_z3(v, z3_vars, z3_mod) for v in node.values]
        if isinstance(node.op, _ast.And):
            return z3_mod.And(*values)
        if isinstance(node.op, _ast.Or):
            return z3_mod.Or(*values)
        msg = f"Unsupported bool op: {type(node.op).__name__}"
        raise ValueError(msg)

    msg = f"Unsupported AST node: {type(node).__name__}"
    raise ValueError(msg)


def _z3_worker(
    queue: multiprocessing.Queue,  # type: ignore[type-arg]
    constraints_data: list[dict[str, Any]],
    action_data: dict[str, Any],
    timeout_ms: int,
    rlimit: int = 500_000,
    max_memory_mb: int = 512,
) -> None:
    """Worker function for Z3 subprocess. Runs in a spawned process.

    Evaluates COMPOSITE constraints using either:
    - Python fast path (all variables concrete)
    - Z3 QF_LIA/QF_LRA (unbound variables with bounds)

    Non-COMPOSITE Tier 2-3 constraints are skipped (future extension).
    """
    import ast as _ast

    # Enforce memory limit (best-effort, Linux only)
    try:
        import resource

        mem_bytes = max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    except (ImportError, ValueError, OSError):
        pass  # Not available or not enforceable on this platform

    violations: list[dict[str, Any]] = []
    try:
        import z3

        z3.set_param("timeout", timeout_ms)
        z3.set_param("rlimit", rlimit)

        args = action_data.get("args", {})

        for cdata in constraints_data:
            check = cdata.get("check")
            if not check or check.get("type") != "composite":
                continue

            variables = check.get("variables", {})
            expression = check.get("expression", "")
            constraint_name = cdata.get("name", "__unknown__")
            constraint_category = cdata.get("category", "")
            severity = cdata.get("severity", "high")
            tier = cdata.get("tier", 2)

            if not variables or not expression:
                continue

            # Resolve variables using shared helper
            resolved = _resolve_composite_variables(variables, args, allow_unbound=True)

            if resolved.error:
                msg_map = {
                    "non-numeric": "Non-numeric value for composite variable",
                    "out-of-bounds": "Composite variable out of bounds",
                }
                violations.append(
                    _make_worker_violation(
                        constraint_name,
                        constraint_category,
                        severity,
                        msg_map.get(resolved.error, "Variable resolution error"),
                        tier,
                    )
                )
                continue

            if not resolved.unbound:
                # All concrete → shared expression evaluator
                eval_result = _eval_composite_expression(expression, resolved.concrete)
                if not eval_result.holds:
                    msg_map = {
                        "nan-inf": "NaN/Inf value in composite expression",
                        "arithmetic": "Arithmetic error in composite expression",
                        "nan-inf-result": "Composite expression violated",
                        "non-boolean": "Composite expression violated",
                        "": "Composite expression violated",
                    }
                    violations.append(
                        _make_worker_violation(
                            constraint_name,
                            constraint_category,
                            severity,
                            msg_map.get(eval_result.error, "Composite expression violated"),
                            tier,
                        )
                    )
            else:
                # Unbound variables → Z3 solver
                try:
                    solver = z3.Solver()
                    z3_vars: dict[str, Any] = {}

                    # Promote Int→Real when expression contains `/`.
                    # Python `/` is true division (7/2=3.5) but Z3 Int `/`
                    # is truncating integer division (7/2=3) — semantic
                    # mismatch that can cause false SAFE.
                    has_div = _expression_has_div(expression)

                    # Declare all variables
                    for var_name, raw_var in variables.items():
                        accessor = _VarAccessor(raw_var)
                        use_real = accessor.type == "real" or has_div
                        z3_var = z3.Real(var_name) if use_real else z3.Int(var_name)
                        z3_vars[var_name] = z3_var

                        if accessor.min is not None:
                            solver.add(z3_var >= accessor.min)
                        if accessor.max is not None:
                            solver.add(z3_var <= accessor.max)

                    # Set concrete values as equalities
                    for var_name, val in resolved.concrete.items():
                        solver.add(z3_vars[var_name] == val)

                    # Parse expression and convert to Z3
                    tree = _ast.parse(expression, mode="eval")
                    z3_expr = _ast_to_z3(tree, z3_vars, z3)

                    # Guard against Z3 division-by-zero: Z3 treats x/0 as
                    # an uninterpreted function (returns arbitrary value),
                    # which can cause false SAFE.  Assert divisors != 0.
                    for dname in _collect_divisor_names(expression):
                        if dname in z3_vars:
                            solver.add(z3_vars[dname] != 0)

                    # Assert negation: looking for a counterexample
                    solver.add(z3.Not(z3_expr))
                    check_result = solver.check()

                    if check_result == z3.sat:
                        violations.append(
                            _make_worker_violation(
                                constraint_name,
                                constraint_category,
                                severity,
                                "Composite expression can be violated (counterexample found)",
                                tier,
                            )
                        )
                    elif check_result == z3.unsat:
                        pass  # Safe — no counterexample exists
                    else:
                        violations.append(
                            _make_worker_violation(
                                constraint_name,
                                constraint_category,
                                severity,
                                "Z3 returned unknown for composite expression (fail-closed)",
                                tier,
                                source="infra",
                            )
                        )
                except Exception:
                    violations.append(
                        _make_worker_violation(
                            constraint_name,
                            constraint_category,
                            severity,
                            "Z3 encoding error (fail-closed)",
                            tier,
                            source="infra",
                        )
                    )

        queue.put({"violations": violations, "status": "ok"})
    except Exception:
        logger.exception("Z3 worker failed")
        # Preserve any violations accumulated before the crash
        queue.put({"violations": violations, "status": "error"})


class Z3SubprocessPool:
    """Process pool for Z3 Tier 2-3 runtime checks.

    Uses ``multiprocessing.get_context("spawn")`` for macOS fork safety.
    Phase 1: spawns a process per request. Phase 2: persistent worker pool.
    """

    __slots__ = ("_config", "_semaphore")

    def __init__(self, config: SolverConfig | None = None) -> None:
        self._config = config or SolverConfig()
        self._semaphore = threading.BoundedSemaphore(self._config.max_workers)
        ok, msg = check_z3_version(self._config.z3_version_required)
        if not ok:
            logger.warning("Z3 version check: %s", msg)

    def check(self, action: Action, constraints: Sequence[Constraint]) -> list[Violation]:
        """Check an action against Tier 2-3 constraints using Z3.

        All errors are fail-closed: timeouts, crashes, and queue errors
        produce CRITICAL violations rather than silently passing.

        Args:
            action: The action to verify.
            constraints: Constraints to check (should be Tier 2-3).

        Returns:
            List of violations found.
        """
        # Filter to Tier 2-3 constraints
        tier_constraints = [c for c in constraints if c.tier in (Tier.TIER_2, Tier.TIER_3)]
        if not tier_constraints:
            return []

        acquired = self._semaphore.acquire(timeout=self._config.process_timeout_s)
        if not acquired:
            return self._fail_violation("Z3 worker pool exhausted (max_workers reached)")

        try:
            return self._run_check(tier_constraints, action)
        finally:
            self._semaphore.release()

    def _run_check(self, tier_constraints: list[Constraint], action: Action) -> list[Violation]:
        """Run Z3 check in subprocess (called with semaphore held)."""
        queue: multiprocessing.Queue[dict[str, Any]] = _spawn_context.Queue()
        constraints_data = [c.model_dump() for c in tier_constraints]
        action_data = action.model_dump()

        proc = _spawn_context.Process(
            target=_z3_worker,
            args=(
                queue,
                constraints_data,
                action_data,
                self._config.timeout_ms,
                self._config.rlimit,
                self._config.max_memory_mb,
            ),
        )
        try:
            return self._run_worker(proc, queue)
        finally:
            queue.close()
            queue.join_thread()
            proc.close()

    def _fail_violation(self, message: str) -> list[Violation]:
        """Return a system violation on error, or [] if fail_behavior is FAIL_OPEN."""
        if self._config.fail_behavior == FailBehavior.FAIL_OPEN:
            logger.warning("%s (fail-open: allowing)", message)
            return []
        return [
            _make_system_violation(
                f"{message} (fail-closed)",
                tier=Tier.TIER_2,
                source=ViolationSource.INFRA,
            )
        ]

    def _run_worker(
        self,
        proc: multiprocessing.process.BaseProcess,
        queue: multiprocessing.Queue[dict[str, Any]],
    ) -> list[Violation]:
        """Run Z3 worker and collect results (extracted for resource cleanup)."""
        proc.start()
        proc.join(timeout=self._config.process_timeout_s)

        if proc.is_alive():
            proc.kill()
            proc.join()
            logger.error("Z3 solver timeout after %ss", self._config.process_timeout_s)
            return self._fail_violation("Z3 solver timeout")

        if proc.exitcode != 0:
            logger.error("Z3 worker crashed with exit code %s", proc.exitcode)
            return self._fail_violation(f"Z3 worker process crashed with exit code {proc.exitcode}")

        try:
            result = queue.get_nowait()
        except QueueEmpty:
            logger.error("Z3 worker returned no result")
            return self._fail_violation("Z3 worker returned no result")

        if result.get("status") == "error":
            logger.error("Z3 worker reported error")
            return self._fail_violation("Z3 worker reported internal error")

        try:
            return [Violation(**v) for v in result.get("violations", [])]
        except Exception:
            logger.exception("Z3 worker returned malformed violation data")
            return self._fail_violation("Z3 worker returned malformed violation data")
