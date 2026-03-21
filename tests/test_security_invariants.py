"""AST-based static security invariant checks.

These tests parse source code and verify structural security properties
that have historically been sources of recurring bugs.  They run as part
of ``make ci`` (auto-discovered by pytest) and act as CI guardrails:
when new code violates an invariant, the test fails before the code
reaches review.

Checked invariants:
- Bool-before-int guard on every ``isinstance(x, int|float)``
- No ``except`` block returns ``[]`` (fail-open by accident)
- No raw values leaked in Z3 worker violation dicts
- No ``repr()`` calls in ``_eval_composite_python``
- No ``str(exc)`` in HTTP-facing code (info leak)
- Z3 division safety functions called in ``_z3_worker``
- CORS defaults are empty (not wildcard)
- No ``yaml.load()`` (only ``yaml.safe_load()``)
- No ``str(exc)`` in ``_make_system_violation`` calls
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import ClassVar

import pytest

_PACKAGE_DIR = Path(__file__).resolve().parent.parent / "src" / "munio"

# All solver-related modules that security invariants must cover.
_SOLVER_MODULES = {
    "solver.py": _PACKAGE_DIR / "solver.py",
    "_matching.py": _PACKAGE_DIR / "_matching.py",
    "_composite.py": _PACKAGE_DIR / "_composite.py",
    "_z3_runtime.py": _PACKAGE_DIR / "_z3_runtime.py",
    "_z3_regex.py": _PACKAGE_DIR / "_z3_regex.py",
    "_policy_verifier.py": _PACKAGE_DIR / "_policy_verifier.py",
}
_ALL_TREES = {
    name: ast.parse(path.read_text(), filename=str(path)) for name, path in _SOLVER_MODULES.items()
}

# Files scanned for str(exc) info leak detection.
# cli.py is excluded — CLI output goes to operator's terminal (acceptable).
_STR_EXC_MODULES = {
    "server.py": _PACKAGE_DIR / "server.py",
    "solver.py": _PACKAGE_DIR / "solver.py",
    "_policy_verifier.py": _PACKAGE_DIR / "_policy_verifier.py",
    "_langchain.py": _PACKAGE_DIR / "adapters" / "_langchain.py",
    "_crewai.py": _PACKAGE_DIR / "adapters" / "_crewai.py",
    "_mcp.py": _PACKAGE_DIR / "adapters" / "_mcp.py",
    "_openai_agents.py": _PACKAGE_DIR / "adapters" / "_openai_agents.py",
}
_STR_EXC_TREES = {
    name: ast.parse(path.read_text(), filename=str(path)) for name, path in _STR_EXC_MODULES.items()
}

# All source files for broad scans (yaml.safe_load, etc.)
_ALL_SOURCE_FILES = list(_PACKAGE_DIR.rglob("*.py"))

# Convenience aliases for backward compatibility in tests
_SOLVER_TREE = _ALL_TREES["solver.py"]
_COMPOSITE_TREE = _ALL_TREES["_composite.py"]
_Z3_RUNTIME_TREE = _ALL_TREES["_z3_runtime.py"]


# ── Helpers ─────────────────────────────────────────────────────────────


def _extract_type_names(node: ast.expr) -> set[str]:
    """Extract type names from the second arg of isinstance().

    Handles:
    - ``isinstance(x, int)`` -> ``Name``
    - ``isinstance(x, (int, float))`` -> ``Tuple``
    - ``isinstance(x, int | float)`` -> ``BinOp(BitOr)``
    """
    names: set[str] = set()
    if isinstance(node, ast.Name):
        names.add(node.id)
    elif isinstance(node, ast.Tuple):
        for elt in node.elts:
            names.update(_extract_type_names(elt))
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        names.update(_extract_type_names(node.left))
        names.update(_extract_type_names(node.right))
    return names


def _get_isinstance_var(node: ast.Call) -> str | None:
    """Return the variable name from isinstance(var, type) or None."""
    if (
        isinstance(node.func, ast.Name)
        and node.func.id == "isinstance"
        and len(node.args) == 2
        and isinstance(node.args[0], ast.Name)
    ):
        return node.args[0].id
    return None


def _is_isinstance_call(node: ast.expr, *, var: str, types: set[str]) -> bool:
    """Check if node is ``isinstance(var, <types>)``."""
    if not isinstance(node, ast.Call):
        return False
    if _get_isinstance_var(node) != var:
        return False
    return _extract_type_names(node.args[1]) == types


def _has_bool_guard_in_boolop(boolop: ast.BoolOp, var_name: str) -> bool:
    """Check if a BoolOp(And) contains ``not isinstance(var, bool)``."""
    if not isinstance(boolop.op, ast.And):
        return False
    for value in boolop.values:
        if (
            isinstance(value, ast.UnaryOp)
            and isinstance(value.op, ast.Not)
            and isinstance(value.operand, ast.Call)
            and _is_isinstance_call(value.operand, var=var_name, types={"bool"})
        ):
            return True
    return False


def _find_functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Return all function definitions in the module."""
    return [
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]


def _find_function_by_name(
    tree: ast.Module,
    name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find a function definition by name."""
    for func in _find_functions(tree):
        if func.name == name:
            return func
    return None


def _has_preceding_bool_check(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    target_line: int,
    var_name: str,
) -> bool:
    """Check if there's an isinstance(var, bool) early-exit before target_line.

    Walks all if-statements in the function body (including nested in if/elif
    chains) looking for ``isinstance(var, bool)`` tests with a body that always
    exits (raise/return/continue/break).
    """

    def _body_always_exits(body: list[ast.stmt]) -> bool:
        if not body:
            return False
        last = body[-1]
        return isinstance(last, ast.Return | ast.Raise | ast.Continue | ast.Break)

    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        if node.lineno >= target_line:
            continue
        test = node.test
        if (
            isinstance(test, ast.Call)
            and _is_isinstance_call(test, var=var_name, types={"bool"})
            and _body_always_exits(node.body)
        ):
            return True
    return False


# ── Test classes ────────────────────────────────────────────────────────


class TestBoolBeforeIntGuard:
    """Every isinstance(x, int|float) must have a bool guard.

    Python's ``isinstance(True, int)`` is ``True``.  Without a bool guard,
    threshold shortcuts and numeric coercion silently treat ``True`` as ``1``.

    Acceptable patterns:
    1. ``isinstance(x, int|float) and not isinstance(x, bool)`` (same condition)
    2. Preceding ``isinstance(x, bool)`` early-return in the same function
    """

    @staticmethod
    def _find_unguarded_isinstance(
        tree: ast.Module,
    ) -> list[tuple[int, str, str]]:
        """Find isinstance(x, int|float) calls without bool guards.

        Returns list of (line, var_name, func_name) for unguarded occurrences.
        """
        unguarded: list[tuple[int, str, str]] = []
        funcs = _find_functions(tree)

        for func in funcs:
            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue

                var_name = _get_isinstance_var(node)
                if var_name is None:
                    continue

                type_names = _extract_type_names(node.args[1])
                # Only flag when 'int' is in the type set (bool is subclass of int,
                # NOT float).  isinstance(True, float) is False, so float-only checks
                # are safe.  Also skip if bool is already in the type set.
                if "int" not in type_names or "bool" in type_names:
                    continue

                # Check 1: is this inside a BoolOp(And) with `not isinstance(var, bool)`?
                guarded = False
                for parent in ast.walk(func):
                    if (
                        isinstance(parent, ast.BoolOp)
                        and any(v is node for v in parent.values)
                        and _has_bool_guard_in_boolop(parent, var_name)
                    ):
                        guarded = True
                        break

                # Check 2: is there a preceding isinstance(var, bool) early-exit?
                if not guarded and _has_preceding_bool_check(func, node.lineno, var_name):
                    guarded = True

                if not guarded:
                    unguarded.append((node.lineno, var_name, func.name))

        return unguarded

    def test_all_isinstance_int_float_have_bool_guard(self) -> None:
        unguarded: list[tuple[int, str, str]] = []
        for tree in _ALL_TREES.values():
            unguarded.extend(self._find_unguarded_isinstance(tree))
        if unguarded:
            details = "\n".join(
                f"  line {line}: isinstance({var}, ...) in {func}()"
                for line, var, func in unguarded
            )
            pytest.fail(
                f"Found isinstance(x, int|float) without bool guard:\n{details}\n"
                "Fix: add `not isinstance(x, bool)` guard or preceding bool check."
            )


class TestFailClosedExceptBlocks:
    """No except block fails open (returns [] or bare pass on broad exception).

    Returning [] from an except block = fail-open: the error is swallowed
    and the constraint is treated as satisfied.  Except blocks must either
    append a violation, re-raise, or return a non-empty failure indicator.

    Also checks adapter files for ``except Exception: pass`` which silently
    ignores errors.  Narrow exceptions (ImportError, ValueError, etc.) with
    ``pass`` are allowed — only broad ``Exception`` / bare ``except`` are flagged.
    """

    @staticmethod
    def _find_failopen_except_blocks(tree: ast.Module) -> list[tuple[int, str]]:
        """Find except blocks that return [].

        Returns list of (line, func_name).
        """
        failures: list[tuple[int, str]] = []
        for func in _find_functions(tree):
            for node in ast.walk(func):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                failures.extend(
                    (stmt.lineno, func.name)
                    for stmt in ast.walk(node)
                    if isinstance(stmt, ast.Return)
                    and isinstance(stmt.value, ast.List)
                    and len(stmt.value.elts) == 0
                )
        return failures

    @staticmethod
    def _find_broad_except_pass(tree: ast.Module) -> list[tuple[int, str]]:
        """Find ``except Exception: pass`` or bare ``except: pass``.

        Only flags broad exception handlers (Exception or bare except)
        whose body is a single ``pass`` statement.  Narrow exceptions
        like ImportError, ValueError are legitimate with pass.
        """
        failures: list[tuple[int, str]] = []
        for func in _find_functions(tree):
            for node in ast.walk(func):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                # Check if this is a broad exception (Exception or bare except)
                is_broad = node.type is None  # bare except:
                if isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    is_broad = True
                if not is_broad:
                    continue
                # Check if body is just pass
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    failures.append((node.lineno, func.name))
        return failures

    def test_no_except_returns_empty_list(self) -> None:
        failures: list[tuple[int, str]] = []
        for tree in _ALL_TREES.values():
            failures.extend(self._find_failopen_except_blocks(tree))
        if failures:
            details = "\n".join(f"  line {line}: in {func}()" for line, func in failures)
            pytest.fail(
                f"Found except blocks returning [] (fail-open):\n{details}\n"
                "Fix: append a violation or return a failure indicator."
            )

    def test_no_broad_except_pass(self) -> None:
        """No ``except Exception: pass`` in solver or adapter code."""
        failures: list[tuple[str, int, str]] = []
        # Scan solver modules + adapter modules
        all_trees = {**_ALL_TREES, **_STR_EXC_TREES}
        for name, tree in all_trees.items():
            for line, func in self._find_broad_except_pass(tree):
                failures.append((name, line, func))
        if failures:
            details = "\n".join(f"  {fname}:{line}: in {func}()" for fname, line, func in failures)
            pytest.fail(
                f"Found 'except Exception: pass' (fail-open):\n{details}\n"
                "Fix: log the error and block/re-raise."
            )


class TestNoRawValuesInWorkerViolations:
    """Z3 worker violation dicts must not leak raw values.

    All ``actual_value`` fields must be ``""`` (empty string).  No f-string
    interpolation of variables named raw, val, exc, value, concrete, result.
    """

    _LEAK_VARNAMES: ClassVar[set[str]] = {
        "raw",
        "val",
        "exc",
        "value",
        "concrete",
        "result",
        "values",
    }

    @staticmethod
    def _find_worker_func(tree: ast.Module) -> ast.FunctionDef | None:
        return _find_function_by_name(tree, "_z3_worker")  # type: ignore[return-value]

    def test_actual_value_always_empty(self) -> None:
        func = self._find_worker_func(_Z3_RUNTIME_TREE)
        assert func is not None, "_z3_worker not found"

        violations: list[tuple[int, str]] = []
        for node in ast.walk(func):
            if not isinstance(node, ast.Dict):
                continue
            for key, val in zip(node.keys, node.values, strict=True):
                if not isinstance(key, ast.Constant) or key.value != "actual_value":
                    continue
                # Must be Constant("") — empty string
                if isinstance(val, ast.Constant) and val.value == "":
                    continue
                violations.append((val.lineno, ast.dump(val)))

        if violations:
            details = "\n".join(f"  line {line}: actual_value={expr}" for line, expr in violations)
            pytest.fail(
                f"Z3 worker leaks raw values in actual_value:\n{details}\n"
                'Fix: use actual_value="" (empty string).'
            )

    def test_no_fstring_interpolation_of_raw_values(self) -> None:
        func = self._find_worker_func(_Z3_RUNTIME_TREE)
        assert func is not None, "_z3_worker not found"

        violations: list[tuple[int, str]] = []
        for node in ast.walk(func):
            if not isinstance(node, ast.JoinedStr):  # f-string
                continue
            violations.extend(
                (node.lineno, val.value.id)
                for val in node.values
                if isinstance(val, ast.FormattedValue)
                and isinstance(val.value, ast.Name)
                and val.value.id in self._LEAK_VARNAMES
            )

        if violations:
            details = "\n".join(
                f"  line {line}: f-string includes {{{var}}}" for line, var in violations
            )
            pytest.fail(
                f"Z3 worker leaks values via f-strings:\n{details}\n"
                "Fix: use generic messages without interpolating raw values."
            )


class TestNoReprInCompositeEval:
    """No repr() calls or !r conversions in _eval_composite_python.

    repr() of user-controlled values can leak sensitive data in violation
    messages that cross process/API boundaries.  f-string ``!r`` conversion
    (``f"{x!r}"``) is equivalent to ``repr(x)`` and must also be detected.
    """

    def test_no_repr_calls(self) -> None:
        func = _find_function_by_name(_COMPOSITE_TREE, "_eval_composite_python")
        assert func is not None, "_eval_composite_python not found"

        repr_calls = [
            node.lineno
            for node in ast.walk(func)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "repr"
        ]

        if repr_calls:
            lines = ", ".join(str(ln) for ln in repr_calls)
            pytest.fail(
                f"Found repr() calls in _eval_composite_python at lines: {lines}\n"
                "Fix: use empty string or generic placeholder instead of repr(raw)."
            )

    def test_no_fstring_repr_conversion(self) -> None:
        func = _find_function_by_name(_COMPOSITE_TREE, "_eval_composite_python")
        assert func is not None, "_eval_composite_python not found"

        # ast.FormattedValue.conversion: -1=none, 115=!s, 114=!r, 97=!a
        repr_conversions = [
            node.lineno
            for node in ast.walk(func)
            if isinstance(node, ast.FormattedValue) and node.conversion == ord("r")
        ]

        if repr_conversions:
            lines = ", ".join(str(ln) for ln in repr_conversions)
            pytest.fail(
                f"Found f-string !r conversion in _eval_composite_python at lines: {lines}\n"
                "Fix: use !s or remove conversion to avoid leaking repr() output."
            )


class TestNoStrExcInResponses:
    """No str(exc) in HTTP-facing code.

    ``str(exc)`` in HTTP responses, violation messages, or adapter output
    leaks internal details (paths, thresholds, constraint names) to callers.
    Log the exception, return a generic message.

    Scans: server.py, solver.py, _policy_verifier.py, all 4 adapter files.
    Excluded: cli.py (operator-facing, acceptable).
    """

    _EXC_VARNAMES: ClassVar[set[str]] = {"exc", "e", "err", "error"}

    @staticmethod
    def _find_str_exc_calls(tree: ast.Module) -> list[tuple[int, str, str]]:
        """Find str(exc) calls where exc is a common exception variable name.

        Returns list of (line, var_name, func_name).
        """
        findings: list[tuple[int, str, str]] = []
        for func in _find_functions(tree):
            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Name) or node.func.id != "str":
                    continue
                if len(node.args) != 1:
                    continue
                arg = node.args[0]
                if isinstance(arg, ast.Name) and arg.id in TestNoStrExcInResponses._EXC_VARNAMES:
                    findings.append((node.lineno, arg.id, func.name))
        return findings

    def test_no_str_exc_in_http_facing_code(self) -> None:
        all_findings: list[tuple[str, int, str, str]] = []
        for name, tree in _STR_EXC_TREES.items():
            for line, var, func in self._find_str_exc_calls(tree):
                all_findings.append((name, line, var, func))

        if all_findings:
            details = "\n".join(
                f"  {fname}:{line}: str({var}) in {func}()"
                for fname, line, var, func in all_findings
            )
            pytest.fail(
                f"Found str(exc) in HTTP-facing code (info leak):\n{details}\n"
                "Fix: log the exception, return a generic message."
            )


class TestZ3DivisionSafetyFunctions:
    """_z3_worker must call _expression_has_div and _collect_divisor_names.

    Tripwire test: catches accidental removal of division safety functions
    during refactoring.  Functional correctness is verified by
    TestZ3DivisionSoundness in test_solver.py.
    """

    @pytest.mark.parametrize(
        "func_name",
        ["_expression_has_div", "_collect_divisor_names"],
    )
    def test_z3_worker_calls_division_safety_function(self, func_name: str) -> None:
        worker = _find_function_by_name(_Z3_RUNTIME_TREE, "_z3_worker")
        assert worker is not None, "_z3_worker not found"

        calls = [
            node
            for node in ast.walk(worker)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == func_name
        ]
        assert calls, (
            f"_z3_worker does not call {func_name}(). "
            "Division safety requires both _expression_has_div (Int->Real promotion) "
            "and _collect_divisor_names (non-zero guard)."
        )


class TestCorsDefaultNotWildcard:
    """CORS defaults must be empty, not wildcard.

    A wildcard ``["*"]`` default enables browser-based constraint probing
    from any origin.
    """

    def test_server_config_cors_default_empty(self) -> None:
        from munio.server import ServerConfig

        config = ServerConfig()
        assert config.cors_origins == [], (
            f"ServerConfig.cors_origins default must be [] (empty), got {config.cors_origins!r}"
        )


class TestNoUnsafeYamlLoad:
    """Only yaml.safe_load() is allowed, never yaml.load().

    yaml.load() without Loader= can execute arbitrary Python code.
    """

    def test_no_yaml_load_in_source(self) -> None:
        violations: list[tuple[str, int]] = []
        for source_file in _ALL_SOURCE_FILES:
            try:
                tree = ast.parse(source_file.read_text(), filename=str(source_file))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                # Match yaml.load( but not yaml.safe_load(
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "load"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "yaml"
                ):
                    violations.append((source_file.name, node.lineno))
        if violations:
            details = "\n".join(f"  {fname}:{line}" for fname, line in violations)
            pytest.fail(f"Found yaml.load() (unsafe, use yaml.safe_load()):\n{details}")


class TestNoRawExcInSystemViolations:
    """_make_system_violation must not receive str(exc) as message.

    System violation messages flow to HTTP responses via
    Tier1Solver -> Verifier -> server.py.  str(exc) leaks internal
    thresholds and implementation details.
    """

    def test_no_str_exc_in_make_system_violation(self) -> None:
        violations: list[tuple[int, str]] = []
        for func in _find_functions(_SOLVER_TREE):
            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue
                # Match _make_system_violation(str(exc), ...)
                if not isinstance(node.func, ast.Name):
                    continue
                if node.func.id != "_make_system_violation":
                    continue
                if not node.args:
                    continue
                first_arg = node.args[0]
                # Detect str(exc) / str(e) pattern
                if (
                    isinstance(first_arg, ast.Call)
                    and isinstance(first_arg.func, ast.Name)
                    and first_arg.func.id == "str"
                    and len(first_arg.args) == 1
                    and isinstance(first_arg.args[0], ast.Name)
                ):
                    violations.append((node.lineno, first_arg.args[0].id))

        if violations:
            details = "\n".join(
                f"  line {line}: _make_system_violation(str({var}))" for line, var in violations
            )
            pytest.fail(
                f"Found str(exc) in _make_system_violation (info leak via HTTP):\n{details}\n"
                'Fix: use a generic message like "input too large".'
            )
