"""Property-based tests for munio.solver — Hypothesis fuzzing.

Tests security-critical functions: sanitization, matching, extraction,
conditions, thresholds, and Guard integration (never-crash).
"""

from __future__ import annotations

import math
import string
import unicodedata
from typing import Any

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from munio.guard import Guard
from munio.models import (
    Action,
    CheckType,
    CompositeVariable,
    Constraint,
    ConstraintCheck,
    ConstraintCondition,
    MatchMode,
    OnViolation,
    Tier,
    VerificationMode,
)
from munio.solver import (
    _MISSING,
    _STRIP_CHARS,
    InputTooLargeError,
    Tier1Solver,
    _check_conditions,
    _coerce_numeric,
    _collect_string_values,
    _extract_field,
    _match_value,
    _resolve_composite_variables,
    _sanitize_string,
    _strict_eq,
)
from tests.core.conftest import (
    make_action,
    make_denylist_constraint,
    make_registry,
    make_threshold_constraint,
)
from tests.core.strategies import (
    STRIP_ALPHABET,
    st_action,
    st_adversarial_numeric,
    st_adversarial_unicode,
    st_any_unicode,
    st_ascii_alphanumeric,
    st_composite_constraint_and_args,
    st_fullwidth,
    st_leaf_value,
    st_nested_dict,
    st_non_regex_match_mode,
    st_numeric_value,
)

pytestmark = pytest.mark.hypothesis


# ── Sanitization properties ─────────────────────────────────────────


class TestSanitizeStringProperties:
    """Property-based tests for _sanitize_string()."""

    @given(s=st_any_unicode)
    def test_idempotent(self, s: str) -> None:
        """f(f(x)) == f(x) for all unicode strings."""
        once = _sanitize_string(s)
        twice = _sanitize_string(once)
        assert twice == once

    @given(s=st_any_unicode)
    def test_output_is_nfkc_normalized(self, s: str) -> None:
        """Result is already in NFKC form."""
        result = _sanitize_string(s)
        assert unicodedata.normalize("NFKC", result) == result

    @given(s=st_ascii_alphanumeric)
    def test_preserves_ascii_alphanumeric(self, s: str) -> None:
        """All ASCII a-z, A-Z, 0-9 characters survive sanitization unchanged."""
        assert _sanitize_string(s) == s

    @given(s=st_adversarial_unicode)
    def test_output_contains_no_strip_chars(self, s: str) -> None:
        """After sanitization, no strippable characters remain."""
        result = _sanitize_string(s)
        for ch in result:
            assert ch not in _STRIP_CHARS

    @given(s=st_fullwidth)
    def test_fullwidth_sanitized(self, s: str) -> None:
        """Fullwidth chars are sanitized: NFKC normalization + percent-decode +
        strip. Result length never exceeds input (NFKC may create percent-sequences
        that get decoded, producing shorter or non-ASCII output)."""
        result = _sanitize_string(s)
        assert len(result) <= len(s)

    @given(
        base=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=20),
        inject=st.text(
            alphabet=st.sampled_from(list(STRIP_ALPHABET)),
            min_size=1,
            max_size=10,
        ),
    )
    def test_strip_chars_interleaved_with_ascii(self, base: str, inject: str) -> None:
        """Injecting invisible chars between ASCII chars: all ASCII survives."""
        # Interleave: b[0] + i[0] + b[1] + i[1] + ...
        parts: list[str] = []
        for i in range(max(len(base), len(inject))):
            if i < len(base):
                parts.append(base[i])
            if i < len(inject):
                parts.append(inject[i])
        mixed = "".join(parts)
        result = _sanitize_string(mixed)
        # All base chars must survive
        assert all(c in result for c in base)


# ── Match value properties ──────────────────────────────────────────


class TestMatchValueProperties:
    """Property-based tests for _match_value() mode semantics."""

    @given(s=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=50))
    def test_exact_reflexive(self, s: str) -> None:
        """EXACT mode: every string matches itself."""
        sanitized = _sanitize_string(s)
        assert _match_value(sanitized, sanitized, MatchMode.EXACT, case_sensitive=True)

    @given(
        a=st.text(alphabet=string.ascii_letters, min_size=1, max_size=20),
        b=st.text(alphabet=string.ascii_letters, min_size=1, max_size=20),
    )
    def test_exact_case_insensitive_symmetric(self, a: str, b: str) -> None:
        """EXACT case-insensitive: match(a,b) == match(b,a)."""
        forward = _match_value(a, b, MatchMode.EXACT, case_sensitive=False)
        backward = _match_value(b, a, MatchMode.EXACT, case_sensitive=False)
        assert forward == backward

    @given(
        prefix=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=20),
        suffix=st.text(alphabet=string.ascii_letters + string.digits, min_size=0, max_size=20),
    )
    def test_prefix_mode_always_matches(self, prefix: str, suffix: str) -> None:
        """PREFIX: value starting with entry always matches."""
        value = prefix + suffix
        assert _match_value(value, prefix, MatchMode.PREFIX, case_sensitive=True)

    @given(
        prefix=st.text(alphabet=string.ascii_letters + string.digits, min_size=0, max_size=20),
        suffix=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=20),
    )
    def test_suffix_mode_always_matches(self, prefix: str, suffix: str) -> None:
        """SUFFIX: value ending with entry always matches."""
        value = prefix + suffix
        assert _match_value(value, suffix, MatchMode.SUFFIX, case_sensitive=True)

    @given(
        a=st.text(alphabet=string.ascii_letters, min_size=0, max_size=15),
        b=st.text(alphabet=string.ascii_letters, min_size=1, max_size=15),
        c=st.text(alphabet=string.ascii_letters, min_size=0, max_size=15),
    )
    def test_contains_mode_always_matches(self, a: str, b: str, c: str) -> None:
        """CONTAINS: a+b+c always contains b."""
        value = a + b + c
        assert _match_value(value, b, MatchMode.CONTAINS, case_sensitive=True)

    @given(s=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=30))
    def test_glob_star_matches_everything(self, s: str) -> None:
        """GLOB: pattern '*' matches any string."""
        assert _match_value(s, "*", MatchMode.GLOB, case_sensitive=True)

    @given(s=st.text(alphabet=string.ascii_letters, min_size=1, max_size=20))
    def test_regex_dot_star_matches_everything(self, s: str) -> None:
        """REGEX: pattern '.*' matches any string."""
        assert _match_value(s, ".*", MatchMode.REGEX, case_sensitive=True)

    @given(
        value=st.text(alphabet=string.ascii_letters, min_size=1, max_size=20),
        entry=st.text(alphabet=string.ascii_letters, min_size=1, max_size=20),
        mode=st_non_regex_match_mode,
    )
    def test_case_insensitive_superset_of_case_sensitive(
        self, value: str, entry: str, mode: MatchMode
    ) -> None:
        """Case-insensitive match is a superset of case-sensitive match."""
        if _match_value(value, entry, mode, case_sensitive=True):
            assert _match_value(value, entry, mode, case_sensitive=False)


# ── Collect string values properties ─────────────────────────────────


class TestCollectStringValuesProperties:
    """Property-based tests for _collect_string_values()."""

    @given(args=st_nested_dict(max_depth=3, max_breadth=4))
    def test_output_is_well_formed(self, args: dict[str, Any]) -> None:
        """Collected values are a list of sanitized strings."""
        result = _collect_string_values(args)
        assert isinstance(result, list)
        for fv in result:
            assert isinstance(fv.value, str)
            assert _sanitize_string(fv.value) == fv.value

    def test_leaf_limit_raises(self) -> None:
        """InputTooLargeError when leaf count exceeds 10,000."""
        huge = {f"k{i}": f"v{i}" for i in range(10_001)}
        with pytest.raises(InputTooLargeError):
            _collect_string_values(huge)


# ── Extract field properties ─────────────────────────────────────────


class TestExtractFieldProperties:
    """Property-based tests for _extract_field()."""

    @given(
        key=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10),
        value=st_leaf_value(),
    )
    def test_single_level_always_found(self, key: str, value: object) -> None:
        """Single-level extraction always finds the value."""
        # Keys with dots are split, so filter them out
        assume("." not in key)
        result = _extract_field({key: value}, key)
        assert result is not _MISSING

    @given(depth=st.integers(min_value=33, max_value=40))
    def test_depth_exceeding_32_returns_missing(self, depth: int) -> None:
        """Paths with >32 segments return _MISSING."""
        path = ".".join(f"k{i}" for i in range(depth))
        assert _extract_field({}, path) is _MISSING

    @given(
        keys=st.lists(
            st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=5),
            min_size=1,
            max_size=32,
            unique=True,
        ),
    )
    def test_constructed_path_found(self, keys: list[str]) -> None:
        """A dict built from a key path can be extracted with that path."""
        # Filter keys containing dots (would be split by _extract_field)
        assume(all("." not in k for k in keys))

        # Build nested dict
        d: dict[str, object] = {}
        current: dict[str, object] = d
        for k in keys[:-1]:
            child: dict[str, object] = {}
            current[k] = child
            current = child
        current[keys[-1]] = "FOUND"

        path = ".".join(keys)
        assert _extract_field(d, path) == "FOUND"


# ── Condition checking properties ────────────────────────────────────


class TestCheckConditionsProperties:
    """Property-based tests for _check_conditions() AND logic."""

    @given(args=st_nested_dict(max_depth=2, max_breadth=3))
    def test_empty_conditions_always_true(self, args: dict[str, object]) -> None:
        """No conditions = always satisfied (vacuous truth)."""
        assert _check_conditions(args, []) is True

    @pytest.mark.parametrize(
        ("condition_attr", "expected"),
        [("equals", True), ("not_equals", False)],
        ids=["equals-passes", "not_equals-fails"],
    )
    @given(
        key=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10),
        value=st.text(min_size=1, max_size=20),
    )
    def test_condition_with_matching_value(
        self, key: str, value: str, condition_attr: str, expected: bool
    ) -> None:
        """equals returns True, not_equals returns False when field matches value."""
        assume("." not in key)
        cond = ConstraintCondition(field=key, **{condition_attr: value})
        assert _check_conditions({key: value}, [cond]) is expected


# ── Strict equality properties ──────────────────────────────────────


class TestStrictEqProperties:
    """Property-based tests for _strict_eq() type-safety."""

    @pytest.mark.parametrize("bool_val", [True, False])
    @given(x=st.integers())
    def test_bool_never_equals_int(self, x: int, bool_val: bool) -> None:
        """bool != any integer (True != 1, False != 0)."""
        assert _strict_eq(bool_val, x) is False

    @given(x=st.one_of(st.integers(), st.floats(allow_nan=False), st.text(), st.booleans()))
    def test_reflexive(self, x: object) -> None:
        """_strict_eq(x, x) is True for all non-NaN values."""
        assert _strict_eq(x, x) is True

    @given(a=st.booleans(), b=st.booleans())
    def test_bool_to_bool_normal(self, a: bool, b: bool) -> None:
        """Bool-to-bool comparison behaves as normal equality."""
        assert _strict_eq(a, b) == (a == b)


# ── Threshold properties ────────────────────────────────────────────


class TestThresholdProperties:
    """Property-based tests for threshold boundary semantics."""

    @pytest.mark.parametrize("side", ["min", "max"], ids=["at-min", "at-max"])
    @given(boundary=st.floats(min_value=-1e9, max_value=1e9, allow_nan=False, allow_infinity=False))
    def test_value_at_boundary_does_not_violate(self, boundary: float, side: str) -> None:
        """value == boundary does NOT violate (boundaries are inclusive)."""
        kwargs = {"min_val": boundary} if side == "min" else {"max_val": boundary}
        constraint = make_threshold_constraint(**kwargs)
        action = make_action(tool="http_request", cost=boundary)
        solver = Tier1Solver()
        violations = solver.check(action, [constraint])
        assert len(violations) == 0

    @given(val=st.sampled_from([float("nan"), float("inf"), float("-inf")]))
    def test_nan_inf_always_violates(self, val: float) -> None:
        """NaN and Inf always produce violations."""
        constraint = make_threshold_constraint(min_val=0, max_val=1000)
        action = make_action(tool="http_request", cost=val)
        solver = Tier1Solver()
        violations = solver.check(action, [constraint])
        assert len(violations) >= 1


# ── Guard integration (never crash) ─────────────────────────────────


class TestGuardCheckNeverCrashes:
    """Integration: Guard.check() with random valid inputs never crashes."""

    @pytest.mark.parametrize(
        "constraint_factory",
        [
            lambda: make_denylist_constraint(["evil.com"]),
            lambda: make_threshold_constraint(min_val=0, max_val=1000),
        ],
        ids=["denylist", "threshold"],
    )
    @given(action=st_action())
    def test_guard_never_crashes(self, action: object, constraint_factory: Any) -> None:
        """Guard.check() with random action and fixed constraint never crashes."""
        constraint = constraint_factory()
        registry = make_registry(constraint)
        guard = Guard(registry=registry, mode=VerificationMode.ENFORCE)
        result = guard.check(action)  # type: ignore[arg-type]
        assert isinstance(result.allowed, bool)

    @given(action=st_action())
    def test_tier1_solver_never_crashes(self, action: object) -> None:
        """Tier1Solver.check() with any action and valid constraints never crashes."""
        constraints = [
            make_denylist_constraint(["evil.com"], name="d1"),
            make_threshold_constraint(min_val=0, max_val=100, name="t1"),
        ]
        solver = Tier1Solver()
        violations = solver.check(action, constraints)  # type: ignore[arg-type]
        assert isinstance(violations, list)


# ── COMPOSITE invariant tests (Phase 6c WS2) ────────────────────────


class TestResolveVariablesAgreement:
    """_VarAccessor produces identical results from CompositeVariable and dict."""

    @given(val=st_numeric_value)
    def test_pydantic_and_dict_agree(self, val: int | float) -> None:
        pydantic_var = CompositeVariable(field="amount", type="int", min=-10000, max=10000)
        dict_var = pydantic_var.model_dump()

        result_pydantic = _resolve_composite_variables({"x": pydantic_var}, {"amount": val})
        result_dict = _resolve_composite_variables({"x": dict_var}, {"amount": val})

        assert result_pydantic.error == result_dict.error
        assert result_pydantic.concrete == result_dict.concrete


class TestCoerceNumericInvariants:
    """Security invariants for _coerce_numeric."""

    @given(val=st_adversarial_numeric)
    def test_nan_inf_never_returned(self, val: Any) -> None:

        result = _coerce_numeric(val, "int")
        if result is not None:
            assert not (isinstance(result, float) and math.isnan(result))
            assert not (isinstance(result, float) and math.isinf(result))

    @given(val=st_adversarial_numeric)
    def test_bool_coerced_to_int_not_bool(self, val: Any) -> None:
        result = _coerce_numeric(val, "int")
        if result is not None:
            assert not isinstance(result, bool), (
                f"_coerce_numeric returned bool {result!r} instead of int"
            )

    @pytest.mark.parametrize(
        ("val", "desc"),
        [
            ([1, 2, 3], "list"),
            ({"a": 1}, "dict"),
        ],
    )
    def test_non_scalar_rejected(self, val: Any, desc: str) -> None:
        assert _coerce_numeric(val, "int") is None

    @pytest.mark.parametrize(
        ("val", "desc"),
        [
            ("nan", "nan-string"),
            ("NaN", "NaN-string"),
            ("inf", "inf-string"),
            ("-inf", "neg-inf-string"),
            ("Infinity", "Infinity-string"),
        ],
    )
    def test_string_nan_inf_rejected(self, val: str, desc: str) -> None:
        assert _coerce_numeric(val, "int") is None


class TestGuardCompositeNeverCrashes:
    """Guard.check() with random COMPOSITE input never raises."""

    @given(data=st_composite_constraint_and_args())
    def test_no_crash(self, data: tuple[dict, str, dict]) -> None:
        variables, expression, args = data
        constraint = Constraint(
            name="fuzz-composite",
            action="*",
            tier=Tier.TIER_1,
            check=ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={k: CompositeVariable(**v) for k, v in variables.items()},
                expression=expression,
            ),
            on_violation=OnViolation.BLOCK,
        )
        guard = Guard(registry=make_registry(constraint))
        action = Action(tool="fuzz_tool", args=args)
        # Must not raise — violations are fine, crashes are not
        guard.check(action)


class TestViolationMessageSafety:
    """Violation messages from COMPOSITE evaluation don't leak raw values."""

    @given(data=st_composite_constraint_and_args())
    def test_no_repr_in_messages(self, data: tuple[dict, str, dict]) -> None:
        variables, expression, args = data
        constraint = Constraint(
            name="fuzz-composite",
            action="*",
            tier=Tier.TIER_1,
            check=ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={k: CompositeVariable(**v) for k, v in variables.items()},
                expression=expression,
            ),
            on_violation=OnViolation.BLOCK,
        )
        guard = Guard(registry=make_registry(constraint))
        action = Action(tool="fuzz_tool", args=args)
        result = guard.check(action)

        for violation in result.violations:
            msg = violation.message.lower()
            assert "repr(" not in msg
