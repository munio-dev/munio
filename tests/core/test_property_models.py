"""Property-based tests for munio.models — Hypothesis fuzzing.

Tests Pydantic validators: ConstraintCheck field consistency, constraint
name validation, ReDoS pattern detection, SolverConfig timeout invariant.
"""

from __future__ import annotations

import re
import string

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st
from pydantic import ValidationError

from munio.models import (
    _NESTED_QUANTIFIER_RE,
    CheckType,
    Constraint,
    ConstraintCheck,
    MatchMode,
    SolverConfig,
)
from tests.core.strategies import st_constraint_name, st_non_regex_match_mode

pytestmark = pytest.mark.hypothesis

# Reusable check object for Constraint tests (frozen, safe to share)
_STUB_CHECK = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"])


# ── ConstraintCheck validator properties ─────────────────────────────


class TestConstraintCheckValidatorProperties:
    """Property-based tests for ConstraintCheck validators."""

    def test_denylist_rejects_empty_values(self) -> None:
        """Denylist with empty values list is rejected."""
        with pytest.raises(ValidationError, match="non-empty"):
            ConstraintCheck(type=CheckType.DENYLIST, field="url", values=[])

    @given(
        before=st.lists(st.text(min_size=1, max_size=10), min_size=0, max_size=3),
        after=st.lists(st.text(min_size=1, max_size=10), min_size=0, max_size=3),
    )
    def test_denylist_rejects_empty_string_in_values(
        self, before: list[str], after: list[str]
    ) -> None:
        """Any empty string in values list is rejected."""
        values = [*before, "", *after]
        with pytest.raises(ValidationError, match="empty strings"):
            ConstraintCheck(type=CheckType.DENYLIST, field="url", values=values)

    @given(
        values=st.lists(
            st.text(
                min_size=1,
                max_size=20,
                alphabet=st.characters(
                    categories=("L", "N", "P", "S", "Z"),
                    exclude_characters="\x00",
                ),
            ),
            min_size=1,
            max_size=5,
        ),
        match=st_non_regex_match_mode,
    )
    def test_denylist_accepts_valid_values(self, values: list[str], match: MatchMode) -> None:
        """Denylist with non-empty values and valid mode always succeeds.

        Values are pre-sanitized at load time (stripping invisible/control chars),
        so we restrict generation to printable chars that survive sanitization.
        """
        from hypothesis import assume

        from munio._matching import _sanitize_string

        # Skip if sanitization would produce empty strings (rejected by validator)
        assume(all(_sanitize_string(v) for v in values))
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=values, match=match)
        # Values may be sanitized (NFKC, control char stripping) but must be non-empty
        assert len(check.values) == len(values)
        assert all(v for v in check.values)

    @pytest.mark.parametrize("attr", ["min", "max"])
    @given(val=st.sampled_from([float("nan"), float("inf"), float("-inf")]))
    def test_threshold_rejects_nan_inf(self, val: float, attr: str) -> None:
        """NaN/Inf in threshold min or max is rejected at validation time."""
        with pytest.raises(ValidationError, match="finite number"):
            ConstraintCheck(type=CheckType.THRESHOLD, field="cost", **{attr: val})

    @given(
        min_val=st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False),
        max_val=st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False),
    )
    def test_threshold_accepts_finite_values(self, min_val: float, max_val: float) -> None:
        """Finite min/max values are always accepted."""
        check = ConstraintCheck(type=CheckType.THRESHOLD, field="cost", min=min_val, max=max_val)
        assert check.min == min_val
        assert check.max == max_val


# ── Constraint name properties ──────────────────────────────────────


class TestConstraintNameProperties:
    """Property-based tests for constraint name validation."""

    @given(name=st_constraint_name)
    def test_generated_names_accepted(self, name: str) -> None:
        """All names matching ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ are accepted."""
        c = Constraint(name=name, check=_STUB_CHECK)
        assert c.name == name

    @given(
        name=st.text(min_size=1, max_size=100).filter(
            lambda n: not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", n)
        ),
    )
    def test_invalid_names_rejected(self, name: str) -> None:
        """Names not matching the pattern are rejected."""
        with pytest.raises(ValidationError):
            Constraint(name=name, check=_STUB_CHECK)

    @given(length=st.integers(min_value=101, max_value=200))
    def test_names_too_long_rejected(self, length: int) -> None:
        """Names longer than 100 chars are rejected."""
        name = "a" * length
        with pytest.raises(ValidationError, match="too long"):
            Constraint(name=name, check=_STUB_CHECK)


# ── ReDoS prevention properties ─────────────────────────────────────


class TestReDoSPreventionProperties:
    """Property-based tests for nested quantifier (ReDoS) detection."""

    @given(
        inner=st.text(alphabet=string.ascii_lowercase + ".", min_size=1, max_size=5),
        inner_quant=st.sampled_from(["+", "*"]),
        outer_quant=st.sampled_from(["+", "*", "{2}", "{1,3}"]),
    )
    def test_nested_quantifiers_always_rejected(
        self, inner: str, inner_quant: str, outer_quant: str
    ) -> None:
        """Patterns like (x+)+, (x*)+, (x+)*, (x+){n} are always rejected."""
        pattern = f"({inner}{inner_quant}){outer_quant}"
        # Only test if the pattern is valid regex
        try:
            re.compile(pattern)
        except re.error:
            assume(False)
        with pytest.raises(ValidationError, match="nested quantifiers"):
            ConstraintCheck(type=CheckType.REGEX_DENY, field="cmd", patterns=[pattern])

    @given(
        base=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10),
    )
    def test_simple_patterns_accepted(self, base: str) -> None:
        """Simple regex patterns without nesting are accepted."""
        pattern = re.escape(base)
        check = ConstraintCheck(type=CheckType.REGEX_DENY, field="cmd", patterns=[pattern])
        assert check.patterns == [pattern]

    @given(pattern=st.text(min_size=1, max_size=30))
    def test_regex_validation_oracle(self, pattern: str) -> None:
        """Arbitrary strings are correctly classified as invalid/nested/valid regex."""
        try:
            re.compile(pattern)
            valid = True
        except re.error:
            valid = False

        has_nesting = bool(_NESTED_QUANTIFIER_RE.search(pattern))

        if not valid:
            with pytest.raises(ValidationError, match="Invalid regex"):
                ConstraintCheck(type=CheckType.REGEX_DENY, field="cmd", patterns=[pattern])
        elif has_nesting:
            with pytest.raises(ValidationError, match="nested quantifiers"):
                ConstraintCheck(type=CheckType.REGEX_DENY, field="cmd", patterns=[pattern])
        else:
            check = ConstraintCheck(type=CheckType.REGEX_DENY, field="cmd", patterns=[pattern])
            assert check.patterns == [pattern]


# ── SolverConfig properties ─────────────────────────────────────────


class TestSolverConfigProperties:
    """Property-based tests for SolverConfig timeout invariant."""

    @given(
        timeout_ms=st.integers(min_value=100, max_value=60_000),
        process_s=st.integers(min_value=1, max_value=120),
    )
    def test_process_timeout_must_exceed_solver_timeout(
        self, timeout_ms: int, process_s: int
    ) -> None:
        """process_timeout_s * 1000 must be > timeout_ms."""
        if process_s * 1000 <= timeout_ms:
            with pytest.raises(ValidationError, match="process_timeout_s"):
                SolverConfig(timeout_ms=timeout_ms, process_timeout_s=process_s)
        else:
            config = SolverConfig(timeout_ms=timeout_ms, process_timeout_s=process_s)
            assert config.process_timeout_s * 1000 > config.timeout_ms

    @given(timeout_ms=st.integers(min_value=100, max_value=9_999))
    def test_default_process_timeout_always_valid(self, timeout_ms: int) -> None:
        """Default process_timeout_s=10 is valid for any timeout_ms < 10000."""
        config = SolverConfig(timeout_ms=timeout_ms)
        assert config.process_timeout_s * 1000 > config.timeout_ms
