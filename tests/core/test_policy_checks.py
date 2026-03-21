"""Tests for Tier 4 deploy-time Z3 policy checks: NO_NEW_ACCESS, DATA_FLOW, FILTER_COMPLETENESS."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from munio.models import (
    CheckType,
    Constraint,
    ConstraintCheck,
    ConstraintCondition,
    DeployCheck,
    DeployCheckType,
    MatchMode,
    OnViolation,
    PolicyResult,
)
from munio.solver import PolicyVerifier, _regex_to_z3

# ── Helpers ───────────────────────────────────────────────────────────


def _threshold(
    name: str, field: str = "cost", *, min_val: float | None = None, max_val: float | None = None
) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(type=CheckType.THRESHOLD, field=field, min=min_val, max=max_val),
    )


def _denylist(name: str, field: str, values: list[str]) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(
            type=CheckType.DENYLIST, field=field, values=values, match=MatchMode.EXACT
        ),
    )


def _allowlist(name: str, field: str, values: list[str]) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(
            type=CheckType.ALLOWLIST, field=field, values=values, match=MatchMode.EXACT
        ),
    )


def _regex_deny(name: str, field: str, patterns: list[str]) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(type=CheckType.REGEX_DENY, field=field, patterns=patterns),
    )


def _regex_allow(name: str, field: str, patterns: list[str]) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(type=CheckType.REGEX_ALLOW, field=field, patterns=patterns),
    )


def _denylist_mode(
    name: str, field: str, values: list[str], mode: MatchMode = MatchMode.EXACT
) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(type=CheckType.DENYLIST, field=field, values=values, match=mode),
    )


def _composite(name: str, expression: str = "price * qty <= 10000") -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(
            type=CheckType.COMPOSITE,
            field="price * qty",
            expression=expression,
            variables={
                "price": {"field": "price"},
                "qty": {"field": "quantity"},
            },
        ),
    )


def _allowlist_mode(
    name: str, field: str, values: list[str], mode: MatchMode = MatchMode.EXACT
) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(type=CheckType.ALLOWLIST, field=field, values=values, match=mode),
    )


# ── TestNoNewAccess ──────────────────────────────────────────────────


class TestNoNewAccess:
    """Tests for NO_NEW_ACCESS deploy-time check."""

    @pytest.mark.z3
    def test_identical_thresholds_safe(self) -> None:
        """Same min/max in old and new → SAFE."""
        c = _threshold("max-spend", min_val=0, max_val=100)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["max-spend"],
            baseline_constraints_ref=["max-spend"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [c], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    @pytest.mark.z3
    def test_relaxed_max_unsafe(self) -> None:
        """Old max=100, new max=200 → UNSAFE (more permissive)."""
        old = _threshold("old-spend", max_val=100)
        new = _threshold("new-spend", max_val=200)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-spend"],
            baseline_constraints_ref=["old-spend"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "issues" in result.details

    @pytest.mark.z3
    def test_tightened_max_safe(self) -> None:
        """Old max=200, new max=100 → SAFE (more restrictive)."""
        old = _threshold("old-spend", max_val=200)
        new = _threshold("new-spend", max_val=100)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-spend"],
            baseline_constraints_ref=["old-spend"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    def test_removed_denylist_entry_unsafe(self) -> None:
        """Old denylist {evil,bad}, new {evil} → UNSAFE (removed entry)."""
        old = _denylist("old-deny", "url", ["evil.com", "bad.com"])
        new = _denylist("new-deny", "url", ["evil.com"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny"],
            baseline_constraints_ref=["old-deny"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "bad.com" in str(result.details)

    def test_added_denylist_entry_safe(self) -> None:
        """Old denylist {evil}, new {evil,bad} → SAFE (more restrictive)."""
        old = _denylist("old-deny", "url", ["evil.com"])
        new = _denylist("new-deny", "url", ["evil.com", "bad.com"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny"],
            baseline_constraints_ref=["old-deny"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    def test_added_allowlist_entry_unsafe(self) -> None:
        """New allowlist has extra entry → UNSAFE (more permissive)."""
        old = _allowlist("old-allow", "domain", ["safe.com"])
        new = _allowlist("new-allow", "domain", ["safe.com", "risky.com"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-allow"],
            baseline_constraints_ref=["old-allow"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "risky.com" in str(result.details)

    def test_missing_constraint_ref_error(self) -> None:
        """Referenced constraint name not found → ERROR."""
        c = _threshold("existing", max_val=100)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["nonexistent"],
            baseline_constraints_ref=["existing"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [c], deploy_check=dc)
        assert result.result == PolicyResult.ERROR
        assert "nonexistent" in str(result.details)

    def test_z3_not_installed_error(self) -> None:
        """Without Z3 and threshold constraints → ERROR."""
        old = _threshold("old-spend", max_val=100)
        new = _threshold("new-spend", max_val=200)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-spend"],
            baseline_constraints_ref=["old-spend"],
        )
        verifier = PolicyVerifier()
        with patch.dict("sys.modules", {"z3": None}):
            result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.ERROR

    def test_no_thresholds_denylists_only(self) -> None:
        """Only denylist constraints, no thresholds → still runs Python check."""
        old = _denylist("old-deny", "url", ["evil.com", "bad.com"])
        new = _denylist("new-deny", "url", ["evil.com"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny"],
            baseline_constraints_ref=["old-deny"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE

    def test_missing_deploy_check_error(self) -> None:
        """No deploy_check parameter → ERROR."""
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [])
        assert result.result == PolicyResult.ERROR

    # ── C1: Non-EXACT match modes ──────────────────────────────────

    def test_removed_contains_denylist_entry_unsafe(self) -> None:
        """CONTAINS denylist: removed entry detected → UNSAFE."""
        old = _denylist_mode("old-deny", "url", ["evil.com", "bad.com"], MatchMode.CONTAINS)
        new = _denylist_mode("new-deny", "url", ["evil.com"], MatchMode.CONTAINS)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny"],
            baseline_constraints_ref=["old-deny"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "bad.com" in str(result.details)

    def test_match_mode_downgrade_denylist_unsafe(self) -> None:
        """Changing denylist from CONTAINS to EXACT (narrower) → UNSAFE."""
        old = _denylist_mode("old-deny", "url", ["evil.com"], MatchMode.CONTAINS)
        new = _denylist_mode("new-deny", "url", ["evil.com"], MatchMode.EXACT)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny"],
            baseline_constraints_ref=["old-deny"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "narrowed" in str(result.details)

    # ── C2: regex_deny / regex_allow support ───────────────────────

    def test_removed_regex_deny_pattern_unsafe(self) -> None:
        """Removing a regex_deny pattern → UNSAFE."""
        old = _regex_deny("old-re", "query", ["DROP.*TABLE", "INSERT.*INTO"])
        new = _regex_deny("new-re", "query", ["DROP.*TABLE"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-re"],
            baseline_constraints_ref=["old-re"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "INSERT.*INTO" in str(result.details)

    def test_added_regex_allow_pattern_unsafe(self) -> None:
        """Adding a regex_allow pattern → UNSAFE (more permissive)."""
        old = _regex_allow("old-re", "url", [r"^https://safe\.com"])
        new = _regex_allow("new-re", "url", [r"^https://safe\.com", r"^https://risky\.com"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-re"],
            baseline_constraints_ref=["old-re"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "risky" in str(result.details)

    def test_identical_regex_deny_safe(self) -> None:
        """Same regex_deny patterns → SAFE."""
        old = _regex_deny("old-re", "query", ["DROP.*TABLE"])
        new = _regex_deny("new-re", "query", ["DROP.*TABLE"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-re"],
            baseline_constraints_ref=["old-re"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    # ── Allowlist removal / match mode broadening ──────────────────

    def test_allowlist_removed_entirely_unsafe(self) -> None:
        """Old policy has allowlist on 'domain', new has none → UNSAFE."""
        old = _allowlist("old-allow", "domain", ["safe.com"])
        new = _denylist("new-deny", "domain", ["evil.com"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny"],
            baseline_constraints_ref=["old-allow"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "removed" in str(result.details).lower()

    def test_allowlist_exact_to_contains_unsafe(self) -> None:
        """EXACT → CONTAINS allowlist = more permissive → UNSAFE."""
        old = _allowlist_mode("old-allow", "url", ["safe.com"], MatchMode.EXACT)
        new = _allowlist_mode("new-allow", "url", ["safe.com"], MatchMode.CONTAINS)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-allow"],
            baseline_constraints_ref=["old-allow"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "broadened" in str(result.details).lower()

    @pytest.mark.z3
    def test_baseline_denylist_only_new_adds_thresholds_safe(self) -> None:
        """Old policy had only denylists (no thresholds), new adds threshold → SAFE."""
        old = _denylist("old-deny", "url", ["evil.com"])
        new_deny = _denylist("new-deny", "url", ["evil.com"])
        new_threshold = _threshold("new-spend", max_val=100)
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny", "new-spend"],
            baseline_constraints_ref=["old-deny"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(
            DeployCheckType.NO_NEW_ACCESS, [old, new_deny, new_threshold], deploy_check=dc
        )
        assert result.result == PolicyResult.SAFE

    # ── Structural soundness (C1/C2/H1/H2) ────────────────────────

    @pytest.mark.parametrize(
        ("old", "new", "detail_keyword"),
        [
            pytest.param(
                _composite("old-composite"),
                _threshold("new-threshold", field="price * qty", max_val=99999),
                "composite",
                id="composite-removed",
            ),
            pytest.param(
                _composite("old-composite"),
                _denylist("new-deny", "url", ["evil.com"]),
                "lost all checks",
                id="composite-field-dropped",
            ),
            pytest.param(
                Constraint(
                    name="old-deny",
                    action="*",
                    check=ConstraintCheck(
                        type=CheckType.DENYLIST, field="path", values=["/etc/passwd"]
                    ),
                ),
                Constraint(
                    name="new-deny",
                    action="file_read",
                    check=ConstraintCheck(
                        type=CheckType.DENYLIST, field="path", values=["/etc/passwd"]
                    ),
                ),
                "action scope",
                id="action-scope-narrowed",
            ),
            pytest.param(
                Constraint(
                    name="old-deny",
                    check=ConstraintCheck(
                        type=CheckType.DENYLIST, field="url", values=["evil.com"]
                    ),
                ),
                Constraint(
                    name="new-deny",
                    conditions=[ConstraintCondition(field="auth_type", equals="api_key")],
                    check=ConstraintCheck(
                        type=CheckType.DENYLIST, field="url", values=["evil.com"]
                    ),
                ),
                "conditions",
                id="unconditional-to-conditional",
            ),
        ],
    )
    def test_structural_change_unsafe(
        self, old: Constraint, new: Constraint, detail_keyword: str
    ) -> None:
        """Structural relaxation detected → UNSAFE."""
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=[new.name],
            baseline_constraints_ref=[old.name],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert detail_keyword in str(result.details).lower()

    @pytest.mark.parametrize(
        ("old_violation", "new_violation"),
        [
            (OnViolation.BLOCK, OnViolation.WARN),
            (OnViolation.BLOCK, OnViolation.SHADOW),
            (OnViolation.WARN, OnViolation.SHADOW),
        ],
        ids=["block-to-warn", "block-to-shadow", "warn-to-shadow"],
    )
    def test_on_violation_downgrade_unsafe(
        self, old_violation: OnViolation, new_violation: OnViolation
    ) -> None:
        """Weakening on_violation is more permissive → UNSAFE."""
        old = Constraint(
            name="old-deny",
            on_violation=old_violation,
            check=ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["evil.com"]),
        )
        new = Constraint(
            name="new-deny",
            on_violation=new_violation,
            check=ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["evil.com"]),
        )
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny"],
            baseline_constraints_ref=["old-deny"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "on_violation" in str(result.details).lower()

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            pytest.param(
                _composite("old-composite"),
                _composite("new-composite", expression="price * qty <= 5000"),
                id="composite-replaced-same-field",
            ),
            pytest.param(
                _denylist("old-deny", "path", ["/etc/passwd"]),
                _denylist("new-deny", "path", ["/etc/passwd"]),
                id="action-scope-stays-wildcard",
            ),
            pytest.param(
                Constraint(
                    name="old-deny",
                    on_violation=OnViolation.SHADOW,
                    check=ConstraintCheck(
                        type=CheckType.DENYLIST, field="url", values=["evil.com"]
                    ),
                ),
                Constraint(
                    name="new-deny",
                    on_violation=OnViolation.BLOCK,
                    check=ConstraintCheck(
                        type=CheckType.DENYLIST, field="url", values=["evil.com"]
                    ),
                ),
                id="on-violation-tightened",
            ),
            pytest.param(
                Constraint(
                    name="old-deny",
                    conditions=[ConstraintCondition(field="auth_type", equals="api_key")],
                    check=ConstraintCheck(
                        type=CheckType.DENYLIST, field="url", values=["evil.com"]
                    ),
                ),
                Constraint(
                    name="new-deny",
                    check=ConstraintCheck(
                        type=CheckType.DENYLIST, field="url", values=["evil.com"]
                    ),
                ),
                id="conditional-to-unconditional",
            ),
        ],
    )
    def test_structural_change_safe(self, old: Constraint, new: Constraint) -> None:
        """Structural tightening or same → SAFE."""
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=[new.name],
            baseline_constraints_ref=[old.name],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    # ── H2: Temporal check type disappearance detection ──

    @pytest.mark.parametrize(
        ("check_type", "check_kwargs", "keyword"),
        [
            pytest.param(
                CheckType.RATE_LIMIT,
                {"field": "*", "window_seconds": 60, "max_count": 10},
                "rate_limit",
                id="rate-limit-removed",
            ),
            pytest.param(
                CheckType.SEQUENCE_DENY,
                {"field": "*", "steps": ["read_file", "exec"], "window_seconds": 300},
                "sequence_deny",
                id="sequence-deny-removed",
            ),
        ],
    )
    def test_temporal_check_removal_unsafe(
        self, check_type: CheckType, check_kwargs: dict, keyword: str
    ) -> None:
        """Removing RATE_LIMIT/SEQUENCE_DENY check type is detected as UNSAFE (H2 fix)."""
        old = Constraint(
            name="old-temporal",
            check=ConstraintCheck(type=check_type, **check_kwargs),
        )
        new = _denylist("new-deny", "url", ["evil.com"])
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-deny"],
            baseline_constraints_ref=["old-temporal"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        details_str = str(result.details).lower()
        assert keyword in details_str

    def test_temporal_check_kept_safe(self) -> None:
        """Keeping a RATE_LIMIT check type across versions is SAFE."""
        old = Constraint(
            name="old-rate",
            check=ConstraintCheck(
                type=CheckType.RATE_LIMIT, field="*", window_seconds=60, max_count=10
            ),
        )
        new = Constraint(
            name="new-rate",
            check=ConstraintCheck(
                type=CheckType.RATE_LIMIT, field="*", window_seconds=60, max_count=10
            ),
        )
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-rate"],
            baseline_constraints_ref=["old-rate"],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.NO_NEW_ACCESS, [old, new], deploy_check=dc)
        assert result.result == PolicyResult.SAFE


# ── TestDataFlow ─────────────────────────────────────────────────────


class TestDataFlow:
    """Tests for DATA_FLOW deploy-time check."""

    @pytest.mark.z3
    def test_direct_path_unsafe(self) -> None:
        """Direct edge source→sink → UNSAFE."""
        dc = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source="db_query",
            forbidden_sink="http_request",
            flow_edges=[["db_query", "http_request"]],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.DATA_FLOW, [], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "path" in result.details

    @pytest.mark.z3
    def test_no_path_safe(self) -> None:
        """No edges reaching sink → SAFE."""
        dc = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source="db_query",
            forbidden_sink="http_request",
            flow_edges=[
                ["db_query", "transform"],
                ["transform", "file_write"],
                ["other", "http_request"],  # sink exists but not reachable from source
            ],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.DATA_FLOW, [], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    @pytest.mark.z3
    def test_transitive_path_unsafe(self) -> None:
        """source→A→sink → UNSAFE."""
        dc = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source="db_query",
            forbidden_sink="http_request",
            flow_edges=[
                ["db_query", "transform"],
                ["transform", "http_request"],
            ],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.DATA_FLOW, [], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        path = result.details.get("path", [])
        assert "db_query" in path
        assert "http_request" in path

    @pytest.mark.z3
    def test_filter_on_all_paths_safe(self) -> None:
        """All paths go through filter → SAFE."""
        dc = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source="user_input",
            forbidden_sink="db_query",
            through="sanitizer",
            flow_edges=[
                ["user_input", "sanitizer"],
                ["sanitizer", "db_query"],
            ],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.DATA_FLOW, [], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    @pytest.mark.z3
    def test_filter_bypass_unsafe(self) -> None:
        """Extra edge bypasses filter → UNSAFE."""
        dc = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source="user_input",
            forbidden_sink="db_query",
            through="sanitizer",
            flow_edges=[
                ["user_input", "sanitizer"],
                ["sanitizer", "db_query"],
                ["user_input", "db_query"],  # bypass!
            ],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.DATA_FLOW, [], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE

    def test_z3_not_installed_error(self) -> None:
        """Without Z3 → ERROR."""
        dc = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source="a",
            forbidden_sink="b",
            flow_edges=[["a", "b"]],
        )
        verifier = PolicyVerifier()
        with patch.dict("sys.modules", {"z3": None}):
            result = verifier.verify(DeployCheckType.DATA_FLOW, [], deploy_check=dc)
        assert result.result == PolicyResult.ERROR

    def test_missing_deploy_check_error(self) -> None:
        """No deploy_check parameter → ERROR."""
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.DATA_FLOW, [])
        assert result.result == PolicyResult.ERROR

    # ── Input validation (merged from TestDataFlowValidation) ──────

    @pytest.mark.z3
    @pytest.mark.parametrize(
        ("source", "forbidden_sink", "through"),
        [
            pytest.param("nonexistent", "b", None, id="invalid-source"),
            pytest.param("a", "b", "nonexistent", id="invalid-through"),
        ],
    )
    def test_invalid_node_reference_error(
        self, source: str, forbidden_sink: str, through: str | None
    ) -> None:
        """Node reference not in flow_edges → ERROR."""
        dc = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source=source,
            forbidden_sink=forbidden_sink,
            through=through,
            flow_edges=[["a", "b"]],
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.DATA_FLOW, [], deploy_check=dc)
        assert result.result == PolicyResult.ERROR
        assert "nonexistent" in str(result.details)


# ── TestFilterCompleteness ───────────────────────────────────────────


class TestFilterCompleteness:
    """Tests for FILTER_COMPLETENESS deploy-time check."""

    @pytest.mark.z3
    def test_complete_filter_safe(self) -> None:
        """Deny pattern covers the dangerous concept → SAFE."""
        deny = _regex_deny("sqli-deny", "query", [".*DROP.*"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    @pytest.mark.z3
    def test_incomplete_filter_unsafe(self) -> None:
        """Deny pattern misses some variant → UNSAFE + counterexample."""
        deny = _regex_deny("sqli-deny", "query", ["DROP TABLE"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE
        assert "counterexample" in result.details

    @pytest.mark.z3
    def test_no_deny_patterns_catch_concept(self) -> None:
        """Deny pattern doesn't match concept → UNSAFE."""
        deny = _regex_deny("sqli-deny", "query", ["harmless"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.UNSAFE

    def test_too_many_patterns_error(self) -> None:
        """More than 8 deny patterns → ERROR."""
        patterns = [f"pattern{i}" for i in range(9)]
        deny = _regex_deny("sqli-deny", "query", patterns)
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP;TABLE",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.ERROR
        assert "Too many" in str(result.details)

    def test_non_regex_constraint_error(self) -> None:
        """Referenced constraint is denylist, not regex_deny → ERROR."""
        deny = _denylist("not-regex", "query", ["DROP TABLE"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["not-regex"],
            dangerous_pattern="DROP;TABLE",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.ERROR
        assert "regex_deny" in str(result.details)

    def test_z3_not_installed_error(self) -> None:
        """Without Z3 → ERROR."""
        deny = _regex_deny("sqli-deny", "query", ["DROP"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP;TABLE",
        )
        verifier = PolicyVerifier()
        with patch.dict("sys.modules", {"z3": None}):
            result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.ERROR

    def test_unsupported_regex_feature_error(self) -> None:
        """Pattern with backreference → ERROR."""
        deny = _regex_deny("sqli-deny", "query", [r"(foo)\1"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP;TABLE",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.ERROR
        assert "Backreference" in str(result.details) or "not supported" in str(result.details)

    def test_missing_deploy_check_error(self) -> None:
        """No deploy_check parameter → ERROR."""
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [])
        assert result.result == PolicyResult.ERROR

    def test_missing_constraint_ref_error(self) -> None:
        """Referenced constraint not found → ERROR."""
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["nonexistent"],
            dangerous_pattern="DROP;TABLE",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [], deploy_check=dc)
        assert result.result == PolicyResult.ERROR
        assert "nonexistent" in str(result.details)

    def test_word_boundary_rejected(self) -> None:
        r"""Pattern with \b word boundary → ERROR (not silently dropped)."""
        deny = _regex_deny("sqli-deny", "query", [r"\bDROP\b"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.ERROR
        assert "boundary" in str(result.details).lower() or "not supported" in str(result.details)

    @pytest.mark.z3
    def test_custom_max_string_length(self) -> None:
        """Custom max_string_length is used in Z3 query."""
        deny = _regex_deny("sqli-deny", "query", [".*DROP.*"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP",
            max_string_length=50,
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.SAFE

    # ── Disabled constraint / empty pattern edge cases ─────────────

    @pytest.mark.z3
    def test_disabled_constraint_not_collected(self) -> None:
        """Disabled constraint → no deny patterns → ERROR (not found)."""
        deny = Constraint(
            name="sqli-deny",
            enabled=False,
            check=ConstraintCheck(type=CheckType.REGEX_DENY, field="query", patterns=["DROP"]),
        )
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["sqli-deny"],
            dangerous_pattern="DROP",
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        assert result.result == PolicyResult.ERROR

    def test_empty_dangerous_pattern_rejected_by_model(self) -> None:
        """Empty dangerous_pattern is rejected at model construction time."""
        with pytest.raises(Exception):  # noqa: B017, PT011
            DeployCheck(
                type=DeployCheckType.FILTER_COMPLETENESS,
                constraints_ref=["sqli-deny"],
                dangerous_pattern="",
            )


# ── TestRegexToZ3 ──────────────────────────────────────────────────────


class TestRegexToZ3:
    """Tests for _regex_to_z3() translator (sre_parse → Z3 regex).

    Each test verifies that the translated Z3 regex matches/rejects
    the same strings as Python's re module.
    """

    @pytest.mark.z3
    @pytest.mark.parametrize(
        ("pattern", "should_match", "should_reject"),
        [
            # Literal string
            ("hello", ["hello"], ["world", "hell", "helloo"]),
            # Dot (any char)
            ("a.c", ["abc", "axc", "a1c"], ["ac", "abbc"]),
            # Star (zero or more)
            ("ab*c", ["ac", "abc", "abbc"], ["abx"]),
            # Plus (one or more)
            ("ab+c", ["abc", "abbc"], ["ac"]),
            # Option (zero or one)
            ("ab?c", ["ac", "abc"], ["abbc"]),
            # Alternation (branch)
            ("cat|dog", ["cat", "dog"], ["car", "cats"]),
            # Character class [a-z]
            ("[abc]", ["a", "b", "c"], ["d", "ab"]),
            # Character range
            ("[a-f]", ["a", "c", "f"], ["g", "z"]),
            # Negated character class
            ("[^abc]", ["d", "x", "1"], ["a", "b"]),
            # \\d digit shorthand
            (r"\d", ["0", "5", "9"], ["a", "z"]),
            # \\w word char shorthand
            (r"\w", ["a", "Z", "0", "_"], [" ", "!"]),
            # \\s whitespace shorthand
            (r"\s", [" ", "\t", "\n"], ["a", "0"]),
            # Quantifier {n,m}
            ("a{2,4}", ["aa", "aaa", "aaaa"], ["a", "aaaaa"]),
            # Group (subpattern)
            ("(ab)+", ["ab", "abab"], ["a", "b"]),
            # .* (Full optimization)
            (".*", ["", "anything", "hello world"], []),
            # .+ (Plus of any)
            (".+", ["a", "hello"], [""]),
            # Anchors ^ and $ (safe to skip for Z3 fullmatch)
            ("^abc$", ["abc"], ["xabc", "abcx"]),
        ],
    )
    def test_pattern_match_semantics(
        self, pattern: str, should_match: list[str], should_reject: list[str]
    ) -> None:
        """Verify Z3 regex matches the same strings as Python re.fullmatch."""
        import z3

        z3_re = _regex_to_z3(pattern)

        for s in should_match:
            solver = z3.Solver()
            string_var = z3.String("s")
            solver.add(string_var == z3.StringVal(s))
            solver.add(z3.InRe(string_var, z3_re))
            assert solver.check() == z3.sat, f"Pattern {pattern!r} should match {s!r}"

        for s in should_reject:
            solver = z3.Solver()
            string_var = z3.String("s")
            solver.add(string_var == z3.StringVal(s))
            solver.add(z3.InRe(string_var, z3_re))
            assert solver.check() == z3.unsat, f"Pattern {pattern!r} should reject {s!r}"

    @pytest.mark.z3
    def test_not_literal(self) -> None:
        """NOT_LITERAL: [^x] matches any single char except x."""
        import z3

        z3_re = _regex_to_z3("[^x]")
        solver = z3.Solver()
        s = z3.String("s")
        solver.add(s == z3.StringVal("a"))
        solver.add(z3.InRe(s, z3_re))
        assert solver.check() == z3.sat

        solver2 = z3.Solver()
        solver2.add(s == z3.StringVal("x"))
        solver2.add(z3.InRe(s, z3_re))
        assert solver2.check() == z3.unsat

    @pytest.mark.z3
    def test_consecutive_literals_merged(self) -> None:
        """Multiple consecutive literals are merged into one Re(StringVal)."""
        import z3

        z3_re = _regex_to_z3("abcdef")
        solver = z3.Solver()
        s = z3.String("s")
        solver.add(s == z3.StringVal("abcdef"))
        solver.add(z3.InRe(s, z3_re))
        assert solver.check() == z3.sat

    @pytest.mark.z3
    def test_loop_bounded_repeat(self) -> None:
        """Loop {2,3}: matches exactly 2 or 3 repetitions."""
        import z3

        z3_re = _regex_to_z3("x{2,3}")
        for s_val, expected in [
            ("x", z3.unsat),
            ("xx", z3.sat),
            ("xxx", z3.sat),
            ("xxxx", z3.unsat),
        ]:
            solver = z3.Solver()
            s = z3.String("s")
            solver.add(s == z3.StringVal(s_val))
            solver.add(z3.InRe(s, z3_re))
            assert solver.check() == expected, f"x{{2,3}} vs {s_val!r}"

    @pytest.mark.z3
    def test_unbounded_repeat_not_truncated(self) -> None:
        """H2: {n,} must not truncate to {n,n+50} — strings > n+50 must still match.

        Before fix, `a{3,}` was encoded as `Loop(a, 3, 53)`, rejecting
        strings longer than 53 'a's. Now encoded as `Loop(a,3,3) + Star(a)`.
        """
        import z3

        z3_re = _regex_to_z3("a{3,}")
        # 100 a's should match (previously truncated at 53)
        solver = z3.Solver()
        s = z3.String("s")
        solver.add(s == z3.StringVal("a" * 100))
        solver.add(z3.InRe(s, z3_re))
        assert solver.check() == z3.sat, "a{3,} should match 100 a's"

        # 2 a's should NOT match (minimum is 3)
        solver2 = z3.Solver()
        solver2.add(s == z3.StringVal("aa"))
        solver2.add(z3.InRe(s, z3_re))
        assert solver2.check() == z3.unsat, "a{3,} should reject 2 a's"

    @pytest.mark.z3
    def test_empty_pattern(self) -> None:
        """Empty regex matches only empty string."""
        import z3

        z3_re = _regex_to_z3("")
        solver = z3.Solver()
        s = z3.String("s")
        solver.add(s == z3.StringVal(""))
        solver.add(z3.InRe(s, z3_re))
        assert solver.check() == z3.sat

    @pytest.mark.z3
    def test_complex_combined_pattern(self) -> None:
        """Combined pattern: literal + class + quantifier + alternation."""
        import z3

        z3_re = _regex_to_z3(r"DROP\s+(TABLE|DATABASE)")
        solver = z3.Solver()
        s = z3.String("s")
        solver.add(s == z3.StringVal("DROP TABLE"))
        solver.add(z3.InRe(s, z3_re))
        assert solver.check() == z3.sat

        solver2 = z3.Solver()
        solver2.add(s == z3.StringVal("DROP DATABASE"))
        solver2.add(z3.InRe(s, z3_re))
        assert solver2.check() == z3.sat

        solver3 = z3.Solver()
        solver3.add(s == z3.StringVal("DROP INDEX"))
        solver3.add(z3.InRe(s, z3_re))
        assert solver3.check() == z3.unsat

    # ── Error cases (unsupported regex features) ──

    @pytest.mark.parametrize(
        ("pattern", "match_re"),
        [
            pytest.param(r"(foo)\1", r"[Bb]ackreference", id="backreference"),
            pytest.param(r"foo(?=bar)", r"[Ll]ookahead|not supported", id="lookahead"),
            pytest.param(r"(?<=foo)bar", r"[Ll]ook|not supported", id="lookbehind"),
            pytest.param(r"\bword\b", r"[Bb]oundary|not supported", id="word-boundary"),
            pytest.param(r"\Bword\B", r"[Bb]oundary|not supported", id="non-boundary"),
            pytest.param(r"\D", r"\\D|not supported", id="negated-digit"),
            pytest.param(r"\W", r"\\W|not supported", id="negated-word"),
            pytest.param(r"\S", r"\\S|not supported", id="negated-space"),
        ],
    )
    def test_unsupported_feature_rejected(self, pattern: str, match_re: str) -> None:
        """Unsupported regex features → ValueError."""
        with pytest.raises(ValueError, match=match_re):
            _regex_to_z3(pattern)

    def test_unsupported_category_rejected(self) -> None:
        """Unknown regex category → ValueError."""
        from munio.solver import _sre_category_to_z3

        with pytest.raises(ValueError, match=r"[Uu]nsupported"):
            _sre_category_to_z3(999)

    @pytest.mark.z3
    def test_single_branch_alternation(self) -> None:
        """Single-branch alternation (degenerate case) works."""
        import z3

        z3_re = _regex_to_z3("(?:abc)")
        solver = z3.Solver()
        s = z3.String("s")
        solver.add(s == z3.StringVal("abc"))
        solver.add(z3.InRe(s, z3_re))
        assert solver.check() == z3.sat

    @pytest.mark.z3
    def test_charset_with_category_and_range(self) -> None:
        r"""Character class with mixed elements: range + category [a-z\d]."""
        import z3

        z3_re = _regex_to_z3(r"[a-z\d]")
        for s_val in ["a", "m", "z", "0", "5", "9"]:
            solver = z3.Solver()
            s = z3.String("s")
            solver.add(s == z3.StringVal(s_val))
            solver.add(z3.InRe(s, z3_re))
            assert solver.check() == z3.sat, f"[a-z\\d] should match {s_val!r}"

    @pytest.mark.z3
    def test_filter_completeness_unknown_result(self) -> None:
        """Trigger Z3 unknown result via complex string theory query."""
        deny = _regex_deny("complex-deny", "query", [r".*(?:a|b).*(?:c|d).*"])
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["complex-deny"],
            dangerous_pattern="DROP;TABLE;SELECT",
            max_string_length=10,
        )
        verifier = PolicyVerifier()
        result = verifier.verify(DeployCheckType.FILTER_COMPLETENESS, [deny], deploy_check=dc)
        # May be SAFE, UNSAFE, or UNKNOWN depending on Z3 solver — all are valid
        assert result.result in (PolicyResult.SAFE, PolicyResult.UNSAFE, PolicyResult.UNKNOWN)


# ── TestRejectInlineRegexFlags ─────────────────────────────────────


class TestRejectInlineRegexFlags:
    """Tests for S4: _sre_to_z3 rejects inline regex flags in SUBPATTERN nodes."""

    @pytest.mark.parametrize(
        ("pattern", "flag_desc"),
        [
            ("(?i:abc)", "scoped-case-insensitive"),
            ("(?s:a.b)", "scoped-dotall"),
            ("(?m:^abc$)", "scoped-multiline"),
            ("(?im:abc)", "scoped-combined"),
        ],
        ids=["ignorecase", "dotall", "multiline", "combined"],
    )
    def test_scoped_inline_flags_rejected(self, pattern: str, flag_desc: str) -> None:
        """_regex_to_z3 raises ValueError for scoped inline flags (?X:...)."""
        with pytest.raises(ValueError, match=r"[Ff]lag|not supported"):
            _regex_to_z3(pattern)

    def test_no_flags_accepted(self) -> None:
        """Pattern without inline flags is accepted."""
        result = _regex_to_z3("abc")
        assert result is not None

    def test_non_capturing_group_without_flags_accepted(self) -> None:
        """Non-capturing group (?:...) without flags is accepted."""
        result = _regex_to_z3("(?:abc)")
        assert result is not None

    def test_subpattern_with_del_flags_rejected(self) -> None:
        """SUBPATTERN with del_flags (e.g. (?-i:abc)) is also rejected."""
        with pytest.raises(ValueError, match=r"[Ff]lag|not supported"):
            _regex_to_z3("(?-i:abc)")
