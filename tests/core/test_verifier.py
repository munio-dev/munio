"""Tests for munio.verifier — verification pipeline."""

from __future__ import annotations

import threading

import pytest

from munio.constraints import load_constraints_dir
from munio.models import (
    Action,
    CheckType,
    Constraint,
    ConstraintCheck,
    ConstraintConfig,
    MatchMode,
    OnViolation,
    ProofAgentError,
    Tier,
    VerificationMode,
    VerificationResult,
    Violation,
    ViolationSeverity,
)
from munio.verifier import Verifier, averify_action, verify_action
from tests.core.conftest import (
    CONSTRAINTS_DIR,
)
from tests.core.conftest import (
    make_action as _make_action,
)
from tests.core.conftest import (
    make_denylist_constraint as _make_denylist_constraint,
)
from tests.core.conftest import (
    make_registry as _make_registry,
)
from tests.core.conftest import (
    make_threshold_constraint as _make_threshold_constraint,
)

# ── TestVerifier ──


class TestVerifier:
    """Tests for Verifier.verify() core pipeline."""

    # ── Mode handling ──

    def test_disabled_mode_returns_allowed(self) -> None:
        config = ConstraintConfig(mode=VerificationMode.DISABLED)
        registry = _make_registry(_make_denylist_constraint(["evil.com"]))
        verifier = Verifier(registry, config)
        result = verifier.verify(_make_action(url="evil.com"))
        assert result.allowed is True
        assert result.mode == VerificationMode.DISABLED

    def test_disabled_mode_zero_checked(self) -> None:
        config = ConstraintConfig(mode=VerificationMode.DISABLED)
        registry = _make_registry(_make_denylist_constraint(["evil.com"]))
        verifier = Verifier(registry, config)
        result = verifier.verify(_make_action(url="evil.com"))
        assert result.checked_constraints == 0
        assert result.violations == []

    def test_shadow_mode_always_allowed(self) -> None:
        config = ConstraintConfig(mode=VerificationMode.SHADOW)
        registry = _make_registry(_make_denylist_constraint(["evil.com"]))
        verifier = Verifier(registry, config)
        result = verifier.verify(_make_action(url="evil.com"))
        assert result.allowed is True

    def test_shadow_mode_populates_violations(self) -> None:
        config = ConstraintConfig(mode=VerificationMode.SHADOW)
        registry = _make_registry(_make_denylist_constraint(["evil.com"]))
        verifier = Verifier(registry, config)
        result = verifier.verify(_make_action(url="evil.com"))
        assert len(result.violations) > 0
        assert result.has_violations is True

    @pytest.mark.parametrize(
        ("on_violation", "expected_allowed"),
        [
            (OnViolation.BLOCK, False),
            (OnViolation.WARN, True),
            (OnViolation.SHADOW, True),
        ],
        ids=["block", "warn", "shadow"],
    )
    def test_enforce_on_violation_behavior(
        self, on_violation: OnViolation, expected_allowed: bool
    ) -> None:
        config = ConstraintConfig(mode=VerificationMode.ENFORCE)
        c = _make_denylist_constraint(["evil.com"], on_violation=on_violation)
        verifier = Verifier(_make_registry(c), config)
        result = verifier.verify(_make_action(url="evil.com"))
        assert result.allowed is expected_allowed
        assert len(result.violations) > 0

    def test_mixed_block_and_warn_blocks(self) -> None:
        config = ConstraintConfig(mode=VerificationMode.ENFORCE)
        c_block = _make_denylist_constraint(
            ["evil.com"], name="deny-block", on_violation=OnViolation.BLOCK
        )
        c_warn = _make_denylist_constraint(
            ["evil.com"], name="deny-warn", on_violation=OnViolation.WARN
        )
        verifier = Verifier(_make_registry(c_block, c_warn), config)
        result = verifier.verify(_make_action(url="evil.com"))
        assert result.allowed is False

    # ── Unmatched action handling ──

    @pytest.mark.parametrize(
        ("on_unmatched", "expected_allowed", "expected_severity", "expect_violation"),
        [
            (OnViolation.WARN, True, ViolationSeverity.INFO, True),
            (OnViolation.BLOCK, False, ViolationSeverity.HIGH, True),
            (OnViolation.SHADOW, True, None, False),
        ],
        ids=["warn", "block", "shadow"],
    )
    def test_no_match_on_unmatched(
        self,
        on_unmatched: OnViolation,
        expected_allowed: bool,
        expected_severity: ViolationSeverity | None,
        expect_violation: bool,
    ) -> None:
        config = ConstraintConfig(
            mode=VerificationMode.ENFORCE,
            default_on_unmatched=on_unmatched,
        )
        verifier = Verifier(_make_registry(), config)
        result = verifier.verify(_make_action(url="anything"))
        assert result.allowed is expected_allowed
        assert result.checked_constraints == 0
        if expect_violation:
            assert len(result.violations) == 1
            assert result.violations[0].constraint_name == "__unmatched__"
            assert result.violations[0].severity == expected_severity
            assert "No constraints matched" in result.violations[0].message
        else:
            assert result.violations == []

    def test_no_match_global_shadow_mode(self) -> None:
        """Global SHADOW mode overrides default_on_unmatched=BLOCK."""
        config = ConstraintConfig(
            mode=VerificationMode.SHADOW,
            default_on_unmatched=OnViolation.BLOCK,
        )
        verifier = Verifier(_make_registry(), config)
        result = verifier.verify(_make_action(url="anything"))
        assert result.allowed is True
        assert result.violations == []

    # ── System violations ──

    def test_system_violation_always_blocks(self) -> None:
        """__system__ violations block regardless of on_violation settings."""
        config = ConstraintConfig(mode=VerificationMode.ENFORCE)
        # Create a constraint with field="*" and an action with >10000 leaves
        # to trigger InputTooLargeError → __system__ violation.
        c = _make_denylist_constraint(
            ["bad"],
            field="*",
            on_violation=OnViolation.WARN,
        )
        # Create args with >10000 leaves
        big_args = {f"k{i}": f"v{i}" for i in range(10_001)}
        action = Action(tool="http_request", args=big_args)
        verifier = Verifier(_make_registry(c), config)
        result = verifier.verify(action)
        assert result.allowed is False

    # ── Result shape ──

    def test_tier_breakdown_populated(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c))
        result = verifier.verify(_make_action(url="safe.com"))
        assert result.tier_breakdown == {"tier_1": 1}
        assert sum(result.tier_breakdown.values()) == result.checked_constraints

    def test_tier_breakdown_separates_tier2_tier3(self) -> None:
        c2 = Constraint(
            name="tier2-constraint",
            tier=Tier.TIER_2,
            check=ConstraintCheck(type=CheckType.THRESHOLD, field="cost", min=0.0, max=100.0),
        )
        c3 = Constraint(
            name="tier3-constraint",
            tier=Tier.TIER_3,
            check=ConstraintCheck(type=CheckType.THRESHOLD, field="cost", min=0.0, max=100.0),
        )
        c1 = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c1, c2, c3))
        result = verifier.verify(_make_action(url="safe.com", cost=50))
        assert result.tier_breakdown == {"tier_1": 1, "tier_2": 1, "tier_3": 1}
        assert sum(result.tier_breakdown.values()) == result.checked_constraints

    def test_elapsed_ms_positive(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c))
        result = verifier.verify(_make_action(url="safe.com"))
        assert result.elapsed_ms >= 0

    def test_checked_constraints_count(self) -> None:
        c1 = _make_denylist_constraint(["a"], name="c1")
        c2 = _make_denylist_constraint(["b"], name="c2")
        verifier = Verifier(_make_registry(c1, c2))
        result = verifier.verify(_make_action(url="safe.com"))
        assert result.checked_constraints == 2

    def test_timestamp_is_recent(self) -> None:
        from datetime import datetime, timedelta, timezone

        before = datetime.now(timezone.utc)
        verifier = Verifier(_make_registry(_make_denylist_constraint(["x"])))
        result = verifier.verify(_make_action(url="y"))
        after = datetime.now(timezone.utc)
        assert before - timedelta(seconds=1) <= result.timestamp <= after + timedelta(seconds=1)

    # ── Post-processing ──

    def test_include_violation_values_false_strips_actual(self) -> None:
        config = ConstraintConfig(include_violation_values=False)
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), config)
        result = verifier.verify(_make_action(url="evil.com"))
        assert len(result.violations) > 0
        for v in result.violations:
            assert v.actual_value == ""

    def test_include_violation_values_true_preserves(self) -> None:
        config = ConstraintConfig(include_violation_values=True)
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), config)
        result = verifier.verify(_make_action(url="evil.com"))
        assert len(result.violations) > 0
        assert any(v.actual_value != "" for v in result.violations)

    def test_postprocess_empty_violations_no_crash(self) -> None:
        config = ConstraintConfig(include_violation_values=False)
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), config)
        result = verifier.verify(_make_action(url="safe.com"))
        assert result.violations == []

    def test_max_violation_value_length_truncates(self) -> None:
        config = ConstraintConfig(max_violation_value_length=10)
        c = _make_denylist_constraint(["evil"], match=MatchMode.CONTAINS)
        verifier = Verifier(_make_registry(c), config)
        long_url = "https://evil.com/" + "x" * 200
        result = verifier.verify(_make_action(url=long_url))
        assert len(result.violations) > 0
        for v in result.violations:
            # Truncated to max_len total (including "..." suffix)
            assert len(v.actual_value) <= 10

    # ── Tier routing ──

    def test_tier4_skipped_at_runtime(self) -> None:
        from munio.models import DeployCheck, DeployCheckType

        c4 = Constraint(
            name="tier4-only",
            tier=Tier.TIER_4,
            deploy_check=DeployCheck(type=DeployCheckType.CONSISTENCY),
        )
        verifier = Verifier(_make_registry(c4))
        result = verifier.verify(_make_action(cost=200))
        # Tier 4 should not be checked at runtime — constraints_for returns it
        # but tier routing skips it
        assert result.checked_constraints == 0

    def test_tier1_only_no_z3_init(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c))
        verifier.verify(_make_action(url="safe.com"))
        # Z3 pool should not have been initialized
        assert verifier._z3_pool is None

    def test_empty_registry_all_unmatched(self) -> None:
        verifier = Verifier(_make_registry())
        result = verifier.verify(_make_action(url="anything"))
        assert result.checked_constraints == 0

    # ── Edge cases ──

    def test_constraint_enabled_false_skipped(self) -> None:
        c = Constraint(
            name="disabled-constraint",
            enabled=False,
            check=ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["evil.com"]),
        )
        verifier = Verifier(_make_registry(c))
        result = verifier.verify(_make_action(url="evil.com"))
        # Disabled constraints are filtered out by constraints_for
        assert result.checked_constraints == 0

    def test_multiple_constraints_same_action_all_checked(self) -> None:
        c1 = _make_denylist_constraint(["evil.com"], name="c1")
        c2 = _make_threshold_constraint(max_val=100, name="c2")
        verifier = Verifier(_make_registry(c1, c2))
        result = verifier.verify(_make_action(url="evil.com", cost=200))
        assert result.checked_constraints == 2
        violation_names = {v.constraint_name for v in result.violations}
        assert violation_names == {"c1", "c2"}

    def test_action_with_empty_tool_name(self) -> None:
        c = _make_denylist_constraint(["evil.com"], action="http_request")
        verifier = Verifier(_make_registry(c))
        result = verifier.verify(Action(tool="", args={"url": "evil.com"}))
        # Empty tool name doesn't match "http_request"
        assert result.checked_constraints == 0

    def test_repr(self) -> None:
        config = ConstraintConfig(mode=VerificationMode.SHADOW)
        c = _make_denylist_constraint(["x"])
        verifier = Verifier(_make_registry(c), config)
        r = repr(verifier)
        assert "Verifier" in r
        assert "shadow" in r
        assert "1" in r  # 1 constraint


# ── TestDetermineAllowed ──


class TestDetermineAllowed:
    """Tests for Verifier._determine_allowed() logic."""

    def _make_verifier(
        self,
        mode: VerificationMode = VerificationMode.ENFORCE,
    ) -> Verifier:
        config = ConstraintConfig(mode=mode)
        return Verifier(_make_registry(), config)

    def test_no_violations_allowed(self) -> None:
        verifier = self._make_verifier()
        assert verifier._determine_allowed([], []) is True

    @pytest.mark.parametrize(
        ("on_violation", "expected"),
        [
            (OnViolation.BLOCK, False),
            (OnViolation.WARN, True),
            (OnViolation.SHADOW, True),
        ],
        ids=["block", "warn", "shadow"],
    )
    def test_on_violation_determines_allowed(
        self, on_violation: OnViolation, expected: bool
    ) -> None:
        c = _make_denylist_constraint(["x"], on_violation=on_violation)
        verifier = self._make_verifier()
        violation = Violation(constraint_name="test-deny", message="test")
        assert verifier._determine_allowed([violation], [c]) is expected

    def test_system_violation_not_allowed(self) -> None:
        verifier = self._make_verifier()
        violation = Violation(
            constraint_name="__system__",
            severity=ViolationSeverity.CRITICAL,
            message="system error",
        )
        assert verifier._determine_allowed([violation], []) is False

    def test_unknown_constraint_fail_closed(self) -> None:
        verifier = self._make_verifier()
        violation = Violation(constraint_name="nonexistent-constraint", message="unknown")
        assert verifier._determine_allowed([violation], []) is False


# ── TestVerifyAction ──


class TestVerifyAction:
    """Tests for verify_action() convenience function."""

    def test_dict_input_converted(self) -> None:
        result = verify_action(
            {"tool": "http_request", "args": {"url": "safe.com"}},
            constraints="generic",
        )
        assert isinstance(result, VerificationResult)

    def test_action_input_passthrough(self) -> None:
        action = Action(tool="http_request", args={"url": "safe.com"})
        result = verify_action(action, constraints="generic")
        assert isinstance(result, VerificationResult)

    def test_loads_from_real_yaml(self) -> None:
        result = verify_action(
            Action(tool="http_request", args={"url": "https://evil.com/payload"}),
            constraints="generic",
        )
        assert result.allowed is False
        assert any(
            "evil.com" in v.message.lower() or "evil.com" in v.actual_value
            for v in result.violations
        )

    def test_invalid_dict_raises_validation_error(self) -> None:
        with pytest.raises(ProofAgentError, match="Invalid action format"):
            verify_action({"not_a_valid_field": 123})  # type: ignore[arg-type]


# ── TestAverifyAction ──


class TestAverifyAction:
    """Tests for averify_action() async wrapper."""

    @pytest.mark.asyncio
    async def test_returns_same_as_sync(self) -> None:
        action = Action(tool="http_request", args={"url": "https://evil.com/x"})
        sync_result = verify_action(action, constraints="generic")
        async_result = await averify_action(action, constraints="generic")
        assert sync_result.allowed == async_result.allowed
        assert len(sync_result.violations) == len(async_result.violations)


# ── TestIntegration ──


class TestIntegration:
    """End-to-end: YAML → Registry → Verifier."""

    def _make_verifier_from_yaml(
        self,
        mode: VerificationMode = VerificationMode.ENFORCE,
    ) -> Verifier:
        registry = load_constraints_dir(CONSTRAINTS_DIR, packs=["generic"])
        config = ConstraintConfig(mode=mode)
        return Verifier(registry, config)

    def test_blocks_evil_com(self) -> None:
        verifier = self._make_verifier_from_yaml()
        result = verifier.verify(_make_action(url="https://evil.com/payload"))
        assert result.allowed is False
        assert result.has_violations is True

    def test_allows_safe_url(self) -> None:
        verifier = self._make_verifier_from_yaml()
        result = verifier.verify(_make_action(url="https://api.example.com/data"))
        # url-allowlist uses prefix "https://api." — should be allowed
        # (only denylist violations matter; allowlist may or may not match)
        # The safe URL should not trigger denylist
        deny_violations = [
            v for v in result.violations if v.constraint_name == "block-dangerous-urls"
        ]
        assert len(deny_violations) == 0

    def test_url_case_insensitive(self) -> None:
        verifier = self._make_verifier_from_yaml()
        result = verifier.verify(_make_action(url="https://EVIL.COM/PAYLOAD"))
        assert result.allowed is False

    def test_enforce_to_shadow_toggle(self) -> None:
        registry = load_constraints_dir(CONSTRAINTS_DIR, packs=["generic"])
        action = _make_action(url="https://evil.com/payload")

        # ENFORCE: blocked
        enforce_verifier = Verifier(registry, ConstraintConfig(mode=VerificationMode.ENFORCE))
        enforce_result = enforce_verifier.verify(action)
        assert enforce_result.allowed is False

        # SHADOW: allowed (same violations)
        shadow_verifier = Verifier(registry, ConstraintConfig(mode=VerificationMode.SHADOW))
        shadow_result = shadow_verifier.verify(action)
        assert shadow_result.allowed is True
        assert len(shadow_result.violations) > 0


# ── TestConcurrency ──


class TestConcurrency:
    """Thread safety tests for Verifier."""

    def test_concurrent_verify_calls(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c))

        results: dict[str, VerificationResult] = {}
        errors: list[Exception] = []

        def worker(url: str, key: str) -> None:
            try:
                result = verifier.verify(_make_action(url=url))
                results[key] = result
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=("evil.com", "evil1")),
            threading.Thread(target=worker, args=("safe.com", "safe")),
            threading.Thread(target=worker, args=("evil.com", "evil2")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0
        assert len(results) == 3
        assert results["evil1"].allowed is False
        assert results["evil2"].allowed is False
        assert results["safe"].allowed is True


# ── TestVerifierTemporal ──


class TestVerifierTemporal:
    """Tests for Verifier temporal integration (store lifecycle + record_call)."""

    # ── Auto-creation of store ──

    def test_auto_creates_store_when_none(self) -> None:
        """Verifier auto-creates InMemoryTemporalStore when temporal_store=None."""
        from munio._temporal import InMemoryTemporalStore

        verifier = Verifier(_make_registry())
        assert verifier._temporal_store is not None
        assert isinstance(verifier._temporal_store, InMemoryTemporalStore)

    def test_external_store_passed_through(self) -> None:
        """External store is used when provided."""
        from munio._temporal import InMemoryTemporalStore

        store = InMemoryTemporalStore()
        verifier = Verifier(_make_registry(), temporal_store=store)
        assert verifier._temporal_store is store

    def test_tier1_solver_receives_store(self) -> None:
        """Tier1Solver receives the same store as the Verifier."""
        from munio._temporal import InMemoryTemporalStore

        store = InMemoryTemporalStore()
        verifier = Verifier(_make_registry(), temporal_store=store)
        assert verifier._tier1._temporal_store is store

    # ── record_call invoked after verify ──

    def test_record_call_invoked_after_verify(self) -> None:
        """record_call is called unconditionally after verify()."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        # Need at least one matching constraint so verify reaches record_call
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), temporal_store=store)
        verifier.verify(_make_action(tool="http_request", url="safe.com"))
        assert store.record_call.called

    def test_record_call_receives_sanitized_tool(self) -> None:
        """record_call receives casefolded sanitized tool name."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), temporal_store=store)
        verifier.verify(_make_action(tool="HTTP_Request"))
        # All record_call calls should use casefolded tool
        for call in store.record_call.call_args_list:
            assert call[0][1] == "http_request"

    def test_record_call_global_scope_always(self) -> None:
        """record_call records to __global__ scope for all calls."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        c = _make_denylist_constraint(["evil.com"], action="exec")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        verifier.verify(_make_action(tool="exec"))
        # First record_call should be for __global__
        global_calls = [c for c in store.record_call.call_args_list if c[0][0] == "__global__"]
        assert len(global_calls) >= 1

    def test_record_call_agent_scope_when_agent_id(self) -> None:
        """record_call also records to agent scope when agent_id is set."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        c = _make_denylist_constraint(["evil.com"], action="exec")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        action = Action(tool="exec", args={}, agent_id="my-agent")
        verifier.verify(action)
        scope_keys = [c[0][0] for c in store.record_call.call_args_list]
        assert "__global__" in scope_keys
        agent_keys = [k for k in scope_keys if k.startswith("agent:")]
        assert len(agent_keys) >= 1
        assert "my-agent" in agent_keys[0]

    # ── record_call failure -> log warning, action still allowed ──

    def test_record_call_failure_allows_action(self) -> None:
        """record_call failure does not block the action."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        store.record_call.side_effect = RuntimeError("store down")
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), temporal_store=store)
        result = verifier.verify(_make_action(url="safe.com"))
        # Action is still allowed despite record_call failure
        assert result.allowed is True

    def test_record_call_failure_with_violation_still_blocks(self) -> None:
        """record_call failure does not override existing violations."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        store.record_call.side_effect = RuntimeError("store down")
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), temporal_store=store)
        result = verifier.verify(_make_action(url="evil.com"))
        # Denylist violation still blocks
        assert result.allowed is False

    # ── agent_id sanitization in scope key ──

    @pytest.mark.parametrize(
        ("agent_id", "should_not_contain"),
        [
            ("\x00agent", "\x00"),
            ("agent\u200b1", "\u200b"),
            ("\x1bagent", "\x1b"),
            ("ag\ufffaent", "\ufffa"),
        ],
        ids=["null-byte", "zero-width-space", "escape-char", "interlinear"],
    )
    def test_agent_id_sanitized_in_scope(self, agent_id: str, should_not_contain: str) -> None:
        """Agent IDs with control/invisible characters are sanitized."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        verifier = Verifier(_make_registry(), temporal_store=store)
        action = Action(tool="exec", args={}, agent_id=agent_id)
        verifier.verify(action)
        # Check agent scope key is sanitized
        agent_calls = [c for c in store.record_call.call_args_list if c[0][0].startswith("agent:")]
        for call in agent_calls:
            assert should_not_contain not in call[0][0]

    # ── Temporal violations flow through _determine_allowed ──

    def test_temporal_violation_blocks_on_block(self) -> None:
        """RATE_LIMIT violation with on_violation=BLOCK results in not allowed."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        store = InMemoryTemporalStore()
        c = make_rate_limit_constraint(max_count=1, on_violation=OnViolation.BLOCK)
        verifier = Verifier(_make_registry(c), temporal_store=store)
        verifier.verify(_make_action(tool="http_request"))
        result = verifier.verify(_make_action(tool="http_request"))
        assert result.allowed is False
        assert len(result.violations) >= 1

    def test_temporal_violation_allows_on_warn(self) -> None:
        """RATE_LIMIT violation with on_violation=WARN is still allowed."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        store = InMemoryTemporalStore()
        c = make_rate_limit_constraint(max_count=1, on_violation=OnViolation.WARN)
        verifier = Verifier(_make_registry(c), temporal_store=store)
        verifier.verify(_make_action(tool="http_request"))
        result = verifier.verify(_make_action(tool="http_request"))
        assert result.allowed is True
        assert len(result.violations) >= 1

    # ── Rate limit E2E ──

    def test_rate_limit_e2e_blocks_after_n_plus_1(self) -> None:
        """Rate limit E2E: N+1 calls results in last one blocked."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        n = 3
        store = InMemoryTemporalStore()
        c = make_rate_limit_constraint(max_count=n, window_seconds=60)
        verifier = Verifier(_make_registry(c), temporal_store=store)
        for i in range(n):
            result = verifier.verify(_make_action(tool="http_request"))
            assert result.allowed is True, f"Call {i + 1} should be allowed"
        result = verifier.verify(_make_action(tool="http_request"))
        assert result.allowed is False

    def test_rate_limit_e2e_violation_name_matches_constraint(self) -> None:
        """Rate limit violation references the correct constraint name."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        store = InMemoryTemporalStore()
        c = make_rate_limit_constraint(max_count=1, name="my-rate-limit")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        verifier.verify(_make_action(tool="http_request"))
        result = verifier.verify(_make_action(tool="http_request"))
        assert any(v.constraint_name == "my-rate-limit" for v in result.violations)

    # ── Sequence deny E2E ──

    def test_sequence_deny_e2e_blocks_full_chain(self) -> None:
        """Sequence deny E2E: read_file then http_request is blocked."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_sequence_deny_constraint

        store = InMemoryTemporalStore()
        c = make_sequence_deny_constraint(steps=["read_file", "http_request"], scope="global")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        # First call: read_file (allowed)
        result1 = verifier.verify(_make_action(tool="read_file"))
        assert result1.allowed is True
        # Second call: http_request (blocked — completes sequence)
        result2 = verifier.verify(_make_action(tool="http_request"))
        assert result2.allowed is False

    def test_sequence_deny_e2e_partial_chain_allowed(self) -> None:
        """Sequence deny E2E: partial chain is allowed."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_sequence_deny_constraint

        store = InMemoryTemporalStore()
        c = make_sequence_deny_constraint(steps=["read_file", "http_request"], scope="global")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        # Only read_file — no http_request yet
        result = verifier.verify(_make_action(tool="read_file"))
        assert result.allowed is True

    # ── Temporal + non-temporal combined ──

    def test_temporal_and_denylist_combined(self) -> None:
        """Both temporal and non-temporal violations coexist."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        store = InMemoryTemporalStore()
        c_rate = make_rate_limit_constraint(max_count=1)
        c_deny = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c_rate, c_deny), temporal_store=store)
        verifier.verify(_make_action(url="safe.com"))
        result = verifier.verify(_make_action(url="evil.com"))
        assert result.allowed is False
        violation_names = {v.constraint_name for v in result.violations}
        assert "test-rate-limit" in violation_names
        assert "test-deny" in violation_names

    # ── Shadow mode with temporal ──

    def test_shadow_mode_temporal_still_populates_violations(self) -> None:
        """Shadow mode records temporal violations but allows the action."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        store = InMemoryTemporalStore()
        c = make_rate_limit_constraint(max_count=1)
        config = ConstraintConfig(mode=VerificationMode.SHADOW)
        verifier = Verifier(_make_registry(c), config, temporal_store=store)
        verifier.verify(_make_action(tool="http_request"))
        result = verifier.verify(_make_action(tool="http_request"))
        assert result.allowed is True
        assert len(result.violations) >= 1

    # ── Tier breakdown includes temporal ──

    def test_temporal_in_tier_breakdown(self) -> None:
        """Temporal constraints appear in tier_breakdown as tier_1."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        store = InMemoryTemporalStore()
        c = make_rate_limit_constraint(max_count=100)
        verifier = Verifier(_make_registry(c), temporal_store=store)
        result = verifier.verify(_make_action(tool="http_request"))
        assert result.tier_breakdown.get("tier_1", 0) >= 1


# ── TestReviewRound12Fixes ──


class TestReviewRound12Fixes:
    """Tests for Review Round 12 fixes (C1, C2, M1-M4)."""

    # ── C1: anonymous agent records to agent:__anonymous__ ──

    def test_anonymous_agent_records_to_anonymous_scope(self) -> None:
        """agent_id=None records to agent:__anonymous__ (C1 fix)."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), temporal_store=store)
        # Action with no agent_id
        action = Action(tool="http_request", args={"url": "safe.com"})
        verifier.verify(action)
        agent_calls = [c for c in store.record_call.call_args_list if c[0][0].startswith("agent:")]
        assert len(agent_calls) >= 1
        assert agent_calls[0][0][0] == "agent:__anonymous__"

    def test_anonymous_agent_sequence_deny_blocks(self) -> None:
        """SEQUENCE_DENY with scope=agent blocks agent_id=None via __anonymous__ (C1 fix)."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_sequence_deny_constraint

        store = InMemoryTemporalStore()
        c = make_sequence_deny_constraint(steps=["read_file", "http_request"], scope="agent")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        # Both calls with agent_id=None → both record to agent:__anonymous__
        result1 = verifier.verify(Action(tool="read_file", args={}))
        assert result1.allowed is True
        result2 = verifier.verify(Action(tool="http_request", args={}))
        assert result2.allowed is False

    # ── C2: unmatched tools still recorded in temporal history ──

    def test_unmatched_tool_still_recorded(self) -> None:
        """Unmatched tools are recorded in temporal store (C2 fix)."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        # Registry with constraint only for "exec"
        c = _make_denylist_constraint(["bad"], action="exec")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        # Call with "read_file" — no matching constraints
        verifier.verify(Action(tool="read_file", args={}))
        # record_call should still be called for __global__ and agent:__anonymous__
        assert store.record_call.called
        global_calls = [c for c in store.record_call.call_args_list if c[0][0] == "__global__"]
        assert len(global_calls) >= 1
        assert global_calls[0][0][1] == "read_file"

    def test_unmatched_tool_sequence_detected(self) -> None:
        """Unmatched tool in history enables sequence detection on later matched tool (C2 fix)."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_sequence_deny_constraint

        store = InMemoryTemporalStore()
        # Sequence: read_file → http_request
        c = make_sequence_deny_constraint(steps=["read_file", "http_request"], scope="global")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        # read_file matches no constraints (unmatched) but MUST be recorded
        # so sequence detection can catch it
        verifier.verify(Action(tool="read_file", args={}))
        # http_request matches the sequence constraint → blocked
        result = verifier.verify(Action(tool="http_request", args={}))
        assert result.allowed is False

    # ── Record_call invoked even when action is blocked ──

    def test_record_call_invoked_when_action_blocked(self) -> None:
        """record_call is called even when the action triggers a violation (blocked)."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.return_value = True
        store.check_sequence.return_value = True
        c = _make_denylist_constraint(["evil.com"])
        verifier = Verifier(_make_registry(c), temporal_store=store)
        result = verifier.verify(_make_action(url="evil.com"))
        assert result.allowed is False
        # record_call should still be called
        assert store.record_call.called

    # ── Store exception messages don't leak ──

    def test_store_exception_message_not_leaked(self) -> None:
        """Store exception details are not in violation messages."""
        from unittest.mock import MagicMock

        store = MagicMock()
        store.check_and_record_rate.side_effect = RuntimeError("SECRET_DB_CRED")
        solver_store = MagicMock()
        solver_store.check_and_record_rate.side_effect = RuntimeError("SECRET_DB_CRED")
        solver_store.check_sequence.return_value = True
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        store = InMemoryTemporalStore()
        from munio.solver import Tier1Solver

        broken_store = MagicMock()
        broken_store.check_and_record_rate.side_effect = RuntimeError("SECRET_DB_CRED")
        solver = Tier1Solver(temporal_store=broken_store)
        c = make_rate_limit_constraint(max_count=10)
        violations = solver.check(_make_action(tool="http_request"), [c])
        assert len(violations) == 1
        assert "SECRET_DB_CRED" not in violations[0].message

    # ── record_call happens BEFORE constraint matching ──

    def test_record_call_before_constraint_matching(self) -> None:
        """record_call happens before _handle_unmatched returns (ordering test)."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_sequence_deny_constraint

        store = InMemoryTemporalStore()
        # Constraint matches http_request (via action="*")
        c = make_sequence_deny_constraint(steps=["unknown_tool", "http_request"], scope="global")
        verifier = Verifier(_make_registry(c), temporal_store=store)
        # First: unknown_tool has no matching constraints but IS recorded
        verifier.verify(Action(tool="unknown_tool", args={}))
        # Verify it was recorded in the store
        assert "__global__" in store._sequence_data
        history = [(ts, tool) for ts, tool in store._sequence_data["__global__"]]
        tools = [tool for _, tool in history]
        assert "unknown_tool" in tools
