"""Tests for munio.models — Pydantic models, enums, and configuration."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from munio.models import (
    Action,
    CheckType,
    CompositeVariable,
    Constraint,
    ConstraintCheck,
    ConstraintCondition,
    ConstraintConfig,
    DeployCheck,
    DeployCheckType,
    FailBehavior,
    MatchMode,
    OnViolation,
    PolicyResult,
    PolicyVerificationResult,
    SolverConfig,
    Tier,
    VerificationMode,
    VerificationResult,
    Violation,
    ViolationSeverity,
)

# ── Enum tests ────────────────────────────────────────────────────────────────


class TestEnums:
    @pytest.mark.parametrize(
        ("enum_cls", "expected_values"),
        [
            (
                CheckType,
                {
                    "denylist",
                    "allowlist",
                    "threshold",
                    "regex_deny",
                    "regex_allow",
                    "composite",
                    "rate_limit",
                    "sequence_deny",
                },
            ),
            (DeployCheckType, {"consistency", "no_new_access", "data_flow", "filter_completeness"}),
            (MatchMode, {"exact", "contains", "prefix", "suffix", "regex", "glob"}),
            (PolicyResult, {"safe", "unsafe", "timeout", "unknown", "error"}),
        ],
    )
    def test_enum_completeness(self, enum_cls, expected_values):
        """Detect accidental addition or removal of enum members."""
        assert {e.value for e in enum_cls} == expected_values

    def test_policy_result_rejects_invalid(self):
        """PolicyResult enum rejects arbitrary strings."""
        with pytest.raises(ValueError, match="'banana' is not a valid PolicyResult"):
            PolicyResult("banana")


# ── Action tests ──────────────────────────────────────────────────────────────


class TestAction:
    def test_minimal_action(self):
        action = Action(tool="http_request")
        assert action.tool == "http_request"
        assert action.args == {}
        assert action.agent_id is None
        assert action.metadata == {}

    def test_full_action(self):
        action = Action(
            tool="http_request",
            args={"url": "https://api.example.com", "method": "GET"},
            agent_id="agent-1",
            metadata={"session_id": "sess-abc", "user_id": "user-123"},
        )
        assert action.tool == "http_request"
        assert action.args["url"] == "https://api.example.com"
        assert action.agent_id == "agent-1"
        assert action.metadata["session_id"] == "sess-abc"

    def test_action_is_frozen(self):
        action = Action(tool="test")
        with pytest.raises(ValidationError):
            action.tool = "changed"  # type: ignore[misc]

    def test_action_missing_tool_raises(self):
        with pytest.raises(ValidationError):
            Action()  # type: ignore[call-arg]


# ── ConstraintCheck tests ─────────────────────────────────────────────────────


class TestConstraintCheck:
    def test_denylist_check(self):
        check = ConstraintCheck(
            type=CheckType.DENYLIST,
            field="url",
            values=["evil.com", "malware.org"],
            match=MatchMode.CONTAINS,
        )
        assert check.type == CheckType.DENYLIST
        assert len(check.values) == 2
        assert check.match == MatchMode.CONTAINS

    def test_threshold_check(self):
        check = ConstraintCheck(
            type=CheckType.THRESHOLD,
            field="cost",
            max=100.0,
            unit="USD",
        )
        assert check.max == 100.0
        assert check.unit == "USD"
        assert check.min is None

    def test_allowlist_check(self):
        check = ConstraintCheck(
            type=CheckType.ALLOWLIST,
            field="url",
            values=["api.openai.com", "api.anthropic.com"],
            match=MatchMode.PREFIX,
        )
        assert check.type == CheckType.ALLOWLIST
        assert len(check.values) == 2
        assert check.match == MatchMode.PREFIX

    def test_regex_deny_check(self):
        check = ConstraintCheck(
            type=CheckType.REGEX_DENY,
            field="command",
            patterns=[r"rm\s+-rf", r"DROP\s+TABLE"],
        )
        assert len(check.patterns) == 2

    def test_regex_allow_check(self):
        check = ConstraintCheck(
            type=CheckType.REGEX_ALLOW,
            field="url",
            patterns=[r"^https://api\.example\.com/"],
        )
        assert check.type == CheckType.REGEX_ALLOW
        assert len(check.patterns) == 1

    @pytest.mark.parametrize(
        ("check_type", "match_msg"),
        [
            (CheckType.DENYLIST, "non-empty 'values'"),
            (CheckType.ALLOWLIST, "non-empty 'values'"),
            (CheckType.THRESHOLD, "at least 'min' or 'max'"),
            (CheckType.REGEX_DENY, "non-empty 'patterns'"),
            (CheckType.REGEX_ALLOW, "non-empty 'patterns'"),
        ],
    )
    def test_check_type_requires_fields(self, check_type, match_msg):
        with pytest.raises(ValidationError, match=match_msg):
            ConstraintCheck(type=check_type, field="test")

    @pytest.mark.parametrize(
        ("kwargs", "match_msg"),
        [
            (
                {"type": CheckType.DENYLIST, "field": "url", "values": ["x"], "min": 0},
                "must not have 'min'/'max'",
            ),
            (
                {"type": CheckType.DENYLIST, "field": "url", "values": ["x"], "patterns": ["y"]},
                "must not have 'patterns'",
            ),
            (
                {"type": CheckType.ALLOWLIST, "field": "url", "values": ["x"], "min": 0},
                "must not have 'min'/'max'",
            ),
            (
                {"type": CheckType.ALLOWLIST, "field": "url", "values": ["x"], "patterns": ["y"]},
                "must not have 'patterns'",
            ),
            (
                {"type": CheckType.THRESHOLD, "field": "cost", "max": 100, "values": ["x"]},
                "must not have 'values'",
            ),
            (
                {"type": CheckType.THRESHOLD, "field": "cost", "max": 100, "patterns": ["x"]},
                "must not have 'patterns'",
            ),
            (
                {"type": CheckType.REGEX_DENY, "field": "cmd", "patterns": ["x"], "values": ["y"]},
                "must not have 'values'",
            ),
            (
                {"type": CheckType.REGEX_DENY, "field": "cmd", "patterns": ["x"], "min": 0},
                "must not have 'min'/'max'",
            ),
            (
                {"type": CheckType.REGEX_ALLOW, "field": "cmd", "patterns": ["x"], "values": ["y"]},
                "must not have 'values'",
            ),
            (
                {"type": CheckType.REGEX_ALLOW, "field": "cmd", "patterns": ["x"], "min": 0},
                "must not have 'min'/'max'",
            ),
        ],
    )
    def test_rejects_foreign_fields(self, kwargs, match_msg):
        with pytest.raises(ValidationError, match=match_msg):
            ConstraintCheck(**kwargs)

    def test_regex_invalid_pattern_rejected(self):
        """Invalid regex pattern must fail at model creation, not at runtime."""
        with pytest.raises(ValidationError, match="Invalid regex pattern"):
            ConstraintCheck(
                type=CheckType.REGEX_DENY,
                field="cmd",
                patterns=[r"[unclosed"],
            )


# ── Constraint tests ──────────────────────────────────────────────────────────


class TestConstraint:
    def test_minimal_constraint(self):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["evil.com"])
        constraint = Constraint(name="test-constraint", check=check)
        assert constraint.name == "test-constraint"
        assert constraint.description == ""
        assert constraint.category == ""
        assert constraint.tier == Tier.TIER_1
        assert constraint.action == "*"
        assert constraint.check is not None
        assert constraint.deploy_check is None
        assert constraint.on_violation == OnViolation.BLOCK
        assert constraint.severity == ViolationSeverity.HIGH
        assert constraint.enabled is True
        assert constraint.actions is None

    def test_actions_field_parses(self):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="*", values=["evil.com"])
        constraint = Constraint(
            name="cap-test",
            check=check,
            actions=["*read*", "*file*", "*directory*"],
        )
        assert constraint.actions is not None
        assert len(constraint.actions) == 3
        assert constraint.action == "*"  # default unchanged
        assert constraint.actions[0] == "*read*"

    def test_actions_none_by_default(self):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="*", values=["evil.com"])
        constraint = Constraint(name="no-actions", check=check)
        assert constraint.actions is None

    def test_full_runtime_constraint(self):
        constraint = Constraint(
            name="block-dangerous-urls",
            description="Block HTTP requests to known dangerous domains",
            category="ASI02",
            tier=Tier.TIER_1,
            action="http_request",
            check=ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=["evil.com"],
                match=MatchMode.CONTAINS,
            ),
            on_violation=OnViolation.BLOCK,
            severity=ViolationSeverity.CRITICAL,
        )
        assert constraint.check is not None
        assert constraint.check.type == CheckType.DENYLIST
        assert constraint.deploy_check is None

    def test_deploy_time_constraint(self):
        constraint = Constraint(
            name="constraint-consistency",
            category="ASI02",
            tier=Tier.TIER_4,
            deploy_check=DeployCheck(
                type=DeployCheckType.CONSISTENCY,
                constraints_ref=["max-spend", "max-concurrent"],
                verify="sum(per_request * concurrent) <= daily",
            ),
        )
        assert constraint.tier == Tier.TIER_4
        assert constraint.deploy_check is not None
        assert constraint.deploy_check.type == DeployCheckType.CONSISTENCY
        assert constraint.check is None

    def test_constraint_with_conditions(self):
        constraint = Constraint(
            name="api-allowlist-with-auth",
            action="http_request",
            check=ConstraintCheck(
                type=CheckType.ALLOWLIST,
                field="url",
                values=["api.openai.com"],
                match=MatchMode.PREFIX,
            ),
            conditions=[
                ConstraintCondition(field="headers.authorization", exists=True),
            ],
        )
        assert len(constraint.conditions) == 1
        assert constraint.conditions[0].field == "headers.authorization"
        assert constraint.conditions[0].exists is True

    def test_constraint_is_frozen(self):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"])
        constraint = Constraint(name="test", check=check)
        with pytest.raises(ValidationError):
            constraint.name = "changed"  # type: ignore[misc]

    def test_category_valid_owasp(self):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"])
        c = Constraint(name="t", category="ASI02", check=check)
        assert c.category == "ASI02"

    def test_category_empty_is_valid(self):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"])
        c = Constraint(name="t", check=check)
        assert c.category == ""

    @pytest.mark.parametrize("bad_category", ["asi02", "hello world!"])
    def test_category_rejects_invalid(self, bad_category):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"])
        with pytest.raises(ValidationError, match="category"):
            Constraint(name="t", category=bad_category, check=check)

    def test_tier1_3_without_check_rejected(self):
        """Tier 1-3 constraint without check is a silent no-op — must be rejected."""
        with pytest.raises(ValidationError, match="must have 'check'"):
            Constraint(name="no-check")

    @pytest.mark.parametrize(
        "bad_name",
        ["", "__system__", "__dunder__", "has space", "слово", "/path", "a" * 101],
        ids=["empty", "system-dunder", "custom-dunder", "space", "non-ascii", "slash", "too-long"],
    )
    def test_name_rejects_invalid(self, bad_name: str):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"])
        with pytest.raises(ValidationError, match="name"):
            Constraint(name=bad_name, check=check)

    @pytest.mark.parametrize(
        "good_name",
        ["a", "block-dangerous-urls", "ASI02_rule.v1", "my-constraint-123"],
        ids=["single-char", "kebab-case", "dots-underscores", "alphanumeric"],
    )
    def test_name_accepts_valid(self, good_name: str):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"])
        c = Constraint(name=good_name, check=check)
        assert c.name == good_name


# ── DeployCheck tests ─────────────────────────────────────────────────────────


class TestDeployCheck:
    def test_consistency_check(self):
        check = DeployCheck(
            type=DeployCheckType.CONSISTENCY,
            constraints_ref=["a", "b", "c"],
            verify="no contradictions",
        )
        assert check.type == DeployCheckType.CONSISTENCY
        assert len(check.constraints_ref) == 3

    def test_data_flow_check(self):
        check = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source="database_read",
            forbidden_sink="external_api",
            through="*",
            flow_edges=[["database_read", "external_api"]],
            verify="no transitive path from source to sink",
        )
        assert check.source == "database_read"
        assert check.forbidden_sink == "external_api"
        assert check.flow_edges == [["database_read", "external_api"]]

    def test_no_new_access_check(self):
        check = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new-policy"],
            baseline_constraints_ref=["old-policy"],
        )
        assert check.type == DeployCheckType.NO_NEW_ACCESS
        assert check.baseline_constraints_ref == ["old-policy"]


# ── Result model tests ────────────────────────────────────────────────────────


class TestVerificationResult:
    def test_allowed_result(self):
        result = VerificationResult(
            allowed=True,
            checked_constraints=5,
            elapsed_ms=0.008,
        )
        assert result.allowed is True
        assert result.violations == []
        assert result.checked_constraints == 5
        assert result.has_violations is False

    def test_blocked_result_with_violations(self):
        violation = Violation(
            constraint_name="block-dangerous-urls",
            constraint_category="ASI02",
            severity=ViolationSeverity.CRITICAL,
            message="URL contains blocked domain: evil.com",
            field="url",
            actual_value="https://evil.com/steal-data",
            tier=Tier.TIER_1,
        )
        result = VerificationResult(
            allowed=False,
            violations=[violation],
            checked_constraints=5,
            elapsed_ms=0.003,
            tier_breakdown={"tier_1": 5},
        )
        assert result.allowed is False
        assert len(result.violations) == 1
        assert result.violations[0].severity == ViolationSeverity.CRITICAL
        assert result.has_violations is True

    def test_shadow_mode_result(self):
        """Shadow mode: allowed=True even with violations."""
        result = VerificationResult(
            allowed=True,
            mode=VerificationMode.SHADOW,
            violations=[
                Violation(
                    constraint_name="test",
                    message="Would have been blocked",
                ),
            ],
        )
        assert result.allowed is True
        assert result.has_violations is True
        assert len(result.violations) == 1
        assert result.mode == VerificationMode.SHADOW

    def test_disabled_mode_result(self):
        """DISABLED mode: allowed=True, no violations, no checks."""
        result = VerificationResult(
            allowed=True,
            mode=VerificationMode.DISABLED,
            checked_constraints=0,
        )
        assert result.allowed is True
        assert result.mode == VerificationMode.DISABLED
        assert result.has_violations is False
        assert result.checked_constraints == 0

    def test_tier_breakdown_valid_keys(self):
        result = VerificationResult(
            allowed=True,
            tier_breakdown={"tier_1": 5, "tier_4": 1},
        )
        assert result.tier_breakdown == {"tier_1": 5, "tier_4": 1}

    def test_tier_breakdown_invalid_keys(self):
        with pytest.raises(ValidationError, match="Invalid tier_breakdown"):
            VerificationResult(allowed=True, tier_breakdown={"banana": 1})


class TestPolicyVerificationResult:
    def test_safe_result(self):
        result = PolicyVerificationResult(
            result=PolicyResult.SAFE,
            elapsed_ms=1200.0,
            check_type=DeployCheckType.CONSISTENCY,
            constraints_checked=["a", "b", "c"],
        )
        assert result.safe is True
        assert result.result == PolicyResult.SAFE

    def test_unsafe_result_with_counterexample(self):
        result = PolicyVerificationResult(
            result=PolicyResult.UNSAFE,
            details={
                "counterexample": {
                    "per_request_spend": 100,
                    "concurrent_requests": 10,
                    "total": 1000,
                    "daily_limit": 500,
                },
                "message": "10 concurrent requests at $100 each = $1000 > $500 daily limit",
            },
            check_type=DeployCheckType.CONSISTENCY,
        )
        assert result.safe is False
        assert "counterexample" in result.details

    def test_timeout_result(self):
        result = PolicyVerificationResult(
            result=PolicyResult.TIMEOUT,
            details={"message": "Z3 solver exceeded 5000ms timeout"},
        )
        assert result.safe is False
        assert result.result == PolicyResult.TIMEOUT

    def test_invalid_result_rejected(self):
        """PolicyResult enum rejects invalid values at model level."""
        with pytest.raises(ValidationError):
            PolicyVerificationResult(result="banana")  # type: ignore[arg-type]


# ── Configuration tests ───────────────────────────────────────────────────────


class TestSolverConfig:
    def test_defaults(self):
        config = SolverConfig()
        assert config.timeout_ms == 5000
        assert config.rlimit == 500_000
        assert config.process_timeout_s == 10
        assert config.z3_version_required == "4.16.0.0"
        assert config.fail_behavior == FailBehavior.FAIL_CLOSED
        assert config.max_memory_mb == 512

    def test_custom_config(self):
        config = SolverConfig(
            timeout_ms=10000,
            process_timeout_s=15,
            rlimit=1_000_000,
            fail_behavior=FailBehavior.FAIL_OPEN,
        )
        assert config.timeout_ms == 10000
        assert config.process_timeout_s == 15
        assert config.fail_behavior == FailBehavior.FAIL_OPEN


class TestConstraintConfig:
    def test_defaults(self):
        config = ConstraintConfig()
        assert config.mode == VerificationMode.ENFORCE
        assert config.constraints_dir == Path("constraints")
        assert config.constraint_packs == ["generic"]
        assert config.default_on_unmatched == OnViolation.WARN
        assert config.include_violation_values is True
        assert config.max_violation_value_length == 200
        assert isinstance(config.solver, SolverConfig)

    def test_custom_config(self):
        config = ConstraintConfig(
            mode=VerificationMode.SHADOW,
            constraints_dir="/custom/constraints",
            constraint_packs=["generic", "fintech"],
        )
        assert config.mode == VerificationMode.SHADOW
        assert config.constraints_dir == Path("/custom/constraints")
        assert "fintech" in config.constraint_packs

    def test_frozen(self):
        config = ConstraintConfig()
        with pytest.raises(ValidationError):
            config.mode = VerificationMode.SHADOW  # type: ignore[misc]

    @pytest.mark.parametrize("bad_length", [0, -1, 1, 2, 3])
    def test_max_violation_value_length_rejects_below_minimum(self, bad_length: int) -> None:
        """max_violation_value_length must be >= 4 (room for at least 1 char + '...')."""
        with pytest.raises(ValidationError):
            ConstraintConfig(max_violation_value_length=bad_length)

    def test_constraint_config_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ConstraintConfig(unknown_field="oops")  # type: ignore[call-arg]

    def test_model_copy_update(self):
        """Frozen config is modified via model_copy, not mutation."""
        original = ConstraintConfig()
        shadow = original.model_copy(update={"mode": VerificationMode.SHADOW})
        assert original.mode == VerificationMode.ENFORCE
        assert shadow.mode == VerificationMode.SHADOW


# ── Serialization round-trip tests ────────────────────────────────────────────


class TestSerialization:
    """Verify model_dump() -> JSON -> model reconstruction works correctly."""

    def test_action_round_trip(self):
        original = Action(
            tool="http_request",
            args={"url": "https://api.example.com"},
            agent_id="agent-1",
        )
        data = original.model_dump()
        restored = Action(**data)
        assert restored == original

    def test_action_json_round_trip(self):
        original = Action(tool="http_request", args={"url": "https://evil.com"})
        json_str = original.model_dump_json()
        parsed = json.loads(json_str)
        restored = Action(**parsed)
        assert restored == original

    def test_constraint_round_trip(self):
        original = Constraint(
            name="block-urls",
            category="ASI02",
            tier=Tier.TIER_1,
            action="http_request",
            check=ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=["evil.com"],
                match=MatchMode.CONTAINS,
            ),
            conditions=[
                ConstraintCondition(field="headers.auth", exists=True),
            ],
            on_violation=OnViolation.BLOCK,
            severity=ViolationSeverity.CRITICAL,
        )
        data = original.model_dump()
        restored = Constraint(**data)
        assert restored == original
        assert restored.check is not None
        assert restored.check.values == ["evil.com"]

    def test_verification_result_json_round_trip(self):
        violation = Violation(
            constraint_name="test",
            message="blocked",
            severity=ViolationSeverity.HIGH,
            tier=Tier.TIER_1,
        )
        original = VerificationResult(
            allowed=False,
            violations=[violation],
            checked_constraints=3,
            elapsed_ms=0.05,
            tier_breakdown={"tier_1": 3},
        )
        json_str = original.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["has_violations"] is True  # computed field in JSON output
        parsed.pop("has_violations")  # computed fields are output-only
        restored = VerificationResult(**parsed)
        assert restored.allowed is False
        assert len(restored.violations) == 1
        assert restored.violations[0].constraint_name == "test"

    def test_policy_result_json_round_trip(self):
        original = PolicyVerificationResult(
            result=PolicyResult.UNSAFE,
            details={"counterexample": {"x": 42}},
            check_type=DeployCheckType.CONSISTENCY,
            constraints_checked=["a", "b"],
        )
        json_str = original.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["safe"] is False  # computed field in JSON output
        parsed.pop("safe")  # computed fields are output-only
        restored = PolicyVerificationResult(**parsed)
        assert restored.safe is False
        assert restored.result == PolicyResult.UNSAFE
        assert restored.details["counterexample"]["x"] == 42

    def test_constraint_config_round_trip(self):
        original = ConstraintConfig(
            mode=VerificationMode.SHADOW,
            constraint_packs=["generic", "fintech"],
            solver=SolverConfig(
                timeout_ms=10000, process_timeout_s=15, fail_behavior=FailBehavior.FAIL_OPEN
            ),
        )
        data = original.model_dump()
        restored = ConstraintConfig(**data)
        assert restored.mode == VerificationMode.SHADOW
        assert restored.solver.timeout_ms == 10000
        assert restored.solver.fail_behavior == FailBehavior.FAIL_OPEN


class TestConstraintCondition:
    """Dedicated tests for ConstraintCondition model."""

    def test_exists_condition(self):
        cond = ConstraintCondition(field="headers.authorization", exists=True)
        assert cond.field == "headers.authorization"
        assert cond.exists is True
        assert cond.equals is None
        assert cond.not_equals is None

    def test_equals_condition(self):
        cond = ConstraintCondition(field="method", equals="GET")
        assert cond.equals == "GET"

    def test_not_equals_condition(self):
        cond = ConstraintCondition(field="env", not_equals="production")
        assert cond.not_equals == "production"

    def test_requires_at_least_one_condition(self):
        """ConstraintCondition without any condition is invalid."""
        with pytest.raises(ValidationError, match="at least one of"):
            ConstraintCondition(field="test")

    def test_exists_false_with_equals_rejected(self):
        """exists=False + equals is contradictory: field absent, nothing to compare."""
        with pytest.raises(ValidationError, match="exists=False cannot be combined"):
            ConstraintCondition(field="test", exists=False, equals="x")

    def test_exists_false_with_not_equals_rejected(self):
        """exists=False + not_equals is contradictory."""
        with pytest.raises(ValidationError, match="exists=False cannot be combined"):
            ConstraintCondition(field="test", exists=False, not_equals="x")

    def test_exists_false_alone_is_valid(self):
        """exists=False without equals/not_equals is fine (check field absence)."""
        cond = ConstraintCondition(field="test", exists=False)
        assert cond.exists is False

    def test_exists_true_with_equals_is_valid(self):
        """exists=True + equals is fine (check field exists AND has value)."""
        cond = ConstraintCondition(field="test", exists=True, equals="x")
        assert cond.exists is True
        assert cond.equals == "x"

    def test_frozen(self):
        cond = ConstraintCondition(field="test", exists=True)
        with pytest.raises(ValidationError):
            cond.field = "changed"  # type: ignore[misc]


# ── Model validator tests ────────────────────────────────────────────────────


class TestModelValidators:
    """Tests for @model_validator invariants."""

    def test_solver_config_process_timeout_must_exceed_z3(self):
        with pytest.raises(ValidationError, match="process_timeout_s"):
            SolverConfig(timeout_ms=10000, process_timeout_s=5)

    def test_solver_config_process_timeout_equal_rejected(self):
        """Boundary: process_timeout_s exactly equal to timeout_ms/1000 must fail."""
        with pytest.raises(ValidationError, match="process_timeout_s"):
            SolverConfig(timeout_ms=10000, process_timeout_s=10)

    def test_solver_config_valid_timeouts(self):
        config = SolverConfig(timeout_ms=5000, process_timeout_s=10)
        assert config.process_timeout_s == 10

    def test_solver_config_rejects_extra_field(self):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            SolverConfig(unknown_field="oops")  # type: ignore[call-arg]

    def test_constraint_tier4_requires_deploy_check(self):
        with pytest.raises(ValidationError, match="deploy_check"):
            Constraint(
                name="bad",
                tier=Tier.TIER_4,
                check=ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"]),
            )

    def test_constraint_deploy_check_only_tier4(self):
        with pytest.raises(ValidationError, match="only valid for Tier 4"):
            Constraint(
                name="bad",
                tier=Tier.TIER_1,
                deploy_check=DeployCheck(
                    type=DeployCheckType.CONSISTENCY,
                    constraints_ref=["a"],
                ),
            )

    @pytest.mark.parametrize(
        ("policy_result", "expected_safe"),
        [
            (PolicyResult.SAFE, True),
            (PolicyResult.UNSAFE, False),
            (PolicyResult.TIMEOUT, False),
            (PolicyResult.UNKNOWN, False),
            (PolicyResult.ERROR, False),
        ],
    )
    def test_computed_safe_matches_result(self, policy_result, expected_safe):
        """safe is derived from result, not independently settable."""
        pvr = PolicyVerificationResult(result=policy_result)
        assert pvr.safe is expected_safe


# ── Phase 1: case_sensitive, extra="forbid", field="*"+threshold ─────────


class TestCaseSensitiveField:
    """Tests for the case_sensitive field on ConstraintCheck."""

    def test_default_is_true(self):
        check = ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["evil.com"])
        assert check.case_sensitive is True

    def test_explicit_false(self):
        check = ConstraintCheck(
            type=CheckType.DENYLIST, field="url", values=["evil.com"], case_sensitive=False
        )
        assert check.case_sensitive is False

    def test_round_trip_includes_case_sensitive(self):
        check = ConstraintCheck(
            type=CheckType.DENYLIST, field="url", values=["evil.com"], case_sensitive=False
        )
        data = check.model_dump()
        assert data["case_sensitive"] is False
        restored = ConstraintCheck.model_validate(data)
        assert restored.case_sensitive is False

    def test_case_sensitive_in_full_constraint(self):
        constraint = Constraint(
            name="test",
            check=ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=["evil.com"],
                case_sensitive=False,
            ),
        )
        assert constraint.check is not None
        assert constraint.check.case_sensitive is False


class TestExtraForbid:
    """Tests for extra='forbid' on config models."""

    def test_constraint_rejects_extra_field(self):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            Constraint(
                name="test",
                check=ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"]),
                unknown_field="oops",  # type: ignore[call-arg]
            )

    def test_constraint_check_rejects_extra_field(self):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=["x"],
                typo_field="bad",  # type: ignore[call-arg]
            )

    def test_constraint_condition_rejects_extra_field(self):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ConstraintCondition(
                field="url",
                exists=True,
                oops="bad",  # type: ignore[call-arg]
            )

    def test_deploy_check_rejects_extra_field(self):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            DeployCheck(
                type=DeployCheckType.CONSISTENCY,
                constraints_ref=["a"],
                bad_field="nope",  # type: ignore[call-arg]
            )


class TestThresholdWildcardRejection:
    """Tests that field='*' + type=threshold is rejected."""

    def test_threshold_star_field_rejected(self):
        with pytest.raises(ValidationError, match="semantically meaningless"):
            ConstraintCheck(type=CheckType.THRESHOLD, field="*", min=0, max=100)

    def test_threshold_normal_field_accepted(self):
        check = ConstraintCheck(type=CheckType.THRESHOLD, field="cost", min=0, max=100)
        assert check.field == "cost"

    def test_denylist_star_field_accepted(self):
        """field='*' is valid for non-threshold check types."""
        check = ConstraintCheck(type=CheckType.DENYLIST, field="*", values=["evil.com"])
        assert check.field == "*"


# ── TestDenylistValuesLimit ──────────────────────────────────────────


class TestDenylistValuesLimit:
    """Tests for values/patterns count limits and match=regex validation."""

    def test_values_exceeds_max_rejected(self):
        """More than 10K values → validation error."""
        with pytest.raises(ValidationError, match="values"):
            ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=[f"val{i}" for i in range(10_001)],
            )

    def test_patterns_exceeds_max_rejected(self):
        """More than 1K patterns → validation error."""
        with pytest.raises(ValidationError, match="patterns"):
            ConstraintCheck(
                type=CheckType.REGEX_DENY,
                field="query",
                patterns=[f"pat{i}" for i in range(1001)],
            )

    def test_match_regex_invalid_regex_rejected(self):
        """match=regex with invalid regex pattern in values → error."""
        with pytest.raises(ValidationError, match="regex"):
            ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=["[invalid(regex"],
                match=MatchMode.REGEX,
            )

    def test_match_regex_redos_rejected(self):
        """match=regex with ReDoS pattern in values → error."""
        with pytest.raises(ValidationError, match="quantifier"):
            ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=["(a+)+"],
                match=MatchMode.REGEX,
            )

    def test_match_regex_valid_accepted(self):
        """match=regex with valid regex in values → ok."""
        check = ConstraintCheck(
            type=CheckType.DENYLIST,
            field="url",
            values=[r"evil\.com", r"bad\d+"],
            match=MatchMode.REGEX,
        )
        assert len(check.values) == 2


# ── TestDeployCheckValidation ────────────────────────────────────────


class TestDeployCheckValidation:
    """Tests for DeployCheck field validators."""

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("source", ""),
            ("forbidden_sink", ""),
        ],
    )
    def test_data_flow_missing_required_fields(self, field, value):
        kwargs = {
            "type": DeployCheckType.DATA_FLOW,
            "source": "a",
            "forbidden_sink": "b",
            "flow_edges": [["a", "b"]],
        }
        kwargs[field] = value
        with pytest.raises(ValidationError):
            DeployCheck(**kwargs)

    def test_data_flow_empty_flow_edges_rejected(self):
        with pytest.raises(ValidationError, match="flow_edges"):
            DeployCheck(
                type=DeployCheckType.DATA_FLOW,
                source="a",
                forbidden_sink="b",
                flow_edges=[],
            )

    def test_data_flow_malformed_edge_rejected(self):
        with pytest.raises(ValidationError, match="flow_edges"):
            DeployCheck(
                type=DeployCheckType.DATA_FLOW,
                source="a",
                forbidden_sink="b",
                flow_edges=[["a"]],  # not [from, to]
            )

    def test_data_flow_empty_string_in_edge_rejected(self):
        with pytest.raises(ValidationError):
            DeployCheck(
                type=DeployCheckType.DATA_FLOW,
                source="a",
                forbidden_sink="b",
                flow_edges=[["a", ""]],
            )

    def test_no_new_access_missing_constraints_ref(self):
        with pytest.raises(ValidationError, match="constraints_ref"):
            DeployCheck(
                type=DeployCheckType.NO_NEW_ACCESS,
                constraints_ref=[],
                baseline_constraints_ref=["old"],
            )

    def test_no_new_access_missing_baseline(self):
        with pytest.raises(ValidationError, match="baseline"):
            DeployCheck(
                type=DeployCheckType.NO_NEW_ACCESS,
                constraints_ref=["new"],
                baseline_constraints_ref=[],
            )

    def test_filter_completeness_missing_constraints_ref(self):
        with pytest.raises(ValidationError, match="constraints_ref"):
            DeployCheck(
                type=DeployCheckType.FILTER_COMPLETENESS,
                constraints_ref=[],
                dangerous_pattern="DROP",
            )

    def test_filter_completeness_missing_dangerous_pattern(self):
        with pytest.raises(ValidationError, match="dangerous_pattern"):
            DeployCheck(
                type=DeployCheckType.FILTER_COMPLETENESS,
                constraints_ref=["deny"],
                dangerous_pattern="",
            )

    def test_filter_completeness_empty_keywords_rejected(self):
        with pytest.raises(ValidationError, match="keyword"):
            DeployCheck(
                type=DeployCheckType.FILTER_COMPLETENESS,
                constraints_ref=["deny"],
                dangerous_pattern=";;;",
            )

    def test_valid_data_flow_accepted(self):
        dc = DeployCheck(
            type=DeployCheckType.DATA_FLOW,
            source="a",
            forbidden_sink="b",
            flow_edges=[["a", "b"]],
        )
        assert dc.source == "a"

    def test_valid_no_new_access_accepted(self):
        dc = DeployCheck(
            type=DeployCheckType.NO_NEW_ACCESS,
            constraints_ref=["new"],
            baseline_constraints_ref=["old"],
        )
        assert len(dc.constraints_ref) == 1

    def test_valid_filter_completeness_accepted(self):
        dc = DeployCheck(
            type=DeployCheckType.FILTER_COMPLETENESS,
            constraints_ref=["deny"],
            dangerous_pattern="DROP;TABLE",
        )
        assert dc.dangerous_pattern == "DROP;TABLE"


# ── TestLazyImports ──────────────────────────────────────────────────


class TestLazyImports:
    """Test lazy __getattr__ imports in munio and munio.adapters."""

    def test_package_lazy_import_guard(self):
        """munio.Guard loads via lazy import."""
        import munio

        assert munio.Guard is not None

    def test_package_lazy_import_action(self):
        """munio.Action loads via lazy import."""
        import munio

        assert munio.Action is not None

    def test_package_unknown_attr_raises(self):
        """munio.nonexistent → AttributeError."""
        import munio

        with pytest.raises(AttributeError, match="nonexistent"):
            _ = munio.nonexistent  # type: ignore[attr-defined]

    def test_adapters_lazy_import_create_crew_hook(self):
        """munio.adapters.create_crew_hook loads via lazy import."""
        import munio.adapters

        assert munio.adapters.create_crew_hook is not None

    def test_adapters_unknown_attr_raises(self):
        """munio.adapters.nonexistent → AttributeError."""
        import munio.adapters

        with pytest.raises(AttributeError, match="nonexistent"):
            _ = munio.adapters.nonexistent  # type: ignore[attr-defined]

    def test_cli_module_getattr_app(self):
        """munio.cli.app loads via module __getattr__."""
        import munio.cli

        assert munio.cli.app is not None

    def test_cli_module_getattr_unknown_raises(self):
        """munio.cli.nonexistent → AttributeError."""
        import munio.cli

        with pytest.raises(AttributeError, match="nonexistent"):
            _ = munio.cli.nonexistent  # type: ignore[attr-defined]


# ── S1: Polynomial ReDoS detection ──────────────────────────────────


class TestPolyReDoSDetection:
    """Tests for S1: _POLY_REDOS_RE rejects 5+ consecutive quantified atoms.

    Patterns with 5+ consecutive quantified atoms cause polynomial O(n^k) or
    exponential backtracking. The regex validator rejects them at model creation.
    """

    @pytest.mark.parametrize(
        "pattern",
        [
            r"[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+",
            r"a*a*a*a*a*",
            r"\d+\d+\d+\d+\d+",
            r"\w+\w+\w+\w+\w+",
            r".*.*.*.*.*",
            r".+.+.+.+.+",
            r"[0-9]+[0-9]+[0-9]+[0-9]+[0-9]+",
            r"a+b+c+d+e+",
            r"\s*\s*\s*\s*\s*",
        ],
        ids=[
            "char-class-plus-5",
            "literal-star-5",
            "digit-plus-5",
            "word-plus-5",
            "dot-star-5",
            "dot-plus-5",
            "range-plus-5",
            "mixed-literal-plus-5",
            "space-star-5",
        ],
    )
    def test_5_plus_consecutive_quantified_atoms_rejected(self, pattern: str) -> None:
        """Patterns with 5+ consecutive quantified atoms are rejected."""
        with pytest.raises(ValidationError, match="quantified atoms"):
            ConstraintCheck(
                type=CheckType.REGEX_DENY,
                field="query",
                patterns=[pattern],
            )

    @pytest.mark.parametrize(
        "pattern",
        [
            r"[a-z]+[a-z]+[a-z]+",
            r"a+b+c+",
            r"\d+\d+\d+\d+",
            r"[a-z]+[0-9]+[a-z]+[0-9]+",
            r".*DROP.*TABLE.*",
            r"\w+@\w+\.\w+",
        ],
        ids=[
            "char-class-plus-3",
            "literal-plus-3",
            "digit-plus-4",
            "mixed-plus-4",
            "dot-star-3",
            "email-like",
        ],
    )
    def test_3_to_4_consecutive_quantified_atoms_accepted(self, pattern: str) -> None:
        """Patterns with 3-4 consecutive quantified atoms are accepted."""
        check = ConstraintCheck(
            type=CheckType.REGEX_DENY,
            field="query",
            patterns=[pattern],
        )
        assert len(check.patterns) == 1

    def test_poly_redos_in_values_match_regex_rejected(self) -> None:
        """Poly ReDoS patterns in values (match=regex) are also rejected."""
        with pytest.raises(ValidationError, match="quantified atoms"):
            ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=[r"[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+"],
                match=MatchMode.REGEX,
            )


# ── S5: Empty regex pattern rejection ────────────────────────────────


class TestEmptyRegexPatternRejection:
    """Tests for S5: empty string in patterns list is rejected.

    An empty regex matches everything, which would silently allow-all
    or deny-all depending on check type.
    """

    def test_empty_pattern_regex_deny_rejected(self) -> None:
        """ConstraintCheck(type=regex_deny, patterns=[""]) raises ValidationError."""
        with pytest.raises(ValidationError, match="empty"):
            ConstraintCheck(
                type=CheckType.REGEX_DENY,
                field="query",
                patterns=[""],
            )

    def test_empty_pattern_regex_allow_rejected(self) -> None:
        """ConstraintCheck(type=regex_allow, patterns=[""]) raises ValidationError."""
        with pytest.raises(ValidationError, match="empty"):
            ConstraintCheck(
                type=CheckType.REGEX_ALLOW,
                field="url",
                patterns=[""],
            )

    def test_empty_pattern_among_valid_rejected(self) -> None:
        """Even one empty pattern in a list of valid patterns is rejected."""
        with pytest.raises(ValidationError, match="empty"):
            ConstraintCheck(
                type=CheckType.REGEX_DENY,
                field="query",
                patterns=[r"DROP\s+TABLE", ""],
            )

    def test_empty_value_in_denylist_rejected(self) -> None:
        """Empty string in denylist values is also rejected."""
        with pytest.raises(ValidationError, match="empty"):
            ConstraintCheck(
                type=CheckType.DENYLIST,
                field="url",
                values=[""],
            )

    def test_empty_value_in_allowlist_rejected(self) -> None:
        """Empty string in allowlist values is also rejected."""
        with pytest.raises(ValidationError, match="empty"):
            ConstraintCheck(
                type=CheckType.ALLOWLIST,
                field="url",
                values=[""],
            )


# ── COMPOSITE model validation tests ────────────────────────────────────────


def _cv(field: str = "x", **kwargs: object) -> CompositeVariable:
    """Shorthand to create a CompositeVariable."""
    return CompositeVariable(field=field, **kwargs)  # type: ignore[arg-type]


class TestCompositeVariable:
    """Tests for CompositeVariable model validation."""

    def test_valid_defaults(self) -> None:
        v = CompositeVariable(field="cost")
        assert v.type == "int"
        assert v.min is None
        assert v.max is None
        assert v.default is None

    @pytest.mark.parametrize(
        ("attr", "val"),
        [
            ("min", float("nan")),
            ("max", float("nan")),
            ("default", float("nan")),
            ("min", float("inf")),
            ("max", float("-inf")),
            ("default", float("inf")),
        ],
        ids=["min-nan", "max-nan", "default-nan", "min-inf", "max-neginf", "default-inf"],
    )
    def test_nan_inf_rejected(self, attr: str, val: float) -> None:
        with pytest.raises(ValidationError, match="finite"):
            CompositeVariable(field="x", **{attr: val})

    def test_min_greater_than_max_rejected(self) -> None:
        with pytest.raises(ValidationError, match=r"min.*>.*max"):
            CompositeVariable(field="x", min=100, max=10)

    def test_default_below_min_rejected(self) -> None:
        with pytest.raises(ValidationError, match=r"default.*<.*min"):
            CompositeVariable(field="x", min=10, default=5)

    def test_default_above_max_rejected(self) -> None:
        with pytest.raises(ValidationError, match=r"default.*>.*max"):
            CompositeVariable(field="x", max=100, default=200)

    def test_real_type(self) -> None:
        v = CompositeVariable(field="price", type="real")
        assert v.type == "real"

    def test_frozen(self) -> None:
        v = CompositeVariable(field="x")
        with pytest.raises(ValidationError):
            v.field = "y"  # type: ignore[misc]

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Extra inputs"):
            CompositeVariable(field="x", unknown="val")  # type: ignore[call-arg]


class TestCompositeConstraintCheck:
    """Tests for COMPOSITE type in ConstraintCheck validation."""

    def test_valid_composite(self) -> None:
        check = ConstraintCheck(
            type=CheckType.COMPOSITE,
            field="*",
            variables={"x": _cv("cost"), "y": _cv("qty")},
            expression="x * y <= 10000",
        )
        assert check.type == CheckType.COMPOSITE
        assert len(check.variables) == 2

    def test_missing_expression_rejected(self) -> None:
        with pytest.raises(ValidationError, match="expression"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("cost")},
                expression="",
            )

    def test_missing_variables_rejected(self) -> None:
        with pytest.raises(ValidationError, match="variables"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={},
                expression="x > 0",
            )

    def test_undeclared_variable_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Undeclared variable"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("cost")},
                expression="x + y <= 100",
            )

    @pytest.mark.parametrize(
        ("expr", "match_msg"),
        [
            ("__import__('os')", "Disallowed AST node"),
            ("x.__class__", "Disallowed AST node"),
            ("x[0]", "Disallowed AST node"),
            ("x if True else 0", "Disallowed AST node"),
            ("(x := 5)", "Disallowed AST node"),
            ("lambda: x", "Disallowed AST node"),
        ],
        ids=["call", "attribute", "subscript", "ifexp", "namedexpr", "lambda"],
    )
    def test_dangerous_ast_nodes_rejected(self, expr: str, match_msg: str) -> None:
        with pytest.raises(ValidationError, match=match_msg):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression=expr,
            )

    @pytest.mark.parametrize(
        "expr",
        ["x // 2 > 0", "x % 3 == 0"],
        ids=["floordiv", "mod"],
    )
    def test_floordiv_mod_rejected(self, expr: str) -> None:
        """FloorDiv and Mod rejected: Python vs Z3 semantics differ for negatives."""
        with pytest.raises(ValidationError, match="Disallowed AST node"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression=expr,
            )

    def test_bool_constant_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Boolean constant"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression="True + x",
            )

    @pytest.mark.parametrize(
        ("expr", "match_msg"),
        [
            ('"hello" + x', "Disallowed constant type"),
            ("None", "Disallowed constant type"),
            ("1j + x", "Disallowed constant type"),
        ],
        ids=["str", "none", "complex"],
    )
    def test_disallowed_constant_types(self, expr: str, match_msg: str) -> None:
        with pytest.raises(ValidationError, match=match_msg):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression=expr,
            )

    def test_constant_only_expression_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least one variable"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression="42",
            )

    def test_expression_too_long_rejected(self) -> None:
        long_expr = "x + " * 126  # 504 chars > 500
        with pytest.raises(ValidationError, match="500"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression=long_expr.rstrip(" +") + " + x",
            )

    def test_too_many_variables_rejected(self) -> None:
        variables = {f"v{i}": _cv(f"f{i}") for i in range(21)}
        with pytest.raises(ValidationError, match="20"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables=variables,
                expression=" + ".join(variables),
            )

    def test_ast_depth_exceeded_rejected(self) -> None:
        # Deeply nested: ((((((((((x + 1) + 1) + 1) ...)))))))
        expr = "x"
        for _ in range(11):
            expr = f"({expr} + 1)"
        with pytest.raises(ValidationError, match="depth"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression=expr,
            )

    @pytest.mark.parametrize(
        ("name", "match_msg"),
        [
            ("__builtins__", "must match"),  # starts with _ — rejected by regex
            ("import", "keyword"),
            ("abs", "builtin"),
            ("123bad", "must match"),
            ("a b", "must match"),
            ("", "must match"),
        ],
        ids=["dunder", "keyword", "builtin", "leading-digit", "space", "empty"],
    )
    def test_invalid_variable_names(self, name: str, match_msg: str) -> None:
        with pytest.raises(ValidationError, match=match_msg):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={name: _cv("val")},
                expression=f"{name} > 0",
            )

    def test_composite_with_values_rejected(self) -> None:
        with pytest.raises(ValidationError, match="values"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression="x > 0",
                values=["bad"],
            )

    def test_composite_with_patterns_rejected(self) -> None:
        with pytest.raises(ValidationError, match="patterns"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression="x > 0",
                patterns=["bad"],
            )

    def test_composite_with_min_max_rejected(self) -> None:
        with pytest.raises(ValidationError, match=r"min.*max"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression="x > 0",
                min=0,
            )

    def test_round_trip_serialization(self) -> None:
        check = ConstraintCheck(
            type=CheckType.COMPOSITE,
            field="*",
            variables={"cost": _cv("cost", type="int", min=0, max=10000)},
            expression="cost <= 5000",
        )
        data = check.model_dump()
        restored = ConstraintCheck.model_validate(data)
        assert restored == check

    def test_composite_constraint_full(self) -> None:
        """Full Constraint with COMPOSITE check parses correctly."""
        c = Constraint(
            name="spend-limit",
            action="purchase",
            tier=Tier.TIER_2,
            check=ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={
                    "cost": _cv("cost", type="int", min=0),
                    "qty": _cv("quantity", type="int", min=1, max=10000),
                    "budget": _cv("budget", type="int", default=10000),
                },
                expression="cost * qty <= budget",
            ),
        )
        assert c.tier == Tier.TIER_2
        assert c.check is not None
        assert len(c.check.variables) == 3
        assert c.check.variables["budget"].default == 10000

    def test_pow_operator_rejected(self) -> None:
        """** (Pow) is not in the AST whitelist — prevents CPU/memory DoS."""
        with pytest.raises(ValidationError, match="Disallowed AST node"):
            ConstraintCheck(
                type=CheckType.COMPOSITE,
                field="*",
                variables={"x": _cv("val")},
                expression="x ** 2",
            )


# ── RATE_LIMIT model validation tests ────────────────────────────────────────


class TestRateLimitValidation:
    """Tests for RATE_LIMIT check type field validation."""

    @pytest.mark.parametrize(
        ("kwargs", "desc"),
        [
            (
                {"type": CheckType.RATE_LIMIT, "field": "*", "window_seconds": 60, "max_count": 10},
                "basic-valid",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "*",
                    "window_seconds": 60,
                    "max_count": 10,
                    "scope": "agent",
                },
                "scope-agent",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "*",
                    "window_seconds": 1.0,
                    "max_count": 1,
                },
                "min-boundary",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "*",
                    "window_seconds": 86400,
                    "max_count": 1_000_000,
                },
                "max-boundary",
            ),
        ],
        ids=["basic-valid", "scope-agent", "min-boundary", "max-boundary"],
    )
    def test_valid_rate_limit(self, kwargs: dict, desc: str) -> None:
        """Valid RATE_LIMIT configurations are accepted."""
        check = ConstraintCheck(**kwargs)
        assert check.type == CheckType.RATE_LIMIT
        assert check.window_seconds is not None
        assert check.max_count is not None

    @pytest.mark.parametrize(
        ("kwargs", "match_msg", "desc"),
        [
            (
                {"type": CheckType.RATE_LIMIT, "field": "*", "max_count": 10},
                "window_seconds",
                "missing-window",
            ),
            (
                {"type": CheckType.RATE_LIMIT, "field": "*", "window_seconds": 60},
                "max_count",
                "missing-max-count",
            ),
            (
                {"type": CheckType.RATE_LIMIT, "field": "*", "window_seconds": 0, "max_count": 10},
                "must be >= 1",
                "window-zero",
            ),
            (
                {"type": CheckType.RATE_LIMIT, "field": "*", "window_seconds": -1, "max_count": 10},
                "must be >= 1",
                "window-negative",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "*",
                    "window_seconds": 86401,
                    "max_count": 10,
                },
                "must be <=",
                "window-exceeds-max",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "*",
                    "window_seconds": float("nan"),
                    "max_count": 10,
                },
                "must be finite",
                "window-nan",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "*",
                    "window_seconds": float("inf"),
                    "max_count": 10,
                },
                "must be <=",
                "window-inf",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "*",
                    "window_seconds": float("-inf"),
                    "max_count": 10,
                },
                "must be >= 1",
                "window-neg-inf",
            ),
            (
                {"type": CheckType.RATE_LIMIT, "field": "*", "window_seconds": 60, "max_count": 0},
                "must be >= 1",
                "max-count-zero",
            ),
            (
                {"type": CheckType.RATE_LIMIT, "field": "*", "window_seconds": 60, "max_count": -1},
                "must be >= 1",
                "max-count-negative",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "*",
                    "window_seconds": 60,
                    "max_count": 1_000_001,
                },
                "must be <=",
                "max-count-exceeds-max",
            ),
            (
                {
                    "type": CheckType.RATE_LIMIT,
                    "field": "url",
                    "window_seconds": 60,
                    "max_count": 10,
                },
                "field='\\*'",
                "field-not-star",
            ),
        ],
        ids=[
            "missing-window",
            "missing-max-count",
            "window-zero",
            "window-negative",
            "window-exceeds-max",
            "window-nan",
            "window-inf",
            "window-neg-inf",
            "max-count-zero",
            "max-count-negative",
            "max-count-exceeds-max",
            "field-not-star",
        ],
    )
    def test_invalid_rate_limit(self, kwargs: dict, match_msg: str, desc: str) -> None:
        """Invalid RATE_LIMIT configurations are rejected."""
        with pytest.raises(ValidationError, match=match_msg):
            ConstraintCheck(**kwargs)

    @pytest.mark.parametrize(
        ("forbidden_field", "forbidden_value"),
        [
            ("values", ["evil.com"]),
            ("patterns", [r"DROP\s+TABLE"]),
            ("min", 0),
            ("max", 100),
            ("variables", {"x": _cv("cost")}),
            ("expression", "x > 0"),
            ("steps", ["read_file", "exec"]),
        ],
        ids=["values", "patterns", "min", "max", "variables", "expression", "steps"],
    )
    def test_rate_limit_rejects_forbidden_fields(
        self, forbidden_field: str, forbidden_value: object
    ) -> None:
        """RATE_LIMIT must not have non-temporal or steps fields."""
        kwargs = {
            "type": CheckType.RATE_LIMIT,
            "field": "*",
            "window_seconds": 60,
            "max_count": 10,
            forbidden_field: forbidden_value,
        }
        with pytest.raises(ValidationError, match=forbidden_field):
            ConstraintCheck(**kwargs)


# ── SEQUENCE_DENY model validation tests ──────────────────────────────────────


class TestSequenceDenyValidation:
    """Tests for SEQUENCE_DENY check type field validation."""

    @pytest.mark.parametrize(
        ("kwargs", "desc"),
        [
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "exec"],
                    "window_seconds": 300,
                },
                "2-step",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": [f"step{i}" for i in range(10)],
                    "window_seconds": 600,
                },
                "10-step-max",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "exec"],
                    "window_seconds": 300,
                    "scope": "agent",
                },
                "scope-agent",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_*", "http_*"],
                    "window_seconds": 1.0,
                },
                "glob-patterns",
            ),
        ],
        ids=["2-step", "10-step-max", "scope-agent", "glob-patterns"],
    )
    def test_valid_sequence_deny(self, kwargs: dict, desc: str) -> None:
        """Valid SEQUENCE_DENY configurations are accepted."""
        check = ConstraintCheck(**kwargs)
        assert check.type == CheckType.SEQUENCE_DENY
        assert len(check.steps) >= 2

    @pytest.mark.parametrize(
        ("kwargs", "match_msg", "desc"),
        [
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": [],
                    "window_seconds": 300,
                },
                "non-empty 'steps'",
                "empty-steps",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["only_one"],
                    "window_seconds": 300,
                },
                "at least 2 steps",
                "1-step",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": [f"s{i}" for i in range(11)],
                    "window_seconds": 300,
                },
                "max",
                "11-steps-exceeds-max",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", ""],
                    "window_seconds": 300,
                },
                "empty or whitespace",
                "empty-string-in-step",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "x" * 257],
                    "window_seconds": 300,
                },
                "exceeds max",
                "step-too-long",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "exec"],
                },
                "window_seconds",
                "missing-window",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "exec"],
                    "window_seconds": 0,
                },
                "must be >= 1",
                "window-zero",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "exec"],
                    "window_seconds": -5,
                },
                "must be >= 1",
                "window-negative",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "exec"],
                    "window_seconds": 86401,
                },
                "must be <=",
                "window-exceeds-max",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "exec"],
                    "window_seconds": float("nan"),
                },
                "must be finite",
                "window-nan",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "*",
                    "steps": ["read_file", "exec"],
                    "window_seconds": float("inf"),
                },
                "must be <=",
                "window-inf",
            ),
            (
                {
                    "type": CheckType.SEQUENCE_DENY,
                    "field": "url",
                    "steps": ["read_file", "exec"],
                    "window_seconds": 300,
                },
                "field='\\*'",
                "field-not-star",
            ),
        ],
        ids=[
            "empty-steps",
            "1-step",
            "11-steps-exceeds-max",
            "empty-string-in-step",
            "step-too-long",
            "missing-window",
            "window-zero",
            "window-negative",
            "window-exceeds-max",
            "window-nan",
            "window-inf",
            "field-not-star",
        ],
    )
    def test_invalid_sequence_deny(self, kwargs: dict, match_msg: str, desc: str) -> None:
        """Invalid SEQUENCE_DENY configurations are rejected."""
        with pytest.raises(ValidationError, match=match_msg):
            ConstraintCheck(**kwargs)

    @pytest.mark.parametrize(
        ("forbidden_field", "forbidden_value"),
        [
            ("values", ["evil.com"]),
            ("patterns", [r"DROP\s+TABLE"]),
            ("min", 0),
            ("max", 100),
            ("variables", {"x": _cv("cost")}),
            ("expression", "x > 0"),
            ("max_count", 10),
        ],
        ids=["values", "patterns", "min", "max", "variables", "expression", "max-count"],
    )
    def test_sequence_deny_rejects_forbidden_fields(
        self, forbidden_field: str, forbidden_value: object
    ) -> None:
        """SEQUENCE_DENY must not have non-temporal or max_count fields."""
        kwargs = {
            "type": CheckType.SEQUENCE_DENY,
            "field": "*",
            "steps": ["read_file", "exec"],
            "window_seconds": 300,
            forbidden_field: forbidden_value,
        }
        with pytest.raises(ValidationError, match=forbidden_field):
            ConstraintCheck(**kwargs)


# ── Temporal field exclusion tests ───────────────────────────────────────────


class TestTemporalFieldExclusion:
    """Tests that non-temporal check types reject temporal fields.

    Non-temporal types: denylist, allowlist, threshold, regex_deny, regex_allow, composite.
    Temporal fields: window_seconds, max_count, steps, scope (non-default).
    """

    @pytest.mark.parametrize(
        ("check_type", "base_kwargs"),
        [
            (
                CheckType.DENYLIST,
                {"field": "url", "values": ["evil.com"]},
            ),
            (
                CheckType.ALLOWLIST,
                {"field": "url", "values": ["safe.com"]},
            ),
            (
                CheckType.THRESHOLD,
                {"field": "cost", "max": 100},
            ),
            (
                CheckType.REGEX_DENY,
                {"field": "cmd", "patterns": [r"DROP\s+TABLE"]},
            ),
            (
                CheckType.REGEX_ALLOW,
                {"field": "url", "patterns": [r"^https://api\.example\.com/"]},
            ),
            (
                CheckType.COMPOSITE,
                {"field": "*", "variables": {"x": _cv("cost")}, "expression": "x > 0"},
            ),
        ],
        ids=["denylist", "allowlist", "threshold", "regex_deny", "regex_allow", "composite"],
    )
    @pytest.mark.parametrize(
        ("temporal_field", "temporal_value", "match_msg"),
        [
            ("window_seconds", 60.0, "window_seconds"),
            ("max_count", 10, "max_count"),
            ("steps", ["read_file", "exec"], "steps"),
            ("scope", "agent", "scope"),
        ],
        ids=["window_seconds", "max_count", "steps", "scope-agent"],
    )
    def test_non_temporal_rejects_temporal_field(
        self,
        check_type: CheckType,
        base_kwargs: dict,
        temporal_field: str,
        temporal_value: object,
        match_msg: str,
    ) -> None:
        """Non-temporal check types must reject temporal fields with ValueError."""
        kwargs = {"type": check_type, **base_kwargs, temporal_field: temporal_value}
        with pytest.raises(ValidationError, match=match_msg):
            ConstraintCheck(**kwargs)


# ── Review Round 12 model validation tests ──────────────────────────────────


class TestReviewRound12ModelValidation:
    """Tests for M1 (min window), M2 (whitespace steps), M3 (bool rejection)."""

    # ── M3: bool coercion behavior ──
    #
    # Pydantic v2 coerces bool→float and bool→int in non-strict mode BEFORE
    # the model validator runs, so isinstance(val, bool) can never fire.
    # Protection relies on numeric bounds instead:
    # - True → 1.0/1 (passes min check for both window_seconds and max_count)
    # - False → 0.0/0 (rejected by min_window_seconds=1.0 / max_count>=1)

    def test_rate_limit_window_false_rejected_as_too_low(self) -> None:
        """False coerced to 0.0 → rejected by min window check (M3)."""
        with pytest.raises(ValidationError, match="must be >= 1"):
            ConstraintCheck(
                type=CheckType.RATE_LIMIT,
                field="*",
                window_seconds=False,
                max_count=10,  # type: ignore[arg-type]
            )

    def test_rate_limit_max_count_false_rejected(self) -> None:
        """False coerced to 0 → rejected by max_count >= 1 (M3)."""
        with pytest.raises(ValidationError, match="must be >= 1"):
            ConstraintCheck(
                type=CheckType.RATE_LIMIT,
                field="*",
                window_seconds=60,
                max_count=False,  # type: ignore[arg-type]
            )

    def test_sequence_deny_window_false_rejected(self) -> None:
        """False coerced to 0.0 → rejected by min window check (M3)."""
        with pytest.raises(ValidationError, match="must be >= 1"):
            ConstraintCheck(
                type=CheckType.SEQUENCE_DENY,
                field="*",
                steps=["read_file", "exec"],
                window_seconds=False,  # type: ignore[arg-type]
            )

    # ── M1: minimum window_seconds ──

    @pytest.mark.parametrize(
        ("window", "desc"),
        [(0.5, "half-sec"), (0.001, "sub-ms"), (0.999, "just-under-1")],
        ids=["half-sec", "sub-ms", "just-under-1"],
    )
    def test_rate_limit_sub_second_window_rejected(self, window: float, desc: str) -> None:
        """RATE_LIMIT rejects window_seconds < 1.0 (M1 fix)."""
        with pytest.raises(ValidationError, match="must be >= 1"):
            ConstraintCheck(
                type=CheckType.RATE_LIMIT,
                field="*",
                window_seconds=window,
                max_count=10,
            )

    @pytest.mark.parametrize(
        ("window", "desc"),
        [(0.5, "half-sec"), (0.001, "sub-ms"), (0.999, "just-under-1")],
        ids=["half-sec", "sub-ms", "just-under-1"],
    )
    def test_sequence_deny_sub_second_window_rejected(self, window: float, desc: str) -> None:
        """SEQUENCE_DENY rejects window_seconds < 1.0 (M1 fix)."""
        with pytest.raises(ValidationError, match="must be >= 1"):
            ConstraintCheck(
                type=CheckType.SEQUENCE_DENY,
                field="*",
                steps=["read_file", "exec"],
                window_seconds=window,
            )

    def test_rate_limit_exactly_1_second_accepted(self) -> None:
        """RATE_LIMIT accepts window_seconds=1.0 (boundary)."""
        check = ConstraintCheck(
            type=CheckType.RATE_LIMIT,
            field="*",
            window_seconds=1.0,
            max_count=10,
        )
        assert check.window_seconds == 1.0

    def test_sequence_deny_exactly_1_second_accepted(self) -> None:
        """SEQUENCE_DENY accepts window_seconds=1.0 (boundary)."""
        check = ConstraintCheck(
            type=CheckType.SEQUENCE_DENY,
            field="*",
            steps=["read_file", "exec"],
            window_seconds=1.0,
        )
        assert check.window_seconds == 1.0

    # ── M2: whitespace-only steps ──

    @pytest.mark.parametrize(
        ("step", "desc"),
        [("  ", "spaces"), ("\t", "tab"), (" \t\n ", "mixed-ws"), ("\n", "newline")],
        ids=["spaces", "tab", "mixed-ws", "newline"],
    )
    def test_sequence_deny_whitespace_only_step_rejected(self, step: str, desc: str) -> None:
        """SEQUENCE_DENY rejects whitespace-only steps (M2 fix)."""
        with pytest.raises(ValidationError, match="empty or whitespace"):
            ConstraintCheck(
                type=CheckType.SEQUENCE_DENY,
                field="*",
                steps=["read_file", step],
                window_seconds=300,
            )
