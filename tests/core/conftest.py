"""Shared test helpers for unit tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from munio.constraints import ConstraintRegistry
from munio.models import (
    Action,
    CheckType,
    CompositeVariable,
    Constraint,
    ConstraintCheck,
    DeployCheck,
    MatchMode,
    OnViolation,
    Tier,
    ViolationSeverity,
)

CONSTRAINTS_DIR = Path(__file__).parent.parent.parent / "constraints"


def make_registry(*constraints: Constraint) -> ConstraintRegistry:
    return ConstraintRegistry(constraints)


def make_action(tool: str = "http_request", **args: object) -> Action:
    return Action(tool=tool, args=dict(args))


def make_denylist_constraint(
    values: list[str],
    field: str = "url",
    match: MatchMode = MatchMode.CONTAINS,
    case_sensitive: bool = True,
    action: str = "*",
    name: str = "test-deny",
    on_violation: OnViolation = OnViolation.BLOCK,
    severity: ViolationSeverity = ViolationSeverity.CRITICAL,
) -> Constraint:
    return Constraint(
        name=name,
        action=action,
        check=ConstraintCheck(
            type=CheckType.DENYLIST,
            field=field,
            values=values,
            match=match,
            case_sensitive=case_sensitive,
        ),
        on_violation=on_violation,
        severity=severity,
    )


def make_allowlist_constraint(
    values: list[str],
    field: str = "url",
    match: MatchMode = MatchMode.PREFIX,
    case_sensitive: bool = True,
    name: str = "test-allow",
    on_violation: OnViolation = OnViolation.BLOCK,
) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(
            type=CheckType.ALLOWLIST,
            field=field,
            values=values,
            match=match,
            case_sensitive=case_sensitive,
        ),
        on_violation=on_violation,
    )


def make_threshold_constraint(
    min_val: float | None = None,
    max_val: float | None = None,
    field: str = "cost",
    name: str = "test-threshold",
    on_violation: OnViolation = OnViolation.BLOCK,
) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(type=CheckType.THRESHOLD, field=field, min=min_val, max=max_val),
        on_violation=on_violation,
    )


def make_regex_constraint(
    patterns: list[str],
    check_type: CheckType = CheckType.REGEX_DENY,
    field: str = "query",
    name: str = "test-regex",
) -> Constraint:
    return Constraint(
        name=name,
        check=ConstraintCheck(type=check_type, field=field, patterns=patterns),
    )


def make_tier4_constraint(
    deploy_check: DeployCheck,
    name: str = "test-tier4",
) -> Constraint:
    return Constraint(
        name=name,
        tier=Tier.TIER_4,
        deploy_check=deploy_check,
    )


def make_rate_limit_constraint(
    max_count: int = 10,
    window_seconds: float = 60,
    scope: str = "global",
    action: str = "*",
    name: str = "test-rate-limit",
    on_violation: OnViolation = OnViolation.BLOCK,
) -> Constraint:
    """Create a RATE_LIMIT constraint for testing."""
    return Constraint(
        name=name,
        action=action,
        check=ConstraintCheck(
            type=CheckType.RATE_LIMIT,
            field="*",
            max_count=max_count,
            window_seconds=window_seconds,
            scope=scope,
        ),
        on_violation=on_violation,
    )


def make_sequence_deny_constraint(
    steps: list[str] | None = None,
    window_seconds: float = 300,
    scope: str = "agent",
    action: str = "*",
    name: str = "test-sequence-deny",
    on_violation: OnViolation = OnViolation.BLOCK,
) -> Constraint:
    """Create a SEQUENCE_DENY constraint for testing."""
    return Constraint(
        name=name,
        action=action,
        check=ConstraintCheck(
            type=CheckType.SEQUENCE_DENY,
            field="*",
            steps=steps or ["read_file", "http_request"],
            window_seconds=window_seconds,
            scope=scope,
        ),
        on_violation=on_violation,
    )


def make_composite_constraint(
    expression: str,
    variables: dict[str, dict[str, Any]],
    name: str = "test-composite",
    tier: Tier = Tier.TIER_2,
    action: str = "*",
    on_violation: OnViolation = OnViolation.BLOCK,
) -> Constraint:
    """Create a COMPOSITE constraint for testing."""
    return Constraint(
        name=name,
        action=action,
        tier=tier,
        check=ConstraintCheck(
            type=CheckType.COMPOSITE,
            field="*",
            variables={k: CompositeVariable(**v) for k, v in variables.items()},
            expression=expression,
        ),
        on_violation=on_violation,
    )
