"""Tests for L6 protocol analysis models."""

from __future__ import annotations

from typing import Any

import pytest

from munio.gate.protocol_models import (
    ElicitationConfig,
    McpCapabilities,
    NotificationConfig,
    ProtocolAction,
    ProtocolConfig,
    ProtocolViolation,
    ProtocolViolationType,
    SamplingConfig,
    SessionConfig,
    SessionPhase,
    ToolRegistryConfig,
    ToolSnapshot,
)


# ── ProtocolViolationType ────────────────────────────────────────────


class TestProtocolViolationType:
    @pytest.mark.parametrize(
        "member,value",
        [
            (ProtocolViolationType.INIT_RACE_WINDOW, "IRWE"),
            (ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION, "CPE"),
            (ProtocolViolationType.NOTIFICATION_STORM_DESYNC, "NSD"),
            (ProtocolViolationType.TOOL_LIST_MUTATION, "TLM"),
            (ProtocolViolationType.PROGRESS_TIMEOUT_ABUSE, "PTTRA"),
            (ProtocolViolationType.SAMPLING_RECURSIVE_AMPLIFICATION, "SRAL"),
            (ProtocolViolationType.ELICITATION_PHISHING, "ECPC"),
            (ProtocolViolationType.TRANSPORT_DOWNGRADE, "TDBCP"),
        ],
    )
    def test_violation_type_values(self, member: ProtocolViolationType, value: str) -> None:
        assert member.value == value


# ── ProtocolViolation ────────────────────────────────────────────────


class TestProtocolViolation:
    def test_create_violation(self) -> None:
        v = ProtocolViolation(
            violation_type=ProtocolViolationType.INIT_RACE_WINDOW,
            action=ProtocolAction.BLOCK,
            message="Tool call before init",
            monitor="SessionStateMonitor",
        )
        assert v.violation_type == ProtocolViolationType.INIT_RACE_WINDOW
        assert v.action == ProtocolAction.BLOCK
        assert v.details == {}

    def test_violation_with_details(self) -> None:
        v = ProtocolViolation(
            violation_type=ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION,
            action=ProtocolAction.ALERT,
            message="CPE detected",
            details={"method": "sampling/createMessage"},
            monitor="SessionStateMonitor",
        )
        assert v.details["method"] == "sampling/createMessage"

    def test_violation_frozen(self) -> None:
        v = ProtocolViolation(
            violation_type=ProtocolViolationType.INIT_RACE_WINDOW,
            action=ProtocolAction.BLOCK,
            message="test",
            monitor="test",
        )
        with pytest.raises(Exception):
            v.action = ProtocolAction.ALERT  # type: ignore[misc]


# ── SessionPhase ─────────────────────────────────────────────────────


class TestSessionPhase:
    @pytest.mark.parametrize(
        "phase,value",
        [
            (SessionPhase.AWAITING_INIT, "awaiting_init"),
            (SessionPhase.INITIALIZING, "initializing"),
            (SessionPhase.INITIALIZED, "initialized"),
            (SessionPhase.OPERATING, "operating"),
            (SessionPhase.SHUTTING_DOWN, "shutting_down"),
        ],
    )
    def test_phase_values(self, phase: SessionPhase, value: str) -> None:
        assert phase.value == value


# ── McpCapabilities ──────────────────────────────────────────────────


class TestMcpCapabilities:
    def test_from_empty_result(self) -> None:
        caps = McpCapabilities.from_initialize_result({})
        assert not caps.tools
        assert not caps.sampling
        assert not caps.elicitation

    def test_from_full_result(self) -> None:
        result: dict[str, Any] = {
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True},
                "prompts": {"listChanged": True},
                "logging": {},
                "sampling": {},
                "roots": {"listChanged": True},
                "elicitation": {},
            }
        }
        caps = McpCapabilities.from_initialize_result(result)
        assert caps.tools
        assert caps.resources
        assert caps.prompts
        assert caps.logging
        assert caps.sampling
        assert caps.roots
        assert caps.elicitation

    def test_partial_capabilities(self) -> None:
        result: dict[str, Any] = {
            "capabilities": {
                "tools": {"listChanged": True},
            }
        }
        caps = McpCapabilities.from_initialize_result(result)
        assert caps.tools
        assert not caps.resources
        assert not caps.sampling

    def test_non_dict_capabilities(self) -> None:
        result: dict[str, Any] = {"capabilities": "invalid"}
        caps = McpCapabilities.from_initialize_result(result)
        assert not caps.tools


# ── SessionConfig ────────────────────────────────────────────────────


class TestSessionConfig:
    def test_defaults(self) -> None:
        c = SessionConfig()
        assert c.require_initialization is True
        assert c.max_init_timeout_ms == 5000
        assert c.block_capability_escalation is True

    def test_custom_values(self) -> None:
        c = SessionConfig(max_init_timeout_ms=10000, require_initialization=False)
        assert c.max_init_timeout_ms == 10000
        assert c.require_initialization is False

    @pytest.mark.parametrize("bad_timeout", [50, 70000])
    def test_timeout_bounds(self, bad_timeout: int) -> None:
        with pytest.raises(Exception):
            SessionConfig(max_init_timeout_ms=bad_timeout)


# ── NotificationConfig ───────────────────────────────────────────────


class TestNotificationConfig:
    def test_defaults(self) -> None:
        c = NotificationConfig()
        assert c.max_list_changed_per_minute == 10
        assert c.max_progress_per_request == 100
        assert c.progress_timeout_ms == 120_000

    @pytest.mark.parametrize("bad_rate", [0, -1])
    def test_rate_bounds(self, bad_rate: int) -> None:
        with pytest.raises(Exception):
            NotificationConfig(max_list_changed_per_minute=bad_rate)


# ── SamplingConfig ───────────────────────────────────────────────────


class TestSamplingConfig:
    def test_defaults(self) -> None:
        c = SamplingConfig()
        assert c.max_depth == 3
        assert c.max_cost_budget_usd == 1.0

    def test_max_depth_bounds(self) -> None:
        with pytest.raises(Exception):
            SamplingConfig(max_depth=0)
        with pytest.raises(Exception):
            SamplingConfig(max_depth=25)


# ── ElicitationConfig ────────────────────────────────────────────────


class TestElicitationConfig:
    def test_domains_lowercased(self) -> None:
        c = ElicitationConfig(allowed_domains=["GitHub.COM", " Example.ORG "])
        assert c.allowed_domains == ["github.com", "example.org"]

    def test_empty_domains_stripped(self) -> None:
        c = ElicitationConfig(allowed_domains=["valid.com", "", " "])
        assert c.allowed_domains == ["valid.com"]


# ── ToolSnapshot ─────────────────────────────────────────────────────


class TestToolSnapshot:
    def test_create(self) -> None:
        snap = ToolSnapshot(
            version=1,
            tool_names=("a", "b", "c"),
            tool_hash="abc123",
            tool_count=3,
        )
        assert snap.version == 1
        assert len(snap.tool_names) == 3


# ── ProtocolConfig ───────────────────────────────────────────────────


class TestProtocolConfig:
    def test_defaults(self) -> None:
        c = ProtocolConfig()
        assert c.enabled is True
        assert c.session.require_initialization is True
        assert c.notifications.max_list_changed_per_minute == 10
        assert c.sampling.max_depth == 3

    def test_disabled(self) -> None:
        c = ProtocolConfig(enabled=False)
        assert c.enabled is False

    def test_nested_override(self) -> None:
        c = ProtocolConfig(
            session=SessionConfig(max_init_timeout_ms=10000),
            sampling=SamplingConfig(max_depth=5),
        )
        assert c.session.max_init_timeout_ms == 10000
        assert c.sampling.max_depth == 5
