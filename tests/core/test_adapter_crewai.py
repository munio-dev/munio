"""Tests for munio.adapters._crewai — CrewAI before_tool_call hook."""

import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

import munio.adapters._crewai as mod
from munio.adapters._crewai import create_crew_hook
from munio.guard import Guard
from munio.models import VerificationMode
from tests.core.conftest import make_denylist_constraint, make_registry


def _make_context(tool_name: str = "http_request", **tool_input: Any) -> SimpleNamespace:
    """Create a fake CrewAI ToolCallHookContext."""
    return SimpleNamespace(tool_name=tool_name, tool_input=dict(tool_input))


def _make_guard(*values: str, field: str = "url") -> Guard:
    """Create a Guard with a denylist constraint."""
    constraint = make_denylist_constraint(list(values), field=field)
    return Guard(registry=make_registry(constraint), mode=VerificationMode.ENFORCE)


class TestCreateCrewHook:
    """Tests for create_crew_hook()."""

    def test_allowed_action_returns_true(self) -> None:
        """Hook returns True when action is allowed."""
        guard = _make_guard("evil.com")
        hook = create_crew_hook(guard)
        ctx = _make_context(url="https://safe.example.com")
        assert hook(ctx) is True

    def test_blocked_action_returns_false(self) -> None:
        """Hook returns False when action is blocked."""
        guard = _make_guard("evil.com")
        hook = create_crew_hook(guard)
        ctx = _make_context(url="https://evil.com/path")
        assert hook(ctx) is False

    def test_extracts_tool_name_and_input(self) -> None:
        """Hook correctly builds Action from context attributes."""
        guard = _make_guard("evil.com")
        hook = create_crew_hook(guard)
        # Tool name doesn't match constraint action pattern "*" → always checked
        ctx = SimpleNamespace(tool_name="custom_tool", tool_input={"url": "evil.com"})
        assert hook(ctx) is False

    def test_missing_tool_input_defaults_to_empty(self) -> None:
        """Hook handles context without tool_input attribute."""
        guard = _make_guard("evil.com")
        hook = create_crew_hook(guard)
        ctx = SimpleNamespace(tool_name="http_request")  # no tool_input
        # No args → no field to match → allowed
        assert hook(ctx) is True

    def test_string_tool_input_wrapped_as_input(self) -> None:
        """String tool_input is wrapped as {'input': value} for constraint checking."""
        guard = _make_guard("evil.com", field="input")
        hook = create_crew_hook(guard)
        ctx = SimpleNamespace(tool_name="http_request", tool_input="evil.com/path")
        assert hook(ctx) is False

    def test_non_string_non_dict_tool_input_is_fail_closed(self) -> None:
        """Non-string, non-dict tool_input → fail-closed (block)."""
        guard = _make_guard("evil.com")
        hook = create_crew_hook(guard)
        ctx = SimpleNamespace(tool_name="http_request", tool_input=12345)
        assert hook(ctx) is False

    def test_missing_tool_name_is_fail_closed(self) -> None:
        """Context without tool_name attribute → fail-closed (block)."""
        guard = _make_guard("evil.com")
        hook = create_crew_hook(guard)
        ctx = SimpleNamespace(tool_input={"url": "safe.com"})  # no tool_name
        assert hook(ctx) is False

    def test_error_is_fail_closed(self, caplog: pytest.LogCaptureFixture) -> None:
        """Unexpected error in Guard.check() → fail-closed (return False)."""
        guard = _make_guard("evil.com")
        hook = create_crew_hook(guard)
        ctx = _make_context(url="https://safe.example.com")
        with (
            patch.object(Guard, "check", side_effect=RuntimeError("boom")),
            caplog.at_level(logging.WARNING),
        ):
            result = hook(ctx)
        assert result is False
        assert "fail-closed" in caplog.text

    def test_logs_violations_on_block(self, caplog: pytest.LogCaptureFixture) -> None:
        """Blocked actions log violation details."""
        guard = _make_guard("evil.com")
        hook = create_crew_hook(guard)
        ctx = _make_context(url="https://evil.com/steal")
        with caplog.at_level(logging.WARNING):
            result = hook(ctx)
        assert result is False
        assert "blocked tool" in caplog.text
        assert "http_request" in caplog.text

    def test_no_crewai_import_needed(self) -> None:
        """Module imports without crewai installed (no framework dep)."""
        # This test itself proves the import works — _crewai.py is already imported above

        assert hasattr(mod, "create_crew_hook")

    def test_openclaw_constraints_enforced(self) -> None:
        """OpenClaw constraints work through the CrewAI adapter."""
        # Use a denylist that simulates OpenClaw-style constraints
        constraint = make_denylist_constraint(
            ["rm -rf", "sudo", "chmod 777"],
            field="command",
            name="openclaw-no-dangerous-commands",
        )
        guard = Guard(registry=make_registry(constraint), mode=VerificationMode.ENFORCE)
        hook = create_crew_hook(guard)

        # Safe command
        ctx = _make_context(tool_name="execute_command", command="ls -la")
        assert hook(ctx) is True

        # Dangerous command
        ctx = _make_context(tool_name="execute_command", command="sudo rm -rf /")
        assert hook(ctx) is False
