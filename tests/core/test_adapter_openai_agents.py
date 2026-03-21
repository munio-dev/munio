"""Tests for munio.adapters._openai_agents — OpenAI Agents SDK guardrail.

Uses mocked openai-agents (agents package) to avoid requiring the framework for CI.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Mock agents package BEFORE importing the adapter ──────────────────


@dataclass
class _FakeGuardrailFunctionOutput:
    """Mock GuardrailFunctionOutput."""

    output_info: dict[str, Any] | None = None
    tripwire_triggered: bool = False


class _FakeInputGuardrail:
    """Mock InputGuardrail."""

    def __init__(self, guardrail_function: Any = None, name: str = "") -> None:
        self.guardrail_function = guardrail_function
        self.name = name


_mock_guardrails = MagicMock()
_mock_guardrails.GuardrailFunctionOutput = _FakeGuardrailFunctionOutput
_mock_guardrails.InputGuardrail = _FakeInputGuardrail

_mock_agents = MagicMock()
_mock_agents.guardrails = _mock_guardrails
sys.modules.setdefault("agents", _mock_agents)
sys.modules.setdefault("agents.guardrails", _mock_guardrails)

from munio.adapters._openai_agents import (  # noqa: E402
    _extract_tool_calls,
    create_guardrail,
)
from munio.guard import Guard  # noqa: E402
from munio.models import VerificationMode  # noqa: E402
from tests.core.conftest import make_denylist_constraint, make_registry  # noqa: E402


def _make_guard(*values: str, field: str = "url") -> Guard:
    constraint = make_denylist_constraint(list(values), field=field)
    return Guard(registry=make_registry(constraint), mode=VerificationMode.ENFORCE)


class TestCreateGuardrail:
    """Tests for create_guardrail()."""

    def test_returns_input_guardrail(self) -> None:
        """Returns an InputGuardrail instance."""
        guard = _make_guard("evil.com")
        result = create_guardrail(guard)
        assert isinstance(result, _FakeInputGuardrail)

    def test_guardrail_has_name(self) -> None:
        """Custom name is propagated."""
        guard = _make_guard("evil.com")
        result = create_guardrail(guard, name="my-guard")
        assert result.name == "my-guard"

    def test_default_name(self) -> None:
        """Default name is 'munio'."""
        guard = _make_guard("evil.com")
        result = create_guardrail(guard)
        assert result.name == "munio"

    @pytest.mark.asyncio
    async def test_allowed_returns_no_tripwire(self) -> None:
        """Allowed action → tripwire_triggered=False."""
        guard = _make_guard("evil.com")
        guardrail = create_guardrail(guard)
        input_data = {"tool": "http_request", "args": {"url": "https://safe.com"}}
        result = await guardrail.guardrail_function(None, None, input_data)
        assert result.tripwire_triggered is False

    @pytest.mark.asyncio
    async def test_blocked_returns_tripwire(self) -> None:
        """Blocked action → tripwire_triggered=True."""
        guard = _make_guard("evil.com")
        guardrail = create_guardrail(guard)
        input_data = {"tool": "http_request", "args": {"url": "https://evil.com/steal"}}
        result = await guardrail.guardrail_function(None, None, input_data)
        assert result.tripwire_triggered is True

    @pytest.mark.asyncio
    async def test_output_info_contains_violations(self) -> None:
        """Violation details are in output_info."""
        guard = _make_guard("evil.com")
        guardrail = create_guardrail(guard)
        input_data = {"tool": "http_request", "args": {"url": "evil.com/path"}}
        result = await guardrail.guardrail_function(None, None, input_data)
        assert result.tripwire_triggered is True
        violations = result.output_info["violations"]
        assert len(violations) >= 1
        assert violations[0]["tool"] == "http_request"
        assert "message" in violations[0]

    @pytest.mark.asyncio
    async def test_no_tool_calls_passes(self) -> None:
        """String input with no tool calls → no tripwire."""
        guard = _make_guard("evil.com")
        guardrail = create_guardrail(guard)
        result = await guardrail.guardrail_function(None, None, "just a string")
        assert result.tripwire_triggered is False
        assert result.output_info == {"checked": 0}

    @pytest.mark.asyncio
    async def test_function_call_format(self) -> None:
        """OpenAI function_call list format is handled."""
        guard = _make_guard("evil.com")
        guardrail = create_guardrail(guard)
        input_data = [
            {"type": "function_call", "name": "http_request", "arguments": {"url": "evil.com"}}
        ]
        result = await guardrail.guardrail_function(None, None, input_data)
        assert result.tripwire_triggered is True

    @pytest.mark.asyncio
    async def test_no_tool_calls_for_non_string_tool(self) -> None:
        """Dict with non-string tool value → no tool calls extracted."""
        guard = _make_guard("evil.com")
        guardrail = create_guardrail(guard)
        input_data = {"tool": None, "args": {}}
        result = await guardrail.guardrail_function(None, None, input_data)
        # _extract_tool_calls returns empty for non-string tool → checked: 0
        assert result.tripwire_triggered is False
        assert result.output_info == {"checked": 0}

    @pytest.mark.asyncio
    async def test_error_is_fail_closed(self) -> None:
        """Internal error in guard → fail-closed (tripwire_triggered=True)."""
        guard = _make_guard("evil.com")
        guardrail = create_guardrail(guard)
        broken_acheck = AsyncMock(side_effect=RuntimeError("internal error"))
        with patch.object(Guard, "acheck", broken_acheck):
            input_data = {"tool": "http_request", "args": {"url": "test.com"}}
            result = await guardrail.guardrail_function(None, None, input_data)
        assert result.tripwire_triggered is True
        assert result.output_info == {"error": "guardrail_error"}

    @pytest.mark.asyncio
    async def test_openclaw_constraints_enforced(self) -> None:
        """OpenClaw-style constraints work through OpenAI Agents adapter."""
        constraint = make_denylist_constraint(
            ["rm -rf", "sudo"],
            field="command",
            name="openclaw-deny-shell",
        )
        guard = Guard(registry=make_registry(constraint), mode=VerificationMode.ENFORCE)
        guardrail = create_guardrail(guard)

        # Safe command
        input_data = {"tool": "execute", "args": {"command": "ls"}}
        result = await guardrail.guardrail_function(None, None, input_data)
        assert result.tripwire_triggered is False

        # Dangerous command
        input_data = {"tool": "execute", "args": {"command": "sudo rm -rf /"}}
        result = await guardrail.guardrail_function(None, None, input_data)
        assert result.tripwire_triggered is True


class TestExtractToolCalls:
    """Tests for _extract_tool_calls() helper."""

    def test_string_input(self) -> None:
        assert _extract_tool_calls("hello") == []

    def test_dict_with_tool(self) -> None:
        result = _extract_tool_calls({"tool": "search", "args": {"q": "test"}})
        assert result == [("search", {"q": "test"})]

    def test_function_call_list(self) -> None:
        result = _extract_tool_calls(
            [{"type": "function_call", "name": "search", "arguments": {"q": "test"}}]
        )
        assert result == [("search", {"q": "test"})]

    def test_empty_list(self) -> None:
        assert _extract_tool_calls([]) == []

    def test_non_function_call_items_skipped(self) -> None:
        result = _extract_tool_calls(
            [
                {"type": "text", "content": "hello"},
                {"type": "function_call", "name": "search", "arguments": {"q": "x"}},
            ]
        )
        assert len(result) == 1
        assert result[0][0] == "search"

    def test_json_string_arguments_parsed(self) -> None:
        """OpenAI API sends arguments as JSON string — must be parsed."""
        result = _extract_tool_calls(
            [{"type": "function_call", "name": "search", "arguments": '{"q": "test"}'}]
        )
        assert result == [("search", {"q": "test"})]

    def test_invalid_json_string_arguments_fail_closed(self) -> None:
        """Malformed JSON string arguments → fail-closed (include with empty args)."""
        result = _extract_tool_calls(
            [{"type": "function_call", "name": "search", "arguments": "not json at all"}]
        )
        assert result == [("search", {})]

    def test_empty_function_name_skipped(self) -> None:
        """Empty function name is skipped."""
        result = _extract_tool_calls(
            [{"type": "function_call", "name": "", "arguments": {"q": "test"}}]
        )
        assert result == []

    def test_dict_format_json_string_args_parsed(self) -> None:
        """Dict format with JSON-string args is parsed."""
        result = _extract_tool_calls({"tool": "search", "args": '{"q": "test"}'})
        assert result == [("search", {"q": "test"})]

    def test_dict_format_invalid_json_args_fail_closed(self) -> None:
        """Dict format with invalid JSON-string args → fail-closed (include with empty args)."""
        result = _extract_tool_calls({"tool": "search", "args": "not json"})
        assert result == [("search", {})]

    def test_function_call_non_dict_parsed_args_skipped(self) -> None:
        """Parsed JSON that is not a dict (e.g., list) is skipped."""
        result = _extract_tool_calls(
            [{"type": "function_call", "name": "search", "arguments": "[1, 2, 3]"}]
        )
        assert result == []

    def test_invalid_json_with_empty_name_skipped(self) -> None:
        """function_call with invalid JSON AND empty name → skipped (not fail-closed)."""
        result = _extract_tool_calls(
            [{"type": "function_call", "name": "", "arguments": "not json"}]
        )
        assert result == []

    def test_invalid_json_with_non_string_name_skipped(self) -> None:
        """function_call with invalid JSON AND non-string name → skipped."""
        result = _extract_tool_calls(
            [{"type": "function_call", "name": None, "arguments": "not json"}]
        )
        assert result == []

    def test_none_arguments_treated_as_empty(self) -> None:
        """function_call with None arguments → TypeError caught, fail-closed."""
        result = _extract_tool_calls(
            [{"type": "function_call", "name": "search", "arguments": None}]
        )
        # None is not str → goes to isinstance(fn_args, dict) check → fails → skipped
        assert result == []

    def test_non_dict_item_in_list_skipped(self) -> None:
        """Non-dict items in function_call list are skipped."""
        result = _extract_tool_calls(["not a dict", 42, None])
        assert result == []
