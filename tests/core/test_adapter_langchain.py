"""Tests for munio.adapters._langchain — LangChain GuardedTool wrapper.

Uses mocked langchain_core to avoid requiring the framework for CI.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Mock langchain_core BEFORE importing the adapter ──────────────────

_mock_tools = MagicMock()


class _FakeBaseTool:
    """Minimal BaseTool mock for testing."""

    name: str = "test_tool"
    description: str = "A test tool"

    def __init__(self, name: str = "test_tool", **kwargs: Any) -> None:
        self.name = name
        self.description = kwargs.get("description", "A test tool")
        self._run_impl = kwargs.get("run_impl", lambda x, **kw: f"result:{x}")
        self._arun_impl = kwargs.get("arun_impl")

    def _run(self, tool_input: Any, **kwargs: Any) -> str:
        return self._run_impl(tool_input, **kwargs)

    async def _arun(self, tool_input: Any, **kwargs: Any) -> str:
        if self._arun_impl:
            return await self._arun_impl(tool_input, **kwargs)
        return self._run(tool_input, **kwargs)

    def model_copy(self) -> _FakeBaseTool:
        return _FakeBaseTool(
            name=self.name,
            description=self.description,
            run_impl=self._run_impl,
            arun_impl=self._arun_impl,
        )


class _FakeToolError(Exception):
    """Mock ToolException (ruff N818 requires Error suffix)."""


# Patch into sys.modules
_mock_tools.BaseTool = _FakeBaseTool
_mock_tools.ToolException = _FakeToolError
sys.modules.setdefault("langchain_core", MagicMock(tools=_mock_tools))
sys.modules.setdefault("langchain_core.tools", _mock_tools)

from munio.adapters._langchain import guard_tool  # noqa: E402
from munio.guard import Guard  # noqa: E402
from munio.models import VerificationMode  # noqa: E402
from tests.core.conftest import make_denylist_constraint, make_registry  # noqa: E402


def _make_guard(*values: str, field: str = "url") -> Guard:
    """Create a Guard with a denylist constraint."""
    constraint = make_denylist_constraint(list(values), field=field)
    return Guard(registry=make_registry(constraint), mode=VerificationMode.ENFORCE)


class TestGuardTool:
    """Tests for guard_tool()."""

    def test_allowed_action_passes_through(self) -> None:
        """Allowed action passes through to original tool."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="http_request")
        wrapped = guard_tool(tool, guard)
        result = wrapped._run({"url": "https://safe.example.com"})
        assert "result:" in str(result)

    def test_blocked_action_raises_tool_exception(self) -> None:
        """Blocked action raises ToolException in 'raise' mode."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="http_request")
        wrapped = guard_tool(tool, guard, on_block="raise")
        with pytest.raises(_FakeToolError, match="BLOCKED"):
            wrapped._run({"url": "https://evil.com/path"})

    def test_blocked_action_message_mode(self) -> None:
        """Blocked action returns error string in 'message' mode."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="http_request")
        wrapped = guard_tool(tool, guard, on_block="message")
        result = wrapped._run({"url": "https://evil.com/steal"})
        assert isinstance(result, str)
        assert "[BLOCKED]" in result

    def test_string_input_wrapped_in_dict(self) -> None:
        """String tool_input is wrapped as {'input': value}."""
        guard = _make_guard("evil.com", field="input")
        tool = _FakeBaseTool(name="http_request")
        wrapped = guard_tool(tool, guard)
        with pytest.raises(_FakeToolError, match="BLOCKED"):
            wrapped._run("https://evil.com")

    @pytest.mark.asyncio
    async def test_async_tool_works(self) -> None:
        """Async _arun path works."""
        guard = _make_guard("evil.com")

        async def async_impl(tool_input: Any, **kwargs: Any) -> str:
            return f"async_result:{tool_input}"

        tool = _FakeBaseTool(name="http_request", arun_impl=async_impl)
        wrapped = guard_tool(tool, guard)
        result = await wrapped._arun({"url": "https://safe.example.com"})
        assert "async_result" in result

    @pytest.mark.asyncio
    async def test_async_blocked(self) -> None:
        """Async _arun raises ToolException when blocked."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="http_request")
        wrapped = guard_tool(tool, guard)
        with pytest.raises(_FakeToolError, match="BLOCKED"):
            await wrapped._arun({"url": "https://evil.com"})

    def test_preserves_tool_metadata(self) -> None:
        """Wrapped tool preserves name and description."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="my_search", description="Search the web")
        wrapped = guard_tool(tool, guard)
        assert wrapped.name == "my_search"
        assert wrapped.description == "Search the web"

    def test_original_tool_not_mutated(self) -> None:
        """Original tool still works independently after wrapping."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="http_request")
        wrapped = guard_tool(tool, guard)

        # Original should still work without guard
        original_result = tool._run({"url": "https://evil.com"})
        assert "result:" in str(original_result)

        # Wrapped should block
        with pytest.raises(_FakeToolError):
            wrapped._run({"url": "https://evil.com"})

    def test_invalid_on_block_raises(self) -> None:
        """Invalid on_block value raises ValueError."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="http_request")
        with pytest.raises(ValueError, match="on_block must be"):
            guard_tool(tool, guard, on_block="invalid")

    def test_guard_error_raises_tool_exception(self) -> None:
        """Guard.check() error → ToolException (fail-closed)."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="http_request")
        wrapped = guard_tool(tool, guard)
        with (
            patch.object(Guard, "check", side_effect=RuntimeError("boom")),
            pytest.raises(_FakeToolError, match="GUARD ERROR"),
        ):
            wrapped._run({"url": "https://test.com"})

    @pytest.mark.asyncio
    async def test_async_guard_error_raises_tool_exception(self) -> None:
        """Guard.check() error in async path → ToolException (fail-closed)."""
        guard = _make_guard("evil.com")
        tool = _FakeBaseTool(name="http_request")
        wrapped = guard_tool(tool, guard)
        with (
            patch.object(Guard, "check", side_effect=RuntimeError("boom")),
            pytest.raises(_FakeToolError, match="GUARD ERROR"),
        ):
            await wrapped._arun({"url": "https://test.com"})

    def test_openclaw_constraints_enforced(self) -> None:
        """OpenClaw-style constraints work through LangChain adapter."""
        constraint = make_denylist_constraint(
            ["rm -rf", "sudo"],
            field="command",
            name="openclaw-deny-shell",
        )
        guard = Guard(registry=make_registry(constraint), mode=VerificationMode.ENFORCE)
        tool = _FakeBaseTool(name="execute_command")
        wrapped = guard_tool(tool, guard)

        # Safe command passes
        result = wrapped._run({"command": "ls -la"})
        assert "result:" in str(result)

        # Dangerous command blocked
        with pytest.raises(_FakeToolError, match="BLOCKED"):
            wrapped._run({"command": "sudo rm -rf /"})
