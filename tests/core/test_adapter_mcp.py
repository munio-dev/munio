"""Tests for munio.adapters._mcp — MCP FastMCP server with verify/scan tools.

Uses mocked fastmcp to avoid requiring the framework for CI.
"""

from __future__ import annotations

import json
import sys
from typing import Any
from unittest.mock import MagicMock, patch

# ── Mock fastmcp BEFORE importing the adapter ────────────────────────


class _FakeFastMCP:
    """Minimal FastMCP mock for testing."""

    def __init__(self, name: str = "test") -> None:
        self.name = name
        self._tools: dict[str, Any] = {}

    def tool(self) -> Any:
        """Decorator that registers a tool function."""

        def decorator(fn: Any) -> Any:
            self._tools[fn.__name__] = fn
            return fn

        return decorator


_mock_fastmcp = MagicMock()
_mock_fastmcp.FastMCP = _FakeFastMCP
sys.modules.setdefault("fastmcp", _mock_fastmcp)

from munio.adapters._mcp import create_guarded_mcp  # noqa: E402
from munio.guard import Guard  # noqa: E402
from munio.models import VerificationMode  # noqa: E402
from tests.core.conftest import make_denylist_constraint, make_registry  # noqa: E402


def _make_guard(*values: str, field: str = "url") -> Guard:
    constraint = make_denylist_constraint(list(values), field=field)
    return Guard(registry=make_registry(constraint), mode=VerificationMode.ENFORCE)


class TestCreateGuardedMcp:
    """Tests for create_guarded_mcp()."""

    def test_returns_fastmcp_instance(self) -> None:
        """Returns a FastMCP server instance."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        assert isinstance(mcp, _FakeFastMCP)

    def test_server_name_configurable(self) -> None:
        """Server name is configurable."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard, name="my-safety-server")
        assert mcp.name == "my-safety-server"

    def test_default_name(self) -> None:
        """Default name is 'munio'."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        assert mcp.name == "munio"

    def test_server_has_two_tools(self) -> None:
        """Server registers 'verify' and 'scan' tools."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        assert "verify" in mcp._tools
        assert "scan" in mcp._tools

    def test_verify_allowed_action(self) -> None:
        """Verify tool returns allowed=True for safe actions."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        result_str = mcp._tools["verify"](tool="http_request", args={"url": "https://safe.com"})
        result = json.loads(result_str)
        assert result["allowed"] is True
        assert result["violations"] == []

    def test_verify_blocked_action(self) -> None:
        """Verify tool returns allowed=False with violations for blocked actions."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        result_str = mcp._tools["verify"](tool="http_request", args={"url": "evil.com/steal"})
        result = json.loads(result_str)
        assert result["allowed"] is False
        assert len(result["violations"]) >= 1
        assert "constraint" in result["violations"][0]
        assert "message" in result["violations"][0]
        assert "severity" in result["violations"][0]

    def test_verify_no_args(self) -> None:
        """Verify tool works with no args (defaults to empty dict)."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        result_str = mcp._tools["verify"](tool="http_request", args=None)
        result = json.loads(result_str)
        assert result["allowed"] is True

    def test_verify_error_fail_closed_no_leak(self) -> None:
        """Verify tool: errors → fail-closed (allowed=False), no detail leak."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        with patch.object(Guard, "check", side_effect=RuntimeError("secret_db_password")):
            result_str = mcp._tools["verify"](tool="http_request", args={"url": "test.com"})
        result = json.loads(result_str)
        assert result["allowed"] is False
        assert result["error"] == "internal_verification_error"
        assert "secret_db_password" not in result_str

    def test_scan_returns_stats(self) -> None:
        """Scan tool returns constraint statistics."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        result_str = mcp._tools["scan"]()
        result = json.loads(result_str)
        assert result["total"] == 1
        assert "test-deny" in result["constraints"]

    def test_scan_multiple_constraints(self) -> None:
        """Scan tool lists all constraints."""
        c1 = make_denylist_constraint(["evil.com"], name="deny-evil")
        c2 = make_denylist_constraint(["bad.com"], name="deny-bad")
        guard = Guard(registry=make_registry(c1, c2), mode=VerificationMode.ENFORCE)
        mcp = create_guarded_mcp(guard)
        result_str = mcp._tools["scan"]()
        result = json.loads(result_str)
        assert result["total"] == 2
        assert set(result["constraints"]) == {"deny-evil", "deny-bad"}

    def test_scan_error_returns_generic_message(self) -> None:
        """Scan tool handles errors without leaking internals."""
        guard = _make_guard("evil.com")
        mcp = create_guarded_mcp(guard)
        # Monkey-patch verifier to have a registry that raises
        original_verifier = guard.verifier

        class _BrokenVerifier:
            @property
            def registry(self) -> Any:
                msg = "boom"
                raise RuntimeError(msg)

        object.__setattr__(guard, "_verifier", _BrokenVerifier())
        result_str = mcp._tools["scan"]()
        result = json.loads(result_str)
        assert result["error"] == "internal_scan_error"
        assert "boom" not in result["error"]
        object.__setattr__(guard, "_verifier", original_verifier)

    def test_openclaw_constraints_enforced(self) -> None:
        """OpenClaw-style constraints work through MCP adapter."""
        constraint = make_denylist_constraint(
            ["rm -rf", "sudo"],
            field="command",
            name="openclaw-deny-shell",
        )
        guard = Guard(registry=make_registry(constraint), mode=VerificationMode.ENFORCE)
        mcp = create_guarded_mcp(guard)

        # Safe command
        result_str = mcp._tools["verify"](tool="execute", args={"command": "ls"})
        result = json.loads(result_str)
        assert result["allowed"] is True

        # Dangerous command
        result_str = mcp._tools["verify"](tool="execute", args={"command": "sudo rm -rf /"})
        result = json.loads(result_str)
        assert result["allowed"] is False
