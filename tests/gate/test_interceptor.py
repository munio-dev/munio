"""Tests for munio.gate.interceptor — Guard integration."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from munio.gate.interceptor import Interceptor


class TestInterceptor:
    """Test the Interceptor wrapper around Guard."""

    def _make_interceptor(
        self, *, allowed: bool = True, violations: list | None = None
    ) -> Interceptor:
        """Create an Interceptor with a mocked Guard."""
        mock_guard = MagicMock()
        mock_result = MagicMock()
        mock_result.allowed = allowed
        mock_result.elapsed_ms = 0.5

        mock_violations = []
        if violations:
            for msg in violations:
                v = MagicMock()
                v.message = msg
                mock_violations.append(v)
        mock_result.violations = mock_violations
        mock_guard.check.return_value = mock_result
        return Interceptor(mock_guard)

    def test_allowed_tool_call(self) -> None:
        interceptor = self._make_interceptor(allowed=True)
        decision = interceptor.check_tool_call("read_file", {"path": "/tmp/x"})
        assert decision.allowed is True
        assert decision.violations == []

    def test_blocked_tool_call(self) -> None:
        interceptor = self._make_interceptor(
            allowed=False,
            violations=["Command matches denylist"],
        )
        decision = interceptor.check_tool_call("exec", {"command": "rm -rf /"})
        assert decision.allowed is False
        assert "denylist" in decision.violations[0]

    def test_none_arguments_treated_as_empty(self) -> None:
        interceptor = self._make_interceptor(allowed=True)
        decision = interceptor.check_tool_call("ping", None)
        assert decision.allowed is True

    def test_fail_closed_on_guard_exception(self) -> None:
        mock_guard = MagicMock()
        mock_guard.check.side_effect = RuntimeError("boom")
        interceptor = Interceptor(mock_guard)
        decision = interceptor.check_tool_call("exec", {"command": "ls"})
        assert decision.allowed is False
        assert "Internal verification error" in decision.violations[0]

    def test_elapsed_ms_forwarded(self) -> None:
        interceptor = self._make_interceptor(allowed=True)
        decision = interceptor.check_tool_call("read", {})
        assert decision.elapsed_ms == pytest.approx(0.5)

    def test_violations_truncated_to_5(self) -> None:
        interceptor = self._make_interceptor(
            allowed=False,
            violations=[f"violation-{i}" for i in range(10)],
        )
        decision = interceptor.check_tool_call("exec", {"command": "x"})
        assert len(decision.violations) == 5
