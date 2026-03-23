"""Tests for munio.gate.models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from munio.gate.models import GateDecision, InterceptionRecord


class TestGateDecision:
    """Test GateDecision model."""

    def test_allowed_decision(self) -> None:
        d = GateDecision(allowed=True, elapsed_ms=0.5)
        assert d.allowed is True
        assert d.violations == []

    def test_blocked_decision(self) -> None:
        d = GateDecision(allowed=False, violations=["denied"], elapsed_ms=1.0)
        assert d.allowed is False
        assert d.violations == ["denied"]

    def test_frozen(self) -> None:

        d = GateDecision(allowed=True)
        with pytest.raises(ValidationError):
            d.allowed = False  # type: ignore[misc]


class TestInterceptionRecord:
    """Test InterceptionRecord model."""

    def test_now_factory(self) -> None:
        record = InterceptionRecord.now(
            tool="exec",
            decision="blocked",
            violations=["denied"],
            elapsed_ms=0.5,
            jsonrpc_id=42,
        )
        assert record.tool == "exec"
        assert record.decision == "blocked"
        assert record.violations == ["denied"]
        assert record.jsonrpc_id == 42
        assert record.timestamp.tzinfo is not None

    def test_now_defaults(self) -> None:
        record = InterceptionRecord.now(tool="ping", decision="allowed")
        assert record.violations == []
        assert record.elapsed_ms == 0.0
        assert record.jsonrpc_id is None

    def test_serialization(self) -> None:
        record = InterceptionRecord.now(tool="exec", decision="blocked")
        json_str = record.model_dump_json()
        assert "exec" in json_str
        assert "blocked" in json_str
