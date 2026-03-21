"""Data models for munio gate proxy."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict


class GateDecision(BaseModel):
    """Result of intercepting a single tool call."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: bool
    violations: list[str] = []
    elapsed_ms: float = 0.0


class InterceptionRecord(BaseModel):
    """Structured log entry for an intercepted tool call."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime
    tool: str
    decision: Literal["allowed", "blocked", "error"]
    violations: list[str] = []
    elapsed_ms: float = 0.0
    jsonrpc_id: int | float | str | None = None

    @classmethod
    def now(
        cls,
        *,
        tool: str,
        decision: Literal["allowed", "blocked", "error"],
        violations: list[str] | None = None,
        elapsed_ms: float = 0.0,
        jsonrpc_id: int | float | str | None = None,
    ) -> InterceptionRecord:
        return cls(
            timestamp=datetime.now(timezone.utc),
            tool=tool,
            decision=decision,
            violations=violations or [],
            elapsed_ms=elapsed_ms,
            jsonrpc_id=jsonrpc_id,
        )
