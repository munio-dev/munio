"""Guard integration for tool call interception.

Fail-closed: any error during verification blocks the call.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from munio.gate.models import GateDecision
from munio.models import Action

if TYPE_CHECKING:
    from munio.guard import Guard

__all__ = ["Interceptor"]

logger = logging.getLogger(__name__)


class Interceptor:
    """Verifies MCP tool calls against munio constraints."""

    __slots__ = ("_guard",)

    def __init__(self, guard: Guard) -> None:
        self._guard = guard

    def check_tool_call(
        self,
        name: str,
        arguments: dict[str, Any] | None,
    ) -> GateDecision:
        """Verify a tool call. Fail-closed on any error."""
        try:
            action = Action(tool=name, args=arguments or {})
            result = self._guard.check(action)
            return GateDecision(
                allowed=result.allowed,
                violations=[v.message for v in result.violations[:5]],
                elapsed_ms=result.elapsed_ms,
            )
        except Exception:
            logger.warning("Verification error for tool %s", name, exc_info=True)
            return GateDecision(
                allowed=False,
                violations=["Internal verification error"],
                elapsed_ms=0.0,
            )
