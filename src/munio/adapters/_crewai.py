"""CrewAI adapter: before_tool_call hook for munio verification.

No crewai import required — the hook is a plain function that reads
attributes from the CrewAI context object.

Usage::

    from munio import Guard
    from munio.adapters import create_crew_hook

    guard = Guard(constraints="generic")
    crew = Crew(agents=[...], tasks=[...])
    crew.register_before_tool_call_hook(create_crew_hook(guard))
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from munio.models import Action

if TYPE_CHECKING:
    from collections.abc import Callable

    from munio.guard import Guard

__all__ = ["create_crew_hook"]

logger = logging.getLogger(__name__)


def create_crew_hook(guard: Guard) -> Callable[..., bool]:
    """Create a CrewAI ``before_tool_call`` hook powered by munio.

    The returned hook receives a CrewAI ``ToolCallHookContext`` and returns
    ``False`` to block the tool call or ``True`` to allow it.

    On unexpected errors, the hook is **fail-closed**: it logs a warning and
    returns ``False`` (blocks the tool call), consistent with the server's
    OpenClaw endpoint behavior.

    Args:
        guard: A configured :class:`~munio.guard.Guard` instance.

    Returns:
        Hook function compatible with ``crew.register_before_tool_call_hook()``.
    """

    def _hook(context: Any) -> bool:
        try:
            if not hasattr(context, "tool_name"):
                logger.warning("munio: context missing tool_name (fail-closed)")
                return False
            tool_name: str = context.tool_name
            tool_input: Any = getattr(context, "tool_input", {})

            if isinstance(tool_input, str):
                tool_input = {"input": tool_input}
            elif not isinstance(tool_input, dict):
                logger.warning(
                    "munio: non-dict tool_input %r (fail-closed)", type(tool_input).__name__
                )
                return False

            action = Action(tool=tool_name, args=tool_input)
            result = guard.check(action)

            if not result.allowed:
                from munio.adapters import format_violations

                violations_summary = format_violations(result.violations)
                logger.warning(
                    "munio blocked tool %r: %s",
                    tool_name,
                    violations_summary,
                )
                return False

            return True

        except Exception:
            logger.warning(
                "munio hook error (fail-closed, blocking tool call)",
                exc_info=True,
            )
            return False

    return _hook
