"""LangChain adapter: wrap any BaseTool with munio verification.

LangChain callbacks (``on_tool_start``) are observational and CANNOT block
execution. The only way to block is to wrap the tool itself, overriding
``_run`` / ``_arun`` with a verification step.

Requires: ``pip install "munio[langchain]"`` (langchain-core>=1.0).

Usage::

    from munio import Guard
    from munio.adapters import guard_tool

    guard = Guard(constraints="generic")
    safe_search = guard_tool(search_tool, guard)
    agent = initialize_agent(tools=[safe_search], ...)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from munio.models import Action

if TYPE_CHECKING:
    from munio.guard import Guard

__all__ = ["guard_tool"]

logger = logging.getLogger(__name__)

try:
    from langchain_core.tools import BaseTool, ToolException
except ImportError as _exc:
    raise ImportError(
        "LangChain adapter requires langchain-core. Install with: pip install 'munio[langchain]'"
    ) from _exc


def guard_tool(
    tool: BaseTool,
    guard: Guard,
    *,
    on_block: str = "raise",
) -> BaseTool:
    """Wrap a LangChain tool with munio pre-execution verification.

    Args:
        tool: Any LangChain ``BaseTool`` instance.
        guard: A configured :class:`~munio.guard.Guard` instance.
        on_block: Behavior when blocked:
            ``"raise"`` — raise ``ToolException`` (default).
            ``"message"`` — return a human-readable error string.

    Returns:
        A new ``BaseTool`` that verifies before running.
        The original tool is NOT mutated.

    Raises:
        ValueError: If *on_block* is not ``"raise"`` or ``"message"``.
    """
    if on_block not in ("raise", "message"):
        msg = f"on_block must be 'raise' or 'message', got {on_block!r}"
        raise ValueError(msg)

    def _check_and_format(tool_input: dict[str, Any] | str) -> str | None:
        """Run guard check, return block message or None if allowed."""
        from munio.adapters import format_violations

        args = tool_input if isinstance(tool_input, dict) else {"input": tool_input}
        action = Action(tool=tool.name, args=args)
        result = guard.check(action)
        if not result.allowed:
            return f"[BLOCKED] {format_violations(result.violations)}"
        return None

    # Create a copy first, then capture original methods from clone
    clone = tool.model_copy()
    original_run = clone._run
    original_arun = clone._arun

    def guarded_run(tool_input: Any, **kwargs: Any) -> Any:
        try:
            block_msg = _check_and_format(tool_input)
        except Exception:
            logger.warning("munio guard error (fail-closed)", exc_info=True)
            raise ToolException("[GUARD ERROR] Verification failed, action blocked") from None
        if block_msg is not None:
            if on_block == "raise":
                raise ToolException(block_msg)
            return block_msg
        return original_run(tool_input, **kwargs)

    async def guarded_arun(tool_input: Any, **kwargs: Any) -> Any:
        try:
            from munio.adapters import format_violations

            args = tool_input if isinstance(tool_input, dict) else {"input": tool_input}
            action = Action(tool=tool.name, args=args)
            result = await guard.acheck(action)
        except Exception:
            logger.warning("munio guard error (fail-closed)", exc_info=True)
            raise ToolException("[GUARD ERROR] Verification failed, action blocked") from None
        if not result.allowed:
            block_msg = f"[BLOCKED] {format_violations(result.violations)}"
            if on_block == "raise":
                raise ToolException(block_msg)
            return block_msg
        return await original_arun(tool_input, **kwargs)

    object.__setattr__(clone, "_run", guarded_run)
    object.__setattr__(clone, "_arun", guarded_arun)
    return clone
