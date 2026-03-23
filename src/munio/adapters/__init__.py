"""Framework adapters: integrate munio into LangChain, CrewAI, OpenAI Agents SDK, MCP.

Each adapter translates framework-specific tool calls into munio Action objects
and routes them through Guard.check(). Adapters are lazy-loaded — importing this
package does NOT pull in any framework dependencies.

Usage::

    # LangChain
    from munio.adapters import guard_tool

    safe_tool = guard_tool(my_tool, guard)

    # CrewAI
    from munio.adapters import create_crew_hook

    crew.register_before_tool_call_hook(create_crew_hook(guard))

    # OpenAI Agents SDK
    from munio.adapters import create_guardrail

    agent = Agent(guardrails=[create_guardrail(guard)])

    # MCP
    from munio.adapters import create_guarded_mcp

    mcp = create_guarded_mcp(guard)
"""

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from munio.adapters._crewai import create_crew_hook
    from munio.adapters._langchain import guard_tool
    from munio.adapters._mcp import create_guarded_mcp
    from munio.adapters._openai_agents import create_guardrail

__all__ = [
    "create_crew_hook",
    "create_guarded_mcp",
    "create_guardrail",
    "format_violations",
    "guard_tool",
]


def format_violations(violations: list[Any], *, limit: int = 3) -> str:
    """Format a list of Violation objects into a human-readable summary.

    Args:
        violations: List of Violation objects (with .message attribute).
        limit: Maximum number of violation messages to include.

    Returns:
        Semicolon-separated violation messages, with overflow count suffix.
    """
    summary = "; ".join(v.message for v in violations[:limit])
    if len(violations) > limit:
        summary += f" (+{len(violations) - limit} more)"
    return summary


_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "guard_tool": ("munio.adapters._langchain", "guard_tool"),
    "create_crew_hook": ("munio.adapters._crewai", "create_crew_hook"),
    "create_guardrail": ("munio.adapters._openai_agents", "create_guardrail"),
    "create_guarded_mcp": ("munio.adapters._mcp", "create_guarded_mcp"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        module = importlib.import_module(module_path)
        value = getattr(module, attr_name)
        globals()[name] = value  # cache for subsequent access
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
