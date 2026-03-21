"""MCP adapter: expose munio verification as MCP tools.

Creates a FastMCP server with two tools:
  - ``verify``: Check if an action is allowed by constraint policies.
  - ``scan``: List constraint pack statistics.

Requires: ``pip install "munio[mcp-adapter]"`` (fastmcp>=3.0).

Usage::

    from munio import Guard
    from munio.adapters import create_guarded_mcp

    guard = Guard(constraints="generic")
    mcp = create_guarded_mcp(guard)
    mcp.run()  # Start MCP server (stdio transport)
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from munio.models import Action

if TYPE_CHECKING:
    from munio.guard import Guard

__all__ = ["create_guarded_mcp"]

logger = logging.getLogger(__name__)

try:
    from fastmcp import FastMCP
except ImportError as _exc:
    raise ImportError(
        "MCP adapter requires fastmcp. Install with: pip install 'munio[mcp-adapter]'"
    ) from _exc


def create_guarded_mcp(
    guard: Guard,
    *,
    name: str = "munio",
) -> FastMCP:
    """Create an MCP server with munio verification tools.

    The server exposes two tools:

    - **verify**: Takes ``tool`` (str) and ``args`` (dict), returns a JSON
      object with ``allowed`` (bool) and ``violations`` (list).
    - **scan**: Returns constraint pack statistics (total count, tiers,
      check types).

    Args:
        guard: A configured :class:`~munio.guard.Guard` instance.
        name: MCP server name (shown to clients).

    Returns:
        A ``FastMCP`` server instance. Call ``.run()`` to start.
    """
    mcp = FastMCP(name)

    @mcp.tool()
    def verify(tool: str, args: dict[str, Any] | None = None) -> str:
        """Check if an agent tool call is allowed by constraint policies.

        Args:
            tool: The tool/function name being called.
            args: Arguments passed to the tool (optional).

        Returns:
            JSON string with 'allowed' (bool), 'violations' (list), and
            'checked_constraints' (int).
        """
        try:
            action = Action(tool=tool, args=args or {})
            result = guard.check(action)
            return json.dumps(
                {
                    "allowed": result.allowed,
                    "violations": [
                        {
                            "constraint": v.constraint_name,
                            "message": v.message,
                            "severity": v.severity.value,
                        }
                        for v in result.violations
                    ],
                    "checked_constraints": result.checked_constraints,
                }
            )
        except Exception:
            logger.warning("munio MCP verify error", exc_info=True)
            return json.dumps({"error": "internal_verification_error", "allowed": False})

    @mcp.tool()
    def scan() -> str:
        """List constraint pack statistics.

        Returns:
            JSON string with 'total' (int), 'constraints' (list of names).
        """
        try:
            registry = guard.verifier.registry
            constraints = list(registry)
            return json.dumps(
                {
                    "total": len(constraints),
                    "constraints": [c.name for c in constraints],
                }
            )
        except Exception:
            logger.warning("munio MCP scan error", exc_info=True)
            return json.dumps({"error": "internal_scan_error"})

    return mcp
