# SAFE: shlex.quote sanitizes command — should NOT trigger L7_001
import os
import shlex

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-cmd")


@mcp.tool()
def run_safe(command: str) -> str:
    """Execute a sanitized command."""
    safe_cmd = shlex.quote(command)
    os.system(safe_cmd)
    return "done"
