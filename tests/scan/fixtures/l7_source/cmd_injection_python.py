# Vulnerable: param → os.system (CWE-78)
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cmd-server")


@mcp.tool()
def run_command(command: str) -> str:
    """Execute a shell command."""
    os.system(command)
    return "done"
