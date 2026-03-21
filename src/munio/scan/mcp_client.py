"""MCP client wrapper: connect to MCP servers and list tool definitions.

Uses the official ``mcp`` SDK (v1.25+) for stdio transport.
Requires: ``pip install "munio[mcp]"``
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from munio.scan.models import ScanConnectionError, ToolDefinition

if TYPE_CHECKING:
    from munio.scan.models import ServerConfig

__all__ = ["ConnectionResult", "connect_and_list_tools", "connect_with_info"]

logger = logging.getLogger(__name__)

_MAX_PAGES = 100


class ConnectionResult(NamedTuple):
    """Extended connection result with server metadata."""

    tools: list[ToolDefinition]
    server_name: str
    server_version: str


async def connect_with_info(
    server: ServerConfig,
    *,
    timeout: float = 30.0,
    max_tools: int = 500,
) -> ConnectionResult:
    """Connect to an MCP server and return tools + serverInfo metadata.

    Like connect_and_list_tools but also returns server name and version
    from the MCP initialize handshake.

    Args:
        server: Server configuration with command and args.
        timeout: Connection and handshake timeout in seconds.
        max_tools: Maximum number of tools to retrieve.

    Returns:
        ConnectionResult with tools, server_name, and server_version.

    Raises:
        ScanConnectionError: If connection fails, times out, or SDK is not installed.
    """
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        msg = "MCP SDK not installed. Install with: pip install 'munio[mcp]'"
        raise ScanConnectionError(msg) from None

    if not server.command:
        msg = f"Server '{server.name}' has no command configured"
        raise ScanConnectionError(msg)

    # Merge server env with current process env so child processes
    # inherit PATH, npm_config_cache, etc. MCP SDK's default env only
    # passes HOME/PATH/SHELL/TERM/USER/LOGNAME — not custom vars like
    # npm_config_cache needed for SSD cache redirection.
    merged_env: dict[str, str] = {**os.environ}
    if server.env:
        merged_env.update(server.env)
    params = StdioServerParameters(
        command=server.command,
        args=server.args,
        env=merged_env,
    )

    devnull = Path(os.devnull).open("w")  # noqa: SIM115
    try:
        async with (
            stdio_client(params, errlog=devnull) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            init_result = await asyncio.wait_for(
                session.initialize(),
                timeout=timeout,
            )

            # Extract serverInfo from handshake
            srv_info = getattr(init_result, "serverInfo", None)
            srv_name = getattr(srv_info, "name", "") if srv_info else ""
            srv_version = getattr(srv_info, "version", "") if srv_info else ""

            tools: list[ToolDefinition] = []
            cursor: str | None = None

            for _ in range(_MAX_PAGES):
                result = await asyncio.wait_for(
                    session.list_tools(cursor=cursor),
                    timeout=timeout,
                )

                for t in result.tools:
                    if len(tools) >= max_tools:
                        logger.warning(
                            "Reached max_tools limit (%d) for server '%s'",
                            max_tools,
                            server.name,
                        )
                        return ConnectionResult(
                            tools=tools,
                            server_name=srv_name,
                            server_version=srv_version,
                        )

                    tools.append(
                        ToolDefinition(
                            name=t.name,
                            title=getattr(t, "title", "") or "",
                            description=t.description or "",
                            input_schema=t.inputSchema or {},
                            output_schema=getattr(t, "outputSchema", None),
                            annotations=(
                                vars(t.annotations) if getattr(t, "annotations", None) else None
                            ),
                            server_name=server.name,
                        )
                    )

                cursor = getattr(result, "nextCursor", None)
                if not cursor:
                    break

            return ConnectionResult(
                tools=tools,
                server_name=srv_name,
                server_version=srv_version,
            )

    except TimeoutError:
        msg = f"Connection to server '{server.name}' timed out"
        raise ScanConnectionError(msg) from None
    except ScanConnectionError:
        raise
    except Exception:
        logger.warning("Failed to connect to server '%s'", server.name, exc_info=True)
        msg = f"Failed to connect to server '{server.name}'"
        raise ScanConnectionError(msg) from None
    finally:
        devnull.close()


async def connect_and_list_tools(
    server: ServerConfig,
    *,
    timeout: float = 30.0,
    max_tools: int = 500,
) -> list[ToolDefinition]:
    """Connect to an MCP server via stdio and list its tools.

    Args:
        server: Server configuration with command and args.
        timeout: Connection and handshake timeout in seconds.
        max_tools: Maximum number of tools to retrieve.

    Returns:
        List of tool definitions from the server.

    Raises:
        ScanConnectionError: If connection fails, times out, or SDK is not installed.
    """
    result = await connect_with_info(server, timeout=timeout, max_tools=max_tools)
    return result.tools
