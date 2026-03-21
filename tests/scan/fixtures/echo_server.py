"""Minimal MCP server for integration tests.

Registers two tools with different schemas to test multi-tool listing,
annotations handling, and schema parsing.
"""

from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, ToolAnnotations

server = Server("echo-test")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="echo",
            description="Echo back the input message",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Message to echo",
                        "maxLength": 1000,
                    }
                },
                "required": ["message"],
                "additionalProperties": False,
            },
            annotations=ToolAnnotations(readOnlyHint=True),
        ),
        Tool(
            name="greet",
            description="Greet a user by name",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "User name"},
                    "formal": {"type": "boolean", "description": "Use formal greeting"},
                },
                "required": ["name"],
            },
        ),
    ]


async def main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
