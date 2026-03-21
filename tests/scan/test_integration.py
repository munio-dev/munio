"""Integration tests: real MCP server subprocess.

These tests launch an actual MCP server process via stdio and verify
the full connection lifecycle: subprocess start → handshake → list_tools → parse.

Run with: uv run pytest tests/munio.scan/test_integration.py -m integration
Skip with: uv run pytest -m "not integration"
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from munio.scan.models import ServerConfig

_ECHO_SERVER = Path(__file__).parent / "fixtures" / "echo_server.py"


def _echo_server_config(*, timeout: float = 10.0) -> ServerConfig:
    """Create a ServerConfig pointing to the echo test server."""
    return ServerConfig(
        name="echo-test",
        source="integration-test",
        command=sys.executable,
        args=[str(_ECHO_SERVER)],
    )


@pytest.mark.integration
class TestRealMCPConnection:
    """Integration tests with real MCP echo server subprocess."""

    @pytest.mark.asyncio
    async def test_connect_and_list_tools(self) -> None:
        """Full lifecycle: connect → list_tools → parse ToolDefinition."""
        from munio.scan.mcp_client import connect_and_list_tools

        server = _echo_server_config()
        tools = await connect_and_list_tools(server, timeout=10.0)

        assert len(tools) == 2

        echo = next(t for t in tools if t.name == "echo")
        assert echo.description == "Echo back the input message"
        assert echo.server_name == "echo-test"
        assert echo.input_schema["properties"]["message"]["type"] == "string"

        greet = next(t for t in tools if t.name == "greet")
        assert greet.description == "Greet a user by name"

    @pytest.mark.asyncio
    async def test_annotations_parsed(self) -> None:
        """Annotations from real MCP Tool objects are correctly captured."""
        from munio.scan.mcp_client import connect_and_list_tools

        server = _echo_server_config()
        tools = await connect_and_list_tools(server, timeout=10.0)

        echo = next(t for t in tools if t.name == "echo")
        assert echo.annotations is not None
        assert echo.annotations["readOnlyHint"] is True

        # greet has no annotations
        greet = next(t for t in tools if t.name == "greet")
        assert greet.annotations is None

    @pytest.mark.asyncio
    async def test_max_tools_limit(self) -> None:
        """max_tools parameter limits returned tools from real server."""
        from munio.scan.mcp_client import connect_and_list_tools

        server = _echo_server_config()
        tools = await connect_and_list_tools(server, timeout=10.0, max_tools=1)

        assert len(tools) == 1
