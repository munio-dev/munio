"""Tests against real MCP servers (requires npx, network).

Run with: pytest -m real_mcp
"""

from __future__ import annotations

import asyncio

import pytest

from munio.scan.mcp_client import connect_and_list_tools
from munio.scan.models import ServerConfig


@pytest.mark.real_mcp
@pytest.mark.timeout(60)
class TestRealMcpServers:
    """Integration tests that connect to real MCP servers via npx."""

    def test_scan_server_everything(self) -> None:
        """Scan the reference 'everything' MCP server."""
        server = ServerConfig(
            name="everything",
            source="test",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-everything"],
        )
        tools = asyncio.run(connect_and_list_tools(server, timeout=30))
        assert len(tools) > 0
        assert all(t.name for t in tools)
