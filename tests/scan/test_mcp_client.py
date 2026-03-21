"""Tests for munio.scan.mcp_client."""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from munio.scan.models import ScanConnectionError, ServerConfig


def _make_server(
    name: str = "test", command: str = "echo", args: list[str] | None = None
) -> ServerConfig:
    return ServerConfig(name=name, source="test", command=command, args=args or [])


class TestConnectAndListTools:
    """Tests for connect_and_list_tools()."""

    @pytest.mark.asyncio
    async def test_no_command_raises(self) -> None:
        """Server with empty command raises ScanConnectionError."""
        from munio.scan.mcp_client import connect_and_list_tools

        server = ServerConfig(name="empty", source="test", command="")
        with pytest.raises(ScanConnectionError, match="no command"):
            await connect_and_list_tools(server)

    @pytest.mark.asyncio
    async def test_successful_connection(self) -> None:
        """Mock a successful MCP connection returning tools."""
        from munio.scan.mcp_client import connect_and_list_tools

        mock_tool = SimpleNamespace(
            name="read_file",
            description="Read a file",
            inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
        )
        mock_result = SimpleNamespace(tools=[mock_tool])

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=mock_result)

        @asynccontextmanager
        async def fake_stdio_client(_params: object, **_kw: object):  # type: ignore[no-untyped-def]
            yield (AsyncMock(), AsyncMock())

        @asynccontextmanager
        async def fake_client_session(_read: object, _write: object):  # type: ignore[no-untyped-def]
            yield mock_session

        with (
            patch("mcp.client.stdio.stdio_client", fake_stdio_client),
            patch("mcp.ClientSession", fake_client_session),
        ):
            tools = await connect_and_list_tools(_make_server())

        assert len(tools) == 1
        assert tools[0].name == "read_file"

    @pytest.mark.asyncio
    async def test_timeout_raises(self) -> None:
        """Timeout raises ScanConnectionError."""
        from munio.scan.mcp_client import connect_and_list_tools

        @asynccontextmanager
        async def fake_stdio_client(_params: object, **_kw: object):  # type: ignore[no-untyped-def]
            raise TimeoutError
            yield  # type: ignore[misc]  # pragma: no cover

        with (
            patch("mcp.client.stdio.stdio_client", fake_stdio_client),
            pytest.raises(ScanConnectionError, match="timed out"),
        ):
            await connect_and_list_tools(_make_server(), timeout=0.1)

    @pytest.mark.asyncio
    async def test_generic_error_no_leak(self) -> None:
        """Generic errors produce generic message (no info leak)."""
        from munio.scan.mcp_client import connect_and_list_tools

        @asynccontextmanager
        async def fake_stdio_client(_params: object, **_kw: object):  # type: ignore[no-untyped-def]
            raise RuntimeError("secret_password_here")
            yield  # type: ignore[misc]  # pragma: no cover

        with patch("mcp.client.stdio.stdio_client", fake_stdio_client):
            with pytest.raises(ScanConnectionError) as exc_info:
                await connect_and_list_tools(_make_server())
            assert "secret_password" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_max_tools_limit(self) -> None:
        """Respects max_tools limit."""
        from munio.scan.mcp_client import connect_and_list_tools

        tools_list = [
            SimpleNamespace(name=f"tool_{i}", description="", inputSchema={}) for i in range(10)
        ]
        mock_result = SimpleNamespace(tools=tools_list)

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=mock_result)

        @asynccontextmanager
        async def fake_stdio_client(_params: object, **_kw: object):  # type: ignore[no-untyped-def]
            yield (AsyncMock(), AsyncMock())

        @asynccontextmanager
        async def fake_client_session(_read: object, _write: object):  # type: ignore[no-untyped-def]
            yield mock_session

        with (
            patch("mcp.client.stdio.stdio_client", fake_stdio_client),
            patch("mcp.ClientSession", fake_client_session),
        ):
            tools = await connect_and_list_tools(_make_server(), max_tools=3)

        assert len(tools) == 3

    @pytest.mark.asyncio
    async def test_pagination_with_cursor(self) -> None:
        """Handles paginated list_tools responses."""
        from munio.scan.mcp_client import connect_and_list_tools

        page1_tool = SimpleNamespace(name="tool_1", description="", inputSchema={})
        page2_tool = SimpleNamespace(name="tool_2", description="", inputSchema={})
        page1 = SimpleNamespace(tools=[page1_tool], nextCursor="page2")
        page2 = SimpleNamespace(tools=[page2_tool])  # no nextCursor

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()
        mock_session.list_tools = AsyncMock(side_effect=[page1, page2])

        @asynccontextmanager
        async def fake_stdio_client(_params: object, **_kw: object):  # type: ignore[no-untyped-def]
            yield (AsyncMock(), AsyncMock())

        @asynccontextmanager
        async def fake_client_session(_read: object, _write: object):  # type: ignore[no-untyped-def]
            yield mock_session

        with (
            patch("mcp.client.stdio.stdio_client", fake_stdio_client),
            patch("mcp.ClientSession", fake_client_session),
        ):
            tools = await connect_and_list_tools(_make_server())

        assert len(tools) == 2
        assert tools[0].name == "tool_1"
        assert tools[1].name == "tool_2"
        # Verify cursor was passed on second call
        assert mock_session.list_tools.call_args_list[1].kwargs["cursor"] == "page2"


class TestToolDefinitionFromRealMCPTypes:
    """Verify our ToolDefinition construction works with real MCP SDK types."""

    def test_from_real_mcp_tool(self) -> None:
        """ToolDefinition can be constructed from real mcp.types.Tool fields."""
        from mcp.types import Tool

        t = Tool(
            name="read_file",
            description="Read a file",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        )
        from munio.scan.models import ToolDefinition

        td = ToolDefinition(
            name=t.name,
            title=getattr(t, "title", "") or "",
            description=t.description or "",
            input_schema=t.inputSchema or {},
            output_schema=getattr(t, "outputSchema", None),
            annotations=vars(t.annotations) if getattr(t, "annotations", None) else None,
            server_name="test",
        )
        assert td.name == "read_file"
        assert td.annotations is None

    def test_from_real_mcp_tool_with_annotations(self) -> None:
        """ToolDefinition correctly captures annotations via vars()."""
        from mcp.types import Tool, ToolAnnotations

        t = Tool(
            name="delete_file",
            description="Delete",
            inputSchema={"type": "object"},
            annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True),
        )
        from munio.scan.models import ToolDefinition

        td = ToolDefinition(
            name=t.name,
            title=getattr(t, "title", "") or "",
            description=t.description or "",
            input_schema=t.inputSchema or {},
            output_schema=getattr(t, "outputSchema", None),
            annotations=vars(t.annotations) if getattr(t, "annotations", None) else None,
            server_name="test",
        )
        assert td.annotations is not None
        assert td.annotations["destructiveHint"] is True
        assert td.annotations["readOnlyHint"] is False
