"""Subprocess-level integration tests for the proxy.

Tests run_proxy with a real subprocess (mock_mcp_server.py),
but use monkeypatched stdin/stdout/stderr to avoid connecting
to the real terminal.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from munio.gate.proxy import _forward_stream, _make_blocked_response

MOCK_SERVER = str(Path(__file__).parent / "mock_mcp_server.py")


class TestForwardStream:
    """Test the transparent stream forwarding function."""

    @pytest.mark.asyncio
    async def test_forwards_lines(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"line1\nline2\n")
        reader.feed_eof()

        # Create a pipe to capture output
        out_reader = asyncio.StreamReader()
        transport = MagicMock()
        transport.is_closing.return_value = False
        protocol = asyncio.StreamReaderProtocol(out_reader)
        writer = asyncio.StreamWriter(transport, protocol, out_reader, asyncio.get_running_loop())

        await _forward_stream(reader, writer, label="test")

        # Verify write was called with each line
        calls = transport.write.call_args_list
        assert len(calls) == 2
        assert calls[0].args[0] == b"line1\n"
        assert calls[1].args[0] == b"line2\n"

    @pytest.mark.asyncio
    async def test_eof_exits_cleanly(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_eof()

        await _forward_stream(reader, None, label="test-eof")

    @pytest.mark.asyncio
    async def test_none_writer_skips(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"data\n")
        reader.feed_eof()

        # Should not raise with None writer
        await _forward_stream(reader, None, label="test-none")


class TestMockMCPServer:
    """Verify the mock MCP server works as expected via subprocess."""

    @pytest.mark.asyncio
    async def test_initialize_response(self) -> None:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None

        msg = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {},
                }
            )
            + "\n"
        )
        proc.stdin.write(msg.encode())
        await proc.stdin.drain()

        line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
        resp = json.loads(line)
        assert resp["id"] == 1
        assert "capabilities" in resp["result"]

        proc.stdin.close()
        await proc.wait()

    @pytest.mark.asyncio
    async def test_tools_call_echo(self) -> None:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None

        msg = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
                }
            )
            + "\n"
        )
        proc.stdin.write(msg.encode())
        await proc.stdin.drain()

        line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
        resp = json.loads(line)
        assert resp["id"] == 2
        content = json.loads(resp["result"]["content"][0]["text"])
        assert content["tool"] == "read_file"
        assert content["args"]["path"] == "/tmp/x"

        proc.stdin.close()
        await proc.wait()

    @pytest.mark.asyncio
    async def test_eof_exits(self) -> None:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdin is not None

        proc.stdin.close()
        code = await asyncio.wait_for(proc.wait(), timeout=5.0)
        assert code == 0

    @pytest.mark.asyncio
    async def test_multiple_messages(self) -> None:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None

        for i in range(1, 4):
            msg = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": i,
                        "method": "tools/call",
                        "params": {"name": f"tool_{i}", "arguments": {}},
                    }
                )
                + "\n"
            )
            proc.stdin.write(msg.encode())
        await proc.stdin.drain()

        responses = []
        for _ in range(3):
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
            responses.append(json.loads(line))

        assert [r["id"] for r in responses] == [1, 2, 3]

        proc.stdin.close()
        await proc.wait()


class TestBlockedResponseIntegration:
    """Test blocked response format compatibility with MCP protocol."""

    @pytest.mark.parametrize(
        ("request_id", "reason"),
        [
            (1, "Policy violation"),
            ("uuid-123", "Command denied by denylist"),
            (None, "Internal error"),
            (999, "Rate limit exceeded"),
        ],
    )
    def test_valid_jsonrpc_response(self, request_id: int | str | None, reason: str) -> None:
        data = _make_blocked_response(request_id, reason)
        parsed = json.loads(data)

        assert parsed["jsonrpc"] == "2.0"
        assert parsed["id"] == request_id
        assert parsed["result"]["isError"] is True
        assert len(parsed["result"]["content"]) == 1
        assert parsed["result"]["content"][0]["type"] == "text"
        # Not a JSON-RPC error (no "error" key)
        assert "error" not in parsed
