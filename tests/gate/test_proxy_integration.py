"""Integration tests for proxy interception pipeline.

Tests _read_agent_forward_to_server with mock async streams to verify
the full interception flow: parse -> intercept -> allow/block -> log.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from munio.gate.models import GateDecision, InterceptionRecord
from munio.gate.proxy import _forward_server_to_agent, _read_agent_forward_to_server


class MockStreamWriter:
    """Captures written bytes for assertion."""

    def __init__(self) -> None:
        self.data = bytearray()
        self._closed = False

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self._closed = True

    async def wait_closed(self) -> None:
        pass

    @property
    def lines(self) -> list[dict[str, Any]]:
        """Parse captured data as newline-delimited JSON."""
        return [
            json.loads(line)
            for line in self.data.decode("utf-8").strip().split("\n")
            if line.strip()
        ]


def _make_interceptor(*, allowed: bool = True, violations: list[str] | None = None) -> Any:
    """Create a mock Interceptor that returns a fixed GateDecision."""
    interceptor = MagicMock()
    interceptor.check_tool_call.return_value = GateDecision(
        allowed=allowed,
        violations=violations or [],
        elapsed_ms=0.42,
    )
    return interceptor


def _feed_lines(reader: asyncio.StreamReader, *lines: str | bytes) -> None:
    """Feed lines into a StreamReader and signal EOF."""
    for line in lines:
        if isinstance(line, str):
            line = line.encode("utf-8")
        if not line.endswith(b"\n"):
            line += b"\n"
        reader.feed_data(line)
    reader.feed_eof()


def _jsonrpc_line(method: str, *, request_id: int = 1, params: dict | None = None) -> str:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _tools_call_line(
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    request_id: int = 1,
) -> str:
    params: dict[str, Any] = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return _jsonrpc_line("tools/call", request_id=request_id, params=params)


async def _run(
    reader: asyncio.StreamReader,
    server_stdin: MockStreamWriter,
    agent_stdout: MockStreamWriter,
    interceptor: Any,
    log_callback: Any = None,
) -> dict[int | float | str, None]:
    """Helper: run _read_agent_forward_to_server with blocked_ids tracking."""
    blocked_ids: dict[int | float | str, None] = {}
    await _read_agent_forward_to_server(
        reader,
        server_stdin,
        agent_stdout,
        interceptor,
        log_callback,
        blocked_ids,
    )
    return blocked_ids


class TestAllowedToolCall:
    """Allowed tool calls should be forwarded to the server."""

    @pytest.mark.asyncio
    async def test_forwarded_to_server(self) -> None:
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()
        interceptor = _make_interceptor(allowed=True)

        line = _tools_call_line("read_file", {"path": "/tmp/x"})
        _feed_lines(reader, line)

        await _run(reader, server_stdin, agent_stdout, interceptor)

        # Should be forwarded to server stdin
        forwarded = server_stdin.lines
        assert len(forwarded) == 1
        assert forwarded[0]["method"] == "tools/call"
        assert forwarded[0]["params"]["name"] == "read_file"

        # Nothing should be written to agent stdout (no block response)
        assert len(agent_stdout.data) == 0

    @pytest.mark.asyncio
    async def test_interceptor_called(self) -> None:
        reader = asyncio.StreamReader()
        interceptor = _make_interceptor(allowed=True)

        _feed_lines(reader, _tools_call_line("ping", {"key": "val"}))

        await _run(reader, MockStreamWriter(), MockStreamWriter(), interceptor)

        interceptor.check_tool_call.assert_called_once_with("ping", {"key": "val"})


class TestBlockedToolCall:
    """Blocked tool calls should return an error response to the agent."""

    @pytest.mark.asyncio
    async def test_blocked_response_sent(self) -> None:
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()
        interceptor = _make_interceptor(allowed=False, violations=["Command denied"])

        _feed_lines(reader, _tools_call_line("exec", {"command": "rm -rf /"}, request_id=42))

        await _run(reader, server_stdin, agent_stdout, interceptor)

        # Nothing forwarded to server
        assert len(server_stdin.data) == 0

        # Blocked response sent to agent
        responses = agent_stdout.lines
        assert len(responses) == 1
        assert responses[0]["id"] == 42
        assert responses[0]["result"]["isError"] is True
        # M1 fix: violation details are sanitized — check for generic message
        assert "blocked by policy" in responses[0]["result"]["content"][0]["text"].lower()

    @pytest.mark.asyncio
    async def test_blocked_no_violations_uses_default_reason(self) -> None:
        reader = asyncio.StreamReader()
        agent_stdout = MockStreamWriter()
        interceptor = _make_interceptor(allowed=False, violations=[])

        _feed_lines(reader, _tools_call_line("exec", {}, request_id=5))

        await _run(reader, MockStreamWriter(), agent_stdout, interceptor)

        response = agent_stdout.lines[0]
        assert "policy violation" in response["result"]["content"][0]["text"].lower()

    @pytest.mark.asyncio
    async def test_blocked_id_tracked(self) -> None:
        """H3: Blocked request IDs are tracked for spoofing prevention."""
        reader = asyncio.StreamReader()
        interceptor = _make_interceptor(allowed=False, violations=["no"])

        _feed_lines(reader, _tools_call_line("exec", {}, request_id=42))

        blocked_ids = await _run(reader, MockStreamWriter(), MockStreamWriter(), interceptor)
        assert 42 in blocked_ids


class TestPassthrough:
    """Non-tool-call messages should be forwarded transparently."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "method",
        ["initialize", "tools/list", "notifications/initialized", "resources/list"],
    )
    async def test_non_tool_methods_forwarded(self, method: str) -> None:
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        interceptor = _make_interceptor()

        _feed_lines(reader, _jsonrpc_line(method, params={}))

        await _run(reader, server_stdin, MockStreamWriter(), interceptor)

        forwarded = server_stdin.lines
        assert len(forwarded) == 1
        assert forwarded[0]["method"] == method

        # Interceptor should NOT be called for non-tool methods
        interceptor.check_tool_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_lines_forwarded(self) -> None:
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()

        reader.feed_data(b"\n")
        reader.feed_data(b"  \n")
        reader.feed_eof()

        await _run(reader, server_stdin, MockStreamWriter(), _make_interceptor())

        # Empty/whitespace lines forwarded
        assert b"\n" in server_stdin.data

    @pytest.mark.asyncio
    async def test_non_json_forwarded(self) -> None:
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()

        _feed_lines(reader, "not json at all")

        await _run(reader, server_stdin, MockStreamWriter(), _make_interceptor())

        assert b"not json at all" in server_stdin.data

    @pytest.mark.asyncio
    async def test_json_non_dict_non_array_forwarded(self) -> None:
        """JSON scalar (number, string, etc.) forwarded as-is."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()

        _feed_lines(reader, "42")

        await _run(reader, server_stdin, MockStreamWriter(), _make_interceptor())

        assert b"42" in server_stdin.data

    @pytest.mark.asyncio
    async def test_response_messages_forwarded(self) -> None:
        """JSON-RPC responses (no method) pass through."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()

        response = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        _feed_lines(reader, response)

        await _run(reader, server_stdin, MockStreamWriter(), _make_interceptor())

        forwarded = server_stdin.lines
        assert len(forwarded) == 1
        assert forwarded[0]["result"]["tools"] == []


class TestBatchArrayInterception:
    """C1 fix: JSON-RPC batch arrays must be intercepted, not forwarded blindly."""

    @pytest.mark.asyncio
    async def test_batch_with_tools_call_blocked(self) -> None:
        """Batch array containing tools/call -> blocked element removed."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()
        interceptor = _make_interceptor(allowed=False, violations=["denied"])

        batch = json.dumps(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "exec", "arguments": {}},
                },
            ]
        )
        _feed_lines(reader, batch)

        await _run(reader, server_stdin, agent_stdout, interceptor)

        # Blocked response sent for the tool call
        responses = agent_stdout.lines
        assert len(responses) == 1
        assert responses[0]["result"]["isError"] is True

    @pytest.mark.asyncio
    async def test_batch_without_tools_call_forwarded(self) -> None:
        """Batch array with no tools/call -> forwarded as-is."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()

        batch = json.dumps(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ]
        )
        _feed_lines(reader, batch)

        await _run(reader, server_stdin, MockStreamWriter(), _make_interceptor())

        # Forwarded as original batch
        assert len(server_stdin.data) > 0


class TestMalformedToolsCallBlocked:
    """C2 fix: Malformed tools/call must be BLOCKED, not forwarded."""

    @pytest.mark.asyncio
    async def test_missing_name_blocked(self) -> None:
        """tools/call without name -> blocked (fail-closed)."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()

        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"arguments": {}},
            }
        )
        _feed_lines(reader, msg)

        await _run(reader, server_stdin, agent_stdout, _make_interceptor())

        # NOT forwarded to server
        assert len(server_stdin.data) == 0
        # Blocked response sent
        responses = agent_stdout.lines
        assert len(responses) == 1
        assert responses[0]["result"]["isError"] is True
        assert "malformed" in responses[0]["result"]["content"][0]["text"].lower()

    @pytest.mark.asyncio
    async def test_non_string_name_blocked(self) -> None:
        """tools/call with numeric name -> blocked."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()

        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": 42, "arguments": {}},
            }
        )
        _feed_lines(reader, msg)

        await _run(reader, server_stdin, agent_stdout, _make_interceptor())

        assert len(server_stdin.data) == 0
        assert len(agent_stdout.lines) == 1

    @pytest.mark.asyncio
    async def test_missing_params_blocked(self) -> None:
        """tools/call without params -> blocked."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()

        msg = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call"})
        _feed_lines(reader, msg)

        await _run(reader, server_stdin, agent_stdout, _make_interceptor())

        assert len(server_stdin.data) == 0


class TestNotificationHandling:
    """H6 fix: Notifications (no 'id') must not receive responses."""

    @pytest.mark.asyncio
    async def test_notification_blocked_no_response(self) -> None:
        """tools/call notification (no id) -> blocked, but no response sent."""
        reader = asyncio.StreamReader()
        agent_stdout = MockStreamWriter()
        interceptor = _make_interceptor(allowed=False, violations=["no"])

        # Notification: no "id" field at all
        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "exec", "arguments": {}},
            }
        )
        _feed_lines(reader, msg)

        await _run(reader, MockStreamWriter(), agent_stdout, interceptor)

        # No response sent (JSON-RPC 2.0: must not reply to notifications)
        assert len(agent_stdout.data) == 0


class TestLogCallback:
    """Log callback should be invoked with InterceptionRecord."""

    @pytest.mark.asyncio
    async def test_allowed_logged(self) -> None:
        reader = asyncio.StreamReader()
        records: list[InterceptionRecord] = []

        _feed_lines(reader, _tools_call_line("read", {"path": "/x"}))

        await _run(
            reader,
            MockStreamWriter(),
            MockStreamWriter(),
            _make_interceptor(allowed=True),
            log_callback=records.append,
        )

        assert len(records) == 1
        assert records[0].tool == "read"
        assert records[0].decision == "allowed"
        assert records[0].jsonrpc_id == 1

    @pytest.mark.asyncio
    async def test_blocked_logged(self) -> None:
        reader = asyncio.StreamReader()
        records: list[InterceptionRecord] = []

        _feed_lines(reader, _tools_call_line("exec", {"cmd": "rm"}, request_id=99))

        await _run(
            reader,
            MockStreamWriter(),
            MockStreamWriter(),
            _make_interceptor(allowed=False, violations=["deny"]),
            log_callback=records.append,
        )

        assert len(records) == 1
        assert records[0].tool == "exec"
        assert records[0].decision == "blocked"
        assert records[0].violations == ["deny"]
        assert records[0].jsonrpc_id == 99

    @pytest.mark.asyncio
    async def test_no_callback_no_error(self) -> None:
        reader = asyncio.StreamReader()
        _feed_lines(reader, _tools_call_line("ping"))

        await _run(reader, MockStreamWriter(), MockStreamWriter(), _make_interceptor())

    @pytest.mark.asyncio
    async def test_non_tool_not_logged(self) -> None:
        reader = asyncio.StreamReader()
        records: list[InterceptionRecord] = []

        _feed_lines(reader, _jsonrpc_line("initialize", params={}))

        await _run(
            reader,
            MockStreamWriter(),
            MockStreamWriter(),
            _make_interceptor(),
            log_callback=records.append,
        )

        assert len(records) == 0

    @pytest.mark.asyncio
    async def test_log_callback_exception_does_not_kill_loop(self) -> None:
        """H4 fix: log_callback exception must not break interception."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        call_count = 0

        def bad_callback(record: InterceptionRecord) -> None:
            nonlocal call_count
            call_count += 1
            raise OSError("disk full")

        interceptor = _make_interceptor(allowed=True)

        # Two tool calls — both should be forwarded even though callback fails
        _feed_lines(
            reader,
            _tools_call_line("tool1", {}, request_id=1),
            _tools_call_line("tool2", {}, request_id=2),
        )

        await _run(reader, server_stdin, MockStreamWriter(), interceptor, bad_callback)

        # Both tool calls should have been forwarded despite callback errors
        assert len(server_stdin.lines) == 2
        assert call_count == 2


class TestMultipleMessages:
    """Test sequences of messages in a single session."""

    @pytest.mark.asyncio
    async def test_mixed_sequence(self) -> None:
        """Initialize -> allowed tool -> blocked tool -> tools/list."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()
        records: list[InterceptionRecord] = []

        # Interceptor: first call allowed, second blocked
        interceptor = MagicMock()
        interceptor.check_tool_call.side_effect = [
            GateDecision(allowed=True, elapsed_ms=0.1),
            GateDecision(allowed=False, violations=["denied"], elapsed_ms=0.2),
        ]

        _feed_lines(
            reader,
            _jsonrpc_line("initialize", request_id=1, params={}),
            _tools_call_line("read", {"path": "/x"}, request_id=2),
            _tools_call_line("exec", {"command": "rm"}, request_id=3),
            _jsonrpc_line("tools/list", request_id=4, params={}),
        )

        await _run(reader, server_stdin, agent_stdout, interceptor, records.append)

        # Server should receive: initialize, read tool call, tools/list (3 messages)
        forwarded = server_stdin.lines
        assert len(forwarded) == 3
        assert forwarded[0]["method"] == "initialize"
        assert forwarded[1]["method"] == "tools/call"
        assert forwarded[1]["params"]["name"] == "read"
        assert forwarded[2]["method"] == "tools/list"

        # Agent stdout: one blocked response
        blocked = agent_stdout.lines
        assert len(blocked) == 1
        assert blocked[0]["id"] == 3
        assert blocked[0]["result"]["isError"] is True

        # Two interceptions logged
        assert len(records) == 2
        assert records[0].decision == "allowed"
        assert records[1].decision == "blocked"


class TestEdgeCases:
    """Edge cases in message parsing."""

    @pytest.mark.asyncio
    async def test_tools_call_no_arguments(self) -> None:
        """tools/call with name but no arguments -> intercepted with empty dict."""
        reader = asyncio.StreamReader()
        interceptor = _make_interceptor(allowed=True)

        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "ping"},
            }
        )
        _feed_lines(reader, msg)

        await _run(reader, MockStreamWriter(), MockStreamWriter(), interceptor)

        interceptor.check_tool_call.assert_called_once_with("ping", {})

    @pytest.mark.asyncio
    async def test_string_request_id(self) -> None:
        """String JSON-RPC id should be preserved in blocked response."""
        reader = asyncio.StreamReader()
        agent_stdout = MockStreamWriter()
        interceptor = _make_interceptor(allowed=False, violations=["no"])

        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "req-abc-123",
                "method": "tools/call",
                "params": {"name": "exec", "arguments": {}},
            }
        )
        _feed_lines(reader, msg)

        await _run(reader, MockStreamWriter(), agent_stdout, interceptor)

        response = agent_stdout.lines[0]
        assert response["id"] == "req-abc-123"

    @pytest.mark.asyncio
    async def test_null_request_id(self) -> None:
        """Null JSON-RPC id preserved in blocked response."""
        reader = asyncio.StreamReader()
        agent_stdout = MockStreamWriter()
        interceptor = _make_interceptor(allowed=False, violations=["no"])

        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": None,
                "method": "tools/call",
                "params": {"name": "exec", "arguments": {}},
            }
        )
        _feed_lines(reader, msg)

        await _run(reader, MockStreamWriter(), agent_stdout, interceptor)

        response = agent_stdout.lines[0]
        assert response["id"] is None

    @pytest.mark.asyncio
    async def test_eof_closes_server_stdin(self) -> None:
        """Agent EOF should close server stdin."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()

        reader.feed_eof()

        await _run(reader, server_stdin, MockStreamWriter(), _make_interceptor())

        assert server_stdin._closed


class TestForwardServerToAgent:
    """H3 fix: _forward_server_to_agent filters responses for blocked request IDs."""

    @pytest.mark.asyncio
    async def test_normal_response_forwarded(self) -> None:
        """Responses for non-blocked IDs are forwarded."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        blocked_ids: dict[int | float | str, None] = {}

        resp = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}) + "\n"
        reader.feed_data(resp.encode())
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        assert len(writer.lines) == 1
        assert writer.lines[0]["id"] == 1

    @pytest.mark.asyncio
    async def test_blocked_id_response_dropped(self) -> None:
        """H3: Responses matching blocked request IDs are dropped (spoofing prevention)."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        blocked_ids: dict[int | float | str, None] = {42: None}

        spoofed = json.dumps({"jsonrpc": "2.0", "id": 42, "result": {"data": "evil"}}) + "\n"
        reader.feed_data(spoofed.encode())
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        # Spoofed response should be dropped
        assert len(writer.data) == 0
        # ID should be removed from blocked set after filtering
        assert 42 not in blocked_ids

    @pytest.mark.asyncio
    async def test_blocked_id_string(self) -> None:
        """String request IDs are also filtered."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        blocked_ids: dict[int | float | str, None] = {"req-abc": None}

        spoofed = json.dumps({"jsonrpc": "2.0", "id": "req-abc", "result": {}}) + "\n"
        reader.feed_data(spoofed.encode())
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        assert len(writer.data) == 0

    @pytest.mark.asyncio
    async def test_non_json_forwarded(self) -> None:
        """Non-JSON server output forwarded as-is."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        blocked_ids: dict[int | float | str, None] = {1: None}

        reader.feed_data(b"not json\n")
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        assert b"not json" in writer.data

    @pytest.mark.asyncio
    async def test_none_writer_no_error(self) -> None:
        """None writer (no agent stdout) should not crash."""
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
        reader.feed_eof()

        await _forward_server_to_agent(reader, None, {}, label="test")

    @pytest.mark.asyncio
    async def test_mixed_blocked_and_normal(self) -> None:
        """Only blocked IDs are dropped; other responses forwarded."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        blocked_ids: dict[int | float | str, None] = {2: None}

        resp1 = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}) + "\n"
        resp2 = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"spoofed": True}}) + "\n"
        resp3 = json.dumps({"jsonrpc": "2.0", "id": 3, "result": {"ok": True}}) + "\n"
        reader.feed_data(resp1.encode() + resp2.encode() + resp3.encode())
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        # Only responses 1 and 3 should be forwarded
        forwarded = writer.lines
        assert len(forwarded) == 2
        assert forwarded[0]["id"] == 1
        assert forwarded[1]["id"] == 3


class TestBatchLogging:
    """Batch array logging should use pre-computed decisions (no double evaluation)."""

    @pytest.mark.asyncio
    async def test_batch_logging_calls_callback(self) -> None:
        """Log callback is invoked for tools/call elements in batch."""
        reader = asyncio.StreamReader()
        records: list[InterceptionRecord] = []
        interceptor = _make_interceptor(allowed=True)

        batch = json.dumps(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "read", "arguments": {"path": "/x"}},
                },
            ]
        )
        _feed_lines(reader, batch)

        await _run(
            reader,
            MockStreamWriter(),
            MockStreamWriter(),
            interceptor,
            records.append,
        )

        # Only the tools/call element should be logged
        assert len(records) == 1
        assert records[0].tool == "read"
        assert records[0].decision == "allowed"


class TestErrorResponseFiltering:
    """H1 fix: Error responses for blocked IDs must also be filtered."""

    @pytest.mark.asyncio
    async def test_error_response_for_blocked_id_dropped(self) -> None:
        """JSON-RPC error response with blocked ID should be dropped."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        blocked_ids: dict[int | float | str, None] = {42: None}

        error_resp = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 42,
                    "error": {"code": -32600, "message": "spoofed error"},
                }
            )
            + "\n"
        )
        reader.feed_data(error_resp.encode())
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        assert len(writer.data) == 0
        assert 42 not in blocked_ids

    @pytest.mark.asyncio
    async def test_error_response_for_unblocked_id_forwarded(self) -> None:
        """Error responses for non-blocked IDs are forwarded normally."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()

        error_resp = (
            json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "ok"}})
            + "\n"
        )
        reader.feed_data(error_resp.encode())
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, {}, label="test")

        assert len(writer.lines) == 1


class TestNullIdBlocking:
    """H4 fix: None must never be added to blocked_ids."""

    @pytest.mark.asyncio
    async def test_null_id_not_tracked(self) -> None:
        """Blocking a request with id:null should NOT add None to blocked_ids."""
        reader = asyncio.StreamReader()
        interceptor = _make_interceptor(allowed=False, violations=["no"])

        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": None,
                "method": "tools/call",
                "params": {"name": "exec", "arguments": {}},
            }
        )
        _feed_lines(reader, msg)

        blocked_ids = await _run(reader, MockStreamWriter(), MockStreamWriter(), interceptor)

        # None must NOT be in blocked_ids — it would filter all null-id server responses
        assert None not in blocked_ids

    @pytest.mark.asyncio
    async def test_null_id_server_response_not_dropped(self) -> None:
        """Server responses with id:null should NOT be dropped after blocking a null-id request."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        # Simulate: blocked_ids does NOT contain None (H4 fix)
        blocked_ids: dict[int | float | str, None] = {}

        resp = json.dumps({"jsonrpc": "2.0", "id": None, "result": {}}) + "\n"
        reader.feed_data(resp.encode())
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        assert len(writer.lines) == 1


class TestBatchMixedAllowedBlocked:
    """Batch with mixed allowed and blocked tool calls."""

    @pytest.mark.asyncio
    async def test_mixed_batch_rebuilds_correctly(self) -> None:
        """Batch with 1 allowed + 1 blocked: only allowed forwarded to server."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()

        # First call allowed, second blocked
        interceptor = MagicMock()
        interceptor.check_tool_call.side_effect = [
            GateDecision(allowed=True, elapsed_ms=0.1),
            GateDecision(allowed=False, violations=["denied"], elapsed_ms=0.2),
        ]

        batch = json.dumps(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "read", "arguments": {}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "exec", "arguments": {}},
                },
            ]
        )
        _feed_lines(reader, batch)

        await _run(reader, server_stdin, agent_stdout, interceptor)

        # Server should receive rebuilt batch with only the allowed element
        forwarded = server_stdin.lines
        assert len(forwarded) == 1
        assert isinstance(forwarded[0], list)
        assert len(forwarded[0]) == 1
        assert forwarded[0][0]["params"]["name"] == "read"

        # Agent should receive blocked response for id=2
        blocked = agent_stdout.lines
        assert len(blocked) == 1
        assert blocked[0]["id"] == 2
        assert blocked[0]["result"]["isError"] is True

    @pytest.mark.asyncio
    async def test_all_blocked_nothing_forwarded(self) -> None:
        """Batch where all tools/call are blocked: nothing forwarded to server."""
        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        interceptor = _make_interceptor(allowed=False, violations=["no"])

        batch = json.dumps(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "exec", "arguments": {}},
                },
            ]
        )
        _feed_lines(reader, batch)

        await _run(reader, server_stdin, MockStreamWriter(), interceptor)

        # Nothing forwarded (all elements blocked, allowed_elements is empty)
        assert len(server_stdin.data) == 0


class TestGuardTimeout:
    """R3-F1: Guard.check() timeout prevents indefinite hang."""

    @pytest.mark.asyncio
    async def test_single_message_timeout_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Timeout on single tools/call -> fail-closed block."""
        import munio.gate.proxy as proxy_mod

        monkeypatch.setattr(proxy_mod, "_CHECK_TIMEOUT_S", 0.05)

        # Interceptor that hangs forever
        import threading

        interceptor = MagicMock()

        def hang(*_args: object, **_kwargs: object) -> GateDecision:
            threading.Event().wait(timeout=10)
            return GateDecision(allowed=True, violations=[], elapsed_ms=0.0)

        interceptor.check_tool_call.side_effect = hang

        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()

        _feed_lines(reader, _tools_call_line("slow_tool", {"x": 1}, request_id=7))

        blocked_ids = await _run(reader, server_stdin, agent_stdout, interceptor)

        # Not forwarded to server
        assert len(server_stdin.data) == 0
        # Blocked response sent to agent
        assert len(agent_stdout.lines) >= 1
        resp = agent_stdout.lines[0]
        assert resp["id"] == 7
        assert resp["result"]["isError"] is True
        # ID tracked to filter spoofed responses
        assert 7 in blocked_ids

    @pytest.mark.asyncio
    async def test_batch_timeout_per_element(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Timeout on one batch element blocks just that element, others proceed."""
        import munio.gate.proxy as proxy_mod

        monkeypatch.setattr(proxy_mod, "_CHECK_TIMEOUT_S", 0.05)

        import threading

        call_count = 0

        def slow_on_first(name: str, args: dict[str, Any]) -> GateDecision:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call hangs
                threading.Event().wait(timeout=10)
            return GateDecision(allowed=True, violations=[], elapsed_ms=0.1)

        interceptor = MagicMock()
        interceptor.check_tool_call.side_effect = slow_on_first

        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()

        batch = json.dumps(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "slow", "arguments": {}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "fast", "arguments": {}},
                },
            ]
        )
        _feed_lines(reader, batch)

        blocked_ids = await _run(reader, server_stdin, agent_stdout, interceptor)

        # First element timed out -> blocked
        assert 1 in blocked_ids
        # Agent got blocked response for id=1
        blocked = [r for r in agent_stdout.lines if r.get("id") == 1]
        assert len(blocked) == 1
        assert blocked[0]["result"]["isError"] is True

        # Second element allowed -> forwarded in rebuilt batch
        forwarded = server_stdin.lines
        assert len(forwarded) == 1
        batch_forwarded = forwarded[0]
        assert isinstance(batch_forwarded, list)
        assert batch_forwarded[0]["params"]["name"] == "fast"

    @pytest.mark.asyncio
    async def test_allowed_fast_check_no_timeout(self) -> None:
        """Normal fast check completes without timeout interference."""
        interceptor = _make_interceptor(allowed=True)

        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()

        _feed_lines(reader, _tools_call_line("read_file", {"path": "/tmp/x"}, request_id=1))

        await _run(reader, server_stdin, MockStreamWriter(), interceptor)

        assert len(server_stdin.lines) == 1
        assert server_stdin.lines[0]["params"]["name"] == "read_file"


class TestBrokenPipeRecovery:
    """Error handling in forwarding loops."""

    @pytest.mark.asyncio
    async def test_server_eof_no_crash(self) -> None:
        """Server closing stdout mid-stream doesn't crash the proxy."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()

        # Feed some data, then EOF
        reader.feed_data(b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, {}, label="test")

        assert len(writer.lines) == 1

    @pytest.mark.asyncio
    async def test_empty_stream(self) -> None:
        """Empty stream (immediate EOF) handled gracefully."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, {}, label="test")

        assert len(writer.data) == 0

    @pytest.mark.asyncio
    async def test_notification_not_filtered(self) -> None:
        """Notification (no id) from server is never filtered by blocked_ids."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        blocked_ids: dict[int | float | str, None] = {1: None}

        notification = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 50}}
        )
        reader.feed_data(notification.encode() + b"\n")
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        assert len(writer.lines) == 1
        assert writer.lines[0]["method"] == "notifications/progress"
        # blocked_ids unchanged
        assert 1 in blocked_ids

    @pytest.mark.asyncio
    async def test_error_response_filtered(self) -> None:
        """Server error response (not just result) for blocked ID is also dropped."""
        reader = asyncio.StreamReader()
        writer = MockStreamWriter()
        blocked_ids: dict[int | float | str, None] = {5: None}

        error_resp = json.dumps(
            {"jsonrpc": "2.0", "id": 5, "error": {"code": -32600, "message": "Invalid Request"}}
        )
        reader.feed_data(error_resp.encode() + b"\n")
        reader.feed_eof()

        await _forward_server_to_agent(reader, writer, blocked_ids, label="test")

        # Error response for blocked ID should also be dropped
        assert len(writer.data) == 0
        assert 5 not in blocked_ids


class TestInterceptorException:
    """Interceptor exception handling (fail-closed)."""

    @pytest.mark.asyncio
    async def test_interceptor_exception_blocks(self) -> None:
        """Exception in interceptor.check_tool_call -> blocked (fail-closed)."""
        interceptor = MagicMock()
        interceptor.check_tool_call.side_effect = RuntimeError("internal error")

        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()

        _feed_lines(reader, _tools_call_line("bad_tool", {}, request_id=99))

        await _run(reader, server_stdin, agent_stdout, interceptor)

        # Not forwarded
        assert len(server_stdin.data) == 0
        # Blocked response sent (from interceptor's fail-closed path)
        assert len(agent_stdout.lines) >= 1
        resp = agent_stdout.lines[0]
        assert resp["result"]["isError"] is True

    @pytest.mark.asyncio
    async def test_batch_element_exception_continues(self) -> None:
        """Exception on one batch element doesn't kill other elements."""
        call_count = 0

        def fail_on_first(name: str, args: dict[str, Any]) -> GateDecision:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("boom")
            return GateDecision(allowed=True, violations=[], elapsed_ms=0.1)

        interceptor = MagicMock()
        interceptor.check_tool_call.side_effect = fail_on_first

        reader = asyncio.StreamReader()
        server_stdin = MockStreamWriter()
        agent_stdout = MockStreamWriter()

        batch = json.dumps(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "bad", "arguments": {}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "good", "arguments": {}},
                },
            ]
        )
        _feed_lines(reader, batch)

        blocked_ids = await _run(reader, server_stdin, agent_stdout, interceptor)

        # First element failed -> blocked
        assert 1 in blocked_ids
        blocked = [r for r in agent_stdout.lines if r.get("id") == 1]
        assert len(blocked) == 1
        assert blocked[0]["result"]["isError"] is True

        # Second element allowed -> forwarded
        forwarded = server_stdin.lines
        assert len(forwarded) >= 1
