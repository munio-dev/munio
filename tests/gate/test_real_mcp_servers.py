"""Integration tests with REAL MCP servers through munio.

Tests the full stack: real munio subprocess → real MCP server.
Uses real published MCP servers (not mocks) to verify munio works
correctly in production-like conditions.

Requires Node.js/npx for @modelcontextprotocol servers.
Marked with @pytest.mark.integration — skipped if npx is not available.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import sys
from pathlib import Path

import pytest

_CONSTRAINTS_DIR = str(Path(__file__).resolve().parent.parent.parent / "constraints")

_HAS_NPX = shutil.which("npx") is not None

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _HAS_NPX, reason="npx not available"),
]


# ── Helpers ──────────────────────────────────────────────────────────────


def _jsonrpc(method: str, params: dict | None = None, *, request_id: int = 1) -> bytes:
    msg: dict = {"jsonrpc": "2.0", "method": method, "id": request_id}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode("utf-8") + b"\n"


def _tools_call(
    name: str,
    arguments: dict | None = None,
    *,
    request_id: int = 1,
) -> bytes:
    return _jsonrpc(
        "tools/call",
        {"name": name, "arguments": arguments or {}},
        request_id=request_id,
    )


def _init_msg(request_id: int = 1) -> bytes:
    return _jsonrpc(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "munio-test", "version": "0.1"},
        },
        request_id=request_id,
    )


async def _spawn_gate(
    *server_cmd: str,
    extra_gate_args: list[str] | None = None,
) -> asyncio.subprocess.Process:
    """Spawn munio run with a real MCP server."""
    gate_args = [
        sys.executable,
        "-m",
        "munio.gate",
        "run",
        "--constraints-dir",
        _CONSTRAINTS_DIR,
        *(extra_gate_args or []),
        "--",
        *server_cmd,
    ]
    return await asyncio.create_subprocess_exec(
        *gate_args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def _send_and_recv(
    process: asyncio.subprocess.Process,
    messages: list[bytes],
    *,
    expected_count: int,
    timeout: float = 15.0,
) -> list[dict]:
    """Send messages and collect expected_count responses. Does NOT close the process."""
    assert process.stdin is not None
    assert process.stdout is not None

    for msg in messages:
        process.stdin.write(msg)
        await process.stdin.drain()

    responses: list[dict] = []
    try:
        async with asyncio.timeout(timeout):
            while len(responses) < expected_count:
                line = await process.stdout.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped:
                    with contextlib.suppress(json.JSONDecodeError):
                        responses.append(json.loads(stripped))
    except TimeoutError:
        pass

    return responses


async def _exchange(
    process: asyncio.subprocess.Process,
    messages: list[bytes],
    *,
    expected_count: int | None = None,
    timeout: float = 15.0,
) -> list[dict]:
    """Send messages, collect responses, and close the process."""
    count = expected_count if expected_count is not None else len(messages)
    responses = await _send_and_recv(
        process,
        messages,
        expected_count=count,
        timeout=timeout,
    )

    # Cleanup
    try:
        assert process.stdin is not None
        process.stdin.close()
        await asyncio.wait_for(process.wait(), timeout=5.0)
    except (TimeoutError, ProcessLookupError):
        process.kill()
        await process.wait()

    return responses


async def _close_gate(process: asyncio.subprocess.Process) -> None:
    """Cleanly close a munio process."""
    try:
        if process.stdin is not None:
            process.stdin.close()
        await asyncio.wait_for(process.wait(), timeout=5.0)
    except (TimeoutError, ProcessLookupError):
        process.kill()
        await process.wait()


# ── server-everything ────────────────────────────────────────────────────


class TestRealEverythingServer:
    """Integration tests with @modelcontextprotocol/server-everything.

    Official MCP test server. Zero side effects, 12 tools.
    """

    @pytest.mark.asyncio
    async def test_initialize(self) -> None:
        """Real server-everything responds to initialize through munio."""
        process = await _spawn_gate("npx", "-y", "@modelcontextprotocol/server-everything")
        responses = await _exchange(process, [_init_msg()], expected_count=1)
        assert len(responses) >= 1
        assert responses[0]["result"]["serverInfo"]["name"] == "mcp-servers/everything"

    @pytest.mark.asyncio
    async def test_echo_tool_allowed(self) -> None:
        """echo tool passes through munio constraints."""
        process = await _spawn_gate("npx", "-y", "@modelcontextprotocol/server-everything")
        responses = await _exchange(
            process,
            [
                _init_msg(request_id=1),
                _tools_call("echo", {"message": "hello from munio"}, request_id=2),
            ],
            expected_count=2,
        )
        by_id = {r["id"]: r for r in responses}
        assert 2 in by_id
        content = by_id[2]["result"]["content"]
        assert any("hello from munio" in c.get("text", "") for c in content)

    @pytest.mark.asyncio
    async def test_get_sum_tool(self) -> None:
        """get-sum tool: arithmetic through real server + munio."""
        process = await _spawn_gate("npx", "-y", "@modelcontextprotocol/server-everything")
        responses = await _exchange(
            process,
            [
                _init_msg(request_id=1),
                _tools_call("get-sum", {"a": 17, "b": 25}, request_id=2),
            ],
            expected_count=2,
        )
        by_id = {r["id"]: r for r in responses}
        assert 2 in by_id
        content_text = by_id[2]["result"]["content"][0]["text"]
        assert "42" in content_text

    @pytest.mark.asyncio
    async def test_blocked_tool_still_blocked(self) -> None:
        """A dangerous tool call is still blocked with a real server behind gate."""
        process = await _spawn_gate("npx", "-y", "@modelcontextprotocol/server-everything")
        responses = await _exchange(
            process,
            [
                _init_msg(request_id=1),
                _tools_call("execute_command", {"command": "eval(os.environ)"}, request_id=2),
            ],
            expected_count=2,
        )
        by_id = {r["id"]: r for r in responses}
        assert 2 in by_id
        assert by_id[2]["result"]["isError"] is True
        assert "Blocked by munio" in by_id[2]["result"]["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_tools_list(self) -> None:
        """tools/list passes through munio untouched."""
        process = await _spawn_gate("npx", "-y", "@modelcontextprotocol/server-everything")
        responses = await _exchange(
            process,
            [
                _init_msg(request_id=1),
                _jsonrpc("tools/list", request_id=2),
            ],
            expected_count=2,
        )
        by_id = {r["id"]: r for r in responses}
        assert 2 in by_id
        tools = by_id[2]["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert "echo" in tool_names
        assert "get-sum" in tool_names


# ── server-filesystem ────────────────────────────────────────────────────


class TestRealFilesystemServer:
    """Integration tests with @modelcontextprotocol/server-filesystem.

    Sandboxed to tmp_path. Tests real file operations through munio.
    """

    @pytest.mark.asyncio
    async def test_initialize(self, tmp_path: Path) -> None:
        """Real filesystem server initializes through munio."""
        process = await _spawn_gate(
            "npx", "-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)
        )
        responses = await _exchange(process, [_init_msg()], expected_count=1)
        assert len(responses) >= 1
        # Server name varies by version, just check it responded
        assert "result" in responses[0]
        assert "serverInfo" in responses[0]["result"]

    @pytest.mark.asyncio
    async def test_read_file(self, tmp_path: Path) -> None:
        """Read a real file through filesystem server + munio."""
        test_file = tmp_path / "hello.txt"
        test_file.write_text("munio integration test content")

        process = await _spawn_gate(
            "npx", "-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)
        )
        responses = await _exchange(
            process,
            [
                _init_msg(request_id=1),
                _tools_call("read_file", {"path": str(test_file)}, request_id=2),
            ],
            expected_count=2,
        )
        by_id = {r["id"]: r for r in responses}
        assert 2 in by_id
        content = by_id[2]["result"]["content"][0]["text"]
        assert "munio integration test content" in content

    @pytest.mark.asyncio
    async def test_write_and_read_file(self, tmp_path: Path) -> None:
        """Write then read a file through filesystem server + munio."""
        target = tmp_path / "written.txt"

        process = await _spawn_gate(
            "npx", "-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)
        )

        # Step 1: init + write, wait for both responses
        responses = await _send_and_recv(
            process,
            [
                _init_msg(request_id=1),
                _tools_call(
                    "write_file",
                    {"path": str(target), "content": "written by munio test"},
                    request_id=2,
                ),
            ],
            expected_count=2,
        )
        by_id = {r["id"]: r for r in responses}
        assert 2 in by_id
        assert "isError" not in by_id[2].get("result", {})

        # Step 2: read back (write already completed)
        responses2 = await _send_and_recv(
            process,
            [_tools_call("read_file", {"path": str(target)}, request_id=3)],
            expected_count=1,
        )
        assert len(responses2) >= 1
        content = responses2[0]["result"]["content"][0]["text"]
        assert "written by munio test" in content

        # Verify on disk too
        assert target.exists()
        assert "written by munio test" in target.read_text()

        await _close_gate(process)

    @pytest.mark.asyncio
    async def test_list_directory(self, tmp_path: Path) -> None:
        """List directory contents through filesystem server + munio."""
        (tmp_path / "file_a.txt").write_text("a")
        (tmp_path / "file_b.txt").write_text("b")
        (tmp_path / "subdir").mkdir()

        process = await _spawn_gate(
            "npx", "-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)
        )
        responses = await _exchange(
            process,
            [
                _init_msg(request_id=1),
                _tools_call("list_directory", {"path": str(tmp_path)}, request_id=2),
            ],
            expected_count=2,
        )
        by_id = {r["id"]: r for r in responses}
        assert 2 in by_id
        listing = by_id[2]["result"]["content"][0]["text"]
        assert "file_a.txt" in listing
        assert "file_b.txt" in listing
        assert "subdir" in listing

    @pytest.mark.asyncio
    async def test_constraint_blocks_dangerous_call(self, tmp_path: Path) -> None:
        """Dangerous tool call blocked even with real filesystem server."""
        process = await _spawn_gate(
            "npx", "-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)
        )
        responses = await _exchange(
            process,
            [
                _init_msg(request_id=1),
                _tools_call(
                    "execute_command",
                    {"command": "eval(os.environ)"},
                    request_id=2,
                ),
            ],
            expected_count=2,
        )
        by_id = {r["id"]: r for r in responses}
        assert 2 in by_id
        assert by_id[2]["result"]["isError"] is True

    @pytest.mark.asyncio
    async def test_log_file_with_real_server(self, tmp_path: Path) -> None:
        """Interception log works correctly with real filesystem server."""
        log_path = tmp_path / "gate.jsonl"
        test_file = tmp_path / "data.txt"
        test_file.write_text("test data")

        process = await _spawn_gate(
            "npx",
            "-y",
            "@modelcontextprotocol/server-filesystem",
            str(tmp_path),
            extra_gate_args=["--log", str(log_path)],
        )
        await _exchange(
            process,
            [
                _init_msg(request_id=1),
                _tools_call("read_file", {"path": str(test_file)}, request_id=2),
                _tools_call("execute_command", {"command": "eval('x')"}, request_id=3),
            ],
            expected_count=3,
        )

        assert log_path.exists()
        log_lines = [
            json.loads(line) for line in log_path.read_text().strip().splitlines() if line.strip()
        ]
        assert len(log_lines) == 2
        assert log_lines[0]["tool"] == "read_file"
        assert log_lines[0]["decision"] == "allowed"
        assert log_lines[1]["tool"] == "execute_command"
        assert log_lines[1]["decision"] == "blocked"
