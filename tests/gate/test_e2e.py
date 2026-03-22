"""End-to-end tests for munio gate: real subprocess proxy + full lifecycle.

Tests the complete flow with real processes, real constraints, real JSON-RPC.

Two proxy test levels:
- TestProxyE2E: internal async pipeline with real MCP subprocess and real Guard
  (sys.stdin/stdout replaced with in-memory pipes -- fast, deterministic).
- TestSubprocessGateE2E: real ``python -m munio.gate run`` subprocess with
  real mock MCP server -- full stack, nothing mocked.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from pathlib import Path, PurePath
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

    from munio.gate.interceptor import Interceptor
    from munio.gate.models import InterceptionRecord

_MOCK_SERVER = str(Path(__file__).parent / "mock_mcp_server.py")
_CONSTRAINTS_DIR = Path(__file__).resolve().parent.parent.parent / "constraints"


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


async def _read_response(
    reader: asyncio.StreamReader,
    *,
    timeout: float = 5.0,
) -> dict:
    line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    assert line, "Expected response but got EOF"
    return json.loads(line)


def _make_real_interceptor() -> Interceptor:
    """Create a real Interceptor with real Guard and real constraints."""
    from munio._temporal import InMemoryTemporalStore
    from munio.gate.interceptor import Interceptor
    from munio.guard import Guard
    from munio.models import VerificationMode

    guard = Guard(
        constraints_dir=_CONSTRAINTS_DIR,
        mode=VerificationMode.ENFORCE,
        temporal_store=InMemoryTemporalStore(),
    )
    return Interceptor(guard)


def _make_shadow_interceptor() -> Interceptor:
    """Interceptor in shadow mode — logs violations but allows all."""
    from munio._temporal import InMemoryTemporalStore
    from munio.gate.interceptor import Interceptor
    from munio.guard import Guard
    from munio.models import VerificationMode

    guard = Guard(
        constraints_dir=_CONSTRAINTS_DIR,
        mode=VerificationMode.SHADOW,
        temporal_store=InMemoryTemporalStore(),
    )
    return Interceptor(guard)


class _MockWriter:
    """In-memory asyncio.StreamWriter replacement that collects written bytes."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._closed = False

    def write(self, data: bytes) -> None:
        self._buf.extend(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self._closed = True

    async def wait_closed(self) -> None:
        pass

    @property
    def lines(self) -> list[dict]:
        return [
            json.loads(line) for line in self._buf.decode().strip().splitlines() if line.strip()
        ]


async def _run_proxy_e2e(
    agent_messages: list[bytes],
    interceptor: Interceptor,
    *,
    log_callback: Callable[[InterceptionRecord], None] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Run the proxy pipeline E2E: real subprocess + real Guard.

    Returns (agent_responses, server_received_messages).
    """
    from munio.gate.proxy import (
        _forward_server_to_agent,
        _forward_stream,
        _read_agent_forward_to_server,
    )

    # Spawn real mock MCP server
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        _MOCK_SERVER,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdin
    assert process.stdout
    assert process.stderr

    # Agent reader: feed messages from test
    agent_reader = asyncio.StreamReader()
    for msg in agent_messages:
        agent_reader.feed_data(msg)
    agent_reader.feed_eof()

    # Agent stdout: collect responses sent back to agent
    agent_stdout = _MockWriter()
    blocked_ids: dict[int | float | str, None] = {}

    # Run the three pipeline tasks
    tasks = [
        asyncio.create_task(
            _read_agent_forward_to_server(
                agent_reader,
                process.stdin,
                agent_stdout,  # type: ignore[arg-type]
                interceptor,
                log_callback,
                blocked_ids,
            )
        ),
        asyncio.create_task(
            _forward_server_to_agent(
                process.stdout,
                agent_stdout,  # type: ignore[arg-type]
                blocked_ids,
                label="server->agent",
            )
        ),
        asyncio.create_task(_forward_stream(process.stderr, None, label="server-stderr")),
    ]

    # Wait for agent reader EOF to propagate, then wait for server to finish
    await asyncio.wait_for(
        asyncio.gather(*tasks, process.wait()),
        timeout=10.0,
    )

    return agent_stdout.lines, []


# ── Proxy E2E ────────────────────────────────────────────────────────────


class TestProxyE2E:
    """E2E: real subprocess mock server + real Guard + real constraints."""

    @pytest.mark.asyncio
    async def test_initialize_passthrough(self) -> None:
        """Initialize request passes through to real server and back."""
        interceptor = _make_real_interceptor()
        responses, _ = await _run_proxy_e2e(
            [_jsonrpc("initialize", request_id=1)],
            interceptor,
        )
        assert len(responses) >= 1
        resp = responses[0]
        assert resp["id"] == 1
        assert resp["result"]["serverInfo"]["name"] == "mock-mcp"

    @pytest.mark.asyncio
    async def test_allowed_tool_call(self) -> None:
        """A safe tool call passes through real Guard and reaches real server."""
        interceptor = _make_real_interceptor()
        responses, _ = await _run_proxy_e2e(
            [_tools_call("my_tool", {"key": "value"}, request_id=2)],
            interceptor,
        )
        assert len(responses) >= 1
        resp = responses[0]
        assert resp["id"] == 2
        content = json.loads(resp["result"]["content"][0]["text"])
        assert content["tool"] == "my_tool"
        assert content["args"] == {"key": "value"}

    @pytest.mark.asyncio
    async def test_blocked_by_regex_deny(self) -> None:
        """execute_command with eval() blocked by no-eval-exec constraint."""
        interceptor = _make_real_interceptor()
        responses, _ = await _run_proxy_e2e(
            [_tools_call("execute_command", {"command": "eval(os.environ)"}, request_id=3)],
            interceptor,
        )
        assert len(responses) >= 1
        resp = responses[0]
        assert resp["id"] == 3
        assert resp["result"]["isError"] is True
        assert "Blocked by munio" in resp["result"]["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_blocked_by_threshold(self) -> None:
        """cost=500 exceeds max-spend-per-request (max=100)."""
        interceptor = _make_real_interceptor()
        responses, _ = await _run_proxy_e2e(
            [_tools_call("purchase", {"cost": 500}, request_id=4)],
            interceptor,
        )
        assert len(responses) >= 1
        resp = responses[0]
        assert resp["id"] == 4
        assert resp["result"]["isError"] is True

    @pytest.mark.asyncio
    async def test_mixed_sequence(self) -> None:
        """Initialize → allowed → blocked → allowed — proxy stays alive."""
        interceptor = _make_real_interceptor()
        responses, _ = await _run_proxy_e2e(
            [
                _jsonrpc("initialize", request_id=1),
                _tools_call("safe_tool", {"x": 1}, request_id=2),
                _tools_call("execute_command", {"command": "exec('x')"}, request_id=3),
                _tools_call("another_tool", {}, request_id=4),
            ],
            interceptor,
        )
        # Should have 4 responses (init, allowed, blocked, allowed)
        # Blocked responses may arrive before server responses (no round-trip)
        assert len(responses) == 4
        by_id = {r["id"]: r for r in responses}

        assert "serverInfo" in by_id[1]["result"]
        assert "isError" not in by_id[2].get("result", {})
        assert by_id[3]["result"]["isError"] is True
        assert "isError" not in by_id[4].get("result", {})

    @pytest.mark.asyncio
    async def test_shadow_mode_allows_violations(self) -> None:
        """In shadow mode, violating calls are forwarded to server (not blocked)."""
        interceptor = _make_shadow_interceptor()
        responses, _ = await _run_proxy_e2e(
            [_tools_call("execute_command", {"command": "eval('x')"}, request_id=1)],
            interceptor,
        )
        assert len(responses) >= 1
        resp = responses[0]
        assert resp["id"] == 1
        # Shadow → forwarded, server echoes back
        content = json.loads(resp["result"]["content"][0]["text"])
        assert content["tool"] == "execute_command"

    @pytest.mark.asyncio
    async def test_log_callback_records(self) -> None:
        """Log callback receives real interception records."""
        interceptor = _make_real_interceptor()
        records: list[InterceptionRecord] = []

        def _log(record: InterceptionRecord) -> None:
            records.append(record)

        await _run_proxy_e2e(
            [
                _tools_call("safe_tool", {}, request_id=1),
                _tools_call("execute_command", {"command": "eval('x')"}, request_id=2),
            ],
            interceptor,
            log_callback=_log,
        )

        assert len(records) == 2
        assert records[0].tool == "safe_tool"
        assert records[0].decision == "allowed"
        assert records[1].tool == "execute_command"
        assert records[1].decision == "blocked"
        assert records[1].elapsed_ms >= 0

    @pytest.mark.asyncio
    async def test_non_tool_passthrough(self) -> None:
        """Non-tools/call methods (resources/list etc) pass through unmodified."""
        interceptor = _make_real_interceptor()
        responses, _ = await _run_proxy_e2e(
            [_jsonrpc("resources/list", request_id=5)],
            interceptor,
        )
        assert len(responses) >= 1
        assert responses[0]["id"] == 5
        assert responses[0]["result"]["echo"] == "resources/list"


# ── Stats E2E ───────────────────────────────────────────────────────────


class TestStatsE2E:
    """E2E: proxy logs interceptions → stats command reads and summarizes."""

    @pytest.mark.asyncio
    async def test_stats_from_proxy_log(self, tmp_path: Path) -> None:
        """Proxy writes log via callback, stats CLI reads it."""
        from typer.testing import CliRunner

        from munio.gate.cli import app

        log_path = tmp_path / "gate.jsonl"
        log_fh = log_path.open("a", encoding="utf-8")

        def _log(record: InterceptionRecord) -> None:
            log_fh.write(record.model_dump_json() + "\n")
            log_fh.flush()

        interceptor = _make_real_interceptor()
        await _run_proxy_e2e(
            [
                _tools_call("safe1", {}, request_id=1),
                _tools_call("safe2", {}, request_id=2),
                _tools_call("safe3", {}, request_id=3),
                _tools_call("execute_command", {"command": "eval('x')"}, request_id=10),
            ],
            interceptor,
            log_callback=_log,
        )
        log_fh.close()

        # Run stats CLI
        runner = CliRunner()
        result = runner.invoke(app, ["stats", "--json", str(log_path)])
        assert result.exit_code == 0

        stats = json.loads(result.output)
        assert stats["allowed"] == 3
        assert stats["blocked"] == 1
        assert stats["total"] == 4
        assert stats["latency_p50_ms"] >= 0


# ── Lifecycle E2E ───────────────────────────────────────────────────────


class TestLifecycleE2E:
    """E2E: init → verify config wrapped → restore → verify config original."""

    def test_init_and_restore_cycle(self, tmp_path: Path) -> None:
        """Full init → restore lifecycle on a config file."""
        from typer.testing import CliRunner

        from munio.gate.cli import app

        runner = CliRunner()

        original_config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                },
                "git": {
                    "command": "python",
                    "args": ["-m", "mcp_git_server"],
                },
            }
        }
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(json.dumps(original_config, indent=2))

        # Init wraps both servers
        result = runner.invoke(app, ["init", "--config", str(config_path)])
        assert result.exit_code == 0

        wrapped = json.loads(config_path.read_text())
        for name in ("filesystem", "git"):
            server = wrapped["mcpServers"][name]
            assert PurePath(server["command"]).name == "munio"
            assert server["args"][0] == "run"
            assert "--" in server["args"]

        # Original command preserved after "--"
        fs_args = wrapped["mcpServers"]["filesystem"]["args"]
        dash_idx = fs_args.index("--")
        assert fs_args[dash_idx + 1] == "npx"
        assert fs_args[dash_idx + 2] == "-y"

        # Backup created
        backup = tmp_path / "claude_desktop_config.munio-backup.json"
        assert backup.exists()
        assert json.loads(backup.read_text())["mcpServers"]["filesystem"]["command"] == "npx"

        # Init again — idempotent
        runner.invoke(app, ["init", "--config", str(config_path)])
        assert json.loads(config_path.read_text()) == wrapped

        # Restore
        result3 = runner.invoke(app, ["restore", "--config", str(config_path)])
        assert result3.exit_code == 0

        restored = json.loads(config_path.read_text())
        assert restored["mcpServers"]["filesystem"]["command"] == "npx"
        assert restored["mcpServers"]["filesystem"]["args"] == [
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/tmp",
        ]
        assert restored["mcpServers"]["git"]["command"] == "python"
        assert restored["mcpServers"]["git"]["args"] == ["-m", "mcp_git_server"]

    def test_init_dry_run_then_real(self, tmp_path: Path) -> None:
        """Dry run previews without writing, then real init wraps."""
        from typer.testing import CliRunner

        from munio.gate.cli import app

        runner = CliRunner()

        config = {"mcpServers": {"s1": {"command": "node", "args": ["index.js"]}}}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))
        original_text = config_path.read_text()

        # Dry run — no change
        runner.invoke(app, ["init", "--dry-run", "--config", str(config_path)])
        assert config_path.read_text() == original_text

        # Real init
        runner.invoke(app, ["init", "--config", str(config_path)])
        wrapped = json.loads(config_path.read_text())
        assert PurePath(wrapped["mcpServers"]["s1"]["command"]).name == "munio"

        # Dry run restore — no change
        runner.invoke(app, ["restore", "--dry-run", "--config", str(config_path)])
        assert json.loads(config_path.read_text()) == wrapped

        # Real restore
        runner.invoke(app, ["restore", "--config", str(config_path)])
        assert json.loads(config_path.read_text())["mcpServers"]["s1"]["command"] == "node"

    def test_vscode_servers_key_lifecycle(self, tmp_path: Path) -> None:
        """VS Code uses 'servers' key — init/restore should handle it."""
        from typer.testing import CliRunner

        from munio.gate.cli import app

        runner = CliRunner()

        config = {"servers": {"myserver": {"command": "python", "args": ["-m", "my_mcp"]}}}
        config_path = tmp_path / "settings.json"
        config_path.write_text(json.dumps(config))

        runner.invoke(app, ["init", "--config", str(config_path)])
        assert (
            PurePath(json.loads(config_path.read_text())["servers"]["myserver"]["command"]).name
            == "munio"
        )

        runner.invoke(app, ["restore", "--config", str(config_path)])
        restored = json.loads(config_path.read_text())
        assert restored["servers"]["myserver"]["command"] == "python"
        assert restored["servers"]["myserver"]["args"] == ["-m", "my_mcp"]


# ── Real subprocess gate E2E ──────────────────────────────────────────


async def _send_and_collect(
    process: asyncio.subprocess.Process,
    messages: list[bytes],
    *,
    timeout: float = 10.0,
) -> list[dict]:
    """Send messages to process stdin, collect all stdout responses."""
    assert process.stdin is not None
    assert process.stdout is not None

    for msg in messages:
        process.stdin.write(msg)
        await process.stdin.drain()

    # Give proxy time to process and relay
    await asyncio.sleep(0.3)

    # Close stdin to signal EOF → proxy closes server → process exits
    process.stdin.close()

    # Collect all responses until process exits
    responses: list[dict] = []
    try:
        async with asyncio.timeout(timeout):
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped:
                    with contextlib.suppress(json.JSONDecodeError):
                        responses.append(json.loads(stripped))
    except TimeoutError:
        process.kill()

    await process.wait()
    return responses


@pytest.mark.integration
class TestSubprocessGateE2E:
    """Full subprocess E2E: real ``python -m munio.gate run`` + real mock MCP server.

    Nothing mocked — tests the entire stack as a user would run it.
    """

    @pytest.mark.asyncio
    async def test_initialize_passthrough(self) -> None:
        """Initialize passes through the real gate process to the real mock server."""
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "munio.gate",
            "run",
            "--constraints-dir",
            str(_CONSTRAINTS_DIR),
            "--",
            sys.executable,
            _MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        responses = await _send_and_collect(process, [_jsonrpc("initialize", request_id=1)])
        assert len(responses) >= 1
        resp = responses[0]
        assert resp["id"] == 1
        assert resp["result"]["serverInfo"]["name"] == "mock-mcp"

    @pytest.mark.asyncio
    async def test_allowed_tool_call(self) -> None:
        """Safe tool call passes through the real gate subprocess."""
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "munio.gate",
            "run",
            "--constraints-dir",
            str(_CONSTRAINTS_DIR),
            "--",
            sys.executable,
            _MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        responses = await _send_and_collect(
            process, [_tools_call("my_tool", {"key": "value"}, request_id=2)]
        )
        assert len(responses) >= 1
        resp = responses[0]
        assert resp["id"] == 2
        content = json.loads(resp["result"]["content"][0]["text"])
        assert content["tool"] == "my_tool"
        assert content["args"] == {"key": "value"}

    @pytest.mark.asyncio
    async def test_blocked_tool_call(self) -> None:
        """Dangerous tool call is blocked by the real gate subprocess."""
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "munio.gate",
            "run",
            "--constraints-dir",
            str(_CONSTRAINTS_DIR),
            "--",
            sys.executable,
            _MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        responses = await _send_and_collect(
            process,
            [_tools_call("execute_command", {"command": "eval(os.environ)"}, request_id=3)],
        )
        assert len(responses) >= 1
        resp = responses[0]
        assert resp["id"] == 3
        assert resp["result"]["isError"] is True
        assert "Blocked by munio" in resp["result"]["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_mixed_allowed_and_blocked(self) -> None:
        """Mix of allowed and blocked calls through the real gate subprocess."""
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "munio.gate",
            "run",
            "--constraints-dir",
            str(_CONSTRAINTS_DIR),
            "--",
            sys.executable,
            _MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        responses = await _send_and_collect(
            process,
            [
                _jsonrpc("initialize", request_id=1),
                _tools_call("safe_tool", {"x": 1}, request_id=2),
                _tools_call("execute_command", {"command": "exec('x')"}, request_id=3),
                _tools_call("another_tool", {}, request_id=4),
            ],
        )
        assert len(responses) == 4
        by_id = {r["id"]: r for r in responses}

        assert "serverInfo" in by_id[1]["result"]
        assert "isError" not in by_id[2].get("result", {})
        assert by_id[3]["result"]["isError"] is True
        assert "isError" not in by_id[4].get("result", {})

    @pytest.mark.asyncio
    async def test_log_file_written(self, tmp_path: Path) -> None:
        """Gate subprocess writes interception log to --log file."""
        log_path = tmp_path / "gate.jsonl"
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "munio.gate",
            "run",
            "--constraints-dir",
            str(_CONSTRAINTS_DIR),
            "--log",
            str(log_path),
            "--",
            sys.executable,
            _MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await _send_and_collect(
            process,
            [
                _tools_call("safe_tool", {}, request_id=1),
                _tools_call("execute_command", {"command": "eval('x')"}, request_id=2),
            ],
        )
        assert log_path.exists()
        lines = [
            json.loads(line) for line in log_path.read_text().strip().splitlines() if line.strip()
        ]
        assert len(lines) == 2
        assert lines[0]["tool"] == "safe_tool"
        assert lines[0]["decision"] == "allowed"
        assert lines[1]["tool"] == "execute_command"
        assert lines[1]["decision"] == "blocked"

    @pytest.mark.asyncio
    async def test_non_tool_passthrough(self) -> None:
        """Non-tools/call methods pass through the real gate subprocess."""
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "munio.gate",
            "run",
            "--constraints-dir",
            str(_CONSTRAINTS_DIR),
            "--",
            sys.executable,
            _MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        responses = await _send_and_collect(process, [_jsonrpc("resources/list", request_id=5)])
        assert len(responses) >= 1
        assert responses[0]["id"] == 5
        assert responses[0]["result"]["echo"] == "resources/list"

    @pytest.mark.asyncio
    async def test_exit_code_on_clean_shutdown(self) -> None:
        """Gate subprocess exits cleanly (code 0) when stdin closes."""
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "munio.gate",
            "run",
            "--constraints-dir",
            str(_CONSTRAINTS_DIR),
            "--",
            sys.executable,
            _MOCK_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert process.stdin is not None
        process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=10.0)
        except TimeoutError:
            process.kill()
            await process.wait()
        assert process.returncode == 0


# ── Workflow E2E ──────────────────────────────────────────────────────


class TestWorkflowE2E:
    """E2E: init → status → restore lifecycle with realistic MCP server configs."""

    def test_full_lifecycle_init_status_restore(self, tmp_path: Path) -> None:
        """Init wraps, status shows protected, restore unwraps back to original."""
        from unittest.mock import patch

        from typer.testing import CliRunner

        from munio.gate.cli import app

        runner = CliRunner()

        config = {
            "mcpServers": {
                "my-server": {
                    "command": "npx",
                    "args": ["server"],
                }
            }
        }
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(json.dumps(config, indent=2))

        # 1) init → wraps the server
        result = runner.invoke(app, ["init", "--config", str(config_path)])
        assert result.exit_code == 0
        assert "wrapped" in result.output.lower()

        # 2) status → shows "protected" (mock discover_configs to return our config)
        from munio.gate.discovery import ConfigEntry

        wrapped_data = json.loads(config_path.read_text())
        entry = ConfigEntry(
            source="test",
            path=config_path,
            key="mcpServers",
            servers=wrapped_data["mcpServers"],
        )
        with patch("munio.gate.cli.run_status.__wrapped__", None, create=True):
            pass  # no-op, real mock below
        with patch("munio.gate.discovery.discover_configs", return_value=[entry]):
            result2 = runner.invoke(app, ["status"])
        assert result2.exit_code == 0
        assert "protected" in result2.output.lower()

        # 3) restore → unwraps
        result3 = runner.invoke(app, ["restore", "--config", str(config_path)])
        assert result3.exit_code == 0

        restored = json.loads(config_path.read_text())
        assert restored["mcpServers"]["my-server"]["command"] == "npx"

    def test_init_idempotent(self, tmp_path: Path) -> None:
        """Running init twice: first wraps, second reports already wrapped."""
        from typer.testing import CliRunner

        from munio.gate.cli import app

        runner = CliRunner()

        config = {
            "mcpServers": {
                "demo": {
                    "command": "npx",
                    "args": ["-y", "@demo/server"],
                }
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        # First init — wraps
        r1 = runner.invoke(app, ["init", "--config", str(config_path)])
        assert r1.exit_code == 0
        assert "wrapped" in r1.output.lower()

        snapshot = config_path.read_text()

        # Second init — already wrapped (skipped)
        r2 = runner.invoke(app, ["init", "--config", str(config_path)])
        assert r2.exit_code == 0
        assert "already wrapped" in r2.output.lower()

        # Config unchanged — no double wrapping
        assert config_path.read_text() == snapshot

        # Command is still munio, not double-wrapped
        data = json.loads(config_path.read_text())
        assert PurePath(data["mcpServers"]["demo"]["command"]).name == "munio"

    def test_init_writes_absolute_path(self, tmp_path: Path) -> None:
        """Init writes an absolute path (or discoverable) munio command."""
        import shutil

        from typer.testing import CliRunner

        from munio.gate.cli import app

        runner = CliRunner()

        config = {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                }
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        runner.invoke(app, ["init", "--config", str(config_path)])

        data = json.loads(config_path.read_text())
        command = data["mcpServers"]["fs"]["command"]

        # Command is either an absolute path (contains "/") or discoverable on PATH
        assert "/" in command or shutil.which(command) is not None
        assert PurePath(command).name == "munio"

    def test_restore_preserves_original_command(self, tmp_path: Path) -> None:
        """Restore recovers the exact original command and args."""
        from typer.testing import CliRunner

        from munio.gate.cli import app

        runner = CliRunner()

        original_args = ["-y", "@foo/server", "--port", "3000"]
        config = {
            "mcpServers": {
                "foo": {
                    "command": "npx",
                    "args": original_args.copy(),
                }
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        # init → wraps
        runner.invoke(app, ["init", "--config", str(config_path)])

        # restore → unwraps
        runner.invoke(app, ["restore", "--config", str(config_path)])

        restored = json.loads(config_path.read_text())
        assert restored["mcpServers"]["foo"]["command"] == "npx"
        assert restored["mcpServers"]["foo"]["args"] == original_args
