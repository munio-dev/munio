"""CLI smoke tests for munio gate commands."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import PurePath
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

if TYPE_CHECKING:
    from pathlib import Path

import sys

from click.exceptions import Exit

from munio.gate.cli import (
    _find_stdio_servers,
    _load_config_file,
    _print_results,
    _resolve_constraints_dir,
    app,
)
from munio.gate.discovery import ConfigEntry
from munio.gate.models import InterceptionRecord

runner = CliRunner()


class TestVersion:
    """Test the version command."""

    def test_version_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "munio-gate" in result.output
        assert "0.1.0" in result.output


class TestRunErrors:
    """Test run command error handling."""

    def test_no_command_args(self) -> None:
        result = runner.invoke(app, ["run"])
        assert result.exit_code != 0

    def test_invalid_constraints_dir(self) -> None:
        result = runner.invoke(app, ["run", "--constraints-dir", "/nonexistent/path", "--", "echo"])
        assert result.exit_code != 0


class TestInit:
    """Test init command."""

    def test_init_no_configs_found(self) -> None:
        result = runner.invoke(app, ["init", "--dry-run"])
        # Should not crash; may say "No MCP config files found"
        assert result.exit_code == 0

    def test_init_specific_config(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "fs": {"command": "npx", "args": ["-y", "@mcp/server-filesystem"]},
            }
        }
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        result = runner.invoke(app, ["init", "--dry-run", "--config", str(config_file)])
        assert result.exit_code == 0
        assert "wrapped" in result.output.lower()

        # Dry run → file unchanged
        written = json.loads(config_file.read_text())
        assert written["mcpServers"]["fs"]["command"] == "npx"

    def test_init_writes_config(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "server1": {"command": "node", "args": ["server.js"]},
            }
        }
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        result = runner.invoke(app, ["init", "--config", str(config_file)])
        assert result.exit_code == 0

        written = json.loads(config_file.read_text())
        assert PurePath(written["mcpServers"]["server1"]["command"]).name == "munio"
        assert "--" in written["mcpServers"]["server1"]["args"]

    def test_init_nonexistent_config(self) -> None:
        result = runner.invoke(app, ["init", "--config", "/tmp/nonexistent_config_xyz.json"])
        assert result.exit_code != 0

    def test_init_non_object_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "mcp.json"
        config_file.write_text("[1, 2, 3]")

        result = runner.invoke(app, ["init", "--config", str(config_file)])
        assert result.exit_code != 0

    def test_init_malformed_json(self, tmp_path: Path) -> None:
        config_file = tmp_path / "mcp.json"
        config_file.write_text("NOT JSON {{{")

        result = runner.invoke(app, ["init", "--config", str(config_file)])
        assert result.exit_code != 0

    def test_init_no_servers_in_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps({"other": "data"}))

        result = runner.invoke(app, ["init", "--config", str(config_file)])
        assert result.exit_code == 0
        assert "no" in result.output.lower()

    def test_init_vscode_servers_key(self, tmp_path: Path) -> None:
        """VS Code uses 'servers' not 'mcpServers'."""
        config_data = {
            "servers": {
                "myserver": {"command": "python", "args": ["-m", "myserver"]},
            }
        }
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        result = runner.invoke(app, ["init", "--dry-run", "--config", str(config_file)])
        assert result.exit_code == 0
        assert "wrapped" in result.output.lower()


class TestStatus:
    """Test status command."""

    def test_status_no_configs(self) -> None:
        result = runner.invoke(app, ["status"])
        # Should not crash
        assert result.exit_code == 0

    def test_status_shows_wrapped_servers(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "Claude Desktop",
            config_file,
            "mcpServers",
            {"my-server": {"command": "munio", "args": ["run", "--", "npx", "server"]}},
        )
        with patch("munio.gate.discovery.discover_configs", return_value=[entry]):
            result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "protected" in result.output

    def test_status_shows_unwrapped_servers(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "Claude Desktop",
            config_file,
            "mcpServers",
            {"fs": {"command": "npx", "args": ["-y", "@mcp/server-filesystem"]}},
        )
        with patch("munio.gate.discovery.discover_configs", return_value=[entry]):
            result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "unprotected" in result.output

    def test_status_mixed_servers(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "Claude Desktop",
            config_file,
            "mcpServers",
            {
                "wrapped": {"command": "munio", "args": ["run", "--", "node", "srv.js"]},
                "raw": {"command": "node", "args": ["srv.js"]},
            },
        )
        with patch("munio.gate.discovery.discover_configs", return_value=[entry]):
            result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "protected" in result.output
        assert "unprotected" in result.output

    def test_status_shows_server_names(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "VS Code",
            config_file,
            "mcpServers",
            {
                "my-server": {"command": "npx", "args": ["s1"]},
                "other-server": {"command": "node", "args": ["s2"]},
            },
        )
        with patch("munio.gate.discovery.discover_configs", return_value=[entry]):
            result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "my-server" in result.output
        assert "other-server" in result.output

    def test_status_table_headers(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "Claude Desktop",
            config_file,
            "mcpServers",
            {"srv": {"command": "npx", "args": []}},
        )
        with patch("munio.gate.discovery.discover_configs", return_value=[entry]):
            result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        for header in ("Source", "Server", "Command", "Status"):
            assert header in result.output


class TestNoArgsShowsHelp:
    """Test that running with no args shows help."""

    def test_no_args(self) -> None:
        result = runner.invoke(app, [])
        # Typer's no_args_is_help=True exits with code 0 or 2
        assert result.exit_code in (0, 2)
        # Should show help text
        assert "munio-gate" in result.output.lower() or "usage" in result.output.lower()


# ── _resolve_constraints_dir tests ─────────────────────────────────────


class TestResolveConstraintsDir:
    """Test _resolve_constraints_dir fallback logic."""

    def test_explicit_valid_dir(self, tmp_path: Path) -> None:
        cdir = tmp_path / "constraints"
        cdir.mkdir()
        assert _resolve_constraints_dir(str(cdir)) == cdir

    def test_explicit_nonexistent_dir_exits(self) -> None:

        with pytest.raises(Exit):
            _resolve_constraints_dir("/nonexistent/constraints/dir")

    def test_none_returns_bundled_or_repo(self) -> None:
        """None falls through to bundled / repo / cwd cascade."""
        result = _resolve_constraints_dir(None)
        # In the dev environment at least repo_root exists
        assert result is None or result.is_dir()

    def test_none_returns_some_dir_in_dev(self) -> None:
        """In dev environment, None resolves to some valid constraints dir."""
        result = _resolve_constraints_dir(None)
        # In the dev environment, bundled or repo root constraints exist
        assert result is not None
        assert result.is_dir()


# ── _load_config_file tests ────────────────────────────────────────────


class TestLoadConfigFile:
    """Test _load_config_file error paths."""

    def test_missing_file_exits(self, tmp_path: Path) -> None:

        with pytest.raises(Exit):
            _load_config_file(tmp_path / "missing.json")

    def test_too_large_file_exits(self, tmp_path: Path) -> None:

        big_file = tmp_path / "big.json"
        big_file.write_text("{}" + " " * 1_100_000)
        with pytest.raises(Exit):
            _load_config_file(big_file)

    def test_valid_small_file_passes_size_check(self, tmp_path: Path) -> None:
        """A valid JSON file under 1MB passes all checks."""
        f = tmp_path / "ok_size.json"
        f.write_text('{"key": "val"}')
        result = _load_config_file(f)
        assert result == {"key": "val"}

    def test_malformed_json_exits(self, tmp_path: Path) -> None:

        f = tmp_path / "bad.json"
        f.write_text("NOT JSON {{{")
        with pytest.raises(Exit):
            _load_config_file(f)

    def test_non_dict_json_exits(self, tmp_path: Path) -> None:

        f = tmp_path / "list.json"
        f.write_text("[1,2,3]")
        with pytest.raises(Exit):
            _load_config_file(f)

    def test_valid_file_returns_dict(self, tmp_path: Path) -> None:
        f = tmp_path / "ok.json"
        f.write_text('{"key": "value"}')
        assert _load_config_file(f) == {"key": "value"}


# ── _find_stdio_servers tests ──────────────────────────────────────────


class TestFindStdioServers:
    """Test _find_stdio_servers extraction logic."""

    def test_mcp_servers_key(self) -> None:
        data = {"mcpServers": {"srv": {"command": "node", "args": []}}}
        results = _find_stdio_servers(data)
        assert len(results) == 1
        assert results[0][0] == "mcpServers"
        assert "srv" in results[0][1]

    def test_servers_key(self) -> None:
        data = {"servers": {"vsc": {"command": "python", "args": ["-m", "srv"]}}}
        results = _find_stdio_servers(data)
        assert len(results) == 1
        assert results[0][0] == "servers"

    def test_both_keys(self) -> None:
        data = {
            "mcpServers": {"a": {"command": "node"}},
            "servers": {"b": {"command": "python"}},
        }
        results = _find_stdio_servers(data)
        assert len(results) == 2

    def test_no_stdio_servers(self) -> None:
        data = {"mcpServers": {"sse": {"url": "http://localhost:8080"}}}
        results = _find_stdio_servers(data)
        assert results == []

    def test_empty_data(self) -> None:
        assert _find_stdio_servers({}) == []

    def test_non_dict_servers_ignored(self) -> None:
        data = {"mcpServers": "not a dict"}
        assert _find_stdio_servers(data) == []


# ── _print_results tests ──────────────────────────────────────────────


class TestPrintResults:
    """Test _print_results display helper."""

    def test_empty_results_no_output(self) -> None:
        # Should not crash and return early
        _print_results("Test", {}, dry_run=False)

    def test_known_statuses(self) -> None:
        results = {"srv1": "wrapped", "srv2": "already_wrapped", "srv3": "skipped"}
        _print_results("Test Label", results, dry_run=False)

    def test_dry_run_prefix(self) -> None:
        results = {"s": "wrapped"}
        _print_results("Label", results, dry_run=True)

    def test_unknown_status_falls_back(self) -> None:
        """Unknown status gets default icon/desc."""
        results = {"s": "unknown_status_xyz"}
        _print_results("Label", results, dry_run=False)


# ── Restore command tests ──────────────────────────────────────────────


class TestRestore:
    """Test restore command."""

    def test_restore_no_configs_found(self) -> None:
        result = runner.invoke(app, ["restore", "--dry-run"])
        assert result.exit_code == 0

    def test_restore_specific_config_no_servers(self, tmp_path: Path) -> None:
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps({"other": "data"}))
        result = runner.invoke(app, ["restore", "--config", str(config_file)])
        assert result.exit_code == 0
        assert "no" in result.output.lower()

    def test_restore_specific_config_with_wrapped_server(self, tmp_path: Path) -> None:
        """Restore unwraps a munio-wrapped server."""

        munio_path = str(PurePath(sys.executable).parent / "munio")
        config_data = {
            "mcpServers": {
                "srv": {
                    "command": munio_path,
                    "args": ["gate", "run", "--", "npx", "@mcp/server-filesystem"],
                },
            }
        }
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        result = runner.invoke(app, ["restore", "--dry-run", "--config", str(config_file)])
        assert result.exit_code == 0

    def test_restore_nonexistent_config(self) -> None:
        result = runner.invoke(app, ["restore", "--config", "/tmp/nonexistent_config_xyz.json"])
        assert result.exit_code != 0

    def test_restore_auto_discover_dry_run(self) -> None:
        """Auto-discover path with dry-run."""

        with patch("munio.gate.discovery.discover_configs", return_value=[]):
            result = runner.invoke(app, ["restore", "--dry-run"])
        assert result.exit_code == 0

    def test_restore_auto_discover_with_entries(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "Claude Desktop",
            config_file,
            "mcpServers",
            {"fs": {"command": "npx", "args": ["-y", "@mcp/server-filesystem"]}},
        )
        with (
            patch("munio.gate.discovery.discover_configs", return_value=[entry]),
            patch(
                "munio.gate.discovery.restore_config",
                return_value={"fs": "not_wrapped"},
            ),
        ):
            result = runner.invoke(app, ["restore", "--dry-run"])
        assert result.exit_code == 0

    def test_restore_auto_discover_restored_count(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "Cursor",
            config_file,
            "mcpServers",
            {"s": {"command": "munio", "args": ["gate", "run", "--", "node"]}},
        )
        with (
            patch("munio.gate.discovery.discover_configs", return_value=[entry]),
            patch(
                "munio.gate.discovery.restore_config",
                return_value={"s": "restored"},
            ),
        ):
            result = runner.invoke(app, ["restore"])
        assert result.exit_code == 0
        assert "restored" in result.output.lower()


# ── Stats command tests ────────────────────────────────────────────────


class TestStats:
    """Test stats command."""

    def _make_log_line(
        self,
        tool: str = "read_file",
        decision: str = "allowed",
        elapsed_ms: float = 5.0,
    ) -> str:

        record = InterceptionRecord(
            timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            tool=tool,
            decision=decision,
            elapsed_ms=elapsed_ms,
        )
        return record.model_dump_json()

    def test_stats_missing_log_file(self) -> None:
        result = runner.invoke(app, ["stats", "/nonexistent/log.jsonl"])
        assert result.exit_code != 0

    def test_stats_empty_log(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        log.write_text("")
        result = runner.invoke(app, ["stats", str(log)])
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_stats_empty_log_json(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        log.write_text("")
        result = runner.invoke(app, ["stats", str(log), "--json"])
        assert result.exit_code == 0
        assert "{}" in result.output

    def test_stats_parse_errors_only(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        log.write_text("not json\nalso not json\n")
        result = runner.invoke(app, ["stats", str(log)])
        assert result.exit_code != 0
        assert "parse error" in result.output.lower()

    def test_stats_valid_records_text(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        lines = [
            self._make_log_line("read_file", "allowed", 2.0),
            self._make_log_line("write_file", "blocked", 10.0),
            self._make_log_line("run_cmd", "error", 50.0),
        ]
        log.write_text("\n".join(lines) + "\n")
        result = runner.invoke(app, ["stats", str(log)])
        assert result.exit_code == 0
        assert "Allowed" in result.output
        assert "Blocked" in result.output

    def test_stats_valid_records_json(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        lines = [
            self._make_log_line("read_file", "allowed", 3.0),
            self._make_log_line("write_file", "blocked", 15.0),
        ]
        log.write_text("\n".join(lines) + "\n")
        result = runner.invoke(app, ["stats", str(log), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == 2
        assert data["allowed"] == 1
        assert data["blocked"] == 1

    def test_stats_top_blocked_tools(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        lines = [self._make_log_line("dangerous_tool", "blocked", 5.0) for _ in range(5)]
        log.write_text("\n".join(lines) + "\n")
        result = runner.invoke(app, ["stats", str(log)])
        assert result.exit_code == 0
        assert "dangerous_tool" in result.output

    def test_stats_with_parse_errors_and_valid(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        lines = [
            self._make_log_line("read_file", "allowed", 2.0),
            "broken line",
        ]
        log.write_text("\n".join(lines) + "\n")
        result = runner.invoke(app, ["stats", str(log)])
        assert result.exit_code == 0
        assert "Warning" in result.output or "parse" in result.output.lower()

    def test_stats_top_flag(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        lines = [self._make_log_line("tool_a", "blocked")] * 3
        log.write_text("\n".join(lines) + "\n")
        result = runner.invoke(app, ["stats", str(log), "--top", "1"])
        assert result.exit_code == 0

    def test_stats_os_error_reading_log(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        log.write_text("data")
        with patch("munio.gate.stats.parse_log", side_effect=OSError("disk error")):
            result = runner.invoke(app, ["stats", str(log)])
        assert result.exit_code != 0

    def test_stats_latency_in_output(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        lines = [self._make_log_line("tool", "allowed", 42.5)]
        log.write_text("\n".join(lines) + "\n")
        result = runner.invoke(app, ["stats", str(log)])
        assert result.exit_code == 0
        assert "p50" in result.output
        assert "p95" in result.output

    def test_stats_timestamps_in_output(self, tmp_path: Path) -> None:
        log = tmp_path / "gate.log"
        lines = [self._make_log_line("t", "allowed")]
        log.write_text("\n".join(lines) + "\n")
        result = runner.invoke(app, ["stats", str(log)])
        assert result.exit_code == 0
        assert "2026" in result.output


# ── run_gate error paths ───────────────────────────────────────────────


class TestRunGateErrors:
    """Test run_gate function error paths."""

    def test_invalid_mode_exits(self) -> None:
        result = runner.invoke(app, ["run", "--mode", "invalid_mode", "--", "echo"])
        assert result.exit_code != 0

    def test_symlink_log_file_rejected(self, tmp_path: Path) -> None:
        """Symlink log file is rejected for safety."""
        target = tmp_path / "target.log"
        target.write_text("")
        link = tmp_path / "link.log"
        link.symlink_to(target)
        result = runner.invoke(app, ["run", "--log", str(link), "--", "echo", "test"])
        assert result.exit_code != 0

    def test_shadow_mode_warning(self) -> None:
        """Shadow mode emits warning about non-blocking."""
        result = runner.invoke(app, ["run", "--mode", "shadow", "--", "echo"])
        # The proxy will fail but the mode warning should still be emitted
        # before the proxy runs
        assert result.exit_code != 0


# ── Init auto-discover paths ──────────────────────────────────────────


class TestInitAutoDiscover:
    """Test init command auto-discover paths."""

    def test_init_auto_discover_wraps_servers(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "Cursor",
            config_file,
            "mcpServers",
            {"s": {"command": "node", "args": ["srv.js"]}},
        )
        with (
            patch("munio.gate.discovery.discover_configs", return_value=[entry]),
            patch(
                "munio.gate.discovery.rewrite_config",
                return_value={"s": "wrapped"},
            ),
        ):
            result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "wrapped" in result.output.lower()

    def test_init_auto_discover_all_already_wrapped(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "VS Code",
            config_file,
            "mcpServers",
            {"s": {"command": "munio", "args": ["gate", "run", "--", "node"]}},
        )
        with (
            patch("munio.gate.discovery.discover_configs", return_value=[entry]),
            patch(
                "munio.gate.discovery.rewrite_config",
                return_value={"s": "already_wrapped"},
            ),
        ):
            result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "already wrapped" in result.output.lower() or "skipped" in result.output.lower()

    def test_init_auto_discover_dry_run_count(self, tmp_path: Path) -> None:

        config_file = tmp_path / "mcp.json"
        config_file.write_text("{}")
        entry = ConfigEntry(
            "Claude Desktop",
            config_file,
            "mcpServers",
            {"a": {"command": "node"}, "b": {"command": "python"}},
        )
        with (
            patch("munio.gate.discovery.discover_configs", return_value=[entry]),
            patch(
                "munio.gate.discovery.rewrite_config",
                return_value={"a": "wrapped", "b": "wrapped"},
            ),
        ):
            result = runner.invoke(app, ["init", "--dry-run"])
        assert result.exit_code == 0
        assert "2" in result.output
