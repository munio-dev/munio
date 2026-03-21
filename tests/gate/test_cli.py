"""CLI smoke tests for munio gate commands."""

from __future__ import annotations

import json
from pathlib import PurePath
from typing import TYPE_CHECKING

from typer.testing import CliRunner

if TYPE_CHECKING:
    from pathlib import Path

from munio.gate.cli import app

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
        from unittest.mock import patch

        from munio.gate.discovery import ConfigEntry

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
        from unittest.mock import patch

        from munio.gate.discovery import ConfigEntry

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
        from unittest.mock import patch

        from munio.gate.discovery import ConfigEntry

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
        from unittest.mock import patch

        from munio.gate.discovery import ConfigEntry

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
        from unittest.mock import patch

        from munio.gate.discovery import ConfigEntry

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
