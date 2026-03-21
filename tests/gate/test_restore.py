"""Tests for munio restore command -- unwrapping munio/munio from MCP configs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from munio.gate.discovery import (
    ConfigEntry,
    _unwrap_server,
    restore_config,
)

if TYPE_CHECKING:
    from pathlib import Path

    from typer.testing import CliRunner


# ── Helpers ──────────────────────────────────────────────────────────────


def _make_config(tmp_path: Path, servers: dict, *, key: str = "mcpServers") -> Path:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({key: servers}))
    return config_path


def _make_entry(config_path: Path, servers: dict, *, key: str = "mcpServers") -> ConfigEntry:
    return ConfigEntry("test", config_path, key, servers)


# ── TestUnwrapServer ────────────────────────────────────────────────────


class TestUnwrapServer:
    @pytest.mark.parametrize(
        ("cfg", "expected"),
        [
            # Basic unwrap
            (
                {"command": "munio", "args": ["run", "--", "npx", "server"]},
                ("npx", ["server"]),
            ),
            # With gate flags before --
            (
                {
                    "command": "munio",
                    "args": ["run", "-d", "/c", "--", "node", "s.js", "--port", "3000"],
                },
                ("node", ["s.js", "--port", "3000"]),
            ),
            # Command only, no original args
            (
                {"command": "munio", "args": ["run", "--", "python"]},
                ("python", []),
            ),
            # Numeric args get stringified
            (
                {"command": "munio", "args": ["run", "--", "cmd", 42]},
                ("cmd", ["42"]),
            ),
        ],
        ids=["basic", "gate-flags", "no-original-args", "numeric-args"],
    )
    def test_valid_unwrap(self, cfg: dict, expected: tuple) -> None:
        assert _unwrap_server(cfg) == expected

    @pytest.mark.parametrize(
        "cfg",
        [
            {"command": "munio", "args": ["run"]},  # no "--"
            {"command": "munio", "args": ["run", "--"]},  # nothing after "--"
            {"command": "munio", "args": "not-a-list"},  # args not a list
            {"command": "munio"},  # no args at all
            {"command": "munio", "args": ["run", "--", ""]},  # empty cmd after "--"
            {"command": "munio", "args": ["run", "--", 42]},  # non-string cmd
        ],
        ids=[
            "no-separator",
            "nothing-after-sep",
            "args-not-list",
            "no-args",
            "empty-cmd",
            "non-string-cmd",
        ],
    )
    def test_invalid_returns_none(self, cfg: dict) -> None:
        assert _unwrap_server(cfg) is None


# ── TestRestoreConfig ───────────────────────────────────────────────────


class TestRestoreConfig:
    def test_basic_restore(self, tmp_path: Path) -> None:
        servers = {
            "fs": {
                "command": "munio",
                "args": ["run", "--", "npx", "-y", "@mcp/server-filesystem", "/tmp"],
            }
        }
        config_path = _make_config(tmp_path, servers)
        entry = _make_entry(config_path, servers)
        results = restore_config(entry)

        assert results["fs"] == "restored"
        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["fs"]["command"] == "npx"
        assert written["mcpServers"]["fs"]["args"] == ["-y", "@mcp/server-filesystem", "/tmp"]

    def test_not_wrapped_skipped(self, tmp_path: Path) -> None:
        servers = {"git": {"command": "npx", "args": ["git-server"]}}
        config_path = _make_config(tmp_path, servers)
        entry = _make_entry(config_path, servers)
        results = restore_config(entry)

        assert results["git"] == "not_wrapped"
        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["git"]["command"] == "npx"

    def test_mixed_servers(self, tmp_path: Path) -> None:
        servers = {
            "wrapped": {"command": "munio", "args": ["run", "--", "node", "s.js"]},
            "plain": {"command": "python", "args": ["-m", "server"]},
            "also_wrapped": {
                "command": "/usr/bin/munio",
                "args": ["run", "-v", "--", "npx", "x"],
            },
        }
        config_path = _make_config(tmp_path, servers)
        entry = _make_entry(config_path, servers)
        results = restore_config(entry)

        assert results["wrapped"] == "restored"
        assert results["plain"] == "not_wrapped"
        assert results["also_wrapped"] == "restored"

        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["wrapped"]["command"] == "node"
        assert written["mcpServers"]["also_wrapped"]["command"] == "npx"

    def test_invalid_wrapper_reported(self, tmp_path: Path) -> None:
        servers = {
            "bad": {"command": "munio", "args": ["run"]},  # no "--"
        }
        config_path = _make_config(tmp_path, servers)
        entry = _make_entry(config_path, servers)
        results = restore_config(entry)

        assert results["bad"] == "invalid_wrapper"
        # File unchanged
        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["bad"]["command"] == "munio"

    def test_dry_run_no_writes(self, tmp_path: Path) -> None:
        servers = {
            "fs": {"command": "munio", "args": ["run", "--", "npx", "server"]},
        }
        config_path = _make_config(tmp_path, servers)
        original_content = config_path.read_text()
        entry = _make_entry(config_path, servers)
        results = restore_config(entry, dry_run=True)

        assert results["fs"] == "restored"
        assert config_path.read_text() == original_content

    def test_backup_created(self, tmp_path: Path) -> None:
        servers = {
            "fs": {"command": "munio", "args": ["run", "--", "npx", "server"]},
        }
        config_path = _make_config(tmp_path, servers)
        entry = _make_entry(config_path, servers)
        restore_config(entry)

        backup = tmp_path / "config.munio-backup.json"
        assert backup.exists()
        backup_data = json.loads(backup.read_text())
        assert backup_data["mcpServers"]["fs"]["command"] == "munio"

    def test_symlink_backup_refused(self, tmp_path: Path) -> None:
        servers = {
            "fs": {"command": "munio", "args": ["run", "--", "npx", "server"]},
        }
        config_path = _make_config(tmp_path, servers)
        backup_path = tmp_path / "config.munio-backup.json"
        backup_path.symlink_to("/tmp/evil")
        entry = _make_entry(config_path, servers)
        results = restore_config(entry)

        assert results == {}

    def test_toctou_aborts(self, tmp_path: Path) -> None:
        servers = {
            "fs": {"command": "munio", "args": ["run", "--", "npx", "server"]},
        }
        config_path = _make_config(tmp_path, servers)
        entry = _make_entry(config_path, servers)

        # Tamper with file after creating entry
        config_path.write_text(json.dumps({"mcpServers": {"evil": {"command": "evil"}}}))

        results = restore_config(entry)
        assert results == {} or "fs" not in results

    def test_all_not_wrapped_returns_no_modification(self, tmp_path: Path) -> None:
        servers = {"s1": {"command": "node"}, "s2": {"command": "python"}}
        config_path = _make_config(tmp_path, servers)
        original_content = config_path.read_text()
        entry = _make_entry(config_path, servers)
        results = restore_config(entry)

        assert all(v == "not_wrapped" for v in results.values())
        assert config_path.read_text() == original_content

    def test_vscode_servers_key(self, tmp_path: Path) -> None:
        servers = {
            "fs": {"command": "munio", "args": ["run", "--", "npx", "server"]},
        }
        config_path = _make_config(tmp_path, servers, key="servers")
        entry = _make_entry(config_path, servers, key="servers")
        results = restore_config(entry)

        assert results["fs"] == "restored"
        written = json.loads(config_path.read_text())
        assert written["servers"]["fs"]["command"] == "npx"

    def test_non_dict_server_skipped(self, tmp_path: Path) -> None:
        servers = {"bad": "not-a-dict"}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"mcpServers": servers}))
        entry = ConfigEntry("test", config_path, "mcpServers", servers)
        results = restore_config(entry)

        assert results["bad"] == "skipped"


# ── TestRestoreCli ──────────────────────────────────────────────────────


class TestRestoreCli:
    @pytest.fixture
    def cli(self) -> tuple[CliRunner, object]:
        from typer.testing import CliRunner

        from munio.gate.cli import app

        return CliRunner(), app

    def test_restore_specific_config(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        config = {
            "mcpServers": {
                "fs": {"command": "munio", "args": ["run", "--", "npx", "server"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        result = runner.invoke(app, ["restore", "--config", str(config_path)])
        assert result.exit_code == 0

        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["fs"]["command"] == "npx"

    def test_restore_dry_run(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        config = {
            "mcpServers": {
                "fs": {"command": "munio", "args": ["run", "--", "npx", "server"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        result = runner.invoke(app, ["restore", "--dry-run", "--config", str(config_path)])
        assert result.exit_code == 0

        # File unchanged
        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["fs"]["command"] == "munio"

    def test_restore_nonexistent_file(self, cli: tuple) -> None:
        runner, app = cli
        result = runner.invoke(app, ["restore", "--config", "/tmp/nonexistent_xyz.json"])
        assert result.exit_code != 0

    def test_restore_no_servers(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"other_key": {}}))

        result = runner.invoke(app, ["restore", "--config", str(config_path)])
        assert result.exit_code == 0  # Not an error, just nothing to do

    def test_restore_not_json_object(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps([1, 2, 3]))

        result = runner.invoke(app, ["restore", "--config", str(config_path)])
        assert result.exit_code != 0

    def test_restore_invalid_wrapper_warns(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        config = {
            "mcpServers": {
                "bad": {"command": "munio", "args": ["run"]},  # no "--"
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        result = runner.invoke(app, ["restore", "--config", str(config_path)])
        assert result.exit_code == 0
        # Rich outputs to stderr; CliRunner merges stdout+stderr in result.output
        assert "invalid wrapper" in result.output.lower()

    def test_restore_malformed_json(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        config_path = tmp_path / "config.json"
        config_path.write_text("NOT JSON {{{")

        result = runner.invoke(app, ["restore", "--config", str(config_path)])
        assert result.exit_code != 0

    def test_restore_creates_backup(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        config = {
            "mcpServers": {
                "fs": {"command": "munio", "args": ["run", "--", "npx", "server"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        result = runner.invoke(app, ["restore", "--config", str(config_path)])
        assert result.exit_code == 0

        backup = tmp_path / "config.munio-backup.json"
        assert backup.exists()
        backup_data = json.loads(backup.read_text())
        # Backup has the wrapped version (before restore)
        assert backup_data["mcpServers"]["fs"]["command"] == "munio"
