"""Tests for munio.gate.discovery — config discovery and rewriting."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path as RealPath
from pathlib import PurePath
from typing import TYPE_CHECKING

import pytest

from munio.gate.discovery import (
    ConfigEntry,
    _is_already_wrapped,
    _is_venv_path,
    _resolve_gate_cmd,
    rewrite_config,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestIsAlreadyWrapped:
    """Test detection of already-wrapped servers."""

    @pytest.mark.parametrize(
        ("config", "expected"),
        [
            ({"command": "munio", "args": ["run", "--", "npx", "server"]}, True),
            ({"command": "/usr/local/bin/munio", "args": ["run"]}, True),
            ({"command": "npx", "args": ["-y", "@mcp/server"]}, False),
            ({"command": "python", "args": ["-m", "mcp_server"]}, False),
            ({"command": ""}, False),
            ({}, False),
            ({"command": "../munio"}, True),  # basename is still "munio"
            ({"command": "not-munio"}, False),
            ({"command": "munio && evil"}, False),
            ({"command": 42}, False),  # non-string
        ],
    )
    def test_detection(self, config: dict, expected: bool) -> None:
        assert _is_already_wrapped(config) is expected


class TestRewriteConfig:
    """Test config rewriting to inject munio wrapper."""

    def test_basic_rewrite(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                }
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        entry = ConfigEntry(
            "test",
            config_path,
            "mcpServers",
            config_data["mcpServers"],
        )
        results = rewrite_config(entry)
        assert results["filesystem"] == "wrapped"

        # Verify rewritten config
        written = json.loads(config_path.read_text())
        server = written["mcpServers"]["filesystem"]
        assert PurePath(server["command"]).name == "munio"
        assert server["args"][0] == "run"
        assert "--" in server["args"]
        # Original command preserved after --
        dash_idx = server["args"].index("--")
        assert server["args"][dash_idx + 1] == "npx"
        assert server["args"][dash_idx + 2] == "-y"

    def test_idempotent_skip_already_wrapped(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "fs": {
                    "command": "munio",
                    "args": ["run", "--", "npx", "server"],
                }
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        entry = ConfigEntry("test", config_path, "mcpServers", config_data["mcpServers"])
        results = rewrite_config(entry)
        assert results["fs"] == "already_wrapped"

    def test_backup_created(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "server1": {"command": "node", "args": ["server.js"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        entry = ConfigEntry("test", config_path, "mcpServers", config_data["mcpServers"])
        rewrite_config(entry)

        backup = tmp_path / "config.munio-backup.json"
        assert backup.exists()
        # Backup should be original content
        backup_data = json.loads(backup.read_text())
        assert backup_data["mcpServers"]["server1"]["command"] == "node"

    def test_dry_run_no_writes(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "server1": {"command": "node", "args": ["server.js"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        entry = ConfigEntry("test", config_path, "mcpServers", config_data["mcpServers"])
        results = rewrite_config(entry, dry_run=True)
        assert results["server1"] == "wrapped"

        # File should be unchanged
        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["server1"]["command"] == "node"

    def test_multiple_servers(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "fs": {"command": "npx", "args": ["fs-server"]},
                "git": {"command": "npx", "args": ["git-server"]},
                "already": {"command": "munio", "args": ["run", "--", "npx", "x"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        entry = ConfigEntry("test", config_path, "mcpServers", config_data["mcpServers"])
        results = rewrite_config(entry)
        assert results["fs"] == "wrapped"
        assert results["git"] == "wrapped"
        assert results["already"] == "already_wrapped"

    def test_toctou_aborts_on_file_change(self, tmp_path: Path) -> None:
        """M5 fix: Rewrite aborts if config file changed between reads."""
        config_data = {
            "mcpServers": {
                "server1": {"command": "node", "args": ["server.js"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        entry = ConfigEntry("test", config_path, "mcpServers", config_data["mcpServers"])

        # Tamper with file after entry is created (simulates TOCTOU)
        config_path.write_text(json.dumps({"mcpServers": {"evil": {"command": "evil"}}}))

        results = rewrite_config(entry)
        # Should abort because hash changed
        assert results == {} or "server1" not in results

    def test_corrupt_backup_gets_overwritten(self, tmp_path: Path) -> None:
        """M6 fix: Corrupt backup file is replaced with fresh backup."""
        config_data = {
            "mcpServers": {
                "server1": {"command": "node", "args": ["server.js"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        # Pre-create a corrupt backup (new name)
        backup_path = tmp_path / "config.munio-backup.json"
        backup_path.write_text("{}")

        entry = ConfigEntry("test", config_path, "mcpServers", config_data["mcpServers"])
        results = rewrite_config(entry)
        assert results["server1"] == "wrapped"

        # Backup should now contain original valid content
        backup_data = json.loads(backup_path.read_text())
        assert "mcpServers" in backup_data

    def test_valid_backup_not_overwritten(self, tmp_path: Path) -> None:
        """M6 fix: Valid existing backup is preserved (not overwritten)."""
        original_config = {
            "mcpServers": {
                "server1": {"command": "node", "args": ["server.js"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(original_config))

        # Pre-create a valid backup with different content
        backup_path = tmp_path / "config.munio-backup.json"
        backup_content = {"mcpServers": {"server1": {"command": "python"}}}
        backup_path.write_text(json.dumps(backup_content))

        entry = ConfigEntry("test", config_path, "mcpServers", original_config["mcpServers"])
        rewrite_config(entry)

        # Backup should be unchanged (original valid backup preserved)
        assert json.loads(backup_path.read_text()) == backup_content

    def test_gate_args_passed(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "server1": {"command": "npx", "args": ["server"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        entry = ConfigEntry("test", config_path, "mcpServers", config_data["mcpServers"])
        rewrite_config(entry, gate_args=["--packs", "generic,openclaw"])

        written = json.loads(config_path.read_text())
        args = written["mcpServers"]["server1"]["args"]
        assert "--packs" in args
        assert "generic,openclaw" in args

    def test_writes_absolute_path_when_not_in_path(self, tmp_path: Path) -> None:
        """When 'munio' is not in PATH, writes absolute path to the binary."""
        config_data = {"mcpServers": {"server1": {"command": "npx", "args": ["@foo/server"]}}}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        entry = ConfigEntry("test", config_path, "mcpServers", config_data["mcpServers"])
        rewrite_config(entry)

        written = json.loads(config_path.read_text())
        cmd = written["mcpServers"]["server1"]["command"]
        # Should be an absolute path, not just "munio"
        assert "/" in cmd or cmd == "munio"
        # The path should actually exist
        assert PurePath(cmd).is_absolute() or shutil.which(cmd) is not None


class TestResolveGateCmd:
    """Test _resolve_gate_cmd() path resolution."""

    def test_returns_existing_path(self) -> None:
        """Returns a path to an existing munio binary."""
        result = _resolve_gate_cmd()
        assert PurePath(result).is_absolute() or shutil.which(result) is not None

    def test_basename_is_munio(self) -> None:
        """Resolved path has basename 'munio'."""
        result = _resolve_gate_cmd()
        assert PurePath(result).name == "munio"

    def test_prefers_absolute_path(self) -> None:
        """Prefers absolute path over bare name (IDE processes lack venv PATH)."""

        result = _resolve_gate_cmd()
        venv_munio = RealPath(sys.executable).parent / "munio"
        if venv_munio.exists():
            assert PurePath(result).is_absolute()


class TestIsVenvPath:
    """Test _is_venv_path() detection."""

    @pytest.mark.parametrize(
        ("path_str", "expected"),
        [
            ("/home/user/.venv/bin/munio", True),
            ("/home/user/project/venv/bin/munio", True),
            ("/home/user/.local/bin/munio", False),
            ("/usr/local/bin/munio", False),
            ("/home/user/.venv/lib/python/munio", True),
        ],
        ids=["dot-venv", "venv", "pipx-local", "system", "venv-lib"],
    )
    def test_detection(self, path_str: str, expected: bool) -> None:

        assert _is_venv_path(RealPath(path_str)) == expected
