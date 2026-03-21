"""Tests for munio.scan.discovery."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from munio.scan.discovery import (
    _get_candidates,
    _read_config_file,
    discover_from_file,
    discover_servers,
)
from munio.scan.models import DiscoveryError


class TestDiscoverServers:
    """Tests for discover_servers()."""

    def test_no_configs_found(self, tmp_path: Path) -> None:
        """Returns empty list when no IDE configs exist."""
        with patch("munio.scan.discovery._get_candidates", return_value=[]):
            result = discover_servers()
        assert result == []

    def test_claude_desktop_config(self, tmp_path: Path) -> None:
        """Parse Claude Desktop mcpServers config."""
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "token123"},
                },
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("claude-desktop", config_file, "mcpServers")],
        ):
            result = discover_servers()

        assert len(result) == 2
        fs = next(s for s in result if s.name == "filesystem")
        assert fs.source == "claude-desktop"
        assert fs.command == "npx"
        assert fs.args == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

    def test_vscode_uses_servers_key(self, tmp_path: Path) -> None:
        """VS Code uses 'servers' key, not 'mcpServers'."""
        config = {
            "servers": {
                "my-server": {"command": "node", "args": ["server.js"]},
            }
        }
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("vscode", config_file, "servers")],
        ):
            # vscode is project-level, requires include_project_level=True
            result = discover_servers(include_project_level=True)

        assert len(result) == 1
        assert result[0].source == "vscode"

    def test_disabled_servers_skipped(self, tmp_path: Path) -> None:
        """Servers with 'disabled: true' are skipped."""
        config = {
            "mcpServers": {
                "active": {"command": "echo"},
                "disabled": {"command": "echo", "disabled": True},
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()

        assert len(result) == 1
        assert result[0].name == "active"

    def test_malformed_json_skipped(self, tmp_path: Path) -> None:
        """Malformed JSON files are silently skipped."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json{{{")

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", bad_file, "mcpServers")],
        ):
            result = discover_servers()

        assert result == []

    def test_missing_file_skipped(self, tmp_path: Path) -> None:
        """Missing files are silently skipped."""
        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", tmp_path / "nonexistent.json", "mcpServers")],
        ):
            result = discover_servers()

        assert result == []

    def test_oversized_file_skipped(self, tmp_path: Path) -> None:
        """Files >1MB are skipped."""
        big_file = tmp_path / "big.json"
        big_file.write_text('{"mcpServers": {}}' + " " * 1_100_000)

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", big_file, "mcpServers")],
        ):
            result = discover_servers()

        assert result == []

    def test_env_parsed_as_strings(self, tmp_path: Path) -> None:
        """Env values are coerced to strings."""
        config = {
            "mcpServers": {
                "s": {"command": "cmd", "env": {"PORT": 8080}},
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()

        assert result[0].env == {"PORT": "8080"}


class TestParseServersEdgeCases:
    """Test edge cases in _parse_servers."""

    def test_non_string_args_skipped(self, tmp_path: Path) -> None:
        """Non-string args items are filtered out."""
        config = {
            "mcpServers": {
                "s": {"command": "echo", "args": ["valid", 123, {"bad": True}]},
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()

        assert result[0].args == ["valid"]

    def test_non_string_command_skipped(self, tmp_path: Path) -> None:
        """Server with non-string command is skipped."""
        config = {
            "mcpServers": {
                "s": {"command": 42},
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()

        assert result == []

    def test_bool_env_values_skipped(self, tmp_path: Path) -> None:
        """Boolean env values are filtered (not coerced)."""
        config = {
            "mcpServers": {
                "s": {"command": "cmd", "env": {"BOOL_VAL": True, "PORT": 8080}},
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()

        assert "BOOL_VAL" not in result[0].env
        assert result[0].env["PORT"] == "8080"

    def test_non_dict_servers_section_skipped(self, tmp_path: Path) -> None:
        """Non-dict mcpServers section returns empty."""
        config = {"mcpServers": "not a dict"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()

        assert result == []

    def test_non_dict_config_file_skipped(self, tmp_path: Path) -> None:
        """Config file that's not a JSON object is skipped."""
        config_file = tmp_path / "config.json"
        config_file.write_text("[1, 2, 3]")

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()

        assert result == []


class TestDiscoverFromFile:
    """Tests for discover_from_file()."""

    def test_valid_config(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"s": {"command": "echo"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))
        result = discover_from_file(p)
        assert len(result) == 1

    def test_servers_key(self, tmp_path: Path) -> None:
        """Auto-detects 'servers' key (VS Code format)."""
        config = {"servers": {"s": {"command": "echo"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))
        result = discover_from_file(p)
        assert len(result) == 1

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(DiscoveryError):
            discover_from_file(tmp_path / "nonexistent.json")

    def test_no_servers_returns_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.json"
        p.write_text("{}")
        result = discover_from_file(p)
        assert result == []


class TestProjectLevelDiscovery:
    """Verify that project-level sources are skipped by default."""

    def test_default_skips_project_level(self, tmp_path: Path) -> None:
        """discover_servers() without flag skips vscode/claude-code sources."""
        vscode_config = {
            "servers": {"evil": {"command": "malicious"}},
        }
        vscode_file = tmp_path / "mcp.json"
        vscode_file.write_text(json.dumps(vscode_config))

        claude_code_config = {
            "mcpServers": {"evil2": {"command": "malicious2"}},
        }
        claude_code_file = tmp_path / "settings.json"
        claude_code_file.write_text(json.dumps(claude_code_config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[
                ("vscode", vscode_file, "servers"),
                ("claude-code", claude_code_file, "mcpServers"),
            ],
        ):
            result = discover_servers()

        assert result == [], "Project-level sources should be skipped by default"

    def test_include_project_level_returns_them(self, tmp_path: Path) -> None:
        """discover_servers(include_project_level=True) includes vscode/claude-code."""
        vscode_config = {
            "servers": {"my-server": {"command": "node", "args": ["server.js"]}},
        }
        vscode_file = tmp_path / "mcp.json"
        vscode_file.write_text(json.dumps(vscode_config))

        claude_code_config = {
            "mcpServers": {"my-server2": {"command": "echo"}},
        }
        claude_code_file = tmp_path / "settings.json"
        claude_code_file.write_text(json.dumps(claude_code_config))

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[
                ("vscode", vscode_file, "servers"),
                ("claude-code", claude_code_file, "mcpServers"),
            ],
        ):
            result = discover_servers(include_project_level=True)

        assert len(result) == 2
        sources = {s.source for s in result}
        assert "vscode" in sources
        assert "claude-code" in sources


class TestDiscoverySizeCheck:
    """Verify that oversized config files are skipped before reading."""

    def test_stat_checked_before_read(self, tmp_path: Path) -> None:
        """Config file >1MB is skipped (stat is checked before read)."""
        big_file = tmp_path / "big_config.json"
        # Write minimal valid JSON but pad to >1MB
        big_file.write_text('{"mcpServers": {"s": {"command": "echo"}}}' + " " * 1_100_000)

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", big_file, "mcpServers")],
        ):
            result = discover_servers()

        assert result == [], "Oversized file should be skipped"

    def test_normal_size_file_not_skipped(self, tmp_path: Path) -> None:
        """Config file under 1MB is read normally."""
        normal_file = tmp_path / "normal_config.json"
        normal_file.write_text('{"mcpServers": {"s": {"command": "echo"}}}')

        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", normal_file, "mcpServers")],
        ):
            result = discover_servers()

        assert len(result) == 1


class TestGetCandidates:
    """Smoke tests for _get_candidates()."""

    def test_returns_nonempty_list(self) -> None:
        """_get_candidates returns non-empty list on any platform."""
        candidates = _get_candidates()
        assert len(candidates) >= 4  # cursor, vscode, cline, junie, claude-code always present

    def test_all_tuples_have_correct_shape(self) -> None:
        """Each candidate is (source:str, path:Path, key:str)."""
        from pathlib import Path as PathCls

        for source, path, key in _get_candidates():
            assert isinstance(source, str)
            assert source
            assert isinstance(path, PathCls)
            assert key in ("mcpServers", "servers")

    def test_contains_expected_sources(self) -> None:
        """Known sources are present regardless of platform."""
        sources = {s for s, _, _ in _get_candidates()}
        # These are always added (not platform-gated)
        assert "cursor" in sources
        assert "junie" in sources
        assert "vscode" in sources
        assert "claude-code" in sources

    def test_claude_desktop_source_present(self) -> None:
        """Claude Desktop candidate exists for current platform."""
        sources = {s for s, _, _ in _get_candidates()}
        if sys.platform in ("darwin", "linux", "win32"):
            assert "claude-desktop" in sources


class TestReadConfigFileEdgeCases:
    """Test _read_config_file edge cases."""

    def test_oserror_on_stat(self, tmp_path: Path) -> None:
        """OSError during stat() returns None."""
        p = tmp_path / "config.json"
        p.write_text('{"mcpServers": {}}')
        with patch.object(type(p), "stat", side_effect=OSError("Permission denied")):
            assert _read_config_file(p) is None

    def test_oserror_on_read_text(self, tmp_path: Path) -> None:
        """OSError during read_text() returns None."""
        p = tmp_path / "config.json"
        p.write_text('{"mcpServers": {}}')
        with patch.object(type(p), "read_text", side_effect=OSError("Disk error")):
            assert _read_config_file(p) is None


class TestParseServersMoreEdgeCases:
    """Additional edge cases for _parse_servers."""

    def test_non_dict_server_entry_skipped(self, tmp_path: Path) -> None:
        """Server entry that's a string (not dict) is skipped."""
        config = {"mcpServers": {"good": {"command": "echo"}, "bad": "not a dict"}}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()
        assert len(result) == 1
        assert result[0].name == "good"

    def test_non_list_args_treated_as_empty(self, tmp_path: Path) -> None:
        """Non-list args value is treated as empty list."""
        config = {"mcpServers": {"s": {"command": "echo", "args": "not-a-list"}}}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()
        assert result[0].args == []

    def test_url_field_parsed(self, tmp_path: Path) -> None:
        """URL field is parsed when present as string."""
        config = {
            "mcpServers": {
                "s": {"command": "echo", "url": "http://localhost:3000/sse"},
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()
        assert result[0].url == "http://localhost:3000/sse"

    def test_non_string_url_ignored(self, tmp_path: Path) -> None:
        """Non-string URL is ignored (set to None)."""
        config = {"mcpServers": {"s": {"command": "echo", "url": 42}}}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[("test", config_file, "mcpServers")],
        ):
            result = discover_servers()
        assert result[0].url is None

    def test_server_sorted_by_source_and_name(self, tmp_path: Path) -> None:
        """Results are sorted by (source, name)."""
        c1 = tmp_path / "c1.json"
        c1.write_text(json.dumps({"mcpServers": {"b_server": {"command": "echo"}}}))
        c2 = tmp_path / "c2.json"
        c2.write_text(json.dumps({"mcpServers": {"a_server": {"command": "echo"}}}))
        with patch(
            "munio.scan.discovery._get_candidates",
            return_value=[
                ("z_source", c1, "mcpServers"),
                ("a_source", c2, "mcpServers"),
            ],
        ):
            result = discover_servers()
        assert result[0].source == "a_source"
        assert result[1].source == "z_source"


class TestExpandFunction:
    """Test _expand helper."""

    def test_expands_tilde(self) -> None:
        """Tilde is expanded to home directory."""
        from munio.scan.discovery import _expand

        result = _expand("~/test")
        assert "~" not in str(result)
        assert str(result).endswith("test")

    def test_expands_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables are expanded."""
        from munio.scan.discovery import _expand

        monkeypatch.setenv("PROOF_TEST_VAR", "/custom/path")
        result = _expand("$PROOF_TEST_VAR/config.json")
        assert str(result) == "/custom/path/config.json"
