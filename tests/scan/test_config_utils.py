"""Tests for munio.scan._config_utils."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from munio.scan._config_utils import get_config_candidates, parse_servers, read_config_file

if TYPE_CHECKING:
    from pathlib import Path

# ── read_config_file ─────────────────────────────────────────────────


class TestReadConfigFile:
    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert read_config_file(tmp_path / "nonexistent.json") is None

    def test_valid_json_object(self, tmp_path: Path) -> None:
        p = tmp_path / "valid.json"
        p.write_text(json.dumps({"key": "value"}))
        result = read_config_file(p)
        assert result == {"key": "value"}

    def test_invalid_json_returns_none(self, tmp_path: Path) -> None:
        p = tmp_path / "invalid.json"
        p.write_text("{not valid json")
        assert read_config_file(p) is None

    def test_non_dict_json_returns_none(self, tmp_path: Path) -> None:
        p = tmp_path / "array.json"
        p.write_text(json.dumps([1, 2, 3]))
        assert read_config_file(p) is None

    def test_file_over_1mb_returns_none(self, tmp_path: Path) -> None:
        p = tmp_path / "large.json"
        # Write a valid JSON object that exceeds 1MB
        p.write_text('{"data": "' + "x" * (1_048_576 + 100) + '"}')
        assert read_config_file(p) is None

    def test_unreadable_file_returns_none(self, tmp_path: Path) -> None:
        p = tmp_path / "noperm.json"
        p.write_text(json.dumps({"a": 1}))
        p.chmod(0o000)
        try:
            assert read_config_file(p) is None
        finally:
            p.chmod(0o644)  # restore for cleanup


# ── parse_servers ────────────────────────────────────────────────────


class TestParseServers:
    def test_valid_servers_dict(self) -> None:
        data = {
            "mcpServers": {
                "server1": {"command": "node", "args": ["app.js"]},
                "server2": {"command": "python", "args": ["srv.py"]},
            }
        }
        result = parse_servers(data, source="test", key="mcpServers")
        assert len(result) == 2
        names = {s.name for s in result}
        assert names == {"server1", "server2"}

    def test_empty_dict_returns_empty(self) -> None:
        data = {"mcpServers": {}}
        result = parse_servers(data, source="test", key="mcpServers")
        assert result == []

    def test_non_dict_servers_value_returns_empty(self) -> None:
        data = {"mcpServers": [1, 2, 3]}
        result = parse_servers(data, source="test", key="mcpServers")
        assert result == []

    def test_disabled_server_skipped(self) -> None:
        data = {
            "mcpServers": {
                "disabled_srv": {"command": "node", "disabled": True},
            }
        }
        result = parse_servers(data, source="test", key="mcpServers")
        assert len(result) == 0

    @pytest.mark.parametrize(
        ("disabled_val", "expected_count", "desc"),
        [
            (False, 1, "disabled=False not skipped"),
            (None, 1, "disabled missing (None in dict) not skipped"),
        ],
    )
    def test_non_disabled_not_skipped(
        self, disabled_val: bool | None, expected_count: int, desc: str
    ) -> None:
        config: dict = {"command": "node"}
        if disabled_val is not None:
            config["disabled"] = disabled_val
        data = {"mcpServers": {"srv": config}}
        result = parse_servers(data, source="test", key="mcpServers")
        assert len(result) == expected_count, desc

    def test_non_string_command_skipped(self) -> None:
        data = {"mcpServers": {"srv": {"command": 42}}}
        result = parse_servers(data, source="test", key="mcpServers")
        assert len(result) == 0

    def test_non_list_args_becomes_empty(self) -> None:
        data = {"mcpServers": {"srv": {"command": "node", "args": "not-a-list"}}}
        result = parse_servers(data, source="test", key="mcpServers")
        assert len(result) == 1
        assert result[0].args == []

    def test_bool_values_filtered_from_env(self) -> None:
        data = {
            "mcpServers": {
                "srv": {
                    "command": "node",
                    "env": {"GOOD": "val", "BAD_BOOL": True, "NUM": 42},
                },
            }
        }
        result = parse_servers(data, source="test", key="mcpServers")
        assert len(result) == 1
        env = result[0].env
        assert env is not None
        assert "GOOD" in env
        assert "NUM" in env  # int is allowed (converted to str)
        assert "BAD_BOOL" not in env

    def test_non_dict_config_entry_skipped(self) -> None:
        data = {"mcpServers": {"srv": "not-a-dict"}}
        result = parse_servers(data, source="test", key="mcpServers")
        assert len(result) == 0


# ── get_config_candidates ────────────────────────────────────────────


class TestGetConfigCandidates:
    def test_returns_non_empty_list(self) -> None:
        candidates = get_config_candidates()
        assert len(candidates) > 0

    def test_all_entries_have_three_elements(self) -> None:
        candidates = get_config_candidates()
        for entry in candidates:
            assert len(entry) == 3, f"Expected 3-tuple, got {len(entry)}: {entry}"

    def test_contains_claude_desktop_source(self) -> None:
        candidates = get_config_candidates()
        sources = {c[0] for c in candidates}
        assert "claude-desktop" in sources

    def test_contains_cursor_source(self) -> None:
        candidates = get_config_candidates()
        sources = {c[0] for c in candidates}
        assert "cursor" in sources
