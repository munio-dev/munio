"""Tests for munio.scan.schema_loader."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from munio.scan.models import SchemaLoadError
from munio.scan.schema_loader import load_from_dict, load_from_file


class TestLoadFromFile:
    """Tests for load_from_file()."""

    def test_array_of_tools(self, tmp_path: Path) -> None:
        """Load array of tool definitions."""
        tools_data = [
            {"name": "tool1", "description": "desc1", "inputSchema": {"type": "object"}},
            {"name": "tool2", "description": "desc2", "inputSchema": {"type": "object"}},
        ]
        p = tmp_path / "tools.json"
        p.write_text(json.dumps(tools_data))
        result = load_from_file(p)
        assert len(result) == 2
        assert result[0].name == "tool1"
        assert result[1].name == "tool2"

    def test_tools_wrapper(self, tmp_path: Path) -> None:
        """Load {"tools": [...]} format."""
        data = {"tools": [{"name": "t1", "inputSchema": {}}]}
        p = tmp_path / "tools.json"
        p.write_text(json.dumps(data))
        result = load_from_file(p)
        assert len(result) == 1

    def test_single_tool(self, tmp_path: Path) -> None:
        """Load single tool definition object."""
        data = {"name": "solo", "description": "solo tool", "inputSchema": {"type": "object"}}
        p = tmp_path / "tool.json"
        p.write_text(json.dumps(data))
        result = load_from_file(p)
        assert len(result) == 1
        assert result[0].name == "solo"

    def test_camel_case_input_schema(self, tmp_path: Path) -> None:
        """Handle both 'inputSchema' and 'input_schema' field names."""
        data = [
            {
                "name": "t",
                "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
            }
        ]
        p = tmp_path / "tools.json"
        p.write_text(json.dumps(data))
        result = load_from_file(p)
        assert "x" in result[0].input_schema.get("properties", {})

    def test_server_name_passed(self, tmp_path: Path) -> None:
        """server_name is set on all loaded tools."""
        data = [{"name": "t"}]
        p = tmp_path / "tools.json"
        p.write_text(json.dumps(data))
        result = load_from_file(p, server_name="my-server")
        assert result[0].server_name == "my-server"

    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(SchemaLoadError, match="not found"):
            load_from_file(tmp_path / "missing.json")

    def test_invalid_json(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("not json")
        with pytest.raises(SchemaLoadError, match="Invalid JSON"):
            load_from_file(p)

    def test_oversized_file(self, tmp_path: Path) -> None:
        p = tmp_path / "big.json"
        p.write_text("[" + ",".join(['{"name":"t"}'] * 100) + "]" + " " * 11_000_000)
        with pytest.raises(SchemaLoadError, match="too large"):
            load_from_file(p)


class TestLoadFromFileEdgeCases:
    """Edge cases for load_from_file()."""

    def test_stat_size_check_before_read(self, tmp_path: Path) -> None:
        """File size is checked via stat() before reading file content."""
        from types import SimpleNamespace
        from unittest.mock import patch

        p = tmp_path / "big.json"
        p.write_text('[{"name":"t"}]')

        fake_result = SimpleNamespace(st_size=20_000_000, st_mode=0o100644)
        with (
            patch.object(type(p), "stat", return_value=fake_result),
            pytest.raises(SchemaLoadError, match="too large"),
        ):
            load_from_file(p)

    def test_oserror_on_stat(self, tmp_path: Path) -> None:
        """OSError during stat() raises SchemaLoadError."""
        from unittest.mock import patch

        p = tmp_path / "unreadable.json"
        p.write_text("[]")

        with (
            patch.object(type(p), "stat", side_effect=OSError("Permission denied")),
            pytest.raises(SchemaLoadError, match="Cannot read"),
        ):
            load_from_file(p)

    def test_model_validate_error(self, tmp_path: Path) -> None:
        """Invalid tool schema raises SchemaLoadError."""
        p = tmp_path / "invalid.json"
        # inputSchema as string (not dict) triggers Pydantic validation error
        p.write_text('[{"name": "t", "inputSchema": "not_a_dict"}]')
        with pytest.raises(SchemaLoadError, match="Invalid tool"):
            load_from_file(p)


class TestLoadFromDict:
    """Tests for load_from_dict()."""

    def test_list_input(self) -> None:
        result = load_from_dict([{"name": "a"}, {"name": "b"}])
        assert len(result) == 2

    def test_dict_with_tools_key(self) -> None:
        result = load_from_dict({"tools": [{"name": "a"}]})
        assert len(result) == 1

    def test_single_tool_dict(self) -> None:
        result = load_from_dict({"name": "a"})
        assert len(result) == 1

    def test_invalid_type(self) -> None:
        with pytest.raises(SchemaLoadError, match="Expected JSON"):
            load_from_dict("not a dict or list")

    def test_non_dict_item(self) -> None:
        with pytest.raises(SchemaLoadError, match="not a JSON object"):
            load_from_dict(["not a dict"])

    def test_too_many_tools(self) -> None:
        items = [{"name": f"t{i}"} for i in range(10_001)]
        with pytest.raises(SchemaLoadError, match="Too many"):
            load_from_dict(items)

    def test_dict_without_tools_or_name(self) -> None:
        """Dict without 'tools' or 'name' key raises SchemaLoadError."""
        with pytest.raises(SchemaLoadError, match="must have a 'tools' array"):
            load_from_dict({"random_key": 123})


class TestLoadFromFileOSErrors:
    """Test OS-level error handling in load_from_file."""

    def test_oserror_on_read_text(self, tmp_path: Path) -> None:
        """OSError during read_text raises SchemaLoadError."""
        from unittest.mock import patch

        p = tmp_path / "unreadable.json"
        p.write_text('[{"name":"t"}]')
        with (
            patch.object(type(p), "read_text", side_effect=OSError("Disk error")),
            pytest.raises(SchemaLoadError, match="Cannot read"),
        ):
            load_from_file(p)
