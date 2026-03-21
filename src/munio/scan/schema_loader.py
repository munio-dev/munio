"""Load MCP tool definitions from JSON files."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from munio.scan.models import SchemaLoadError, ToolDefinition

__all__ = ["load_from_dict", "load_from_file"]

logger = logging.getLogger(__name__)

_MAX_FILE_SIZE = 10_485_760  # 10 MB
_MAX_TOOL_COUNT = 10_000


def load_from_file(path: Path | str, *, server_name: str = "") -> list[ToolDefinition]:
    """Load tool definitions from a JSON file.

    Supports three formats:
      1. Array of tool definitions: ``[{"name": ..., "inputSchema": ...}, ...]``
      2. Object with ``tools`` key: ``{"tools": [...]}``
      3. Single tool definition: ``{"name": ..., "inputSchema": ...}``

    Args:
        path: Path to the JSON file.
        server_name: Server name to associate with loaded tools.

    Returns:
        List of parsed tool definitions.

    Raises:
        SchemaLoadError: If the file cannot be read, parsed, or validated.
    """
    p = Path(path)

    if not p.is_file():
        msg = f"Tool definition file not found: {p}"
        raise SchemaLoadError(msg)

    try:
        size = p.stat().st_size
    except OSError:
        msg = f"Cannot read tool definition file: {p}"
        raise SchemaLoadError(msg) from None

    if size > _MAX_FILE_SIZE:
        msg = f"Tool definition file too large (>{_MAX_FILE_SIZE} bytes): {p}"
        raise SchemaLoadError(msg)

    try:
        raw = p.read_text(encoding="utf-8")
    except OSError:
        msg = f"Cannot read tool definition file: {p}"
        raise SchemaLoadError(msg) from None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        msg = f"Invalid JSON in tool definition file: {p}"
        raise SchemaLoadError(msg) from None

    return load_from_dict(data, server_name=server_name)


def load_from_dict(data: Any, *, server_name: str = "") -> list[ToolDefinition]:
    """Parse tool definitions from a dict or list.

    Args:
        data: Parsed JSON data (dict or list).
        server_name: Server name to associate with loaded tools.

    Returns:
        List of parsed tool definitions.

    Raises:
        SchemaLoadError: If the data is invalid or exceeds limits.
    """
    # Normalize to list
    items: list[Any]
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        if "tools" in data and isinstance(data["tools"], list):
            items = data["tools"]
        elif "name" in data:
            items = [data]
        else:
            msg = "JSON object must have a 'tools' array or be a single tool definition"
            raise SchemaLoadError(msg)
    else:
        msg = f"Expected JSON object or array, got {type(data).__name__}"
        raise SchemaLoadError(msg)

    if len(items) > _MAX_TOOL_COUNT:
        msg = f"Too many tool definitions ({len(items)} > {_MAX_TOOL_COUNT})"
        raise SchemaLoadError(msg)

    tools: list[ToolDefinition] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            msg = f"Tool definition at index {i} is not a JSON object"
            raise SchemaLoadError(msg)

        # Handle both camelCase (MCP SDK) and snake_case field names
        tool_dict: dict[str, Any] = {
            "name": item.get("name", ""),
            "title": item.get("title", ""),
            "description": item.get("description", ""),
            "input_schema": item.get("inputSchema", item.get("input_schema", {})),
            "output_schema": item.get("outputSchema", item.get("output_schema")),
            "annotations": item.get("annotations"),
            "server_name": server_name,
        }

        try:
            tools.append(ToolDefinition.model_validate(tool_dict))
        except Exception:
            msg = f"Invalid tool definition at index {i}"
            raise SchemaLoadError(msg) from None

    logger.debug("Loaded %d tool definition(s)", len(tools))
    return tools
