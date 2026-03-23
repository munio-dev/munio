"""Test helpers for munio tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from munio.scan.models import (
    Finding,
    FindingSeverity,
    Layer,
    ServerConfig,
    ServerScanResult,
    ToolDefinition,
)

CORPUS_PATH = Path(__file__).parent / "mcp_vulnerability_corpus.json"


def load_corpus() -> dict[str, Any]:
    """Load the MCP vulnerability corpus."""
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def make_tool(
    name: str = "test_tool",
    description: str = "A test tool",
    input_schema: dict[str, Any] | None = None,
    server_name: str = "test-server",
) -> ToolDefinition:
    """Create a ToolDefinition for testing."""
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=input_schema or {},
        server_name=server_name,
    )


def make_server_config(
    name: str = "test-server",
    source: str = "test",
    command: str = "echo",
    args: list[str] | None = None,
) -> ServerConfig:
    """Create a ServerConfig for testing."""
    return ServerConfig(
        name=name,
        source=source,
        command=command,
        args=args or [],
    )


def make_finding(
    finding_id: str = "L1_001",
    tool_name: str = "test_tool",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    layer: Layer = Layer.L1_SCHEMA,
    message: str = "Test finding",
) -> Finding:
    """Create a Finding for testing."""
    return Finding(
        id=finding_id,
        layer=layer,
        severity=severity,
        tool_name=tool_name,
        message=message,
    )


def make_server_scan_result(
    server_name: str = "test-server",
    source: str = "test",
    tools: list[ToolDefinition] | None = None,
) -> ServerScanResult:
    """Create a ServerScanResult for testing."""
    tool_list = tools or []
    return ServerScanResult(
        server_name=server_name,
        source=source,
        tool_count=len(tool_list),
        tools=tool_list,
    )
