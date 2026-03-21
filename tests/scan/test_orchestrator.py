"""Tests for munio.scan.orchestrator."""

from __future__ import annotations

import asyncio

from munio.scan.config import ScanConfig
from munio.scan.models import Layer, ServerScanResult
from munio.scan.orchestrator import Orchestrator

from .conftest import make_tool


class TestOrchestrator:
    """Test scan orchestrator pipeline."""

    def _run(self, coro: object) -> object:
        return asyncio.run(coro)  # type: ignore[arg-type]

    def test_empty_tools_no_findings(self) -> None:
        """No tools produce no findings."""
        orch = Orchestrator()
        result = self._run(orch.scan([]))
        assert result.total_findings == 0
        assert result.findings == []

    def test_l1_enabled_by_default(self) -> None:
        """L1 is in enabled_layers by default."""
        config = ScanConfig()
        assert Layer.L1_SCHEMA in config.enabled_layers

    def test_produces_findings(self) -> None:
        """Tools with issues produce findings."""
        tool = make_tool(name="bad", description="", input_schema={})
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator()
        result = self._run(orch.scan([sr]))
        assert result.total_findings > 0

    def test_findings_sorted_by_severity(self) -> None:
        """Findings are sorted CRITICAL first, INFO last."""
        # Create tools that will produce different severity findings
        tool = make_tool(
            name="mixed",
            description="has desc",
            input_schema={
                "type": "object",
                "properties": {
                    "system_prompt": {"type": "string"},  # HIGH (L1_007)
                    "x": {"type": "string"},  # LOW (L1_005)
                    "y": {},  # MEDIUM (L1_004)
                },
            },
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator()
        result = self._run(orch.scan([sr]))

        severities = [f.severity.value for f in result.findings]
        assert severities == sorted(severities), "Findings should be sorted by severity value"

    def test_scan_result_fields(self) -> None:
        """ScanResult has expected fields populated."""
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=0,
            tools=[],
        )
        orch = Orchestrator()
        result = self._run(orch.scan([sr]))
        assert result.scan_id.startswith("scan_")
        assert result.timestamp is not None
        assert result.elapsed_ms >= 0
        assert len(result.servers) == 1

    def test_schema_completeness_computed(self) -> None:
        """Orchestrator computes schema completeness averages."""
        tool = make_tool(
            description="Good tool",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "path",
                        "maxLength": 255,
                    },
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator()
        result = self._run(orch.scan([sr]))
        # Should have a non-zero completeness score
        assert result.servers[0].schema_completeness_avg > 0

    def test_multiple_servers(self) -> None:
        """Handles multiple server results."""
        sr1 = ServerScanResult(
            server_name="server1",
            source="test",
            tool_count=1,
            tools=[make_tool(name="t1", description="")],
        )
        sr2 = ServerScanResult(
            server_name="server2",
            source="test",
            tool_count=1,
            tools=[make_tool(name="t2", description="")],
        )
        orch = Orchestrator()
        result = self._run(orch.scan([sr1, sr2]))
        assert len(result.servers) == 2
        tool_names = {f.tool_name for f in result.findings}
        assert "t1" in tool_names
        assert "t2" in tool_names

    def test_disconnected_server(self) -> None:
        """Disconnected server (no tools) is included in results."""
        sr = ServerScanResult(
            server_name="dead",
            source="test",
            connected=False,
            error="Connection refused",
        )
        orch = Orchestrator()
        result = self._run(orch.scan([sr]))
        assert len(result.servers) == 1
        assert result.servers[0].connected is False
        assert result.total_findings == 0

    def test_disabled_layer(self) -> None:
        """No findings when L1 is not in enabled_layers."""
        config = ScanConfig(enabled_layers=frozenset())
        orch = Orchestrator(config)
        tool = make_tool(description="", input_schema={})
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        result = self._run(orch.scan([sr]))
        assert result.total_findings == 0

    def test_l5_enabled_by_default(self) -> None:
        """L5 is in enabled_layers by default."""
        config = ScanConfig()
        assert Layer.L5_COMPOSITIONAL in config.enabled_layers

    def test_l5_produces_findings_for_dangerous_combo(self) -> None:
        """Orchestrator with L5 detects read_file + send_email cross-server."""
        read = make_tool(name="read_file", description="Read files", server_name="fs")
        send = make_tool(name="send_email", description="Send emails", server_name="email")
        sr1 = ServerScanResult(server_name="fs", source="test", tool_count=1, tools=[read])
        sr2 = ServerScanResult(server_name="email", source="test", tool_count=1, tools=[send])
        orch = Orchestrator()
        result = self._run(orch.scan([sr1, sr2]))
        l5 = [f for f in result.findings if f.layer == Layer.L5_COMPOSITIONAL]
        assert len(l5) > 0

    def test_l5_disabled_no_l5_findings(self) -> None:
        """L5 disabled via config produces no L5 findings."""
        config = ScanConfig(enabled_layers=frozenset({Layer.L1_SCHEMA}))
        read = make_tool(name="read_file", description="Read files", server_name="fs")
        send = make_tool(name="send_email", description="Send emails", server_name="email")
        sr1 = ServerScanResult(server_name="fs", source="test", tool_count=1, tools=[read])
        sr2 = ServerScanResult(server_name="email", source="test", tool_count=1, tools=[send])
        orch = Orchestrator(config)
        result = self._run(orch.scan([sr1, sr2]))
        l5 = [f for f in result.findings if f.layer == Layer.L5_COMPOSITIONAL]
        assert l5 == []

    def test_l3_enabled_by_default(self) -> None:
        """L3 is in enabled_layers by default."""
        config = ScanConfig()
        assert Layer.L3_STATIC in config.enabled_layers

    def test_l3_produces_findings(self) -> None:
        """L3 detects semantic issues like path params without protection."""
        tool = make_tool(
            name="read_file",
            description="Read a file",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                },
            },
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator()
        result = self._run(orch.scan([sr]))
        l3 = [f for f in result.findings if f.layer == Layer.L3_STATIC]
        assert len(l3) > 0

    def test_l3_disabled_no_l3_findings(self) -> None:
        """L3 disabled via config produces no L3 findings."""
        config = ScanConfig(enabled_layers=frozenset({Layer.L1_SCHEMA}))
        tool = make_tool(
            name="read_file",
            description="Read a file",
            input_schema={
                "type": "object",
                "properties": {"file_path": {"type": "string"}},
            },
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator(config)
        result = self._run(orch.scan([sr]))
        l3 = [f for f in result.findings if f.layer == Layer.L3_STATIC]
        assert l3 == []

    def test_l4_enabled_by_default(self) -> None:
        """L4 is in enabled_layers by default."""
        config = ScanConfig()
        assert Layer.L4_Z3 in config.enabled_layers

    def test_l4_produces_findings(self) -> None:
        """L4 detects pattern bypass with formal verification."""
        tool = make_tool(
            name="read_file",
            description="Read a file",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9_./]+$",
                    },
                },
            },
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator()
        result = self._run(orch.scan([sr]))
        l4 = [f for f in result.findings if f.layer == Layer.L4_Z3]
        assert len(l4) > 0

    def test_l4_disabled_no_l4_findings(self) -> None:
        """L4 disabled via config produces no L4 findings."""
        config = ScanConfig(enabled_layers=frozenset({Layer.L1_SCHEMA}))
        tool = make_tool(
            name="read_file",
            description="Read a file",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9_./]+$",
                    },
                },
            },
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator(config)
        result = self._run(orch.scan([sr]))
        l4 = [f for f in result.findings if f.layer == Layer.L4_Z3]
        assert l4 == []
