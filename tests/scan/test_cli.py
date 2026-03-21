"""Tests for munio.scan.cli."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

if TYPE_CHECKING:
    from pathlib import Path

from munio.scan.cli import _format_result_text, _parse_server_command, create_app
from munio.scan.models import (
    AttackType,
    Finding,
    FindingSeverity,
    Layer,
    ScanResult,
    ServerScanResult,
    ToolDefinition,
)

runner = CliRunner()


def _write_tools_file(tmp_path: Path, tools: list[dict] | None = None) -> Path:
    """Write a tools JSON file and return path."""
    if tools is None:
        tools = [
            {
                "name": "safe_tool",
                "description": "A well-described tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query",
                            "maxLength": 500,
                        }
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            }
        ]
    p = tmp_path / "tools.json"
    p.write_text(json.dumps(tools))
    return p


class TestVersion:
    """Test version command."""

    def test_version_output(self) -> None:
        app = create_app()
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "munio-scan" in result.output


class TestScanFile:
    """Test scan --file mode."""

    def test_scan_file_text(self, tmp_path: Path) -> None:
        """Scan a JSON file and get text output."""
        p = _write_tools_file(tmp_path)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p)])
        assert result.exit_code == 0
        assert "munio scan" in result.output

    def test_scan_file_json(self, tmp_path: Path) -> None:
        """Scan a JSON file and get JSON output."""
        p = _write_tools_file(tmp_path)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "scan_id" in data
        assert "findings" in data

    def test_scan_file_quiet(self, tmp_path: Path) -> None:
        """Quiet mode shows only findings."""
        tools = [{"name": "bad", "description": "", "inputSchema": {}}]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--quiet"])
        # Should not contain the header
        assert "munio scan" not in result.output

    def test_missing_file(self) -> None:
        """Missing file produces error exit."""
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", "/nonexistent/path.json"])
        assert result.exit_code == 2
        assert "Error" in result.output

    def test_exit_code_1_on_high_findings(self, tmp_path: Path) -> None:
        """Exit code 1 when HIGH/CRITICAL findings exist."""
        tools = [
            {
                "name": "dangerous",
                "description": "tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "system_prompt": {"type": "string"},
                    },
                },
            }
        ]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p)])
        assert result.exit_code == 1

    def test_exit_code_0_no_high_findings(self, tmp_path: Path) -> None:
        """Exit code 0 when no HIGH/CRITICAL findings."""
        p = _write_tools_file(tmp_path)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p)])
        assert result.exit_code == 0

    def test_findings_in_json_output(self, tmp_path: Path) -> None:
        """JSON output includes findings from L1 analysis."""
        tools = [{"name": "bad", "description": "", "inputSchema": {}}]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--format", "json"])
        data = json.loads(result.output)
        assert data["total_findings"] > 0


class TestScanConfig:
    """Test scan --config mode."""

    def test_missing_config(self) -> None:
        """Missing config file produces error exit."""
        app = create_app()
        result = runner.invoke(app, ["scan", "--config", "/nonexistent/config.json"])
        assert result.exit_code == 2

    def test_empty_config(self, tmp_path: Path) -> None:
        """Config file with no servers produces error exit."""
        p = tmp_path / "config.json"
        p.write_text("{}")
        app = create_app()
        result = runner.invoke(app, ["scan", "--config", str(p)])
        assert result.exit_code == 2


class TestQuietMode:
    """Test quiet mode output sanitization."""

    def test_quiet_ansi_stripped(self, tmp_path: Path) -> None:
        """Control chars in tool names/messages are stripped in quiet mode."""
        tools = [
            {
                "name": "evil\x1b[31m_tool",
                "description": "",
                "inputSchema": {},
            }
        ]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--quiet"])
        # The ANSI escape should be stripped
        assert "\x1b" not in result.output

    def test_json_includes_total_findings(self, tmp_path: Path) -> None:
        """JSON output includes computed total_findings field."""
        tools = [{"name": "t", "description": "", "inputSchema": {}}]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--format", "json"])
        data = json.loads(result.output)
        assert "total_findings" in data
        assert "by_severity" in data
        assert "by_layer" in data


class TestScanErrors:
    """Test error handling in scan command."""

    def test_schema_load_error_message_shown(self, tmp_path: Path) -> None:
        """SchemaLoadError message is shown instead of generic message."""
        p = tmp_path / "bad.json"
        p.write_text("not json")
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p)])
        assert result.exit_code == 2
        assert "Invalid JSON" in result.output

    def test_format_text_is_default(self, tmp_path: Path) -> None:
        """Default format is 'text' (StrEnum)."""
        p = _write_tools_file(tmp_path)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p)])
        assert result.exit_code == 0
        assert "munio scan" in result.output


class TestNoArgs:
    """Test no-args behavior."""

    def test_no_args_shows_help(self) -> None:
        """No arguments shows help text."""
        app = create_app()
        result = runner.invoke(app, [])
        # no_args_is_help shows usage text
        assert "scan" in result.output.lower() or "usage" in result.output.lower()


def _make_mock_tools() -> list[ToolDefinition]:
    """Create mock tools for CLI e2e tests."""
    return [
        ToolDefinition(
            name="read_file",
            description="Read a file from disk",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path"}},
                "required": ["path"],
            },
            server_name="test",
        ),
    ]


class TestScanConfigWithConnection:
    """Test scan --config mode with mocked MCP connection."""

    def test_config_valid_servers(self, tmp_path: Path) -> None:
        """--config with valid IDE config discovers and scans servers."""
        config = {"mcpServers": {"my-server": {"command": "echo", "args": ["hello"]}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))

        mock_tools = _make_mock_tools()
        mock_connect = AsyncMock(return_value=mock_tools)

        app = create_app()
        with patch("munio.scan.mcp_client.connect_and_list_tools", mock_connect):
            result = runner.invoke(app, ["scan", "--config", str(p)])

        assert result.exit_code in (0, 1)
        assert "munio scan" in result.output
        mock_connect.assert_called_once()

    def test_config_json_output(self, tmp_path: Path) -> None:
        """--config mode with --format json produces valid JSON."""
        config = {"mcpServers": {"srv": {"command": "echo"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))

        mock_connect = AsyncMock(return_value=_make_mock_tools())
        app = create_app()
        with patch("munio.scan.mcp_client.connect_and_list_tools", mock_connect):
            result = runner.invoke(app, ["scan", "--config", str(p), "--format", "json"])

        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "findings" in data
        assert data["servers"][0]["server_name"] == "srv"

    def test_config_connection_error(self, tmp_path: Path) -> None:
        """Connection failure shows warning but continues."""
        from munio.scan.models import ScanConnectionError

        config = {"mcpServers": {"bad": {"command": "nonexistent-binary"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))

        mock_connect = AsyncMock(
            side_effect=ScanConnectionError("Failed to connect to server 'bad'")
        )
        app = create_app()
        with patch("munio.scan.mcp_client.connect_and_list_tools", mock_connect):
            result = runner.invoke(app, ["scan", "--config", str(p)])

        # Should complete (not crash) even with connection error
        assert result.exit_code in (0, 1, 2)
        assert "Warning" in result.output or "munio scan" in result.output

    def test_config_generic_exception(self, tmp_path: Path) -> None:
        """Generic exception in --config discover_from_file path."""
        p = tmp_path / "config.json"
        p.write_text('{"mcpServers": {"s": {"command": "e"}}}')

        app = create_app()
        with patch(
            "munio.scan.discovery.discover_from_file",
            side_effect=RuntimeError("unexpected"),
        ):
            result = runner.invoke(app, ["scan", "--config", str(p)])

        assert result.exit_code == 2
        assert "Failed to parse" in result.output


class TestAutoDiscover:
    """Test auto-discover mode (no --file, no --config)."""

    def test_auto_discover_no_servers(self) -> None:
        """Auto-discover with no servers found exits with error."""
        app = create_app()
        with patch("munio.scan.discovery.discover_servers", return_value=[]):
            result = runner.invoke(app, ["scan"])

        assert result.exit_code == 2
        assert "No MCP servers discovered" in result.output

    def test_auto_discover_with_servers(self, tmp_path: Path) -> None:
        """Auto-discover finds servers, connects, and scans."""
        from munio.scan.models import ServerConfig

        servers = [ServerConfig(name="found", source="cursor", command="echo")]
        mock_tools = _make_mock_tools()
        mock_connect = AsyncMock(return_value=mock_tools)

        app = create_app()
        with (
            patch("munio.scan.discovery.discover_servers", return_value=servers),
            patch("munio.scan.mcp_client.connect_and_list_tools", mock_connect),
        ):
            result = runner.invoke(app, ["scan"])

        assert result.exit_code in (0, 1)
        assert "munio scan" in result.output

    def test_trust_project_flag(self) -> None:
        """--trust-project flag is passed to discover_servers."""
        app = create_app()
        with patch("munio.scan.discovery.discover_servers", return_value=[]) as mock_ds:
            runner.invoke(app, ["scan", "--trust-project"])

        mock_ds.assert_called_once_with(include_project_level=True)


class TestFileGenericException:
    """Test generic exception handling in --file mode."""

    def test_file_generic_exception(self, tmp_path: Path) -> None:
        """Generic exception (not SchemaLoadError) shows generic message."""
        p = tmp_path / "ok.json"
        p.write_text('[{"name":"t"}]')

        app = create_app()
        with patch(
            "munio.scan.schema_loader.load_from_file",
            side_effect=RuntimeError("unexpected"),
        ):
            result = runner.invoke(app, ["scan", "--file", str(p)])

        assert result.exit_code == 2
        assert "Failed to load" in result.output


class TestConnectToServers:
    """Test _connect_to_servers helper via CLI integration."""

    def test_multiple_servers_mixed_results(self, tmp_path: Path) -> None:
        """Mix of successful and failed server connections."""
        from munio.scan.models import ScanConnectionError

        config = {
            "mcpServers": {
                "good": {"command": "echo"},
                "bad": {"command": "fail"},
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))

        call_count = 0

        async def mock_connect(server, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal call_count
            call_count += 1
            if server.name == "bad":
                raise ScanConnectionError("Connection failed")
            return _make_mock_tools()

        app = create_app()
        with patch("munio.scan.mcp_client.connect_and_list_tools", side_effect=mock_connect):
            result = runner.invoke(app, ["scan", "--config", str(p)])

        assert call_count == 2
        # Should show warning for failed server but still produce output
        assert "Warning" in result.output or "munio scan" in result.output


class TestSarifOutput:
    """Test SARIF output format."""

    def test_sarif_format_valid_json(self, tmp_path: Path) -> None:
        """--format sarif produces valid SARIF JSON."""
        p = _write_tools_file(tmp_path)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--format", "sarif"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

    def test_sarif_has_tool_driver(self, tmp_path: Path) -> None:
        """SARIF output has tool.driver with munio name."""
        p = _write_tools_file(tmp_path)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--format", "sarif"])
        data = json.loads(result.output)
        assert data["runs"][0]["tool"]["driver"]["name"] == "munio"

    def test_sarif_with_findings(self, tmp_path: Path) -> None:
        """SARIF includes results for findings."""
        tools = [{"name": "bad", "description": "", "inputSchema": {}}]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--format", "sarif"])
        data = json.loads(result.output)
        assert len(data["runs"][0]["results"]) > 0
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) > 0

    def test_sarif_output_to_file(self, tmp_path: Path) -> None:
        """--format sarif --output writes SARIF to file."""
        p = _write_tools_file(tmp_path)
        out = tmp_path / "output.sarif"
        app = create_app()
        result = runner.invoke(
            app, ["scan", "--file", str(p), "--format", "sarif", "--output", str(out)]
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_sarif_exit_code_1_on_critical(self, tmp_path: Path) -> None:
        """Exit code 1 with SARIF when CRITICAL/HIGH findings exist."""
        tools = [
            {
                "name": "dangerous",
                "description": "tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {"system_prompt": {"type": "string"}},
                },
            }
        ]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--format", "sarif"])
        assert result.exit_code == 1

    def test_output_flag_with_json(self, tmp_path: Path) -> None:
        """--output flag works with JSON format too."""
        p = _write_tools_file(tmp_path)
        out = tmp_path / "output.json"
        app = create_app()
        result = runner.invoke(
            app, ["scan", "--file", str(p), "--format", "json", "--output", str(out)]
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "scan_id" in data

    def test_output_flag_with_text(self, tmp_path: Path) -> None:
        """--output flag works with text format."""
        p = _write_tools_file(tmp_path)
        out = tmp_path / "output.txt"
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--output", str(out)])
        assert result.exit_code == 0
        assert "munio scan" in out.read_text()


class TestParseServerCommand:
    """Test _parse_server_command() parsing."""

    @pytest.mark.parametrize(
        ("command_str", "expected_name", "expected_cmd", "expected_args"),
        [
            (
                "npx @foo/mcp-server --arg",
                "mcp-server",
                "npx",
                ["@foo/mcp-server", "--arg"],
            ),
            (
                "uv run mcp-server",
                "mcp-server",
                "uv",
                ["run", "mcp-server"],
            ),
            (
                "python -m mcp_server",
                "mcp_server",
                "python",
                ["-m", "mcp_server"],
            ),
            (
                "node server.js",
                "server.js",
                "node",
                ["server.js"],
            ),
            (
                "npx @modelcontextprotocol/server-everything",
                "server-everything",
                "npx",
                ["@modelcontextprotocol/server-everything"],
            ),
            (
                "myserver",
                "myserver",
                "myserver",
                [],
            ),
            (
                "npx -y @modelcontextprotocol/server-filesystem /tmp",
                "server-filesystem",
                "npx",
                ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            ),
            (
                "npx @scope/server /home/user/data --port 3000",
                "server",
                "npx",
                ["@scope/server", "/home/user/data", "--port", "3000"],
            ),
        ],
        ids=[
            "npx-scoped-with-flag",
            "uv-run",
            "python-module",
            "node-script",
            "npx-scoped-no-flags",
            "bare-command",
            "npx-scoped-with-path-arg",
            "npx-scoped-with-path-and-flags",
        ],
    )
    def test_parse_variants(
        self,
        command_str: str,
        expected_name: str,
        expected_cmd: str,
        expected_args: list[str],
    ) -> None:
        cfg = _parse_server_command(command_str)
        assert cfg.name == expected_name
        assert cfg.command == expected_cmd
        assert list(cfg.args) == expected_args
        assert cfg.source == "cli"

    def test_empty_command_exits(self) -> None:
        """Empty string raises Exit (via typer.Exit)."""
        from click.exceptions import Exit

        with pytest.raises(Exit):
            _parse_server_command("")


class TestScanServer:
    """Test scan --server mode."""

    def test_server_connects_and_scans(self) -> None:
        """--server parses command, connects, and scans."""
        mock_tools = _make_mock_tools()
        mock_connect = AsyncMock(return_value=mock_tools)

        app = create_app()
        with patch("munio.scan.mcp_client.connect_and_list_tools", mock_connect):
            result = runner.invoke(app, ["scan", "--server", "npx @foo/mcp-server"])

        assert result.exit_code in (0, 1)
        assert "munio scan" in result.output
        mock_connect.assert_called_once()
        # Verify the ServerConfig was built correctly
        called_server = mock_connect.call_args[0][0]
        assert called_server.command == "npx"
        assert called_server.name == "mcp-server"
        assert called_server.source == "cli"

    def test_server_json_output(self) -> None:
        """--server with --format json produces valid JSON."""
        mock_connect = AsyncMock(return_value=_make_mock_tools())

        app = create_app()
        with patch("munio.scan.mcp_client.connect_and_list_tools", mock_connect):
            result = runner.invoke(
                app, ["scan", "--server", "uv run mcp-server", "--format", "json"]
            )

        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "findings" in data
        assert data["servers"][0]["server_name"] == "mcp-server"

    def test_server_connection_error(self) -> None:
        """Connection failure with --server shows warning."""
        from munio.scan.models import ScanConnectionError

        mock_connect = AsyncMock(side_effect=ScanConnectionError("Connection refused"))

        app = create_app()
        with patch("munio.scan.mcp_client.connect_and_list_tools", mock_connect):
            result = runner.invoke(app, ["scan", "--server", "npx @bad/server"])

        assert "Warning" in result.output or "munio scan" in result.output


# ── Helpers for grouped output tests ──────────────────────────────────


def _make_finding(
    *,
    check_id: str = "L1_001",
    layer: Layer = Layer.L1_SCHEMA,
    severity: FindingSeverity = FindingSeverity.HIGH,
    tool_name: str = "test_tool",
    message: str = "Test message",
    attack_type: AttackType | None = None,
    cwe: str | None = None,
    location: str = "",
) -> Finding:
    return Finding(
        id=check_id,
        layer=layer,
        severity=severity,
        tool_name=tool_name,
        message=message,
        attack_type=attack_type,
        cwe=cwe,
        location=location,
    )


def _make_scan_result(findings: list[Finding]) -> ScanResult:
    _dummy_tool = ToolDefinition(
        name="dummy", description="d", input_schema={}, server_name="test-server"
    )
    return ScanResult(
        scan_id="test-scan",
        servers=[
            ServerScanResult(
                server_name="test-server",
                source="cli",
                tool_count=5,
                tools=[_dummy_tool],
                schema_completeness_avg=75.0,
            )
        ],
        findings=findings,
        elapsed_ms=10.0,
    )


# ── Grouped output format tests ──────────────────────────────────────


class TestGroupedOutput:
    """Test the table-based grouped text output."""

    def test_severity_in_table(self) -> None:
        """Severity names appear in the table."""
        findings = [
            _make_finding(severity=FindingSeverity.HIGH, message="High issue"),
            _make_finding(
                check_id="L1_009",
                severity=FindingSeverity.INFO,
                message="Info issue",
            ),
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "HIGH" in output
        assert "INFO" in output

    def test_check_grouping_tool_count(self) -> None:
        """Multiple findings with same check_id show tool count in table."""
        findings = [
            _make_finding(
                check_id="L3_001",
                layer=Layer.L3_STATIC,
                tool_name=name,
                message="Path parameter 'path' has no pattern rejecting traversal",
                cwe="CWE-22",
            )
            for name in ("read_file", "write_file", "edit_file")
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "3" in output  # tool count column
        assert "CWE-22" in output

    def test_l5_flow_dedup(self) -> None:
        """L5_002 findings are deduplicated into flow summary."""
        findings = [
            _make_finding(
                check_id="L5_002",
                layer=Layer.L5_COMPOSITIONAL,
                severity=FindingSeverity.MEDIUM,
                tool_name=f"sink_{i}",
                message=(
                    f"Toxic flow: Files can be read and modified. "
                    f"Source: src_{i % 2} (srv), sink: sink_{i} (srv)"
                ),
                location=f"source:src_{i % 2}@srv -> sink:sink_{i}@srv",
                attack_type=AttackType.DATA_EXFILTRATION,
                cwe="CWE-200",
            )
            for i in range(4)
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "4" in output
        assert "toxic data flows" in output
        assert "sources" in output
        assert "sinks" in output

    def test_l5_fallback_on_bad_location(self) -> None:
        """L5_002 with malformed location still renders gracefully."""
        findings = [
            _make_finding(
                check_id="L5_002",
                layer=Layer.L5_COMPOSITIONAL,
                severity=FindingSeverity.MEDIUM,
                tool_name="some_tool",
                message="Some L5 finding without standard format",
                location="bad-format",
            ),
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "MEDIUM" in output
        assert "Some L5 finding" in output

    def test_low_in_table(self) -> None:
        """LOW findings appear as rows in table."""
        findings = [
            _make_finding(
                check_id="L1_005",
                severity=FindingSeverity.LOW,
                tool_name=f"tool_{i}",
                message=f"String parameter 'p{i}' has no effective maxLength",
            )
            for i in range(5)
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "LOW" in output
        assert "5" in output  # tool count

    def test_info_in_table(self) -> None:
        """INFO findings appear as rows in table."""
        findings = [
            _make_finding(
                check_id="L1_009",
                severity=FindingSeverity.INFO,
                tool_name=f"tool_{i}",
                message=f"Parameter 'x{i}' has no description",
            )
            for i in range(3)
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "INFO" in output
        assert "3" in output  # tool count

    def test_cwe_in_table(self) -> None:
        """Finding with CWE shows it in CWE column."""
        findings = [
            _make_finding(cwe="CWE-22", message="Path traversal issue"),
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "CWE-22" in output

    def test_summary_footer(self) -> None:
        """Summary footer shows total counts per severity."""
        findings = [
            _make_finding(severity=FindingSeverity.HIGH, message="Issue 1"),
            _make_finding(
                check_id="L1_005",
                severity=FindingSeverity.LOW,
                message="Issue 2",
            ),
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "2 issues" in output
        assert "tools" in output
        assert "HIGH: 1" in output
        assert "LOW: 1" in output

    def test_no_findings(self) -> None:
        """Zero findings shows 'No findings' message."""
        result = _make_scan_result([])
        output = _format_result_text(result, color=False)

        assert "No findings" in output

    def test_escape_rich_markup(self) -> None:
        """Message with Rich markup chars doesn't crash or render markup."""
        findings = [
            _make_finding(message="Test [red]markup[/red] in message"),
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)
        # Markup should appear as literal text, not rendered
        assert "markup" in output

    def test_table_headers_present(self) -> None:
        """Table has Severity, Finding, CWE, Tools headers."""
        findings = [_make_finding(message="Issue")]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)

        assert "Severity" in output
        assert "Finding" in output
        assert "CWE" in output
        assert "Tools" in output

    def test_verbose_flag_via_cli(self, tmp_path: Path) -> None:
        """--verbose flag works through CLI runner."""
        tools = [
            {
                "name": "test_tool",
                "description": "A tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            }
        ]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()

        result_normal = runner.invoke(app, ["scan", "--file", str(p)])
        result_verbose = runner.invoke(app, ["scan", "--file", str(p), "--verbose"])

        assert result_normal.exit_code in (0, 1)
        assert result_verbose.exit_code in (0, 1)

    def test_color_true_produces_ansi(self) -> None:
        """color=True embeds ANSI escape codes in output."""
        findings = [_make_finding(severity=FindingSeverity.HIGH, message="Issue")]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=True)
        assert "\x1b[" in output

    def test_color_false_no_ansi(self) -> None:
        """color=False produces plain text without ANSI."""
        findings = [_make_finding(severity=FindingSeverity.HIGH, message="Issue")]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)
        assert "\x1b[" not in output

    def test_schema_quality_with_grade(self) -> None:
        """Schema quality shows letter grade and score."""
        result = _make_scan_result([])
        output = _format_result_text(result, color=False)
        assert "Schema quality:" in output
        assert "75/100" in output
        assert "avg across" in output

    def test_next_steps_hint(self) -> None:
        """Next steps hint shown when findings exist and no --details."""
        findings = [_make_finding(message="Issue")]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False)
        assert "--details" in output

    def test_no_hint_with_details(self) -> None:
        """Next steps hint NOT shown when --details is active."""
        findings = [_make_finding(message="Issue")]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False, details=True)
        assert "Run munio scan --details" not in output

    def test_details_shows_tools(self) -> None:
        """--details shows affected tool names."""
        findings = [
            _make_finding(
                check_id="L3_001",
                tool_name="read_file",
                message="Path parameter has no pattern",
                cwe="CWE-22",
            ),
            _make_finding(
                check_id="L3_001",
                tool_name="write_file",
                message="Path parameter has no pattern",
                cwe="CWE-22",
            ),
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False, details=True)
        assert "read_file" in output
        assert "write_file" in output

    def test_details_shows_recommendation(self) -> None:
        """--details shows fix recommendation from registry."""
        findings = [
            _make_finding(
                check_id="L3_001",
                tool_name="read_file",
                message="Path parameter has no pattern",
            ),
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False, details=True)
        # L3_001 recommendation mentions "pattern"
        assert "pattern" in output.lower()
        assert "Fix:" in output  # auto_fixable=True → "Fix:" prefix

    def test_details_shows_counterexample(self) -> None:
        """--details shows counterexample when present."""
        findings = [
            _make_finding(
                check_id="L4_001",
                layer=Layer.L4_Z3,
                tool_name="read_file",
                message="Pattern bypass",
            ),
        ]
        # Manually set counterexample (Finding is frozen, construct with it)
        findings = [
            Finding(
                id="L4_001",
                layer=Layer.L4_Z3,
                severity=FindingSeverity.HIGH,
                tool_name="read_file",
                message="Pattern bypass found",
                counterexample="../../etc/passwd",
            ),
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False, details=True)
        assert "../../etc/passwd" in output
        assert "Proof:" in output

    def test_server_name_in_header(self) -> None:
        """Single server shows server name in header."""
        result = _make_scan_result([])
        output = _format_result_text(result, color=False)
        assert "test-server" in output

    def test_details_flag_via_cli(self, tmp_path: Path) -> None:
        """--details flag works through CLI runner."""
        tools = [
            {
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            }
        ]
        p = _write_tools_file(tmp_path, tools)
        app = create_app()
        result = runner.invoke(app, ["scan", "--file", str(p), "--details"])
        assert result.exit_code in (0, 1)
        # Details should show tool names
        assert "read_file" in result.output
