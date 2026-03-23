"""Tests for munio.scan.cli."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from click.exceptions import Exit
from typer.testing import CliRunner

import munio.scan.cli as cli_mod
from munio.scan.cli import (
    _error_exit,
    _format_config_result_text,
    _format_layers_line,
    _format_result_text,
    _get_app,
    _parse_server_command,
    _score_to_grade,
    _severity_color,
    create_app,
    run_config_scan,
    run_scan,
)
from munio.scan.models import (
    AttackType,
    ConfigFileResult,
    ConfigScanResult,
    Finding,
    FindingSeverity,
    Layer,
    ScanConnectionError,
    ScanResult,
    ServerConfig,
    ServerScanResult,
    SkippedLayer,
    ToolDefinition,
)

if TYPE_CHECKING:
    from pathlib import Path

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

    def test_multi_server_header(self) -> None:
        """Multiple servers shows server count in header."""
        _dummy = ToolDefinition(name="t", description="d", input_schema={}, server_name="s1")
        result = ScanResult(
            scan_id="test",
            servers=[
                ServerScanResult(server_name="s1", source="cli", tool_count=2, tools=[_dummy]),
                ServerScanResult(server_name="s2", source="cli", tool_count=3, tools=[_dummy]),
            ],
            findings=[],
            elapsed_ms=5.0,
        )
        output = _format_result_text(result, color=False)
        assert "2 servers" in output
        assert "5 tools" in output

    def test_skipped_layer_shows_cross(self) -> None:
        """Skipped layers show X mark in layers line."""
        _dummy = ToolDefinition(name="t", description="d", input_schema={}, server_name="srv")
        result = ScanResult(
            scan_id="test",
            servers=[
                ServerScanResult(server_name="srv", source="cli", tool_count=1, tools=[_dummy])
            ],
            findings=[],
            elapsed_ms=5.0,
            enabled_layers=frozenset({Layer.L4_Z3}),
            skipped_layers=(
                SkippedLayer(
                    layer=Layer.L4_Z3,
                    reason="z3 not installed",
                    install_hint="pip install z3-solver",
                ),
            ),
        )
        output = _format_result_text(result, color=False)
        assert "\u2717" in output  # cross mark
        assert "Tip:" in output
        assert "z3-solver" in output

    def test_detail_block_many_tools(self) -> None:
        """--details with >8 tools shows '+N more' suffix."""
        findings = [
            _make_finding(
                check_id="L3_001",
                tool_name=f"tool_{i}",
                message="Path parameter has no pattern",
            )
            for i in range(12)
        ]
        result = _make_scan_result(findings)
        output = _format_result_text(result, color=False, details=True)
        assert "+6 more" in output


# ── _score_to_grade tests ──────────────────────────────────────────────


class TestScoreToGrade:
    """Test letter grade mapping."""

    @pytest.mark.parametrize(
        ("score", "expected_grade"),
        [
            (95, "A"),
            (90, "A"),
            (85, "B"),
            (80, "B"),
            (75, "C"),
            (70, "C"),
            (65, "D"),
            (60, "D"),
            (55, "F"),
            (0, "F"),
        ],
        ids=["95-A", "90-A", "85-B", "80-B", "75-C", "70-C", "65-D", "60-D", "55-F", "0-F"],
    )
    def test_grade_mapping(self, score: float, expected_grade: str) -> None:
        grade, _ = _score_to_grade(score)
        assert grade == expected_grade


# ── _severity_color tests ──────────────────────────────────────────────


class TestSeverityColor:
    """Test severity color mapping."""

    @pytest.mark.parametrize(
        ("severity", "expected_color"),
        [
            (FindingSeverity.CRITICAL, "red bold"),
            (FindingSeverity.HIGH, "red"),
            (FindingSeverity.MEDIUM, "yellow"),
            (FindingSeverity.LOW, "blue"),
            (FindingSeverity.INFO, "dim"),
        ],
    )
    def test_color_mapping(self, severity: FindingSeverity, expected_color: str) -> None:
        assert _severity_color(severity) == expected_color


# ── _format_layers_line tests ──────────────────────────────────────────


class TestFormatLayersLine:
    """Test _format_layers_line for enabled/skipped/opt-in layers."""

    def test_enabled_layers_show_checkmark(self) -> None:
        result = ScanResult(
            scan_id="t",
            findings=[],
            elapsed_ms=1.0,
            enabled_layers=frozenset({Layer.L1_SCHEMA, Layer.L2_HEURISTIC}),
        )
        line = _format_layers_line(result)
        assert "\u2713" in line  # checkmark

    def test_skipped_layer_shows_cross_mark(self) -> None:
        result = ScanResult(
            scan_id="t",
            findings=[],
            elapsed_ms=1.0,
            enabled_layers=frozenset({Layer.L4_Z3}),
            skipped_layers=(
                SkippedLayer(
                    layer=Layer.L4_Z3,
                    reason="not installed",
                    install_hint="pip install z3-solver",
                ),
            ),
        )
        line = _format_layers_line(result)
        assert "\u2717" in line  # cross

    def test_opt_in_layer_shows_circle(self) -> None:
        result = ScanResult(
            scan_id="t",
            findings=[],
            elapsed_ms=1.0,
            enabled_layers=frozenset({Layer.L1_SCHEMA}),
        )
        line = _format_layers_line(result)
        assert "\u25cb" in line  # circle for L7 opt-in


# ── _error_exit tests ─────────────────────────────────────────────────


class TestErrorExit:
    """Test _error_exit helper."""

    def test_raises_typer_exit(self) -> None:

        with pytest.raises(Exit):
            _error_exit("some error")

    def test_custom_exit_code(self) -> None:

        with pytest.raises(Exit) as exc_info:
            _error_exit("msg", code=5)
        assert exc_info.value.exit_code == 5


# ── _get_app caching tests ────────────────────────────────────────────


class TestGetApp:
    """Test _get_app singleton caching."""

    def test_returns_same_instance(self) -> None:

        cli_mod._app = None  # reset
        app1 = _get_app()
        app2 = _get_app()
        assert app1 is app2
        cli_mod._app = None  # cleanup


# ── run_scan error paths ──────────────────────────────────────────────


class TestRunScanErrors:
    """Test run_scan function error handling."""

    def test_invalid_format_exits(self) -> None:

        with pytest.raises(Exit):
            run_scan(output_format="invalid_fmt")

    def test_mutual_exclusion(self, tmp_path: Path) -> None:

        f = tmp_path / "tools.json"
        f.write_text('[{"name":"t","description":"d","inputSchema":{}}]')
        with pytest.raises(Exit):
            run_scan(file=str(f), server="npx @foo/bar")

    def test_no_classifier_flag(self, tmp_path: Path) -> None:
        """--no-classifier disables L2.5 layer."""
        p = _write_tools_file(tmp_path)

        # Should run without error
        try:
            run_scan(file=str(p), no_classifier=True)
        except Exit as e:
            assert e.exit_code in (0, 1)

    def test_source_dir_enables_l7(self, tmp_path: Path) -> None:
        """--source enables L7 source layer."""
        p = _write_tools_file(tmp_path)
        source_dir = tmp_path / "source"
        source_dir.mkdir()

        try:
            run_scan(file=str(p), source=str(source_dir))
        except Exit as e:
            assert e.exit_code in (0, 1)


# ── run_config_scan tests ─────────────────────────────────────────────


class TestRunConfigScan:
    """Test run_config_scan function and _format_config_result_text."""

    def test_config_scan_missing_file(self) -> None:

        with pytest.raises(Exit):
            run_config_scan(config_file="/nonexistent/config.json")

    def test_config_scan_invalid_format(self) -> None:

        with pytest.raises(Exit):
            run_config_scan(output_format="invalid_fmt")

    def test_config_scan_valid_file_text(self, tmp_path: Path) -> None:
        """Config scan produces text output for a config with servers."""
        config_data = {
            "mcpServers": {
                "srv": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "/tmp"]}
            }
        }
        config_file = tmp_path / "mcp_config.json"
        config_file.write_text(json.dumps(config_data))

        try:
            run_config_scan(config_file=str(config_file))
        except Exit as e:
            assert e.exit_code in (0, 1)

    def test_config_scan_valid_file_json(self, tmp_path: Path) -> None:
        """Config scan JSON output is valid JSON."""
        config_data = {
            "mcpServers": {
                "srv": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "/tmp"]}
            }
        }
        config_file = tmp_path / "mcp_config.json"
        config_file.write_text(json.dumps(config_data))

        try:
            run_config_scan(config_file=str(config_file), output_format="json")
        except Exit as e:
            assert e.exit_code in (0, 1)

    def test_config_scan_sarif_output(self, tmp_path: Path) -> None:
        """Config scan SARIF output produces valid SARIF."""
        config_data = {
            "mcpServers": {
                "srv": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "/tmp"]}
            }
        }
        config_file = tmp_path / "mcp_config.json"
        config_file.write_text(json.dumps(config_data))
        out = tmp_path / "out.sarif"

        try:
            run_config_scan(
                config_file=str(config_file),
                output_format="sarif",
                output_file=str(out),
            )
        except Exit as e:
            assert e.exit_code in (0, 1)
        if out.exists():
            data = json.loads(out.read_text())
            assert data["version"] == "2.1.0"

    def test_config_scan_output_file(self, tmp_path: Path) -> None:
        """Config scan writes to file with --output."""
        config_data = {
            "mcpServers": {
                "srv": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "/tmp"]}
            }
        }
        config_file = tmp_path / "mcp_config.json"
        config_file.write_text(json.dumps(config_data))
        out = tmp_path / "output.txt"

        try:
            run_config_scan(config_file=str(config_file), output_file=str(out))
        except Exit as e:
            assert e.exit_code in (0, 1)
        if out.exists():
            assert "config-scan" in out.read_text()

    def test_config_scan_no_files_found(self) -> None:
        """Config scan with no files discovered exits with error."""

        with (
            patch(
                "munio.scan.config_scanner.ConfigScanner.scan_all",
                return_value=ConfigScanResult(scan_id="x", files=[]),
            ),
            pytest.raises(Exit),
        ):
            run_config_scan()

    def test_config_scan_scan_all_exception(self) -> None:
        """Generic exception in scan_all path exits with error."""

        with (
            patch(
                "munio.scan.config_scanner.ConfigScanner.scan_all",
                side_effect=RuntimeError("fail"),
            ),
            pytest.raises(Exit),
        ):
            run_config_scan()

    def test_config_scan_scan_file_exception(self, tmp_path: Path) -> None:
        """Generic exception in scan_file path exits with error."""

        f = tmp_path / "config.json"
        f.write_text("{}")
        with (
            patch(
                "munio.scan.config_scanner.ConfigScanner.scan_file",
                side_effect=RuntimeError("fail"),
            ),
            pytest.raises(Exit),
        ):
            run_config_scan(config_file=str(f))

    def test_config_scan_details_flag(self, tmp_path: Path) -> None:
        """details flag passes through to formatter."""
        config_data = {
            "mcpServers": {
                "srv": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "/tmp"]}
            }
        }
        config_file = tmp_path / "mcp_config.json"
        config_file.write_text(json.dumps(config_data))

        try:
            run_config_scan(config_file=str(config_file), details=True)
        except Exit as e:
            assert e.exit_code in (0, 1)


# ── _format_config_result_text tests ──────────────────────────────────


class TestFormatConfigResultText:
    """Test _format_config_result_text display logic."""

    def _make_config_result(self, *, findings: list[Finding] | None = None) -> ConfigScanResult:
        return ConfigScanResult(
            scan_id="test",
            files=[
                ConfigFileResult(
                    path="/test/config.json",
                    ide="claude",
                    servers_count=2,
                    findings=findings or [],
                )
            ],
        )

    def test_no_findings(self) -> None:
        result = self._make_config_result()
        output = _format_config_result_text(result)
        assert "No supply chain issues" in output
        assert "config-scan" in output

    def test_with_findings(self) -> None:
        findings = [
            Finding(
                id="CS_001",
                layer=Layer.L1_SCHEMA,
                severity=FindingSeverity.HIGH,
                tool_name="bad_server",
                message="Suspicious command detected",
                cwe="CWE-78",
            )
        ]
        result = self._make_config_result(findings=findings)
        output = _format_config_result_text(result)
        assert "HIGH" in output
        assert "CWE-78" in output
        assert "Suspicious command" in output

    def test_with_details(self) -> None:
        findings = [
            Finding(
                id="CS_001",
                layer=Layer.L1_SCHEMA,
                severity=FindingSeverity.MEDIUM,
                tool_name="srv",
                message="Environment variable exposure",
            )
        ]
        result = self._make_config_result(findings=findings)
        output = _format_config_result_text(result, details=True)
        assert "MEDIUM" in output

    def test_summary_line_and_files(self) -> None:
        result = self._make_config_result()
        output = _format_config_result_text(result)
        assert "config files" in output
        assert "servers" in output
        assert "claude" in output

    def test_cross_command_hint(self) -> None:
        result = self._make_config_result()
        output = _format_config_result_text(result)
        assert "munio scan" in output

    def test_files_with_findings_icon(self) -> None:
        """Files with findings show + icon, without show o."""
        result_clean = self._make_config_result()
        output_clean = _format_config_result_text(result_clean)
        # No findings -> 'o' icon (dim)
        assert "o" in output_clean

        findings = [
            Finding(
                id="CS_001",
                layer=Layer.L1_SCHEMA,
                severity=FindingSeverity.LOW,
                tool_name="srv",
                message="Issue",
            )
        ]
        result_dirty = self._make_config_result(findings=findings)
        output_dirty = _format_config_result_text(result_dirty)
        assert "+" in output_dirty


# ── SSE server skip in _connect_to_servers ────────────────────────────


class TestConnectSSEServer:
    """Test that SSE/HTTP servers are skipped."""

    def test_sse_server_skipped(self, tmp_path: Path) -> None:
        """SSE server (url, no command) produces 'not supported' error."""
        config = {"mcpServers": {"sse-server": {"url": "http://localhost:8080/sse"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))

        app = create_app()
        result = runner.invoke(app, ["scan", "--config", str(p)])
        # Should handle gracefully
        assert result.exit_code in (0, 1, 2)
