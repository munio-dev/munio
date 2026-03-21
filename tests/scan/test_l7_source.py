"""Tests for L7 Source Analysis layer — TDD: tests first, implementation second."""

from __future__ import annotations

from pathlib import Path

import pytest

from munio.scan.models import FindingSeverity, Layer

FIXTURES = Path(__file__).parent / "fixtures" / "l7_source"


def _try_import_l7():
    """Import L7 analyzer, skip if tree-sitter not installed."""
    try:
        from munio.scan.layers.l7_source import L7SourceAnalyzer

        return L7SourceAnalyzer
    except ImportError:
        pytest.skip("tree-sitter not installed")


# ── Graceful degradation ────────────────────────────────────────


class TestTreeSitterAvailability:
    """L7 must gracefully handle missing tree-sitter."""

    def test_not_ready_when_no_source_dir(self) -> None:
        L7 = _try_import_l7()
        analyzer = L7(source_dir=None)
        assert analyzer.analyze([]) == []

    def test_not_ready_when_source_dir_missing(self, tmp_path: Path) -> None:
        L7 = _try_import_l7()
        analyzer = L7(source_dir=tmp_path / "nonexistent")
        assert analyzer.analyze([]) == []

    def test_layer_property(self) -> None:
        L7 = _try_import_l7()
        analyzer = L7(source_dir=None)
        assert analyzer.layer == Layer.L7_SOURCE


# ── Handler Detection ────────────────────────────────────────────


class TestJSHandlerDetection:
    """Detect MCP tool handlers in JS/TS source code."""

    def test_server_dot_tool_pattern(self) -> None:
        """server.tool("name", schema, handler) detected."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        # cmd_injection_inline.js has server.tool("run_command", ...)
        tool_names = {f.tool_name for f in findings}
        assert "run_command" in tool_names

    def test_handler_with_helper(self) -> None:
        """Handler that calls local helper is traced."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        # cmd_injection_helper.js: server.tool("execute", ...) → runShell() → exec()
        execute_findings = [f for f in findings if f.tool_name == "execute"]
        assert len(execute_findings) >= 1
        assert execute_findings[0].cwe == "CWE-78"


class TestPythonHandlerDetection:
    """Detect MCP tool handlers in Python source code."""

    def test_fastmcp_decorator(self) -> None:
        """@mcp.tool() decorated function detected."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        tool_names = {f.tool_name for f in findings}
        # cmd_injection_python.py has @mcp.tool() def run_command
        assert "run_command" in tool_names

    def test_python_sql_injection(self) -> None:
        """Python f-string → cursor.execute detected."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        search_findings = [f for f in findings if f.tool_name == "search" and f.cwe == "CWE-89"]
        assert len(search_findings) >= 1


# ── Vulnerability Rules ──────────────────────────────────────────


class TestL7Rules:
    """Test each L7 rule against fixture files."""

    @pytest.mark.parametrize(
        ("fixture", "rule_id", "cwe"),
        [
            ("cmd_injection_inline.js", "L7_001", "CWE-78"),
            ("cmd_injection_helper.js", "L7_001", "CWE-78"),
            ("sql_injection_template.js", "L7_002", "CWE-89"),
            ("path_traversal_direct.js", "L7_003", "CWE-22"),
            ("ssrf_fetch.js", "L7_004", "CWE-918"),
            ("code_injection_eval.js", "L7_005", "CWE-94"),
            ("cmd_injection_python.py", "L7_001", "CWE-78"),
            ("sql_injection_python.py", "L7_002", "CWE-89"),
        ],
        ids=[
            "js-cmd-inline",
            "js-cmd-helper",
            "js-sql-template",
            "js-path-traversal",
            "js-ssrf-fetch",
            "js-eval",
            "py-cmd-os-system",
            "py-sql-fstring",
        ],
    )
    def test_vulnerable_detected(self, fixture: str, rule_id: str, cwe: str) -> None:
        """Known vulnerable fixtures produce the expected finding."""
        L7 = _try_import_l7()
        fixture_dir = FIXTURES / fixture
        # Analyze single fixture file
        analyzer = L7(source_dir=fixture_dir.parent)
        findings = analyzer.analyze([])
        # Filter findings from this specific file
        file_findings = [f for f in findings if fixture in f.location]
        assert len(file_findings) >= 1, f"Expected {rule_id} finding in {fixture}, got none"
        assert any(f.id == rule_id for f in file_findings), (
            f"Expected {rule_id} in {fixture}, got {[f.id for f in file_findings]}"
        )
        assert any(f.cwe == cwe for f in file_findings)

    @pytest.mark.parametrize(
        "fixture",
        [
            "safe_parameterized_query.js",
            "safe_execfile_array.js",
            "safe_shlex_python.py",
            "regex_exec_not_sink.js",
        ],
        ids=[
            "js-parameterized-query",
            "js-execfile-array",
            "py-shlex-quote",
            "js-regex-exec-not-sink",
        ],
    )
    def test_safe_code_no_findings(self, fixture: str) -> None:
        """Safe fixtures produce zero CRITICAL/HIGH findings."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        file_findings = [
            f
            for f in findings
            if fixture in f.location
            and f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        ]
        assert len(file_findings) == 0, (
            f"Expected no CRITICAL/HIGH findings in {fixture}, got {file_findings}"
        )


# ── Taint Propagation ────────────────────────────────────────────


class TestTaintPropagation:
    """Test taint tracking through various code patterns."""

    def test_direct_param_to_sink(self) -> None:
        """args.X → sink() detected with high confidence."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        # cmd_injection_inline.js: args.command → exec() — direct, 1 hop
        inline = [
            f for f in findings if "cmd_injection_inline.js" in f.location and f.id == "L7_001"
        ]
        assert len(inline) >= 1
        assert inline[0].confidence >= 0.85

    def test_template_literal_propagation(self) -> None:
        """Taint through template literal → sink detected."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        # sql_injection_template.js: `SELECT ${args.query}` → db.query()
        sql = [
            f for f in findings if "sql_injection_template.js" in f.location and f.id == "L7_002"
        ]
        assert len(sql) >= 1
        assert sql[0].confidence >= 0.75

    def test_helper_function_taint(self) -> None:
        """Taint through same-file helper function with lower confidence."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        helper = [
            f for f in findings if "cmd_injection_helper.js" in f.location and f.id == "L7_001"
        ]
        assert len(helper) >= 1
        # Helper hop → lower confidence
        assert helper[0].confidence <= 0.80


# ── Sink Matching ────────────────────────────────────────────────


class TestSinkMatching:
    """Test receiver-qualified sink matching."""

    def test_regex_exec_not_matched_as_command_sink(self) -> None:
        """regex.exec() must NOT match as child_process.exec (CWE-78)."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        regex_findings = [f for f in findings if "regex_exec_not_sink.js" in f.location]
        cwe78 = [f for f in regex_findings if f.cwe == "CWE-78"]
        assert len(cwe78) == 0, "regex.exec() should NOT be flagged as CWE-78"

    def test_import_derived_receiver(self) -> None:
        """const { exec } = require('child_process') → bare exec() matches sink."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        # cmd_injection_inline.js has: const { exec } = require("child_process")
        # followed by bare exec(args.command)
        inline = [
            f for f in findings if "cmd_injection_inline.js" in f.location and f.cwe == "CWE-78"
        ]
        assert len(inline) >= 1


# ── Sanitizer Recognition ───────────────────────────────────────


class TestSanitizerRecognition:
    """Test that sanitizers properly kill taint."""

    def test_shlex_quote_kills_cwe78(self) -> None:
        """shlex.quote() sanitizes command injection."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        shlex_findings = [
            f for f in findings if "safe_shlex_python.py" in f.location and f.cwe == "CWE-78"
        ]
        assert len(shlex_findings) == 0

    def test_parameterized_query_kills_cwe89(self) -> None:
        """db.query("SELECT $1", [param]) sanitizes SQL injection."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        param_findings = [
            f
            for f in findings
            if "safe_parameterized_query.js" in f.location and f.cwe == "CWE-89"
        ]
        assert len(param_findings) == 0

    def test_execfile_array_args_kills_cwe78(self) -> None:
        """execFile("cmd", [args]) with array args is NOT command injection."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        execfile_findings = [
            f for f in findings if "safe_execfile_array.js" in f.location and f.cwe == "CWE-78"
        ]
        assert len(execfile_findings) == 0


# ── Integration ──────────────────────────────────────────────────


class TestL7Integration:
    """Integration tests via Orchestrator."""

    def test_l7_not_in_default_layers(self) -> None:
        """L7 is opt-in, not enabled by default."""
        from munio.scan.config import ScanConfig

        config = ScanConfig()
        assert Layer.L7_SOURCE not in config.enabled_layers

    def test_l7_findings_have_physical_location(self) -> None:
        """L7 findings include file:line location."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        for f in findings:
            assert "file:" in f.location, f"Finding {f.id} missing file: prefix in location"
            parts = f.location.split(":")
            assert len(parts) >= 3, f"Finding {f.id} location should be file:path:line"

    def test_l7_findings_have_cwe(self) -> None:
        """All L7 findings include CWE."""
        L7 = _try_import_l7()
        analyzer = L7(source_dir=FIXTURES)
        findings = analyzer.analyze([])
        for f in findings:
            assert f.cwe is not None
            assert f.cwe.startswith("CWE-")
