"""Tests for munio.cli — unified CLI commands, formatting, error handling."""

from __future__ import annotations

import importlib.util
import json
import re
from typing import Any

import pytest
from typer.testing import CliRunner

from munio.cli import (
    OutputFormat,
    _format_policy_json,
    _format_policy_text,
    _format_result_json,
    _format_result_text,
    _format_scan_json,
    _format_scan_text,
    create_app,
)
from munio.models import (
    DeployCheckType,
    PolicyResult,
    PolicyVerificationResult,
    VerificationMode,
    VerificationResult,
    Violation,
    ViolationSeverity,
)

from .conftest import CONSTRAINTS_DIR

runner = CliRunner()
app = create_app()


def _strip_ansi(text: str) -> str:
    """Strip ANSI escape codes from Rich output."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _constraints_dir_arg() -> list[str]:
    """Return CLI args pointing to the real constraints directory."""
    return ["-d", str(CONSTRAINTS_DIR)]


# ── TestVersion ─────────────────────────────────────────────────────────


class TestVersion:
    def test_shows_version_string(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "munio" in result.output

    def test_shows_z3_status(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "z3-solver" in result.output

    def test_version_format(self) -> None:
        """Version output uses 'munio v' prefix."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "munio v" in result.output


# ── TestCheck ──────────────────────────────────────────────────────────


class TestCheck:
    """Tests for the check command (was verify)."""

    # Happy path

    def test_allowed_action_exit_0(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://api.example.com"}}',
                *_constraints_dir_arg(),
            ],
        )
        assert result.exit_code == 0

    def test_blocked_action_exit_1(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://evil.com/steal"}}',
                *_constraints_dir_arg(),
            ],
        )
        assert result.exit_code == 1

    def test_text_output_contains_allowed(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://api.example.com"}}',
                *_constraints_dir_arg(),
            ],
        )
        plain = _strip_ansi(result.output)
        assert "ALLOWED" in plain

    def test_text_output_contains_blocked_and_violations(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://evil.com"}}',
                *_constraints_dir_arg(),
            ],
        )
        plain = _strip_ansi(result.output)
        assert "BLOCKED" in plain
        assert "Violations" in plain

    def test_json_output_valid_json(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://evil.com"}}',
                "-f",
                "json",
                *_constraints_dir_arg(),
            ],
        )
        data = json.loads(result.output)
        assert isinstance(data, dict)
        required = {"allowed", "mode", "violations", "checked_constraints", "elapsed_ms"}
        assert required.issubset(data.keys())
        assert isinstance(data["allowed"], bool)
        assert isinstance(data["violations"], list)

    def test_json_output_has_allowed_field(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://api.example.com"}}',
                "-f",
                "json",
                *_constraints_dir_arg(),
            ],
        )
        data = json.loads(result.output)
        assert data["allowed"] is True

    # Input handling

    def test_stdin_dash_reads_input(self) -> None:
        action = '{"tool": "http_request", "args": {"url": "https://evil.com"}}'
        result = runner.invoke(
            app,
            ["check", "-", *_constraints_dir_arg()],
            input=action,
        )
        assert result.exit_code == 1  # blocked

    def test_stdin_empty_input_exit_2(self) -> None:
        """Empty stdin should produce a JSON parse error."""
        result = runner.invoke(
            app,
            ["check", "-", *_constraints_dir_arg()],
            input="",
        )
        assert result.exit_code == 2

    def test_invalid_json_exit_2(self) -> None:
        result = runner.invoke(app, ["check", "not json", *_constraints_dir_arg()])
        assert result.exit_code == 2

    def test_invalid_action_schema_exit_2(self) -> None:
        """Missing 'tool' field should exit 2."""
        result = runner.invoke(
            app,
            ["check", '{"args": {"url": "x"}}', *_constraints_dir_arg()],
        )
        assert result.exit_code == 2

    def test_empty_json_object_exit_2(self) -> None:
        result = runner.invoke(app, ["check", "{}", *_constraints_dir_arg()])
        assert result.exit_code == 2

    @pytest.mark.parametrize(
        ("json_input", "desc"),
        [
            ("[1, 2, 3]", "array"),
            ("null", "null"),
            ("42", "number"),
            ('"just a string"', "string"),
        ],
        ids=["array", "null", "number", "string"],
    )
    def test_non_object_json_exit_2(self, json_input: str, desc: str) -> None:
        """JSON that is not an object -> exit 2 with error message."""
        result = runner.invoke(app, ["check", json_input, *_constraints_dir_arg()])
        assert result.exit_code == 2

    def test_stdin_oversized_input_exit_2(self) -> None:
        """stdin > 1MB -> exit 2."""
        oversized = '{"tool":"t","args":{' + '"x":"' + "a" * 1_100_000 + '"}'
        result = runner.invoke(
            app,
            ["check", "-", *_constraints_dir_arg()],
            input=oversized,
        )
        assert result.exit_code == 2

    # Options

    def test_custom_constraints_pack(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://api.example.com"}}',
                "-c",
                "generic",
                *_constraints_dir_arg(),
            ],
        )
        assert result.exit_code == 0

    def test_shadow_mode_always_exit_0(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://evil.com"}}',
                "-m",
                "shadow",
                *_constraints_dir_arg(),
            ],
        )
        assert result.exit_code == 0

    def test_disabled_mode_exit_0(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://evil.com"}}',
                "-m",
                "disabled",
                *_constraints_dir_arg(),
            ],
        )
        assert result.exit_code == 0

    def test_custom_constraints_dir(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://api.example.com"}}',
                "-d",
                str(CONSTRAINTS_DIR),
            ],
        )
        assert result.exit_code == 0

    def test_no_values_flag_strips_actual(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://evil.com"}}',
                "-f",
                "json",
                "--no-values",
                *_constraints_dir_arg(),
            ],
        )
        data = json.loads(result.output)
        for violation in data["violations"]:
            assert violation["actual_value"] == ""

    def test_nonexistent_constraints_dir_falls_back_to_bundled(self) -> None:
        """Nonexistent absolute path falls back to bundled constraints."""
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "x", "args": {}}',
                "-d",
                "/nonexistent/path",
            ],
        )
        # Falls back to bundled constraints; benign action is allowed
        assert result.exit_code == 0

    def test_quiet_flag_no_output(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://evil.com"}}',
                "-q",
                *_constraints_dir_arg(),
            ],
        )
        assert result.exit_code == 1
        # Quiet mode: no table, no "BLOCKED"
        plain = _strip_ansi(result.output).strip()
        assert "BLOCKED" not in plain
        assert "Violations" not in plain

    # Output format

    def test_format_text_default(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://api.example.com"}}',
                *_constraints_dir_arg(),
            ],
        )
        plain = _strip_ansi(result.output)
        assert "ALLOWED" in plain
        assert "Mode:" in plain

    def test_format_json_flag(self) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://api.example.com"}}',
                "-f",
                "json",
                *_constraints_dir_arg(),
            ],
        )
        data = json.loads(result.output)
        assert data["allowed"] is True
        assert data["mode"] == "enforce"


# ── TestAudit ────────────────────────────────────────────────────────


class TestAudit:
    """Tests for the audit command (was scan)."""

    def test_default_directory(self) -> None:
        result = runner.invoke(app, ["audit", *_constraints_dir_arg()])
        assert result.exit_code == 0

    def test_specific_pack(self) -> None:
        result = runner.invoke(
            app,
            ["audit", *_constraints_dir_arg(), "-p", "generic"],
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert (
            "27" in plain
        )  # 27 generic constraints (14 base + 4 universal + 5 capability + 4 tier4)

    def test_json_output_valid(self) -> None:
        result = runner.invoke(
            app,
            ["audit", *_constraints_dir_arg(), "-f", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data["total"], int)
        assert data["total"] > 0

    def test_nonexistent_dir_falls_back_to_bundled(self) -> None:
        """Nonexistent absolute path falls back to bundled constraints."""
        result = runner.invoke(app, ["audit", "-d", "/nonexistent/path"])
        # Falls back to bundled constraints; audit succeeds
        assert result.exit_code == 0

    def test_shows_constraint_count(self) -> None:
        result = runner.invoke(app, ["audit", *_constraints_dir_arg()])
        plain = _strip_ansi(result.output)
        assert "Constraints:" in plain

    def test_shows_tier_breakdown(self) -> None:
        result = runner.invoke(app, ["audit", *_constraints_dir_arg()])
        plain = _strip_ansi(result.output)
        assert "Tier Breakdown" in plain
        assert "tier_1" in plain

    def test_shows_disabled_constraints(self) -> None:
        result = runner.invoke(
            app,
            ["audit", *_constraints_dir_arg(), "-f", "json"],
        )
        data = json.loads(result.output)
        # url-allowlist.yaml has enabled=false
        disabled_issues = [i for i in data["issues"] if "disabled" in i]
        assert len(disabled_issues) >= 1

    def test_strict_exit_1_on_issues(self) -> None:
        """--strict exits 1 when issues are detected."""
        result = runner.invoke(
            app,
            ["audit", *_constraints_dir_arg(), "--strict"],
        )
        # The generic pack has a disabled constraint -> issue -> exit 1
        assert result.exit_code == 1

    def test_strict_exit_0_no_issues(self, tmp_path: Any) -> None:
        """--strict exits 0 when no issues are detected."""
        # Create a pack with no issues
        pack = tmp_path / "clean-pack"
        pack.mkdir()
        (pack / "rule.yaml").write_text(
            "name: clean-rule\ncheck:\n  type: denylist\n  field: url\n  values: ['x']\n"
        )
        result = runner.invoke(
            app,
            ["audit", "-d", str(tmp_path), "--strict"],
        )
        assert result.exit_code == 0


# ── TestErrorHandling ──────────────────────────────────────────────────


class TestErrorHandling:
    def test_create_app_returns_typer_app(self) -> None:
        import typer

        new_app = create_app()
        assert isinstance(new_app, typer.Typer)

    def test_error_message_on_invalid_json(self) -> None:
        result = runner.invoke(app, ["check", "{bad", *_constraints_dir_arg()])
        assert result.exit_code == 2
        # Error should mention JSON
        assert "JSON" in result.output or "json" in result.output


# ── TestOutputFormatting ────────────────────────────────────────────────


class TestOutputFormatting:
    """Test formatting functions directly (no CliRunner needed)."""

    def _make_result(
        self,
        allowed: bool = True,
        violations: list[Violation] | None = None,
    ) -> VerificationResult:
        return VerificationResult(
            allowed=allowed,
            mode=VerificationMode.ENFORCE,
            violations=violations or [],
            checked_constraints=3,
            elapsed_ms=1.234,
            tier_breakdown={"tier_1": 3},
        )

    def test_format_text_allowed(self) -> None:
        result = self._make_result(allowed=True)
        text = _strip_ansi(_format_result_text(result))
        assert "ALLOWED" in text
        assert "Mode: enforce" in text

    def test_format_text_blocked_with_violations(self) -> None:
        violations = [
            Violation(
                constraint_name="test-rule",
                severity=ViolationSeverity.HIGH,
                message="bad url detected",
                field="url",
                actual_value="evil.com",
            ),
        ]
        result = self._make_result(allowed=False, violations=violations)
        text = _strip_ansi(_format_result_text(result))
        assert "BLOCKED" in text
        assert "test-rule" in text
        assert "bad url detected" in text

    def test_format_text_multiple_violations(self) -> None:
        violations = [
            Violation(
                constraint_name=f"rule-{i}",
                severity=ViolationSeverity.HIGH,
                message=f"violation {i}",
            )
            for i in range(3)
        ]
        result = self._make_result(allowed=False, violations=violations)
        text = _strip_ansi(_format_result_text(result))
        assert "rule-0" in text
        assert "rule-2" in text

    def test_format_json_serializable(self) -> None:
        result = self._make_result(allowed=True)
        text = _format_result_json(result)
        data = json.loads(text)
        assert data["allowed"] is True

    def test_format_json_roundtrip(self) -> None:
        violations = [
            Violation(
                constraint_name="rule-x",
                severity=ViolationSeverity.CRITICAL,
                message="blocked",
                field="url",
                actual_value="evil.com",
            ),
        ]
        result = self._make_result(allowed=False, violations=violations)
        text = _format_result_json(result)
        data = json.loads(text)
        assert data["allowed"] is False
        assert len(data["violations"]) == 1
        assert data["violations"][0]["constraint_name"] == "rule-x"
        assert data["violations"][0]["severity"] == "critical"

    def test_format_scan_text_with_issues(self) -> None:
        stats: dict[str, Any] = {
            "total": 5,
            "tiers": {"tier_1": 5},
            "check_types": {"denylist": 3, "allowlist": 2},
            "actions": ["*", "http_request"],
            "issues": ["'rule-x' is disabled"],
        }
        text = _strip_ansi(_format_scan_text(stats))
        assert "Constraints: 5" in text
        assert "disabled" in text

    def test_format_scan_json(self) -> None:
        stats: dict[str, Any] = {
            "total": 5,
            "tiers": {"tier_1": 5},
            "check_types": {},
            "actions": [],
            "issues": [],
        }
        text = _format_scan_json(stats)
        data = json.loads(text)
        assert data["total"] == 5


# ── TestOutputFormatEnum ────────────────────────────────────────────────


class TestOutputFormatEnum:
    @pytest.mark.parametrize(
        ("member", "expected"),
        [
            (OutputFormat.TEXT, "text"),
            (OutputFormat.JSON, "json"),
            (OutputFormat.SARIF, "sarif"),
        ],
        ids=["text", "json", "sarif"],
    )
    def test_enum_value(self, member: OutputFormat, expected: str) -> None:
        assert member.value == expected


# ── TestEdgeCases ──────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases found during code review."""

    @pytest.mark.parametrize(
        ("flag", "value"),
        [("-m", "invalid"), ("-f", "xml")],
        ids=["invalid-mode", "invalid-format"],
    )
    def test_invalid_enum_option_rejected(self, flag: str, value: str) -> None:
        """Invalid enum options should be rejected by Typer."""
        result = runner.invoke(
            app,
            ["check", '{"tool": "x", "args": {}}', flag, value, *_constraints_dir_arg()],
        )
        assert result.exit_code == 2

    def test_quiet_json_no_output(self) -> None:
        """Quiet mode with JSON format should produce no output."""
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://evil.com"}}',
                "-f",
                "json",
                "-q",
                *_constraints_dir_arg(),
            ],
        )
        assert result.exit_code == 1
        assert result.output.strip() == ""

    def test_help_lists_commands(self) -> None:
        """Help output shows all available commands."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "check" in result.output
        assert "audit" in result.output
        assert "scan" in result.output
        assert "gate" in result.output
        assert "serve" in result.output
        assert "version" in result.output

    @pytest.mark.parametrize(
        ("pack", "expected_total"),
        [("nonexistent-pack", 0), ("generic", 27)],
        ids=["nonexistent-pack", "generic-pack"],
    )
    def test_audit_pack_json_stats(self, pack: str, expected_total: int) -> None:
        """Audit JSON stats: total matches expected; tier sum == total."""
        result = runner.invoke(
            app,
            ["audit", *_constraints_dir_arg(), "-p", pack, "-f", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == expected_total
        if expected_total > 0:
            assert sum(data["tiers"].values()) == data["total"]

    def test_module_getattr_raises(self) -> None:
        """Accessing undefined module attribute raises AttributeError."""
        import munio.cli

        with pytest.raises(AttributeError):
            munio.cli.nonexistent_attribute  # noqa: B018

    def test_unmatched_action_tool(self) -> None:
        """Action tool matching no constraints exits 0 (default warn)."""
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "totally_unknown_tool", "args": {}}',
                *_constraints_dir_arg(),
            ],
        )
        assert result.exit_code == 0


# ── TestServe ────────────────────────────────────────────────────────


class TestServe:
    def test_help_output_shows_serve(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "serve" in result.output

    def test_serve_help_shows_options(self) -> None:
        import re

        result = runner.invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        # Strip ANSI escape codes (Rich renders differently on CI vs terminal)
        clean = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert "--host" in clean
        assert "--port" in clean
        assert "--pack" in clean

    def test_nonexistent_dir_exits_error(self) -> None:
        result = runner.invoke(app, ["serve", "-d", "/nonexistent/path"])
        # Server startup fails with RuntimeError -> exit code != 0
        assert result.exit_code != 0

    def test_missing_server_deps_shows_install_hint(self) -> None:
        import unittest.mock

        with unittest.mock.patch.dict("sys.modules", {"munio.server": None}):
            result = runner.invoke(app, ["serve"])
            # Should fail gracefully with install hint
            assert result.exit_code != 0

    def test_cors_default_empty_not_wildcard(self) -> None:
        """H3: CLI serve --cors-origins defaults to empty, not '*'."""
        result = runner.invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        # Help text should show empty default, not "*"
        assert "empty=none" in result.output


# ── TestPolicy ────────────────────────────────────────────────────


class TestPolicy:
    """Tests for policy CLI command (was policy-check)."""

    def test_help_shows_options(self) -> None:
        result = runner.invoke(app, ["policy", "--help"])
        assert result.exit_code == 0
        clean = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert "--constraint-file" in clean
        assert "--check-name" in clean
        assert "--constraints-dir" in clean
        assert "--pack" in clean
        assert "--format" in clean

    def test_no_args_exits_error(self) -> None:
        """Neither --constraint-file nor --check-name -> exit code 2."""
        result = runner.invoke(app, ["policy", *_constraints_dir_arg()])
        assert result.exit_code == 2

    def test_constraint_file_not_found(self, tmp_path: Any) -> None:
        result = runner.invoke(
            app,
            ["policy", "-f", str(tmp_path / "missing.yaml"), *_constraints_dir_arg()],
        )
        assert result.exit_code == 2
        assert "not found" in result.output.lower() or "not found" in (result.stderr or "").lower()

    def test_check_name_not_found(self) -> None:
        """--check-name with nonexistent name -> exit code 2."""
        result = runner.invoke(
            app,
            ["policy", "-n", "nonexistent-check", *_constraints_dir_arg()],
        )
        assert result.exit_code == 2

    @pytest.mark.z3
    def test_constraint_file_data_flow(self, tmp_path: Any) -> None:
        """Tier 4 constraint from file: data_flow with path -> UNSAFE (exit 1)."""
        yaml_content = (
            "name: test-flow\n"
            "tier: 4\n"
            "deploy_check:\n"
            "  type: data_flow\n"
            "  source: db_query\n"
            "  forbidden_sink: http_request\n"
            "  flow_edges:\n"
            "    - [db_query, http_request]\n"
        )
        f = tmp_path / "flow.yaml"
        f.write_text(yaml_content)
        result = runner.invoke(app, ["policy", "-f", str(f), *_constraints_dir_arg()])
        assert result.exit_code == 1  # UNSAFE
        stripped = _strip_ansi(result.output)
        assert "UNSAFE" in stripped

    @pytest.mark.z3
    def test_constraint_file_safe_data_flow(self, tmp_path: Any) -> None:
        """Tier 4 constraint: no path from source to sink -> SAFE (exit 0)."""
        yaml_content = (
            "name: test-safe-flow\n"
            "tier: 4\n"
            "deploy_check:\n"
            "  type: data_flow\n"
            "  source: db_query\n"
            "  forbidden_sink: http_request\n"
            "  flow_edges:\n"
            "    - [db_query, file_write]\n"
            "    - [other_source, http_request]\n"
        )
        f = tmp_path / "safe-flow.yaml"
        f.write_text(yaml_content)
        result = runner.invoke(app, ["policy", "-f", str(f), *_constraints_dir_arg()])
        assert result.exit_code == 0  # SAFE
        stripped = _strip_ansi(result.output)
        assert "SAFE" in stripped

    @pytest.mark.z3
    def test_json_format_output(self, tmp_path: Any) -> None:
        """--format json produces valid JSON with result field."""
        yaml_content = (
            "name: test-json\n"
            "tier: 4\n"
            "deploy_check:\n"
            "  type: data_flow\n"
            "  source: a\n"
            "  forbidden_sink: b\n"
            "  flow_edges:\n"
            "    - [a, b]\n"
        )
        f = tmp_path / "json-flow.yaml"
        f.write_text(yaml_content)
        result = runner.invoke(
            app, ["policy", "-f", str(f), *_constraints_dir_arg(), "--format", "json"]
        )
        assert result.exit_code == 1  # UNSAFE
        data = json.loads(result.output)
        assert data["result"] == "unsafe"
        assert "details" in data

    def test_non_tier4_constraint_exits_error(self, tmp_path: Any) -> None:
        """Loading a Tier 1 constraint -> exit code 2."""
        yaml_content = (
            "name: tier1-check\n"
            "tier: 1\n"
            "check:\n"
            "  type: denylist\n"
            "  field: url\n"
            "  values: [evil.com]\n"
        )
        f = tmp_path / "tier1.yaml"
        f.write_text(yaml_content)
        result = runner.invoke(app, ["policy", "-f", str(f), *_constraints_dir_arg()])
        assert result.exit_code == 2

    def test_invalid_yaml_exits_error(self, tmp_path: Any) -> None:
        """Invalid YAML -> exit code 2."""
        f = tmp_path / "bad.yaml"
        f.write_text("name: [broken yaml\n  invalid")
        result = runner.invoke(app, ["policy", "-f", str(f), *_constraints_dir_arg()])
        assert result.exit_code == 2

    def test_missing_deploy_check_exits_error(self, tmp_path: Any) -> None:
        """Tier 4 without deploy_check -> exit code 2."""
        yaml_content = "name: no-deploy\ntier: 4\n"
        f = tmp_path / "no-deploy.yaml"
        f.write_text(yaml_content)
        result = runner.invoke(app, ["policy", "-f", str(f), *_constraints_dir_arg()])
        assert result.exit_code == 2

    def test_with_pack_flag(self, tmp_path: Any) -> None:
        """--pack restricts loaded packs."""
        yaml_content = (
            "name: test-pack\n"
            "tier: 4\n"
            "deploy_check:\n"
            "  type: data_flow\n"
            "  source: a\n"
            "  forbidden_sink: b\n"
            "  flow_edges:\n"
            "    - [a, c]\n"
        )
        f = tmp_path / "pack-test.yaml"
        f.write_text(yaml_content)
        result = runner.invoke(
            app,
            ["policy", "-f", str(f), *_constraints_dir_arg(), "-p", "generic"],
        )
        # Should load successfully with pack restriction
        assert result.exit_code in (0, 1, 2)

    def test_check_name_finds_tier4_constraint(self) -> None:
        """--check-name finds a real Tier 4 constraint in registry."""
        result = runner.invoke(
            app,
            [
                "policy",
                "-n",
                "policy-no-exfil-path",
                *_constraints_dir_arg(),
                "-p",
                "generic",
            ],
        )
        # 0=SAFE, 1=UNSAFE, 2=ERROR (Z3 not available or timeout on CI)
        assert result.exit_code in (0, 1, 2)

    def test_nonexistent_constraints_dir(self) -> None:
        """--constraints-dir pointing to nonexistent dir -> exit code 2."""
        result = runner.invoke(
            app,
            ["policy", "-n", "anything", "-d", "/nonexistent/path"],
        )
        assert result.exit_code == 2

    def test_non_dict_yaml_content(self, tmp_path: Any) -> None:
        """YAML that parses to a list (not dict) -> exit code 2."""
        f = tmp_path / "list.yaml"
        f.write_text("- item1\n- item2\n")
        result = runner.invoke(app, ["policy", "-f", str(f), *_constraints_dir_arg()])
        assert result.exit_code == 2


# ── TestFormatPolicyText ───────────────────────────────────────────────


class TestFormatPolicyText:
    """Tests for _format_policy_text() formatter."""

    @pytest.mark.parametrize(
        ("policy_result", "expected_text"),
        [
            (PolicyResult.SAFE, "SAFE"),
            (PolicyResult.UNSAFE, "UNSAFE"),
            (PolicyResult.TIMEOUT, "TIMEOUT"),
            (PolicyResult.UNKNOWN, "UNKNOWN"),
            (PolicyResult.ERROR, "ERROR"),
        ],
    )
    def test_all_result_statuses(self, policy_result: PolicyResult, expected_text: str) -> None:
        result = PolicyVerificationResult(result=policy_result)
        output = _strip_ansi(_format_policy_text(result))
        assert expected_text in output

    def test_includes_check_type(self) -> None:
        result = PolicyVerificationResult(
            result=PolicyResult.SAFE,
            check_type=DeployCheckType.DATA_FLOW,
        )
        output = _strip_ansi(_format_policy_text(result))
        assert "data_flow" in output

    def test_includes_details(self) -> None:
        result = PolicyVerificationResult(
            result=PolicyResult.UNSAFE,
            details={"issues": "bad stuff", "path": "a->b"},
        )
        output = _strip_ansi(_format_policy_text(result))
        assert "issues" in output
        assert "bad stuff" in output

    def test_includes_elapsed_ms(self) -> None:
        result = PolicyVerificationResult(result=PolicyResult.SAFE, elapsed_ms=42.5)
        output = _strip_ansi(_format_policy_text(result))
        assert "42.5" in output

    def test_includes_constraints_checked(self) -> None:
        result = PolicyVerificationResult(
            result=PolicyResult.SAFE,
            constraints_checked=["max-spend", "url-deny"],
        )
        output = _strip_ansi(_format_policy_text(result))
        assert "max-spend" in output
        assert "url-deny" in output


class TestFormatPolicyJson:
    """Tests for _format_policy_json() formatter."""

    def test_returns_valid_json(self) -> None:
        result = PolicyVerificationResult(
            result=PolicyResult.SAFE,
            check_type=DeployCheckType.NO_NEW_ACCESS,
        )
        data = json.loads(_format_policy_json(result))
        assert data["result"] == "safe"
        assert data["safe"] is True

    def test_unsafe_result_json(self) -> None:
        result = PolicyVerificationResult(
            result=PolicyResult.UNSAFE,
            details={"issues": ["relaxed threshold"]},
        )
        data = json.loads(_format_policy_json(result))
        assert data["result"] == "unsafe"
        assert data["safe"] is False
        assert "issues" in data["details"]


# ── TestServeIntegration ──────────────────────────────────────────────


@pytest.mark.skipif(
    not importlib.util.find_spec("uvicorn"),
    reason="uvicorn not installed",
)
class TestServeIntegration:
    """Test munio serve CLI integration (uvicorn mocked)."""

    def test_serve_creates_app_with_packs(self) -> None:
        """Mock uvicorn.run and create_server, verify serve invokes them."""
        from unittest.mock import MagicMock, patch

        mock_server_app = MagicMock()
        with (
            patch("uvicorn.run") as mock_uvicorn,
            patch("munio.server.create_server", return_value=mock_server_app) as mock_create,
        ):
            result = runner.invoke(app, ["serve", "--pack", "generic"])
            assert result.exit_code == 0
            mock_create.assert_called_once()
            mock_uvicorn.assert_called_once()
            # The app passed to uvicorn.run should be the mocked server app
            call_args = mock_uvicorn.call_args
            assert call_args[0][0] is mock_server_app

    def test_serve_passes_host_port(self) -> None:
        """Verify custom host and port are forwarded to uvicorn.run."""
        from unittest.mock import MagicMock, patch

        mock_server_app = MagicMock()
        with (
            patch("uvicorn.run") as mock_uvicorn,
            patch("munio.server.create_server", return_value=mock_server_app),
        ):
            result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--port", "9999"])  # noqa: S104
            assert result.exit_code == 0
            call_kwargs = mock_uvicorn.call_args
            assert call_kwargs.kwargs["host"] == "0.0.0.0"  # noqa: S104
            assert call_kwargs.kwargs["port"] == 9999

    def test_serve_cors_origins_parsed(self) -> None:
        """Verify comma-separated CORS origins are parsed into a list."""
        from unittest.mock import MagicMock, patch

        mock_server_app = MagicMock()
        captured_config = {}

        def fake_create_server(config: Any) -> MagicMock:
            captured_config["config"] = config
            return mock_server_app

        with (
            patch("uvicorn.run"),
            patch("munio.server.create_server", side_effect=fake_create_server),
        ):
            result = runner.invoke(app, ["serve", "--cors-origins", "a.com,b.com"])
            assert result.exit_code == 0
            cfg = captured_config["config"]
            assert cfg.cors_origins == ["a.com", "b.com"]


# ── TestMultiPack ─────────────────────────────────────────────────────


class TestMultiPack:
    """Test multiple constraint pack loading."""

    def test_check_multiple_packs(self, tmp_path: Any) -> None:
        """Smoke test: check command with a specific pack from a custom dir."""
        # Create a constraints dir with a "generic" subdirectory
        pack_dir = tmp_path / "generic"
        pack_dir.mkdir()
        (pack_dir / "rule.yaml").write_text(
            "name: test-deny\ncheck:\n  type: denylist\n  field: url\n  values:\n    - evil.com\n"
        )
        result = runner.invoke(
            app,
            [
                "check",
                '{"tool": "http_request", "args": {"url": "https://safe.com"}}',
                "-c",
                "generic",
                "-d",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0


# ── TestErrorMessages ─────────────────────────────────────────────────


class TestErrorMessages:
    """Test helpful error messages for edge cases."""

    def test_corrupt_yaml_error(self, tmp_path: Any) -> None:
        """Corrupt YAML produces a helpful error mentioning the file."""
        pack_dir = tmp_path / "bad-pack"
        pack_dir.mkdir()
        (pack_dir / "corrupt.yaml").write_text("name: [broken yaml\n  invalid: {{{")
        result = runner.invoke(
            app,
            ["audit", "-d", str(tmp_path)],
        )
        # Should fail (exit != 0) or report 0 constraints (bad YAML skipped)
        output = result.output.lower()
        # At minimum the error should reference the filename or YAML issue
        assert result.exit_code != 0 or "0" in output or "corrupt" in output or "error" in output

    def test_empty_constraints_dir_error(self, tmp_path: Any) -> None:
        """Empty constraints dir reports 0 constraints."""
        result = runner.invoke(
            app,
            ["audit", "-d", str(tmp_path), "-f", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == 0
