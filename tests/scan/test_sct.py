"""Tests for Safety Control Tampering (SCT) detection.

TDD: tests written first, implementation follows.
Covers: SAFETY_TAMPERING AttackType, SCT constraints, config-scan rules,
L3_020 static analysis, L5 toxic flows.
"""

from __future__ import annotations

from typing import Any

import pytest

from munio.scan.models import AttackType, ToolDefinition

# ── Phase 1: Foundation ──────────────────────────────────────────────


class TestSafetyTamperingAttackType:
    """SAFETY_TAMPERING must exist in AttackType enum."""

    def test_safety_tampering_enum_exists(self) -> None:
        assert hasattr(AttackType, "SAFETY_TAMPERING")

    def test_safety_tampering_value(self) -> None:
        assert AttackType.SAFETY_TAMPERING == 15

    def test_safety_tampering_in_all_types(self) -> None:
        names = [t.name for t in AttackType]
        assert "SAFETY_TAMPERING" in names


class TestSarifCwe346:
    """CWE-346 must be in SARIF CWE taxonomy."""

    def test_cwe_346_in_names(self) -> None:
        from munio.scan.sarif import _CWE_NAMES

        assert "CWE-346" in _CWE_NAMES
        assert _CWE_NAMES["CWE-346"] == "Origin Validation Error"


class TestSctRecommendations:
    """SCT recommendations must exist."""

    @pytest.mark.parametrize("check_id", ["SC_011", "SC_012", "SC_013", "L3_020"])
    def test_recommendation_exists(self, check_id: str) -> None:
        from munio.scan.recommendations import get_recommendation

        rec = get_recommendation(check_id)
        assert rec is not None
        assert len(rec.short) > 10


# ── Phase 2: Constraints ────────────────────────────────────────────


class TestSctConstraints:
    """SCT YAML constraints must load and block/allow correctly."""

    @pytest.fixture
    def guard(self) -> Any:
        from munio import Guard

        return Guard(constraints="generic")

    @pytest.fixture
    def openclaw_guard(self) -> Any:
        from munio import Guard

        return Guard(constraints="openclaw")

    @pytest.mark.parametrize(
        ("action", "field", "value", "should_block"),
        [
            # OpenClaw approval disabling
            ("exec.approvals.set", "ask", "off", True),
            ("exec.approvals.set", "ask", "false", True),
            ("exec.approvals.set", "ask", "no", True),
            ("exec.approvals.set", "ask", "on", False),
            ("exec.approvals.set", "ask", "always", False),
            # OpenClaw security mode
            ("exec.approvals.set", "security", "full", True),
            ("exec.approvals.set", "security", "bypass", True),
            ("exec.approvals.set", "security", "strict", False),
            # Sandbox escape — regex_deny on field: "*" checks all values
            ("config.patch", "config", "sandbox: off", True),
            ("config.patch", "config", "isolation: disabled", True),
            ("config.patch", "config", "host: gateway", True),
            ("config.patch", "config", "sandbox: on", False),
            # Gateway URL override — regex matches gatewayUrl in value
            ("config.patch", "target", "gatewayUrl", True),
            ("config.set", "url", "wss://evil.com/gateway", True),
            ("config.patch", "theme", "dark", False),
        ],
    )
    def test_openclaw_sct_constraint(
        self, openclaw_guard: Any, action: str, field: str, value: str, should_block: bool
    ) -> None:
        result = openclaw_guard.check({"tool": action, "args": {field: value}})
        assert result.allowed != should_block, (
            f"{action} {field}={value}: expected {'BLOCK' if should_block else 'ALLOW'}"
        )

    @pytest.mark.parametrize(
        ("action", "args", "should_warn"),
        [
            # Generic safety control tampering
            ("exec.approvals.set", {"mode": "off"}, True),
            ("security.set", {"level": "disabled"}, True),
            ("guardrails.disable", {"all": "off"}, True),
            # Safe actions
            ("file.read", {"path": "/tmp/safe.txt"}, False),
            ("user.search", {"query": "alice"}, False),
        ],
    )
    def test_generic_sct_constraint(
        self, guard: Any, action: str, args: dict[str, str], should_warn: bool
    ) -> None:
        result = guard.check({"tool": action, "args": args})
        if should_warn:
            assert len(result.violations) > 0
        # Note: generic SCT constraints use on_violation: warn, so allowed may still be True


# ── Phase 3: Config Scanner ─────────────────────────────────────────


class TestSctConfigScanner:
    """Config scanner must detect SCT patterns in server configs."""

    @pytest.mark.parametrize(
        ("env", "args", "expected_rule"),
        [
            # SC_011: Permissive approval defaults
            ({"APPROVAL_MODE": "off"}, [], "SC_011"),
            ({"AUTO_APPROVE": "true"}, [], "SC_011"),
            ({}, ["--no-approval"], "SC_011"),
            ({}, ["--skip-safety"], "SC_011"),
            # SC_012: WebSocket without origin validation
            ({}, [], "SC_012"),  # ws:// URL, no origin config
            # SC_013: Host mode execution
            ({"EXEC_HOST": "gateway"}, [], "SC_013"),
            ({"SANDBOX": "off"}, [], "SC_013"),
            ({}, ["--host-mode"], "SC_013"),
            ({}, ["--privileged"], "SC_013"),
        ],
    )
    def test_sct_config_finding(
        self, env: dict[str, str], args: list[str], expected_rule: str
    ) -> None:
        from munio.scan.config_scanner import _check_server

        server = _make_server_config(
            command="node",
            args=["server.js", *args],
            env=env,
            url="ws://remote-server:8080" if expected_rule == "SC_012" else None,
        )
        findings = _check_server("test-srv", server)
        rule_ids = [f.id for f in findings]
        assert expected_rule in rule_ids, f"Expected {expected_rule} in {rule_ids}"

    def test_sc_012_safe_with_origin_config(self) -> None:
        """WebSocket with ALLOWED_ORIGINS set should not trigger SC_012."""
        from munio.scan.config_scanner import _check_server

        server = _make_server_config(
            command="node",
            args=["server.js"],
            env={"ALLOWED_ORIGINS": "https://app.com"},
            url="ws://remote-server:8080",
        )
        findings = _check_server("test-srv", server)
        rule_ids = [f.id for f in findings]
        assert "SC_012" not in rule_ids


# ── Phase 4: L3 Static + L5 Composition ─────────────────────────────


class TestL3020SafetyToolDetection:
    """L3_020 must flag tools that modify safety controls."""

    @pytest.mark.parametrize(
        ("tool_name", "expected"),
        [
            ("exec.approvals.set", True),
            ("security.config", True),
            ("sandbox.settings", True),
            ("permission.set", True),
            ("guardrails.disable", True),
            ("file.read", False),
            ("user.search", False),
            ("http_request", False),
        ],
    )
    def test_l3_020_detection(self, tool_name: str, expected: bool) -> None:
        from munio.scan.layers.l3_static import L3StaticAnalyzer

        tool = _make_tool(tool_name, {"mode": {"type": "string", "enum": ["on", "off"]}})
        findings = L3StaticAnalyzer().analyze_tool(tool)
        l3_020_ids = [f.id for f in findings if f.id == "L3_020"]
        if expected:
            assert len(l3_020_ids) > 0, f"{tool_name} should trigger L3_020"
        else:
            assert len(l3_020_ids) == 0, f"{tool_name} should NOT trigger L3_020"


class TestSctToxicFlows:
    """L5 composition must detect SCT toxic flows."""

    @pytest.mark.parametrize(
        ("tool_names", "expected_attack_type"),
        [
            # fetch_untrusted → safety_config
            (["fetch_url", "exec.approvals.set"], AttackType.SAFETY_TAMPERING),
            # safety_config → code_exec
            (["exec.approvals.set", "execute_command"], AttackType.SAFETY_TAMPERING),
            # credential_read → safety_config
            (["read_credentials", "security.set"], AttackType.SAFETY_TAMPERING),
            # No SCT flow
            (["fetch_url", "file.read"], None),
        ],
    )
    def test_sct_toxic_flow(
        self, tool_names: list[str], expected_attack_type: AttackType | None
    ) -> None:
        from munio.scan.layers.l5_composition import L5CompositionAnalyzer

        tools = [_make_tool(name) for name in tool_names]
        findings = L5CompositionAnalyzer().analyze(tools)
        sct_findings = [f for f in findings if f.attack_type == AttackType.SAFETY_TAMPERING]
        if expected_attack_type is not None:
            assert len(sct_findings) > 0, f"Expected SAFETY_TAMPERING flow for {tool_names}"
        else:
            assert len(sct_findings) == 0, f"Unexpected SAFETY_TAMPERING flow for {tool_names}"


# ── Helpers ──────────────────────────────────────────────────────────


def _make_tool(name: str, properties: dict[str, Any] | None = None) -> ToolDefinition:
    """Create a minimal tool definition."""
    schema: dict[str, Any] = {"type": "object"}
    if properties:
        schema["properties"] = properties
    return ToolDefinition(
        name=name,
        description=f"Tool {name}",
        input_schema=schema,
    )


def _make_server_config(
    command: str = "node",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    url: str | None = None,
) -> dict[str, Any]:
    """Create a minimal MCP server config dict for config scanner tests."""
    config: dict[str, Any] = {"command": command}
    if args:
        config["args"] = args
    if env:
        config["env"] = env
    if url:
        config["url"] = url
    return config
