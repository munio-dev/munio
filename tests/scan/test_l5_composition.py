"""Tests for L5 Compositional Analysis (P/U/S taint flow)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from munio.scan.layers.composition_taxonomy import (
    _COMBO_INDEX,
    _DANGEROUS_COMBOS,
    _KNOWN_TOOLS,
    _TOXIC_FLOW_RULES,
    Capability,
    ToolRole,
    classify_tool,
    find_known_combo,
    match_toxic_rules,
)
from munio.scan.layers.l5_composition import L5CompositionAnalyzer
from munio.scan.models import AttackType, FindingSeverity, Layer, ToolDefinition

from .conftest import make_tool

CORPUS_PATH = Path(__file__).parent / "mcp_vulnerability_corpus.json"


def _make_tool_with_annotations(
    name: str,
    description: str = "test",
    annotations: dict[str, Any] | None = None,
    server_name: str = "test-server",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    """Create a ToolDefinition with optional annotations."""
    return ToolDefinition(
        name=name,
        description=description,
        annotations=annotations,
        server_name=server_name,
        input_schema=input_schema or {},
    )


# ── TestToolClassification ───────────────────────────────────────────


class TestToolClassification:
    """Tests for classify_tool() — known taxonomy + heuristics."""

    @pytest.mark.parametrize(
        ("tool_name", "expected_role"),
        [
            ("read_file", ToolRole.P),
            ("write_file", ToolRole.S),
            ("send_email", ToolRole.S),
            ("fetch_url", ToolRole.U),
            ("execute_command", ToolRole.P | ToolRole.S),
            ("http_request", ToolRole.U | ToolRole.S),
            ("read_email", ToolRole.P | ToolRole.U),
            ("database_query", ToolRole.P),
            ("secrets_manager_read", ToolRole.P),
            ("git_push", ToolRole.S),
        ],
    )
    def test_known_tool_role(self, tool_name: str, expected_role: ToolRole) -> None:
        """Known tools from taxonomy are classified with correct roles."""
        tool = make_tool(name=tool_name)
        role, _ = classify_tool(tool)
        assert role == expected_role

    @pytest.mark.parametrize(
        ("tool_name", "expected_cap"),
        [
            ("read_file", Capability.FILE_READ),
            ("send_email", Capability.EMAIL_SEND),
            ("execute_command", Capability.CODE_EXEC),
            ("secrets_manager_read", Capability.CREDENTIAL_READ),
            ("fetch_url", Capability.FETCH_UNTRUSTED),
            ("webhook_send", Capability.NETWORK_EXFIL),
            ("database_query", Capability.DB_READ),
            ("git_push", Capability.VCS_PUSH),
        ],
    )
    def test_known_tool_capabilities(self, tool_name: str, expected_cap: Capability) -> None:
        """Known tools have expected capabilities."""
        tool = make_tool(name=tool_name)
        _, caps = classify_tool(tool)
        assert expected_cap in caps

    @pytest.mark.parametrize(
        ("tool_name", "expected_role"),
        [
            ("read_file_contents", ToolRole.P),
            ("send_email_notification", ToolRole.S),
            ("fetch_url_data", ToolRole.U),
            ("webhook_dispatcher", ToolRole.S),
        ],
    )
    def test_unknown_tool_name_keyword_heuristic(
        self, tool_name: str, expected_role: ToolRole
    ) -> None:
        """Unknown tools classified by compound name keywords."""
        tool = make_tool(name=tool_name)
        role, _ = classify_tool(tool)
        assert role & expected_role, f"{tool_name} should have role {expected_role}, got {role}"

    def test_case_insensitive_classification(self) -> None:
        """Tool names are case-insensitive for taxonomy lookup."""
        tool = make_tool(name="Read_File")
        role, _ = classify_tool(tool)
        assert role == ToolRole.P

    def test_hyphen_underscore_equivalent(self) -> None:
        """read-file and read_file both match known taxonomy."""
        tool = make_tool(name="read-file")
        role, _ = classify_tool(tool)
        assert role == ToolRole.P

    def test_no_match_returns_none_role(self) -> None:
        """Tool with no matching heuristic gets NONE role."""
        tool = make_tool(name="my_opaque_helper", description="Does things")
        role, caps = classify_tool(tool)
        assert role == ToolRole.NONE
        assert len(caps) == 0

    def test_annotation_destructive_adds_sink_not_code_exec(self) -> None:
        """destructiveHint=True adds S role but NOT CODE_EXEC capability."""
        tool = _make_tool_with_annotations(
            name="my_custom_action",
            annotations={"destructiveHint": True},
        )
        role, caps = classify_tool(tool)
        assert role & ToolRole.S
        # destructiveHint should NOT add CODE_EXEC (a delete_user API is not code exec)
        assert Capability.CODE_EXEC not in caps

    def test_annotation_readonly_does_not_remove_sink(self) -> None:
        """readOnlyHint=True does NOT remove S — annotation may be from malicious server."""
        tool = _make_tool_with_annotations(
            name="execute_command",
            annotations={"readOnlyHint": True},
        )
        role, _ = classify_tool(tool)
        assert role & ToolRole.S

    def test_description_keyword_classification_s(self) -> None:
        """Tool classified as S by description when name is ambiguous."""
        tool = make_tool(
            name="my_tool",
            description="Sends data to external webhook endpoint",
        )
        role, _ = classify_tool(tool)
        assert role & ToolRole.S

    def test_description_keyword_classification_p(self) -> None:
        """Tool classified as P by description keywords."""
        tool = make_tool(
            name="my_reader",
            description="Reads from internal document store and returns file contents",
        )
        role, _ = classify_tool(tool)
        assert role & ToolRole.P

    def test_description_keyword_classification_u(self) -> None:
        """Tool classified as U by description keywords."""
        tool = make_tool(
            name="my_fetcher",
            description="Fetches data from arbitrary url provided by user",
        )
        role, _ = classify_tool(tool)
        assert role & ToolRole.U

    def test_parameter_name_classification(self) -> None:
        """Tool classified by parameter names in input_schema."""
        tool = _make_tool_with_annotations(
            name="my_dispatch",
            input_schema={
                "type": "object",
                "properties": {"recipient": {"type": "string"}, "body": {"type": "string"}},
            },
        )
        role, _ = classify_tool(tool)
        assert role & ToolRole.S

    def test_parameter_name_classification_p(self) -> None:
        """Tool classified as P by parameter names."""
        tool = _make_tool_with_annotations(
            name="my_reader",
            input_schema={
                "type": "object",
                "properties": {"file_path": {"type": "string"}},
            },
        )
        role, _ = classify_tool(tool)
        assert role & ToolRole.P

    def test_default_capability_inference_from_role(self) -> None:
        """When role is set by desc/params but no caps, default caps are inferred."""
        tool = make_tool(
            name="my_sender",
            description="Sends data to external service",
        )
        role, caps = classify_tool(tool)
        assert role & ToolRole.S
        # Default sink cap should be inferred
        assert len(caps) > 0

    def test_verb_aware_secret_set(self) -> None:
        """set_secret gets S + CLOUD_WRITE, NOT CREDENTIAL_READ."""
        tool = make_tool(name="set_secret")
        role, caps = classify_tool(tool)
        assert role & ToolRole.S
        assert Capability.CREDENTIAL_READ not in caps
        assert Capability.CLOUD_WRITE in caps

    def test_verb_aware_delete_secret(self) -> None:
        """delete_secret gets S + CLOUD_WRITE, NOT CREDENTIAL_READ."""
        tool = make_tool(name="delete_secret")
        role, caps = classify_tool(tool)
        assert role & ToolRole.S
        assert Capability.CREDENTIAL_READ not in caps
        assert Capability.CLOUD_WRITE in caps

    def test_verb_aware_get_secret_is_read(self) -> None:
        """get_secret is P + CREDENTIAL_READ, NOT FETCH_UNTRUSTED."""
        tool = make_tool(name="get_secret")
        role, caps = classify_tool(tool)
        assert role & ToolRole.P
        assert Capability.CREDENTIAL_READ in caps
        # "get" short keyword must NOT add FETCH_UNTRUSTED when source cap present
        assert Capability.FETCH_UNTRUSTED not in caps

    # Short keyword matching
    @pytest.mark.parametrize(
        ("tool_name", "expected_role", "expected_cap"),
        [
            ("query", ToolRole.P, Capability.DB_READ),
            ("insert_record", ToolRole.S, Capability.DB_WRITE),
            ("run_container", ToolRole.S, Capability.CODE_EXEC),
            ("deploy_function", ToolRole.S, Capability.CLOUD_WRITE),
            ("search_web", ToolRole.U, Capability.FETCH_UNTRUSTED),
            ("execute_js", ToolRole.S, Capability.CODE_EXEC),
            # FN fixes
            ("execute_sql", ToolRole.P, Capability.DB_READ),
            ("git_checkout", ToolRole.P, Capability.CODE_READ),
            ("list_channels", ToolRole.P, Capability.COMMS_READ),
            ("add_reaction", ToolRole.S, Capability.COMMS_SEND),
            ("list_folders", ToolRole.P, Capability.FILE_READ),
            ("move_to_folder", ToolRole.S, Capability.FILE_WRITE),
            ("list_containers", ToolRole.P, Capability.SYSTEM_READ),
            # FP fixes — verb prefix + noun mapping
            ("create_directory", ToolRole.S, Capability.FILE_WRITE),
            ("rotate_secret", ToolRole.S, Capability.CLOUD_WRITE),
            ("update_database", ToolRole.S, Capability.DB_WRITE),
            ("reset_password", ToolRole.S, Capability.CLOUD_WRITE),
        ],
    )
    def test_expanded_keywords_catch_real_world_tools(
        self, tool_name: str, expected_role: ToolRole, expected_cap: Capability
    ) -> None:
        """Expanded keywords correctly classify common real-world MCP tool names."""
        tool = make_tool(name=tool_name)
        role, caps = classify_tool(tool)
        assert role & expected_role, f"{tool_name}: expected {expected_role}, got {role}"
        assert expected_cap in caps, f"{tool_name}: expected {expected_cap} in {caps}"

    def test_triple_role_tool_classification(self) -> None:
        """cloud_function_invoke has P|U|S role (from taxonomy)."""
        tool = make_tool(name="cloud_function_invoke")
        role, caps = classify_tool(tool)
        assert role & ToolRole.P
        assert role & ToolRole.U
        assert role & ToolRole.S
        assert Capability.SYSTEM_READ in caps
        assert Capability.FETCH_UNTRUSTED in caps
        assert Capability.CLOUD_WRITE in caps

    def test_set_env_var_is_sink_not_system_read(self) -> None:
        """set_env_var should be S with CODE_EXEC, not SYSTEM_READ."""
        tool = make_tool(name="set_env_var")
        role, caps = classify_tool(tool)
        assert role & ToolRole.S
        assert Capability.CODE_EXEC in caps
        assert Capability.SYSTEM_READ not in caps

    def test_get_file_info_no_fetch_untrusted(self) -> None:
        """get_file_info has FILE_READ, NOT spurious FETCH_UNTRUSTED from 'get'."""
        tool = make_tool(name="get_file_info")
        role, caps = classify_tool(tool)
        assert role & ToolRole.P
        assert Capability.FILE_READ in caps
        assert Capability.FETCH_UNTRUSTED not in caps

    def test_get_weather_unclassified(self) -> None:
        """get_weather — 'get' alone no longer triggers FETCH_UNTRUSTED (too many FP)."""
        tool = make_tool(name="get_weather")
        role, _caps = classify_tool(tool)
        # 'get' removed from short keywords — get_weather needs description context
        assert role == ToolRole.NONE

    def test_malformed_input_schema_properties(self) -> None:
        """Non-dict properties in input_schema doesn't crash."""
        tool = _make_tool_with_annotations(
            name="my_tool",
            input_schema={"properties": "not a dict"},
        )
        role, _ = classify_tool(tool)
        # Should not crash, role based on other heuristics
        assert isinstance(role, ToolRole)


# ── TestToxicFlowRules ───────────────────────────────────────────────


class TestToxicFlowRules:
    """Tests for match_toxic_rules() — capability category matching."""

    @pytest.mark.parametrize(
        ("source_caps", "sink_caps", "expected_risk"),
        [
            ({Capability.CREDENTIAL_READ}, {Capability.NETWORK_EXFIL}, "CRITICAL"),
            ({Capability.FILE_READ}, {Capability.EMAIL_SEND}, "CRITICAL"),
            ({Capability.FETCH_UNTRUSTED}, {Capability.CODE_EXEC}, "CRITICAL"),
            ({Capability.FETCH_UNTRUSTED}, {Capability.FILE_WRITE}, "HIGH"),
            ({Capability.FETCH_UNTRUSTED}, {Capability.DB_WRITE}, "HIGH"),
            ({Capability.COMMS_READ}, {Capability.NETWORK_EXFIL}, "HIGH"),
            ({Capability.CREDENTIAL_READ}, {Capability.CODE_EXEC}, "CRITICAL"),
            ({Capability.DB_READ}, {Capability.DB_WRITE}, "HIGH"),
            ({Capability.FILE_READ}, {Capability.FILE_WRITE}, "MEDIUM"),
        ],
    )
    def test_rule_match(
        self,
        source_caps: set[Capability],
        sink_caps: set[Capability],
        expected_risk: str,
    ) -> None:
        """Toxic flow rules match expected capability combinations."""
        matched = match_toxic_rules(frozenset(source_caps), frozenset(sink_caps))
        assert len(matched) >= 1
        risks = {r.risk for r in matched}
        assert expected_risk in risks

    def test_no_match_returns_empty(self) -> None:
        """Non-matching capabilities return empty list."""
        matched = match_toxic_rules(
            frozenset({Capability.CODE_READ}),
            frozenset({Capability.FILE_WRITE}),
        )
        assert matched == []

    def test_source_only_no_match(self) -> None:
        """Having only source caps with empty sink caps returns no match."""
        matched = match_toxic_rules(
            frozenset({Capability.FILE_READ}),
            frozenset(),
        )
        assert matched == []

    def test_multiple_rules_can_match(self) -> None:
        """Multiple rules can match same capability set."""
        matched = match_toxic_rules(
            frozenset({Capability.CREDENTIAL_READ, Capability.FILE_READ}),
            frozenset({Capability.NETWORK_EXFIL, Capability.CODE_EXEC}),
        )
        assert len(matched) >= 2


# ── TestKnownCombos ──────────────────────────────────────────────────


class TestKnownCombos:
    """Tests for find_known_combo() and known combo database."""

    @pytest.mark.parametrize(
        ("source", "sink", "expected_risk"),
        [
            ("read_file", "send_email", "CRITICAL"),
            ("read_file", "http_request", "CRITICAL"),
            ("secrets_manager_read", "http_request", "CRITICAL"),
            ("fetch_url", "execute_command", "CRITICAL"),
            ("contacts_read", "send_email", "MEDIUM"),
            ("calendar_read", "http_request", "MEDIUM"),
        ],
    )
    def test_known_combo_risk_level(self, source: str, sink: str, expected_risk: str) -> None:
        """Known combos have correct risk levels from corpus."""
        combo = find_known_combo(source, sink)
        assert combo is not None
        assert combo.risk == expected_risk

    def test_unknown_combo_returns_none(self) -> None:
        """Non-dangerous pair returns None."""
        assert find_known_combo("list_directory", "calendar_create") is None

    def test_normalized_name_lookup(self) -> None:
        """Hyphen and case-insensitive lookup works."""
        combo = find_known_combo("Read-File", "Send-Email")
        assert combo is not None
        assert combo.risk == "CRITICAL"


# ── TestL5CompositionAnalyzer ────────────────────────────────────────


class TestL5CompositionAnalyzer:
    """Tests for L5CompositionAnalyzer.analyze()."""

    def test_empty_tools_no_findings(self) -> None:
        """Empty tool list produces no findings."""
        analyzer = L5CompositionAnalyzer()
        assert analyzer.analyze([]) == []

    def test_single_tool_no_findings(self) -> None:
        """Single tool cannot form composition."""
        analyzer = L5CompositionAnalyzer()
        assert analyzer.analyze([make_tool(name="read_file")]) == []

    def test_two_source_tools_no_sink(self) -> None:
        """Two P tools with no S produce no flow findings."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="a"),
                make_tool(name="list_directory", server_name="a"),
            ]
        )
        l5_flows = [f for f in findings if f.id in ("L5_001", "L5_002", "L5_003")]
        assert l5_flows == []

    def test_known_combo_produces_l5_001(self) -> None:
        """read_file + send_email produces L5_001 CRITICAL."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        assert len(l5_001) >= 1
        assert l5_001[0].severity == FindingSeverity.CRITICAL
        assert l5_001[0].tool_name == "send_email"
        assert "read_file" in l5_001[0].message
        assert l5_001[0].confidence == 0.95

    def test_l5_001_attack_type_data_exfil(self) -> None:
        """read_file→send_email (CWE-200) has DATA_EXFILTRATION attack_type."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        assert l5_001[0].attack_type == AttackType.DATA_EXFILTRATION

    def test_l5_001_attack_type_command_injection(self) -> None:
        """fetch_url→execute_command (CWE-94) has COMMAND_INJECTION attack_type."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="fetch_url", server_name="web"),
                make_tool(name="execute_command", server_name="sys"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        assert len(l5_001) >= 1
        assert l5_001[0].attack_type == AttackType.COMMAND_INJECTION

    def test_l5_001_attack_type_prompt_injection(self) -> None:
        """web_scrape→browser_fill_form (CWE-74) has PROMPT_INJECTION attack_type."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="web_scrape", server_name="web"),
                make_tool(name="browser_fill_form", server_name="browser"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        assert len(l5_001) >= 1
        assert l5_001[0].attack_type == AttackType.PROMPT_INJECTION

    def test_l5_001_no_counterexample(self) -> None:
        """Known combo findings should NOT misuse counterexample for citations."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        # counterexample is for concrete violation traces, not citations
        # real_world citation is in description field
        assert l5_001[0].counterexample is None
        assert "Real-world" in l5_001[0].description

    def test_toxic_rule_produces_l5_002(self) -> None:
        """Toxic flow rule match produces L5_002 (not a known combo)."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="docker_logs", server_name="docker"),
                make_tool(name="webhook_send", server_name="hooks"),
            ]
        )
        l5_002 = [f for f in findings if f.id == "L5_002"]
        assert len(l5_002) >= 1
        assert l5_002[0].confidence == 0.75

    def test_l5_002_attack_type_command_injection(self) -> None:
        """L5_002 with CODE_EXEC sink has COMMAND_INJECTION attack_type."""
        analyzer = L5CompositionAnalyzer()
        # docker_logs (P, SYSTEM_READ) → some CODE_EXEC tool not in combos
        # Use a heuristic-classified tool to avoid known combo dedup
        tool_src = make_tool(name="docker_logs", server_name="a")
        tool_snk = make_tool(name="run_container", server_name="b")
        findings = analyzer.analyze([tool_src, tool_snk])
        l5_002 = [f for f in findings if f.id == "L5_002"]
        code_exec_findings = [f for f in l5_002 if f.attack_type == AttackType.COMMAND_INJECTION]
        # If rule matches, attack_type should be COMMAND_INJECTION for CODE_EXEC sink
        if l5_002:
            assert len(code_exec_findings) >= 1

    def test_cross_server_produces_l5_003(self) -> None:
        """Source on server-A, sink on server-B produces L5_003."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs-server"),
                make_tool(name="send_email", server_name="email-server"),
            ]
        )
        l5_003 = [f for f in findings if f.id == "L5_003"]
        assert len(l5_003) >= 1
        assert "cross-server" in l5_003[0].message.lower()
        assert l5_003[0].confidence == 0.90

    def test_same_server_no_l5_003(self) -> None:
        """Source and sink on same server does NOT produce L5_003."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="same"),
                make_tool(name="send_email", server_name="same"),
            ]
        )
        l5_003 = [f for f in findings if f.id == "L5_003"]
        assert l5_003 == []

    def test_empty_server_name_no_l5_003(self) -> None:
        """Tools with empty server_name don't produce cross-server findings."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name=""),
                make_tool(name="send_email", server_name=""),
            ]
        )
        l5_003 = [f for f in findings if f.id == "L5_003"]
        assert l5_003 == []

    def test_lethal_trifecta_produces_l5_004(self) -> None:
        """P + U + S from distinct tools produces L5_004 CRITICAL."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="fetch_url", server_name="web"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        l5_004 = [f for f in findings if f.id == "L5_004"]
        assert len(l5_004) == 1
        assert l5_004[0].severity == FindingSeverity.CRITICAL
        assert "lethal trifecta" in l5_004[0].message.lower()
        assert l5_004[0].confidence == 0.80
        assert l5_004[0].location.startswith("trifecta:")

    def test_trifecta_requires_two_distinct_tools(self) -> None:
        """Single P|U|S tool + one other does NOT produce L5_004 if only 1 distinct name."""
        analyzer = L5CompositionAnalyzer()
        # cloud_function_invoke is P|U|S but we need 2+ distinct names
        # With only cloud_function_invoke and list_directory, all_names has 2 → trifecta can fire
        # But with ONLY cloud_function_invoke, all_names has 1 → no trifecta
        findings = analyzer.analyze(
            [
                make_tool(name="cloud_function_invoke", server_name="a"),
                make_tool(name="cloud_function_invoke", server_name="b"),
            ]
        )
        l5_004 = [f for f in findings if f.id == "L5_004"]
        assert l5_004 == [], "Single P|U|S tool duplicated should not trigger trifecta"

    def test_no_trifecta_without_u(self) -> None:
        """P + S without U does not produce L5_004."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        l5_004 = [f for f in findings if f.id == "L5_004"]
        assert l5_004 == []

    def test_all_findings_have_l5_layer(self) -> None:
        """All L5 findings have layer=L5_COMPOSITIONAL."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="fetch_url", server_name="web"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        for f in findings:
            assert f.layer == Layer.L5_COMPOSITIONAL

    def test_tool_name_is_sink(self) -> None:
        """Finding tool_name is the sink tool (SARIF compatible)."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        assert l5_001[0].tool_name == "send_email"

    def test_self_reference_excluded_known_combos(self) -> None:
        """Same tool on same server does not create a combo finding."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="http_request", server_name="web"),
                make_tool(name="list_directory", server_name="web"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        assert l5_001 == []

    def test_self_reference_excluded_toxic_rules(self) -> None:
        """Dual-role tool on same server is NOT both source and sink in L5_002."""
        analyzer = L5CompositionAnalyzer()
        # cloud_function_invoke is P|U|S — should not produce self-referential L5_002
        findings = analyzer.analyze(
            [
                make_tool(name="cloud_function_invoke", server_name="cloud"),
                make_tool(name="list_directory", server_name="fs"),
            ]
        )
        l5_002 = [f for f in findings if f.id == "L5_002"]
        for f in l5_002:
            # No finding should have same tool as both source and sink
            loc = f.location
            if "cloud_function_invoke" in loc:
                parts = loc.split(" -> ")
                src_part = parts[0] if len(parts) == 2 else ""
                snk_part = parts[1] if len(parts) == 2 else ""
                assert not (
                    "cloud_function_invoke" in src_part
                    and "cloud_function_invoke" in snk_part
                    and "cloud" in src_part
                    and "cloud" in snk_part
                ), "Self-referential L5_002 should not exist"

    def test_same_name_different_servers(self) -> None:
        """Same tool name on different servers CAN form a pair."""
        analyzer = L5CompositionAnalyzer()
        # http_request is U|S — on different servers it's a valid cross-server pair
        findings = analyzer.analyze(
            [
                make_tool(name="http_request", server_name="server-a"),
                make_tool(name="http_request", server_name="server-b"),
            ]
        )
        # Should not be excluded by self-reference (different servers)
        # May or may not produce findings depending on rule matching
        # At minimum, no crash
        assert isinstance(findings, list)

    def test_dual_role_tool_cross_server(self) -> None:
        """Dual-role tool on different servers can create findings."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="execute_command", server_name="server-a"),
                make_tool(name="webhook_send", server_name="server-b"),
            ]
        )
        l5_findings = [f for f in findings if f.id in ("L5_002", "L5_003")]
        assert len(l5_findings) >= 1

    def test_dedup_l5_001_blocks_l5_002(self) -> None:
        """Known combo pair reported as L5_001 is NOT also reported as L5_002."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        l5_002 = [f for f in findings if f.id == "L5_002"]
        assert len(l5_001) >= 1
        # The read_file→send_email pair should NOT appear in L5_002
        for f in l5_002:
            assert not ("read_file" in f.location and "send_email" in f.location), (
                "Known combo should not be duplicated as L5_002"
            )

    def test_fail_safe_per_phase(self) -> None:
        """If one analysis phase raises, other phases still produce findings."""
        analyzer = L5CompositionAnalyzer()
        with patch.object(
            L5CompositionAnalyzer, "_check_known_combos", side_effect=RuntimeError("boom")
        ):
            result = analyzer.analyze(
                [
                    make_tool(name="docker_logs", server_name="docker"),
                    make_tool(name="webhook_send", server_name="hooks"),
                ]
            )
        # Known combos failed, but toxic rules should still produce findings
        l5_002 = [f for f in result if f.id == "L5_002"]
        assert len(l5_002) >= 1

    def test_location_format(self) -> None:
        """Finding location uses source:name@server -> sink:name@server format."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="read_file", server_name="fs"),
                make_tool(name="send_email", server_name="email"),
            ]
        )
        l5_001 = [f for f in findings if f.id == "L5_001"]
        assert "source:read_file@fs" in l5_001[0].location
        assert "sink:send_email@email" in l5_001[0].location

    def test_layer_property(self) -> None:
        """Analyzer layer property returns L5_COMPOSITIONAL."""
        analyzer = L5CompositionAnalyzer()
        assert analyzer.layer == Layer.L5_COMPOSITIONAL

    # Unclassifiable tool detection
    def test_unclassifiable_tool_produces_l5_005(self) -> None:
        """Tool that can't be classified produces L5_005 INFO finding."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="my_opaque_tool", server_name="mystery"),
                make_tool(name="read_file", server_name="fs"),
            ]
        )
        l5_005 = [f for f in findings if f.id == "L5_005"]
        assert len(l5_005) >= 1
        assert l5_005[0].tool_name == "my_opaque_tool"
        assert l5_005[0].severity == FindingSeverity.INFO
        assert l5_005[0].confidence == 0.30

    def test_all_s_tools_no_flow_findings(self) -> None:
        """Only S tools (no P/U) produce no flow findings."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="write_file", server_name="fs"),
                make_tool(name="send_email", server_name="email"),
                make_tool(name="database_write", server_name="db"),
            ]
        )
        flow_findings = [f for f in findings if f.id in ("L5_001", "L5_002", "L5_003", "L5_004")]
        assert flow_findings == []

    def test_all_u_tools_no_trifecta(self) -> None:
        """Only U tools (no P/S) don't produce trifecta."""
        analyzer = L5CompositionAnalyzer()
        findings = analyzer.analyze(
            [
                make_tool(name="fetch_url", server_name="web"),
                make_tool(name="web_scrape", server_name="scraper"),
                make_tool(name="dns_resolve", server_name="dns"),
            ]
        )
        l5_004 = [f for f in findings if f.id == "L5_004"]
        assert l5_004 == []


# ── TestCorpusIntegration ────────────────────────────────────────────


class TestCorpusIntegration:
    """Tests verifying alignment with vulnerability corpus data."""

    @pytest.fixture
    def corpus(self) -> dict[str, Any]:
        return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))

    def test_all_corpus_combos_covered(self, corpus: dict[str, Any]) -> None:
        """All 26 dangerous combos from corpus part4 are in _DANGEROUS_COMBOS."""
        corpus_combos = corpus["part4_dangerous_combinations"]
        for cc in corpus_combos:
            combo = find_known_combo(cc["source"], cc["sink"])
            assert combo is not None, f"Missing combo: {cc['source']} -> {cc['sink']}"
            assert combo.risk == cc["risk"]

    def test_all_corpus_taxonomy_tools_covered(self, corpus: dict[str, Any]) -> None:
        """All 50 tools from corpus part3 are in _KNOWN_TOOLS."""
        taxonomy_tools = corpus["part3_pus_taxonomy"]["tools"]
        for tt in taxonomy_tools:
            normalized = tt["name"].lower().replace("-", "_")
            assert normalized in _KNOWN_TOOLS, f"Missing tool: {tt['name']}"

    @pytest.mark.parametrize(
        ("tool_name", "expected_p"),
        [
            ("read_file", True),
            ("database_query", True),
            ("secrets_manager_read", True),
            ("write_file", False),
            ("send_email", False),
        ],
    )
    def test_corpus_p_flag_matches(self, tool_name: str, expected_p: bool) -> None:
        """Tools marked P in corpus are classified with ToolRole.P."""
        role, _ = classify_tool(make_tool(name=tool_name))
        has_p = bool(role & ToolRole.P)
        assert has_p == expected_p, f"{tool_name}: expected P={expected_p}, got P={has_p}"

    @pytest.mark.parametrize(
        ("tool_name", "expected_s"),
        [
            ("write_file", True),
            ("send_email", True),
            ("execute_command", True),
            ("read_file", False),
            ("list_directory", False),
        ],
    )
    def test_corpus_s_flag_matches(self, tool_name: str, expected_s: bool) -> None:
        """Tools marked S in corpus are classified with ToolRole.S."""
        role, _ = classify_tool(make_tool(name=tool_name))
        has_s = bool(role & ToolRole.S)
        assert has_s == expected_s, f"{tool_name}: expected S={expected_s}, got S={has_s}"

    def test_multi_server_real_world_scenario(self) -> None:
        """Simulate real setup: filesystem + email + web servers."""
        analyzer = L5CompositionAnalyzer()
        tools = [
            make_tool(name="read_file", server_name="filesystem"),
            make_tool(name="list_directory", server_name="filesystem"),
            make_tool(name="send_email", server_name="gmail"),
            make_tool(name="read_email", server_name="gmail"),
            make_tool(name="fetch_url", server_name="web"),
            make_tool(name="http_request", server_name="web"),
        ]
        findings = analyzer.analyze(tools)

        l5_001 = [f for f in findings if f.id == "L5_001"]
        assert len(l5_001) >= 2

        l5_003 = [f for f in findings if f.id == "L5_003"]
        assert len(l5_003) >= 1

        l5_004 = [f for f in findings if f.id == "L5_004"]
        assert len(l5_004) == 1


# ── TestDataIntegrity ────────────────────────────────────────────────


class TestDataIntegrity:
    """Verify internal data consistency."""

    def test_combo_index_matches_combos(self) -> None:
        """_COMBO_INDEX has one entry per _DANGEROUS_COMBOS element."""
        assert len(_COMBO_INDEX) == len(_DANGEROUS_COMBOS)

    def test_all_combos_have_valid_risk(self) -> None:
        """All dangerous combos have valid risk level."""
        for combo in _DANGEROUS_COMBOS:
            assert combo.risk in ("CRITICAL", "HIGH", "MEDIUM")

    def test_all_rules_have_valid_risk(self) -> None:
        """All toxic flow rules have valid risk level."""
        for rule in _TOXIC_FLOW_RULES:
            assert rule.risk in ("CRITICAL", "HIGH", "MEDIUM")

    def test_known_tools_have_non_none_role(self) -> None:
        """All known tools have at least one role set."""
        for name, (role, caps) in _KNOWN_TOOLS.items():
            assert role != ToolRole.NONE, f"{name} has NONE role"
            assert len(caps) > 0, f"{name} has empty capabilities"

    def test_toxic_rules_have_nonempty_caps(self) -> None:
        """All toxic flow rules have non-empty source and sink caps."""
        for rule in _TOXIC_FLOW_RULES:
            assert len(rule.source_caps) > 0
            assert len(rule.sink_caps) > 0

    def test_combo_index_uses_normalized_keys(self) -> None:
        """_COMBO_INDEX keys are normalized (lowercase, underscores)."""
        for src, snk in _COMBO_INDEX:
            assert src == src.lower().replace("-", "_"), f"Non-normalized key: {src}"
            assert snk == snk.lower().replace("-", "_"), f"Non-normalized key: {snk}"
