"""Tests for SARIF 2.1.0 output builder."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from munio.scan.models import (
    AttackType,
    Finding,
    FindingSeverity,
    Layer,
    ScanResult,
)
from munio.scan.sarif import (
    _MAX_RESULTS,
    _confidence_to_precision,
    _fingerprint,
    _severity_to_sarif,
    scan_result_to_sarif,
)


def _make_finding(
    finding_id: str = "L1_001",
    layer: Layer = Layer.L1_SCHEMA,
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    tool_name: str = "test_tool",
    message: str = "Test finding",
    description: str = "",
    attack_type: AttackType | None = None,
    cwe: str | None = None,
    location: str = "",
    confidence: float = 1.0,
) -> Finding:
    return Finding(
        id=finding_id,
        layer=layer,
        severity=severity,
        tool_name=tool_name,
        message=message,
        description=description,
        attack_type=attack_type,
        cwe=cwe,
        location=location,
        confidence=confidence,
    )


def _make_scan_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        scan_id="scan_test123",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings=findings or [],
    )


# ── TestSarifStructure ────────────────────────────────────────────────


class TestSarifStructure:
    """Basic SARIF 2.1.0 structure validation."""

    def test_empty_result_valid_sarif(self) -> None:
        """Empty ScanResult produces valid SARIF with empty results."""
        sarif = scan_result_to_sarif(_make_scan_result())
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_tool_driver_name(self) -> None:
        """Tool driver name is munio."""
        sarif = scan_result_to_sarif(_make_scan_result())
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "munio"

    def test_tool_driver_has_version(self) -> None:
        """Tool driver has a version string."""
        sarif = scan_result_to_sarif(_make_scan_result())
        assert isinstance(sarif["runs"][0]["tool"]["driver"]["version"], str)
        assert len(sarif["runs"][0]["tool"]["driver"]["version"]) > 0

    def test_tool_driver_has_info_uri(self) -> None:
        """Tool driver has informationUri."""
        sarif = scan_result_to_sarif(_make_scan_result())
        assert "informationUri" in sarif["runs"][0]["tool"]["driver"]

    def test_single_finding_produces_one_result_and_rule(self) -> None:
        """Single finding produces 1 result and 1 rule."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding()]))
        assert len(sarif["runs"][0]["results"]) == 1
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1

    def test_multiple_findings_same_id_one_rule(self) -> None:
        """Multiple findings with same ID produce 1 rule, N results."""
        findings = [
            _make_finding(finding_id="L1_001", tool_name="tool_a"),
            _make_finding(finding_id="L1_001", tool_name="tool_b"),
        ]
        sarif = scan_result_to_sarif(_make_scan_result(findings))
        assert len(sarif["runs"][0]["results"]) == 2
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1

    def test_multiple_findings_different_ids(self) -> None:
        """Different finding IDs produce separate rules."""
        findings = [
            _make_finding(finding_id="L1_001"),
            _make_finding(finding_id="L2_001"),
        ]
        sarif = scan_result_to_sarif(_make_scan_result(findings))
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 2
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert rule_ids == {"L1_001", "L2_001"}


# ── TestSeverityMapping ───────────────────────────────────────────────


class TestSeverityMapping:
    """Severity → SARIF level + security-severity mapping."""

    @pytest.mark.parametrize(
        ("severity", "expected_level", "expected_sec_sev"),
        [
            (FindingSeverity.CRITICAL, "error", "9.5"),
            (FindingSeverity.HIGH, "error", "8.0"),
            (FindingSeverity.MEDIUM, "warning", "5.5"),
            (FindingSeverity.LOW, "note", "3.0"),
            (FindingSeverity.INFO, "note", "1.0"),
        ],
    )
    def test_severity_mapping(
        self,
        severity: FindingSeverity,
        expected_level: str,
        expected_sec_sev: str,
    ) -> None:
        """FindingSeverity maps to correct SARIF level and security-severity."""
        level, sec_sev = _severity_to_sarif(severity)
        assert level == expected_level
        assert sec_sev == expected_sec_sev

    @pytest.mark.parametrize(
        ("severity", "expected_level"),
        [
            (FindingSeverity.CRITICAL, "error"),
            (FindingSeverity.HIGH, "error"),
            (FindingSeverity.MEDIUM, "warning"),
            (FindingSeverity.LOW, "note"),
            (FindingSeverity.INFO, "note"),
        ],
    )
    def test_result_level(self, severity: FindingSeverity, expected_level: str) -> None:
        """SARIF result has correct level for each severity."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(severity=severity)]))
        assert sarif["runs"][0]["results"][0]["level"] == expected_level

    def test_result_has_security_severity_property(self) -> None:
        """SARIF result has security-severity in properties."""
        sarif = scan_result_to_sarif(
            _make_scan_result([_make_finding(severity=FindingSeverity.CRITICAL)])
        )
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["security-severity"] == "9.5"


# ── TestRuleGeneration ────────────────────────────────────────────────


class TestRuleGeneration:
    """Rule deduplication and properties."""

    def test_rule_has_short_description(self) -> None:
        """Rule shortDescription includes layer name."""
        sarif = scan_result_to_sarif(
            _make_scan_result([_make_finding(finding_id="L1_001", layer=Layer.L1_SCHEMA)])
        )
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "L1_SCHEMA" in rule["shortDescription"]["text"]

    def test_rule_has_full_description(self) -> None:
        """Rule fullDescription uses finding description."""
        sarif = scan_result_to_sarif(
            _make_scan_result([_make_finding(description="Detailed explanation")])
        )
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["fullDescription"]["text"] == "Detailed explanation"

    def test_rule_default_full_description(self) -> None:
        """Rule fallback fullDescription when finding has no description."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(description="")]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "L1_001" in rule["fullDescription"]["text"]

    def test_rule_with_cwe_has_relationships(self) -> None:
        """Rule with CWE has relationships pointing to CWE taxonomy."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(cwe="CWE-200")]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "relationships" in rule
        rel = rule["relationships"][0]
        assert rel["target"]["id"] == "CWE-200"
        assert rel["target"]["toolComponent"]["name"] == "CWE"

    def test_rule_without_cwe_no_relationships(self) -> None:
        """Rule without CWE has no relationships."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(cwe=None)]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "relationships" not in rule

    def test_rule_with_attack_type_has_tag(self) -> None:
        """Rule with attack_type has type name in tags."""
        sarif = scan_result_to_sarif(
            _make_scan_result([_make_finding(attack_type=AttackType.DATA_EXFILTRATION)])
        )
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "DATA_EXFILTRATION" in rule["properties"]["tags"]

    def test_rule_always_has_security_tag(self) -> None:
        """All rules have 'security' tag."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding()]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "security" in rule["properties"]["tags"]

    @pytest.mark.parametrize(
        ("confidence", "expected_precision"),
        [
            (0.95, "very-high"),
            (0.90, "very-high"),
            (0.80, "high"),
            (0.70, "high"),
            (0.60, "medium"),
            (0.50, "medium"),
            (0.40, "low"),
            (0.10, "low"),
        ],
    )
    def test_confidence_to_precision(self, confidence: float, expected_precision: str) -> None:
        """Confidence maps to correct SARIF precision label."""
        assert _confidence_to_precision(confidence) == expected_precision

    def test_rule_has_precision_property(self) -> None:
        """Rule properties include precision derived from confidence."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(confidence=0.95)]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["precision"] == "very-high"

    def test_result_references_rule_by_index(self) -> None:
        """Result ruleIndex matches the rule's position in rules array."""
        findings = [
            _make_finding(finding_id="L1_001"),
            _make_finding(finding_id="L2_001"),
        ]
        sarif = scan_result_to_sarif(_make_scan_result(findings))
        results = sarif["runs"][0]["results"]
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for res in results:
            assert rules[res["ruleIndex"]]["id"] == res["ruleId"]


# ── TestLocationMapping ───────────────────────────────────────────────


class TestLocationMapping:
    """Location and codeFlows generation."""

    def test_logical_location_fully_qualified_name(self) -> None:
        """Result has logicalLocations with fullyQualifiedName."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(tool_name="exec_cmd")]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert "logicalLocations" in loc
        assert loc["logicalLocations"][0]["kind"] == "module"
        assert "exec_cmd" in loc["logicalLocations"][0]["fullyQualifiedName"]

    def test_l5_finding_with_flow_location_has_code_flows(self) -> None:
        """L5 finding with source→sink location generates codeFlows."""
        finding = _make_finding(
            finding_id="L5_001",
            layer=Layer.L5_COMPOSITIONAL,
            location="source:read_file@fs-server -> sink:send_email@email-server",
        )
        sarif = scan_result_to_sarif(_make_scan_result([finding]))
        result = sarif["runs"][0]["results"][0]
        assert "codeFlows" in result
        thread_flow = result["codeFlows"][0]["threadFlows"][0]
        assert len(thread_flow["locations"]) == 2
        # Source step
        src = thread_flow["locations"][0]["location"]
        assert "read_file" in src["message"]["text"]
        assert "fs-server/read_file" in src["logicalLocations"][0]["fullyQualifiedName"]
        # Sink step
        snk = thread_flow["locations"][1]["location"]
        assert "send_email" in snk["message"]["text"]
        assert "email-server/send_email" in snk["logicalLocations"][0]["fullyQualifiedName"]

    def test_l5_finding_without_parseable_location_no_code_flows(self) -> None:
        """L5 finding without source→sink pattern has no codeFlows."""
        finding = _make_finding(
            finding_id="L5_004",
            layer=Layer.L5_COMPOSITIONAL,
            location="trifecta: P(2) + U(1) + S(3)",
        )
        sarif = scan_result_to_sarif(_make_scan_result([finding]))
        result = sarif["runs"][0]["results"][0]
        assert "codeFlows" not in result

    def test_non_l5_finding_no_code_flows(self) -> None:
        """Non-L5 findings never have codeFlows."""
        finding = _make_finding(layer=Layer.L1_SCHEMA, location="some location")
        sarif = scan_result_to_sarif(_make_scan_result([finding]))
        result = sarif["runs"][0]["results"][0]
        assert "codeFlows" not in result

    def test_location_with_server_in_flow(self) -> None:
        """Server name extracted from L5 location flows."""
        finding = _make_finding(
            finding_id="L5_003",
            layer=Layer.L5_COMPOSITIONAL,
            tool_name="http_request",
            location="source:git_diff@vcs -> sink:http_request@web",
        )
        sarif = scan_result_to_sarif(_make_scan_result([finding]))
        fqn = sarif["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0][
            "fullyQualifiedName"
        ]
        # Server name + tool name in the FQN
        assert fqn == "web/http_request"


# ── TestFingerprints ──────────────────────────────────────────────────


class TestFingerprints:
    """Fingerprint generation for deduplication."""

    def test_same_finding_same_fingerprint(self) -> None:
        """Identical findings produce identical fingerprints."""
        f1 = _make_finding(message="same msg")
        f2 = _make_finding(message="same msg")
        assert _fingerprint(f1) == _fingerprint(f2)

    def test_different_message_different_fingerprint(self) -> None:
        """Different messages produce different fingerprints."""
        f1 = _make_finding(message="message A")
        f2 = _make_finding(message="message B")
        assert _fingerprint(f1) != _fingerprint(f2)

    def test_fingerprint_is_hex_64(self) -> None:
        """Fingerprint is a 64-character hex string (SHA-256)."""
        fp = _fingerprint(_make_finding())
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_result_has_partial_fingerprints(self) -> None:
        """SARIF result includes partialFingerprints."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding()]))
        result = sarif["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert "proofScanFinding/v1" in result["partialFingerprints"]


# ── TestCWETaxonomy ───────────────────────────────────────────────────


class TestCWETaxonomy:
    """CWE taxonomy generation."""

    def test_finding_with_cwe_has_taxonomies(self) -> None:
        """Finding with CWE produces taxonomies array."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(cwe="CWE-200")]))
        assert "taxonomies" in sarif["runs"][0]
        tax = sarif["runs"][0]["taxonomies"][0]
        assert tax["name"] == "CWE"
        assert any(t["id"] == "CWE-200" for t in tax["taxa"])

    def test_no_cwe_no_taxonomies(self) -> None:
        """Findings without CWE produce no taxonomies."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(cwe=None)]))
        assert "taxonomies" not in sarif["runs"][0]

    def test_multiple_cwes_deduplicated(self) -> None:
        """Multiple findings with different CWEs appear in taxa list."""
        findings = [
            _make_finding(finding_id="L1_001", cwe="CWE-200"),
            _make_finding(finding_id="L2_001", cwe="CWE-94"),
            _make_finding(finding_id="L2_002", cwe="CWE-200"),  # duplicate
        ]
        sarif = scan_result_to_sarif(_make_scan_result(findings))
        taxa = sarif["runs"][0]["taxonomies"][0]["taxa"]
        taxa_ids = [t["id"] for t in taxa]
        assert "CWE-200" in taxa_ids
        assert "CWE-94" in taxa_ids
        assert taxa_ids.count("CWE-200") == 1  # deduplicated

    def test_unknown_cwe_uses_id_as_name(self) -> None:
        """Unknown CWE ID uses the ID itself as name fallback."""
        sarif = scan_result_to_sarif(_make_scan_result([_make_finding(cwe="CWE-999")]))
        taxa = sarif["runs"][0]["taxonomies"][0]["taxa"]
        assert taxa[0]["id"] == "CWE-999"
        assert taxa[0]["name"] == "CWE-999"


# ── TestResultCap ─────────────────────────────────────────────────────


class TestResultCap:
    """Result count limit."""

    def test_results_capped_at_max(self) -> None:
        """More than MAX_RESULTS findings are capped."""
        findings = [_make_finding(message=f"Finding {i}") for i in range(_MAX_RESULTS + 10)]
        sarif = scan_result_to_sarif(_make_scan_result(findings))
        assert len(sarif["runs"][0]["results"]) == _MAX_RESULTS


# ── TestEndToEnd ──────────────────────────────────────────────────────


class TestEndToEnd:
    """Integration tests with realistic findings."""

    def test_realistic_l5_finding(self) -> None:
        """Realistic L5 finding produces complete SARIF with codeFlows + CWE."""
        finding = Finding(
            id="L5_001",
            layer=Layer.L5_COMPOSITIONAL,
            severity=FindingSeverity.CRITICAL,
            tool_name="send_email",
            message="Known dangerous combination: read_file can flow to send_email",
            description="Real-world: Invariant Labs WhatsApp+SSH demo",
            attack_type=AttackType.DATA_EXFILTRATION,
            cwe="CWE-200",
            location="source:read_file@fs-server -> sink:send_email@email-server",
            confidence=0.95,
        )
        sarif = scan_result_to_sarif(_make_scan_result([finding]))

        # Verify full structure
        run = sarif["runs"][0]
        assert len(run["results"]) == 1
        assert len(run["tool"]["driver"]["rules"]) == 1

        # Rule
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["id"] == "L5_001"
        assert "DATA_EXFILTRATION" in rule["properties"]["tags"]
        assert rule["properties"]["precision"] == "very-high"
        assert "relationships" in rule

        # Result
        result = run["results"][0]
        assert result["level"] == "error"
        assert result["properties"]["security-severity"] == "9.5"
        assert "codeFlows" in result
        assert len(result["codeFlows"][0]["threadFlows"][0]["locations"]) == 2

        # Taxonomy
        assert "taxonomies" in run
        assert run["taxonomies"][0]["taxa"][0]["id"] == "CWE-200"

    def test_mixed_severities(self) -> None:
        """Mixed severity findings produce correct levels."""
        findings = [
            _make_finding(finding_id="L1_001", severity=FindingSeverity.CRITICAL),
            _make_finding(finding_id="L1_002", severity=FindingSeverity.LOW),
            _make_finding(finding_id="L2_001", severity=FindingSeverity.INFO),
        ]
        sarif = scan_result_to_sarif(_make_scan_result(findings))
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["error", "note", "note"]
