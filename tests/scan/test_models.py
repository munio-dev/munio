"""Tests for munio.scan.models."""

from __future__ import annotations

import json
from datetime import timezone

import pytest
from pydantic import ValidationError

from munio.scan.models import (
    AttackType,
    ConfigFileResult,
    ConfigPermissions,
    ConfigScanResult,
    DiscoveryError,
    Finding,
    FindingSeverity,
    Layer,
    MunioScanError,
    OutputFormat,
    ScanConnectionError,
    ScanResult,
    SchemaLoadError,
    ServerConfig,
    ServerScanResult,
    SkippedLayer,
    ToolDefinition,
)


class TestEnums:
    """Test enum definitions."""

    @pytest.mark.parametrize(
        ("enum_cls", "expected_count"),
        [
            (Layer, 10),
            (FindingSeverity, 5),
            (AttackType, 15),
            (OutputFormat, 4),
        ],
    )
    def test_enum_member_count(self, enum_cls: type, expected_count: int) -> None:
        """Verify enum member counts to detect accidental changes."""
        assert len(enum_cls) == expected_count

    def test_finding_severity_ordering(self) -> None:
        """CRITICAL < HIGH < MEDIUM < LOW < INFO (IntEnum ordering)."""
        assert FindingSeverity.CRITICAL < FindingSeverity.HIGH
        assert FindingSeverity.HIGH < FindingSeverity.MEDIUM
        assert FindingSeverity.MEDIUM < FindingSeverity.LOW
        assert FindingSeverity.LOW < FindingSeverity.INFO


class TestToolDefinition:
    """Test ToolDefinition model."""

    def test_minimal_creation(self) -> None:
        """Create with just a name."""
        tool = ToolDefinition(name="test")
        assert tool.name == "test"
        assert tool.description == ""
        assert tool.input_schema == {}
        assert tool.server_name == ""

    def test_full_creation(self) -> None:
        """Create with all fields."""
        tool = ToolDefinition(
            name="read_file",
            title="File Reader",
            description="Read a file",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            output_schema={"type": "object"},
            annotations={"readOnly": True},
            server_name="filesystem",
        )
        assert tool.name == "read_file"
        assert tool.title == "File Reader"

    def test_frozen(self) -> None:
        """Model is immutable."""
        tool = ToolDefinition(name="test")
        with pytest.raises(ValidationError):
            tool.name = "changed"  # type: ignore[misc]

    def test_extra_forbid(self) -> None:
        """Extra fields are rejected."""
        with pytest.raises(ValidationError):
            ToolDefinition(name="test", unknown_field="x")  # type: ignore[call-arg]


class TestServerConfig:
    """Test ServerConfig model."""

    def test_minimal(self) -> None:
        sc = ServerConfig(name="test", source="cursor")
        assert sc.name == "test"
        assert sc.command == ""
        assert sc.enabled is True

    def test_disabled(self) -> None:
        sc = ServerConfig(name="test", source="cursor", enabled=False)
        assert sc.enabled is False

    def test_with_env(self) -> None:
        sc = ServerConfig(name="s", source="t", env={"KEY": "VAL"})
        assert sc.env == {"KEY": "VAL"}


class TestFinding:
    """Test Finding model."""

    def test_defaults(self) -> None:
        f = Finding(
            id="L1_001",
            layer=Layer.L1_SCHEMA,
            severity=FindingSeverity.LOW,
            tool_name="test",
            message="msg",
        )
        assert f.confidence == 1.0
        assert f.cwe is None
        assert f.attack_type is None

    @pytest.mark.parametrize(
        "confidence",
        [-0.1, 1.1, 2.0],
    )
    def test_confidence_bounds(self, confidence: float) -> None:
        """Confidence must be 0.0-1.0."""
        with pytest.raises(ValidationError):
            Finding(
                id="L1_001",
                layer=Layer.L1_SCHEMA,
                severity=FindingSeverity.LOW,
                tool_name="test",
                message="msg",
                confidence=confidence,
            )

    def test_with_attack_type_and_cwe(self) -> None:
        f = Finding(
            id="L1_007",
            layer=Layer.L1_SCHEMA,
            severity=FindingSeverity.HIGH,
            tool_name="test",
            message="msg",
            attack_type=AttackType.SYSTEM_PROMPT_EXTRACTION,
            cwe="CWE-497",
        )
        assert f.attack_type == AttackType.SYSTEM_PROMPT_EXTRACTION
        assert f.cwe == "CWE-497"


class TestScanResult:
    """Test ScanResult model."""

    def test_empty(self) -> None:
        r = ScanResult(scan_id="test")
        assert r.total_findings == 0
        assert r.by_severity == {}
        assert r.by_layer == {}

    def test_computed_fields(self) -> None:
        findings = [
            Finding(
                id="a",
                layer=Layer.L1_SCHEMA,
                severity=FindingSeverity.HIGH,
                tool_name="t",
                message="m",
            ),
            Finding(
                id="b",
                layer=Layer.L1_SCHEMA,
                severity=FindingSeverity.LOW,
                tool_name="t",
                message="m",
            ),
            Finding(
                id="c",
                layer=Layer.L2_HEURISTIC,
                severity=FindingSeverity.HIGH,
                tool_name="t",
                message="m",
            ),
        ]
        r = ScanResult(scan_id="test", findings=findings)
        assert r.total_findings == 3
        assert r.by_severity == {"HIGH": 2, "LOW": 1}
        assert r.by_layer == {"L1_SCHEMA": 2, "L2_HEURISTIC": 1}


class TestScanResultJSON:
    """Test ScanResult JSON serialization."""

    def test_to_json_dict_includes_computed(self) -> None:
        """to_json_dict() includes computed properties."""
        findings = [
            Finding(
                id="a",
                layer=Layer.L1_SCHEMA,
                severity=FindingSeverity.HIGH,
                tool_name="t",
                message="m",
            ),
        ]
        r = ScanResult(scan_id="test", findings=findings)
        d = r.to_json_dict()
        assert d["total_findings"] == 1
        assert d["by_severity"] == {"HIGH": 1}
        assert d["by_layer"] == {"L1_SCHEMA": 1}

    def test_to_json_dict_roundtrippable(self) -> None:
        """to_json_dict() produces valid JSON-serializable dict."""

        r = ScanResult(scan_id="test")
        d = r.to_json_dict()
        s = json.dumps(d, default=str)
        parsed = json.loads(s)
        assert parsed["scan_id"] == "test"
        assert parsed["total_findings"] == 0


class TestOutputFormat:
    """Test OutputFormat enum."""

    def test_values_are_strings(self) -> None:
        """OutputFormat values are human-readable strings."""
        assert OutputFormat.TEXT == "text"
        assert OutputFormat.JSON == "json"

    def test_str_enum(self) -> None:
        """OutputFormat is a StrEnum."""
        assert isinstance(OutputFormat.TEXT, str)


class TestExceptions:
    """Test exception hierarchy."""

    @pytest.mark.parametrize(
        "exc_cls",
        [ScanConnectionError, DiscoveryError, SchemaLoadError],
    )
    def test_is_munio_scan_error(self, exc_cls: type) -> None:
        """All exceptions inherit from MunioScanError."""
        assert issubclass(exc_cls, MunioScanError)


class TestScanResultJSONAttackType:
    """Test to_json_dict() attack_type enum-to-name conversion."""

    def test_to_json_dict_converts_attack_type_to_name(self) -> None:
        """Findings with attack_type get converted to name strings in JSON dict."""
        findings = [
            Finding(
                id="a",
                layer=Layer.L1_SCHEMA,
                severity=FindingSeverity.HIGH,
                tool_name="t",
                message="m",
                attack_type=AttackType.COMMAND_INJECTION,
            ),
        ]
        r = ScanResult(scan_id="test", findings=findings)
        d = r.to_json_dict()
        f_list = d["findings"]
        assert isinstance(f_list, list)
        assert f_list[0]["attack_type"] == "COMMAND_INJECTION"
        assert f_list[0]["severity"] == "HIGH"
        assert f_list[0]["layer"] == "L1_SCHEMA"

    def test_to_json_dict_null_attack_type_untouched(self) -> None:
        """Findings without attack_type leave the field as None/null."""
        findings = [
            Finding(
                id="b",
                layer=Layer.L2_HEURISTIC,
                severity=FindingSeverity.MEDIUM,
                tool_name="t",
                message="m",
            ),
        ]
        r = ScanResult(scan_id="test", findings=findings)
        d = r.to_json_dict()
        f_list = d["findings"]
        assert isinstance(f_list, list)
        assert f_list[0]["attack_type"] is None

    @pytest.mark.parametrize(
        ("attack", "expected_name"),
        [
            (AttackType.PROMPT_INJECTION, "PROMPT_INJECTION"),
            (AttackType.DATA_EXFILTRATION, "DATA_EXFILTRATION"),
            (AttackType.PATH_TRAVERSAL, "PATH_TRAVERSAL"),
            (AttackType.SSRF, "SSRF"),
            (AttackType.RUG_PULL, "RUG_PULL"),
            (AttackType.CONFIG_INJECTION, "CONFIG_INJECTION"),
        ],
    )
    def test_to_json_dict_all_attack_types(self, attack: AttackType, expected_name: str) -> None:
        """Various attack types are correctly converted to name strings."""
        finding = Finding(
            id="x",
            layer=Layer.L3_STATIC,
            severity=FindingSeverity.CRITICAL,
            tool_name="t",
            message="m",
            attack_type=attack,
        )
        r = ScanResult(scan_id="test", findings=[finding])
        d = r.to_json_dict()
        assert d["findings"][0]["attack_type"] == expected_name


class TestSkippedLayer:
    """Test SkippedLayer model."""

    def test_creation(self) -> None:
        sl = SkippedLayer(
            layer=Layer.L4_Z3,
            reason="z3 not installed",
            install_hint="pip install z3-solver",
        )
        assert sl.layer == Layer.L4_Z3
        assert sl.reason == "z3 not installed"
        assert sl.install_hint == "pip install z3-solver"

    def test_frozen(self) -> None:
        sl = SkippedLayer(layer=Layer.L4_Z3, reason="r", install_hint="h")
        with pytest.raises(ValidationError):
            sl.reason = "changed"  # type: ignore[misc]

    def test_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            SkippedLayer(layer=Layer.L4_Z3, reason="r", install_hint="h", extra="x")  # type: ignore[call-arg]


class TestServerScanResult:
    """Test ServerScanResult model."""

    def test_defaults(self) -> None:
        ssr = ServerScanResult(server_name="test-server", source="config.json")
        assert ssr.tool_count == 0
        assert ssr.tools == []
        assert ssr.connected is True
        assert ssr.error is None
        assert ssr.schema_completeness_avg == 0.0

    def test_with_tools_and_error(self) -> None:
        tool = ToolDefinition(name="read_file")
        ssr = ServerScanResult(
            server_name="s",
            source="f",
            tool_count=1,
            tools=[tool],
            connected=False,
            error="connection refused",
            schema_completeness_avg=75.5,
        )
        assert ssr.tool_count == 1
        assert len(ssr.tools) == 1
        assert ssr.connected is False
        assert ssr.error == "connection refused"
        assert ssr.schema_completeness_avg == 75.5

    @pytest.mark.parametrize("value", [-1.0, 100.1, 200.0])
    def test_schema_completeness_bounds(self, value: float) -> None:
        """schema_completeness_avg must be 0.0-100.0."""
        with pytest.raises(ValidationError):
            ServerScanResult(server_name="s", source="f", schema_completeness_avg=value)

    def test_frozen(self) -> None:
        ssr = ServerScanResult(server_name="s", source="f")
        with pytest.raises(ValidationError):
            ssr.server_name = "changed"  # type: ignore[misc]


class TestConfigPermissions:
    """Test ConfigPermissions model."""

    def test_defaults(self) -> None:
        cp = ConfigPermissions(mode=0o644)
        assert cp.mode == 0o644
        assert cp.world_readable is False
        assert cp.world_writable is False

    def test_world_readable_writable(self) -> None:
        cp = ConfigPermissions(mode=0o777, world_readable=True, world_writable=True)
        assert cp.world_readable is True
        assert cp.world_writable is True

    def test_frozen(self) -> None:
        cp = ConfigPermissions(mode=0o644)
        with pytest.raises(ValidationError):
            cp.mode = 0o755  # type: ignore[misc]

    def test_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            ConfigPermissions(mode=0o644, extra_field="x")  # type: ignore[call-arg]


class TestConfigFileResult:
    """Test ConfigFileResult model."""

    def test_defaults(self) -> None:
        cfr = ConfigFileResult(path="/home/.cursor/mcp.json")
        assert cfr.path == "/home/.cursor/mcp.json"
        assert cfr.ide == "unknown"
        assert cfr.servers_count == 0
        assert cfr.findings == []
        assert cfr.permissions is None

    def test_with_findings_and_permissions(self) -> None:
        finding = Finding(
            id="CS_001",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.HIGH,
            tool_name="config",
            message="world-writable config",
        )
        perms = ConfigPermissions(mode=0o666, world_writable=True)
        cfr = ConfigFileResult(
            path="/p",
            ide="cursor",
            servers_count=3,
            findings=[finding],
            permissions=perms,
        )
        assert cfr.ide == "cursor"
        assert cfr.servers_count == 3
        assert len(cfr.findings) == 1
        assert cfr.permissions is not None
        assert cfr.permissions.world_writable is True

    def test_frozen(self) -> None:
        cfr = ConfigFileResult(path="/p")
        with pytest.raises(ValidationError):
            cfr.path = "/other"  # type: ignore[misc]


class TestConfigScanResult:
    """Test ConfigScanResult model."""

    def test_empty(self) -> None:
        csr = ConfigScanResult(scan_id="cs-1")
        assert csr.total_findings == 0
        assert csr.all_findings == []
        assert csr.by_severity == {}
        assert csr.elapsed_ms == 0.0

    def test_computed_properties_with_findings(self) -> None:
        """total_findings, all_findings, by_severity aggregate across files."""
        f1 = Finding(
            id="a",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.HIGH,
            tool_name="t",
            message="m1",
        )
        f2 = Finding(
            id="b",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.HIGH,
            tool_name="t",
            message="m2",
        )
        f3 = Finding(
            id="c",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.LOW,
            tool_name="t",
            message="m3",
        )
        file1 = ConfigFileResult(path="/a", findings=[f1, f2])
        file2 = ConfigFileResult(path="/b", findings=[f3])
        csr = ConfigScanResult(scan_id="cs-2", files=[file1, file2])

        assert csr.total_findings == 3
        assert len(csr.all_findings) == 3
        assert csr.by_severity == {"HIGH": 2, "LOW": 1}

    def test_all_findings_ordering(self) -> None:
        """all_findings preserves file order then finding order within files."""
        f1 = Finding(
            id="first",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.INFO,
            tool_name="t",
            message="m",
        )
        f2 = Finding(
            id="second",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.MEDIUM,
            tool_name="t",
            message="m",
        )
        file1 = ConfigFileResult(path="/a", findings=[f1])
        file2 = ConfigFileResult(path="/b", findings=[f2])
        csr = ConfigScanResult(scan_id="cs-3", files=[file1, file2])
        ids = [f.id for f in csr.all_findings]
        assert ids == ["first", "second"]

    def test_timestamp_auto_set(self) -> None:
        """timestamp is auto-populated."""

        csr = ConfigScanResult(scan_id="cs-4")
        assert csr.timestamp.tzinfo == timezone.utc

    def test_frozen(self) -> None:
        csr = ConfigScanResult(scan_id="cs-1")
        with pytest.raises(ValidationError):
            csr.scan_id = "changed"  # type: ignore[misc]


class TestScanResultWithSkippedLayers:
    """Test ScanResult with skipped layers and enabled layers."""

    def test_skipped_layers_tuple(self) -> None:
        sl = SkippedLayer(
            layer=Layer.L4_Z3, reason="not installed", install_hint="pip install z3-solver"
        )
        r = ScanResult(scan_id="t", skipped_layers=(sl,))
        assert len(r.skipped_layers) == 1
        assert r.skipped_layers[0].layer == Layer.L4_Z3

    def test_enabled_layers_frozenset(self) -> None:
        r = ScanResult(
            scan_id="t",
            enabled_layers=frozenset({Layer.L1_SCHEMA, Layer.L2_HEURISTIC}),
        )
        assert Layer.L1_SCHEMA in r.enabled_layers
        assert Layer.L4_Z3 not in r.enabled_layers


class TestLayerEnum:
    """Additional Layer enum tests."""

    @pytest.mark.parametrize(
        ("member", "value"),
        [
            (Layer.L0_CONFIG, 5),
            (Layer.L1_SCHEMA, 10),
            (Layer.L2_HEURISTIC, 20),
            (Layer.L2_CLASSIFIER, 25),
            (Layer.L2_MULTILINGUAL, 26),
            (Layer.L3_STATIC, 30),
            (Layer.L4_Z3, 40),
            (Layer.L5_COMPOSITIONAL, 50),
            (Layer.L6_FUZZING, 60),
            (Layer.L7_SOURCE, 70),
        ],
    )
    def test_layer_values(self, member: Layer, value: int) -> None:
        """Layer values are decade-spaced integers."""
        assert member.value == value

    def test_layer_ordering(self) -> None:
        """Layers are ordered by analysis depth."""
        assert Layer.L0_CONFIG < Layer.L1_SCHEMA < Layer.L2_HEURISTIC
        assert Layer.L2_HEURISTIC < Layer.L3_STATIC < Layer.L4_Z3
        assert Layer.L4_Z3 < Layer.L5_COMPOSITIONAL < Layer.L6_FUZZING


class TestAttackTypeEnum:
    """Additional AttackType enum tests."""

    def test_attack_type_is_int_enum(self) -> None:
        assert isinstance(AttackType.PROMPT_INJECTION, int)
        assert AttackType.PROMPT_INJECTION == 1

    @pytest.mark.parametrize(
        ("member", "value"),
        [
            (AttackType.PROMPT_INJECTION, 1),
            (AttackType.DATA_EXFILTRATION, 2),
            (AttackType.COMMAND_INJECTION, 3),
            (AttackType.PATH_TRAVERSAL, 4),
            (AttackType.SSRF, 5),
            (AttackType.CREDENTIAL_EXPOSURE, 6),
            (AttackType.SYSTEM_PROMPT_EXTRACTION, 7),
            (AttackType.CROSS_SERVER_SHADOWING, 8),
            (AttackType.TOKEN_STUFFING, 9),
            (AttackType.SCHEMA_PERMISSIVENESS, 10),
            (AttackType.RUG_PULL, 11),
            (AttackType.AUTHORIZATION_BYPASS, 12),
            (AttackType.SUPPLY_CHAIN, 13),
            (AttackType.CONFIG_INJECTION, 14),
        ],
    )
    def test_attack_type_values(self, member: AttackType, value: int) -> None:
        assert member.value == value


class TestOutputFormatEnum:
    """Additional OutputFormat enum tests."""

    @pytest.mark.parametrize(
        ("member", "value"),
        [
            (OutputFormat.TEXT, "text"),
            (OutputFormat.JSON, "json"),
            (OutputFormat.SARIF, "sarif"),
            (OutputFormat.MARKDOWN, "markdown"),
        ],
    )
    def test_output_format_values(self, member: OutputFormat, value: str) -> None:
        assert member.value == value
        assert member == value

    def test_output_format_lookup_by_value(self) -> None:
        assert OutputFormat("sarif") == OutputFormat.SARIF
        assert OutputFormat("markdown") == OutputFormat.MARKDOWN
