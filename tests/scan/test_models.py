"""Tests for munio.scan.models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from munio.scan.models import (
    AttackType,
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
    ToolDefinition,
)


class TestEnums:
    """Test enum definitions."""

    @pytest.mark.parametrize(
        ("enum_cls", "expected_count"),
        [
            (Layer, 10),
            (FindingSeverity, 5),
            (AttackType, 14),
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
        import json

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
