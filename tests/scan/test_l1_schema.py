"""Tests for munio.scan.layers.l1_schema."""

from __future__ import annotations

from typing import Any

import pytest

from munio.scan.layers.l1_schema import L1SchemaAnalyzer, schema_completeness_score
from munio.scan.models import AttackType, FindingSeverity, Layer, ToolDefinition

from .conftest import load_corpus, make_tool


class TestL1SchemaAnalyzer:
    """Test L1 Schema analysis checks."""

    def setup_method(self) -> None:
        self.analyzer = L1SchemaAnalyzer()

    @property
    def layer(self) -> Layer:
        return Layer.L1_SCHEMA

    def _analyze_one(self, tool: ToolDefinition) -> list[Any]:
        return self.analyzer.analyze([tool])

    def _ids(self, findings: list[Any]) -> set[str]:
        return {f.id for f in findings}

    # L1_001: Missing tool description
    def test_l1_001_missing_description(self) -> None:
        tool = make_tool(description="")
        findings = self._analyze_one(tool)
        assert "L1_001" in self._ids(findings)

    def test_l1_001_present_description(self) -> None:
        tool = make_tool(description="Does something")
        findings = self._analyze_one(tool)
        assert "L1_001" not in self._ids(findings)

    # L1_002: Empty/missing inputSchema
    def test_l1_002_empty_schema(self) -> None:
        tool = make_tool(input_schema={})
        findings = self._analyze_one(tool)
        assert "L1_002" in self._ids(findings)

    def test_l1_002_has_properties(self) -> None:
        tool = make_tool(input_schema={"type": "object", "properties": {"x": {"type": "string"}}})
        findings = self._analyze_one(tool)
        assert "L1_002" not in self._ids(findings)

    # L1_003: additionalProperties not false
    def test_l1_003_not_false(self) -> None:
        tool = make_tool(input_schema={"type": "object", "properties": {"x": {"type": "string"}}})
        findings = self._analyze_one(tool)
        assert "L1_003" in self._ids(findings)

    def test_l1_003_is_false(self) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "string"}},
                "additionalProperties": False,
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_003" not in self._ids(findings)

    # L1_004: Untyped parameter
    def test_l1_004_untyped(self) -> None:
        tool = make_tool(
            input_schema={"type": "object", "properties": {"x": {"description": "no type"}}}
        )
        findings = self._analyze_one(tool)
        assert "L1_004" in self._ids(findings)

    def test_l1_004_typed(self) -> None:
        tool = make_tool(input_schema={"type": "object", "properties": {"x": {"type": "string"}}})
        findings = self._analyze_one(tool)
        assert "L1_004" not in self._ids(findings)

    # L1_005: Missing string bounds
    def test_l1_005_unbounded_string(self) -> None:
        tool = make_tool(input_schema={"type": "object", "properties": {"x": {"type": "string"}}})
        findings = self._analyze_one(tool)
        assert "L1_005" in self._ids(findings)

    @pytest.mark.parametrize(
        ("bound_key", "bound_val"),
        [
            ("maxLength", 100),
            ("pattern", "^[a-z]+$"),
            ("enum", ["a", "b"]),
            ("const", "fixed"),
        ],
    )
    def test_l1_005_bounded_string(self, bound_key: str, bound_val: object) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "string", bound_key: bound_val}},
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_005" not in self._ids(findings)

    @pytest.mark.parametrize(
        ("bound_key", "bound_val"),
        [
            ("maxLength", 999_999_999),
            ("pattern", ".*"),
            ("pattern", "^.*$"),
            ("pattern", ".+"),
        ],
    )
    def test_l1_005_vacuous_bound_detected(self, bound_key: str, bound_val: object) -> None:
        """Vacuous bounds (huge maxLength, match-all pattern) are treated as unbounded."""
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "string", bound_key: bound_val}},
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_005" in self._ids(findings)

    # L1_006: Missing numeric bounds
    @pytest.mark.parametrize("num_type", ["integer", "number"])
    def test_l1_006_unbounded_numeric(self, num_type: str) -> None:
        tool = make_tool(input_schema={"type": "object", "properties": {"x": {"type": num_type}}})
        findings = self._analyze_one(tool)
        assert "L1_006" in self._ids(findings)

    @pytest.mark.parametrize(
        ("bound_key", "bound_val"),
        [
            ("maximum", 100),
            ("minimum", 0),
            ("exclusiveMaximum", 100),
            ("exclusiveMinimum", 0),
            ("enum", [1, 2, 3]),
        ],
    )
    def test_l1_006_bounded_numeric(self, bound_key: str, bound_val: object) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "integer", bound_key: bound_val}},
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_006" not in self._ids(findings)

    # L1_007: Dangerous parameter name
    @pytest.mark.parametrize(
        "param_name",
        [
            "system_prompt",
            "api_key",
            "password",
            "token",
            "ssh_key",
            "private_key",
            "credential",
            "secret",
            "sidenote",
        ],
    )
    def test_l1_007_dangerous_name(self, param_name: str) -> None:
        tool = make_tool(
            input_schema={"type": "object", "properties": {param_name: {"type": "string"}}}
        )
        findings = self._analyze_one(tool)
        assert "L1_007" in self._ids(findings)
        danger = [f for f in findings if f.id == "L1_007"]
        assert danger[0].severity == FindingSeverity.HIGH
        assert danger[0].attack_type == AttackType.SYSTEM_PROMPT_EXTRACTION

    def test_l1_007_case_insensitive(self) -> None:
        """Dangerous name detection is case-insensitive."""
        tool = make_tool(
            input_schema={"type": "object", "properties": {"API_KEY": {"type": "string"}}}
        )
        findings = self._analyze_one(tool)
        assert "L1_007" in self._ids(findings)

    def test_l1_007_safe_name(self) -> None:
        tool = make_tool(
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}}
        )
        findings = self._analyze_one(tool)
        assert "L1_007" not in self._ids(findings)

    # L1_008: Missing required array
    def test_l1_008_no_required(self) -> None:
        tool = make_tool(input_schema={"type": "object", "properties": {"x": {"type": "string"}}})
        findings = self._analyze_one(tool)
        assert "L1_008" in self._ids(findings)

    def test_l1_008_has_required(self) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "string"}},
                "required": ["x"],
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_008" not in self._ids(findings)

    # L1_009: Missing parameter description
    def test_l1_009_no_description(self) -> None:
        tool = make_tool(input_schema={"type": "object", "properties": {"x": {"type": "string"}}})
        findings = self._analyze_one(tool)
        assert "L1_009" in self._ids(findings)

    def test_l1_009_has_description(self) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "string", "description": "A string param"}},
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_009" not in self._ids(findings)

    # L1_010: Excessive parameter count
    def test_l1_010_excessive_params(self) -> None:
        props = {f"p{i}": {"type": "string"} for i in range(25)}
        tool = make_tool(input_schema={"type": "object", "properties": props})
        findings = self._analyze_one(tool)
        assert "L1_010" in self._ids(findings)

    def test_l1_010_acceptable_params(self) -> None:
        props = {f"p{i}": {"type": "string"} for i in range(5)}
        tool = make_tool(input_schema={"type": "object", "properties": props})
        findings = self._analyze_one(tool)
        assert "L1_010" not in self._ids(findings)

    # L1_011: Suspicious default value
    @pytest.mark.parametrize(
        "default_val",
        [
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "~/.config/secret",
            "/etc/passwd",
            "/etc/shadow",
            ".env",
        ],
    )
    def test_l1_011_suspicious_path(self, default_val: str) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string", "default": default_val}},
            }
        )
        findings = self._analyze_one(tool)
        l1_011 = [f for f in findings if f.id == "L1_011"]
        assert len(l1_011) >= 1
        assert l1_011[0].attack_type == AttackType.DATA_EXFILTRATION

    @pytest.mark.parametrize(
        "default_val",
        [
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://10.0.0.1/internal",
            "http://172.16.0.1/admin",
            "http://192.168.1.1/status",
        ],
    )
    def test_l1_011_suspicious_url(self, default_val: str) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"url": {"type": "string", "default": default_val}},
            }
        )
        findings = self._analyze_one(tool)
        l1_011 = [f for f in findings if f.id == "L1_011"]
        assert len(l1_011) >= 1
        assert l1_011[0].attack_type == AttackType.SSRF

    def test_l1_011_safe_default(self) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "string", "default": "hello"}},
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_011" not in self._ids(findings)

    def test_l1_011_list_default(self) -> None:
        """Suspicious values in list defaults are also detected."""
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {
                    "paths": {"type": "array", "default": ["/etc/passwd", "/tmp/safe"]},
                },
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_011" in self._ids(findings)

    def test_l1_011_enum_suspicious(self) -> None:
        """Suspicious values in enum are also detected."""
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "enum": ["http://example.com", "http://169.254.169.254/latest"],
                    },
                },
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_011" in self._ids(findings)

    # L1_012: Overly broad object type
    def test_l1_012_broad_object(self) -> None:
        tool = make_tool(
            input_schema={"type": "object", "properties": {"data": {"type": "object"}}}
        )
        findings = self._analyze_one(tool)
        assert "L1_012" in self._ids(findings)

    def test_l1_012_specified_object(self) -> None:
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {
                    "data": {"type": "object", "properties": {"key": {"type": "string"}}},
                },
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_012" not in self._ids(findings)

    # Multiple tools
    def test_analyzes_multiple_tools(self) -> None:
        tools = [
            make_tool(name="t1", description=""),
            make_tool(name="t2", description=""),
        ]
        findings = self.analyzer.analyze(tools)
        tool_names = {f.tool_name for f in findings if f.id == "L1_001"}
        assert tool_names == {"t1", "t2"}

    # C1+C2: Homoglyph and zero-width char bypass detection
    @pytest.mark.parametrize(
        ("param_name", "desc"),
        [
            ("system_pr\u043empt", "Cyrillic o homoglyph"),
            ("system\u200b_prompt", "zero-width space"),
            ("api\u200c_key", "zero-width non-joiner"),
            ("pass\u200dword", "zero-width joiner"),
            ("t\u2060oken", "word joiner"),
        ],
    )
    def test_l1_007_unicode_bypass_detected(self, param_name: str, desc: str) -> None:
        """Dangerous names with homoglyphs/zero-width chars are still detected."""
        tool = make_tool(
            input_schema={"type": "object", "properties": {param_name: {"type": "string"}}}
        )
        findings = self._analyze_one(tool)
        assert "L1_007" in self._ids(findings), f"Failed to detect: {desc}"

    # C3: Nested object recursion
    def test_nested_dangerous_param_detected(self) -> None:
        """L1_007 detects dangerous param names in nested objects."""
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {
                    "config": {
                        "type": "object",
                        "properties": {
                            "api_key": {"type": "string"},
                        },
                    },
                },
            }
        )
        findings = self._analyze_one(tool)
        assert "L1_007" in self._ids(findings)

    def test_nested_untyped_param_detected(self) -> None:
        """L1_004 detects untyped params in nested objects."""
        tool = make_tool(
            input_schema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "object",
                        "properties": {
                            "untyped": {"description": "no type here"},
                        },
                    },
                },
            }
        )
        findings = self._analyze_one(tool)
        l1_004 = [f for f in findings if f.id == "L1_004"]
        assert any("untyped" in f.message for f in l1_004)

    def test_deeply_nested_respects_depth_limit(self) -> None:
        """Recursion depth limit prevents stack overflow on deeply nested schemas."""
        # Build 15 levels of nesting (deeper than limit of 10)
        inner: dict[str, object] = {"system_prompt": {"type": "string"}}
        for _ in range(15):
            inner = {"wrapper": {"type": "object", "properties": inner}}
        tool = make_tool(input_schema={"type": "object", "properties": inner})
        # Should not crash, findings from shallow levels still produced
        findings = self._analyze_one(tool)
        assert isinstance(findings, list)

    # All findings use correct layer
    def test_all_findings_l1_layer(self) -> None:
        tool = make_tool(description="", input_schema={})
        findings = self._analyze_one(tool)
        assert all(f.layer == Layer.L1_SCHEMA for f in findings)


class TestCorpusIntegration:
    """Run L1 analysis on real vulnerability corpus examples."""

    def test_poisoning_examples_produce_findings(self) -> None:
        """Real poisoning examples should produce at least some findings."""
        corpus = load_corpus()
        analyzer = L1SchemaAnalyzer()

        poisoning = corpus.get("part1_real_poisoning_examples", [])
        tools = [
            make_tool(
                name=ex.get("name", f"tp_{i}"),
                description=ex.get("description", ""),
                input_schema=ex.get("inputSchema", {}),
            )
            for i, ex in enumerate(poisoning)
        ]

        findings = analyzer.analyze(tools)
        # Real poisoning examples should produce findings
        assert len(findings) > 0

    def test_benign_low_false_positives(self) -> None:
        """Benign-but-suspicious examples should have few CRITICAL false positives."""
        corpus = load_corpus()
        analyzer = L1SchemaAnalyzer()

        benign = corpus.get("part2_benign_but_suspicious", [])
        tools = [
            make_tool(
                name=ex.get("name", f"bs_{i}"),
                description=ex.get("description", ""),
                input_schema=ex.get("inputSchema", {}),
            )
            for i, ex in enumerate(benign)
        ]

        findings = analyzer.analyze(tools)
        critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        assert critical_count < 3, f"Too many CRITICAL false positives: {critical_count}"


class TestSchemaCompletenessScore:
    """Test schema_completeness_score()."""

    def test_empty_tool_low_score(self) -> None:
        tool = make_tool(name="empty", description="", input_schema={})
        score = schema_completeness_score(tool)
        assert score == 0.0

    def test_fully_specified_tool(self) -> None:
        tool = ToolDefinition(
            name="complete",
            description="A well-specified tool",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path",
                        "maxLength": 255,
                    },
                    "count": {
                        "type": "integer",
                        "description": "How many items",
                        "minimum": 0,
                        "maximum": 100,
                    },
                },
                "required": ["path"],
                "additionalProperties": False,
            },
            output_schema={"type": "object"},
        )
        score = schema_completeness_score(tool)
        assert score == 100.0

    def test_partial_score(self) -> None:
        """Tool with description + properties but missing bounds."""
        tool = make_tool(
            description="Has desc",
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "string"}},
            },
        )
        score = schema_completeness_score(tool)
        # Has description (20) + has properties (15) + all typed (15)
        assert 40 <= score <= 60

    def test_score_range(self) -> None:
        """Score is always 0-100."""
        tool = make_tool(
            description="x",
            input_schema={"type": "object", "properties": {"a": {"type": "string"}}},
        )
        score = schema_completeness_score(tool)
        assert 0 <= score <= 100
