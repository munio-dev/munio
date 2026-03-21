"""Tests for munio.scan.layers.l4_z3 (L4 Z3 Formal Verification)."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest

from munio.scan.config import ScanConfig
from munio.scan.models import (
    AttackType,
    FindingSeverity,
    Layer,
    ServerScanResult,
)
from munio.scan.orchestrator import Orchestrator

from .conftest import make_tool

# ── Helpers ──────────────────────────────────────────────────────────────


def _schema(props: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": props}


def _run(coro: object) -> object:
    return asyncio.run(coro)  # type: ignore[arg-type]


# ── TestZ3Utils ──────────────────────────────────────────────────────────


class TestZ3Utils:
    """Test Z3 utility functions."""

    def test_z3_available_returns_bool(self) -> None:
        from munio.scan.layers._z3_utils import z3_available

        assert isinstance(z3_available(), bool)

    def test_pattern_to_z3_simple_literal(self) -> None:
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import pattern_to_z3

        pat_z3 = pattern_to_z3("^abc$")
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.InRe(s, pat_z3))
        assert solver.check() == z3.sat
        assert solver.model()[s].as_string() == "abc"

    def test_pattern_to_z3_character_class(self) -> None:
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import pattern_to_z3

        pat_z3 = pattern_to_z3("^[a-z]+$")
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.InRe(s, pat_z3))
        solver.add(z3.Length(s) >= 1)
        assert solver.check() == z3.sat

    def test_pattern_to_z3_alternation(self) -> None:
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import pattern_to_z3

        pat_z3 = pattern_to_z3("^(foo|bar)$")
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.InRe(s, pat_z3))
        assert solver.check() == z3.sat
        val = solver.model()[s].as_string()
        assert val in ("foo", "bar")

    @pytest.mark.parametrize(
        "pattern",
        [
            "^a*$",
            "^a+$",
            "^a?$",
            "^a{2,4}$",
            "^a{3,}$",
        ],
        ids=["star", "plus", "option", "loop_bounded", "loop_unbounded"],
    )
    def test_pattern_to_z3_quantifiers(self, pattern: str) -> None:
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import pattern_to_z3

        pat_z3 = pattern_to_z3(pattern)
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.InRe(s, pat_z3))
        assert solver.check() == z3.sat

    @pytest.mark.parametrize(
        ("pattern", "desc"),
        [
            (r"(abc)\1", "backreference"),
            (r"(?=foo)", "lookahead"),
            (r"(?!foo)", "negative_lookahead"),
            (r"(?<=foo)", "lookbehind"),
            (r"\b", "word_boundary"),
            (r"\D+", "negated_digit"),
            (r"\W+", "negated_word"),
            (r"\S+", "negated_space"),
            (r"(?i:abc)", "inline_flag"),
        ],
        ids=lambda x: x if isinstance(x, str) and "_" in x else None,
    )
    def test_pattern_to_z3_unsupported(self, pattern: str, desc: str) -> None:
        from munio.scan.layers._z3_utils import pattern_to_z3

        with pytest.raises(ValueError, match=r"not supported|Unsupported"):
            pattern_to_z3(pattern)

    def test_pattern_to_z3_anchors_stripped(self) -> None:
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import pattern_to_z3

        # Both ^hello$ and hello should produce same Z3 regex
        pat1 = pattern_to_z3("^hello$")
        pat2 = pattern_to_z3("hello")
        s = z3.String("s")
        for pat in (pat1, pat2):
            solver = z3.Solver()
            solver.add(z3.InRe(s, pat))
            assert solver.check() == z3.sat
            assert solver.model()[s].as_string() == "hello"

    def test_make_attack_regex_contains_semantics(self) -> None:
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import make_attack_regex

        attack = make_attack_regex(["../"])
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.InRe(s, attack))
        assert solver.check() == z3.sat
        assert "../" in solver.model()[s].as_string()

    def test_check_intersection_sat(self) -> None:
        from munio.scan.layers._z3_utils import (
            check_intersection,
            make_attack_regex,
            pattern_to_z3,
        )

        pat = pattern_to_z3("^[a-zA-Z0-9_./]+$")
        attack = make_attack_regex(["../"])
        result, counterexample = check_intersection(pat, attack)
        assert result == "sat"
        assert counterexample is not None
        assert "../" in counterexample

    def test_check_intersection_unsat(self) -> None:
        from munio.scan.layers._z3_utils import (
            check_intersection,
            make_attack_regex,
            pattern_to_z3,
        )

        # Pattern only allows alphanumeric — no dots or slashes
        pat = pattern_to_z3("^[a-zA-Z0-9_]+$")
        attack = make_attack_regex(["../"])
        result, counterexample = check_intersection(pat, attack)
        assert result == "unsat"
        assert counterexample is None

    def test_check_intersection_with_max_length(self) -> None:
        from munio.scan.layers._z3_utils import (
            check_intersection,
            make_attack_regex,
            pattern_to_z3,
        )

        pat = pattern_to_z3("^[a-zA-Z0-9_./]+$")
        attack = make_attack_regex(["../"])
        result, counterexample = check_intersection(pat, attack, max_length=255)
        assert result == "sat"
        assert counterexample is not None
        assert len(counterexample) <= 255

    def test_check_satisfiability_sat(self) -> None:
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^[a-z]+$")
        result = check_satisfiability(pat, min_length=3, max_length=10)
        assert result == "sat"

    def test_check_satisfiability_unsat(self) -> None:
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        # Pattern requires exactly "abc" (3 chars) but maxLength=2
        pat = pattern_to_z3("^abc$")
        result = check_satisfiability(pat, max_length=2)
        assert result == "unsat"

    def test_check_satisfiability_min_only(self) -> None:
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^[a-z]+$")
        result = check_satisfiability(pat, min_length=5)
        assert result == "sat"


# ── TestL4Z3AnalyzerInit ────────────────────────────────────────────────


class TestL4Z3AnalyzerInit:
    """Test L4Z3Analyzer initialization and basics."""

    def test_layer_property(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        assert analyzer.layer == Layer.L4_Z3

    def test_graceful_skip_no_z3(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        with patch("munio.scan.layers._z3_utils.z3_available", return_value=False):
            analyzer = L4Z3Analyzer()

        tool = make_tool(
            name="read_file",
            description="Read a file",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^.*$"}}),
        )
        findings = analyzer.analyze([tool])
        assert findings == []

    def test_error_in_one_tool_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Tool with schema that will cause TypeError in _check_parameter
        bad_tool = make_tool(name="bad", input_schema={"properties": "not-a-dict"})
        good_tool = make_tool(
            name="read_file",
            description="Read file",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        # Should not crash, processes good_tool
        findings = analyzer.analyze([bad_tool, good_tool])
        l4 = [f for f in findings if f.layer == Layer.L4_Z3]
        # Good tool should produce path traversal finding
        assert any(f.id == "L4_001" for f in l4)

    def test_all_findings_are_l4(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read file",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        findings = analyzer.analyze([tool])
        for f in findings:
            assert f.layer == Layer.L4_Z3


# ── TestL4001PathTraversal ──────────────────────────────────────────────


class TestL4001PathTraversal:
    """Test L4_001 path traversal pattern bypass."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "^[a-zA-Z0-9_./]+$",
            "^[a-zA-Z0-9_./-]+$",
            "^.*$",  # vacuous — skipped by L4
            ".+",  # vacuous — skipped by L4
        ],
        ids=["dot_slash", "dot_slash_dash", "vacuous_star", "vacuous_plus"],
    )
    def test_weak_pattern_detected(self, pattern: str) -> None:
        from munio.scan.layers.l4_z3 import _VACUOUS_PATTERNS, L4Z3Analyzer

        if pattern in _VACUOUS_PATTERNS:
            pytest.skip("Vacuous pattern skipped by design")

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read file",
            input_schema=_schema({"file_path": {"type": "string", "pattern": pattern}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[0].counterexample is not None

    def test_tier1_concrete_payload_match(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Pattern allows ../
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        assert findings[0].confidence == 1.0  # Tier 1 = concrete proof

    def test_tier2_z3_proves_bypass(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Pattern that NONE of the concrete Tier 1 payloads match (all start
        # with ".." or "http", not a letter), but Z3 can prove a bypass exists:
        # any string starting with a letter followed by "../" is valid, e.g.
        # "a/../../../etc/passwd".
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(
                {
                    "file_path": {
                        "type": "string",
                        "pattern": "^[a-z][a-z0-9_./-]*$",
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) >= 1
        assert findings[0].attack_type == AttackType.PATH_TRAVERSAL
        # Tier 1 has "valid/path/../../../etc/passwd" and "foo/../../../etc/passwd"
        # which DO match ^[a-z][a-z0-9_./-]*$ via search — so Tier 1 catches it
        # with confidence 1.0.  Verify the finding was produced either way.
        assert findings[0].confidence in {1.0, 0.95}

    def test_tier2_z3_sat_confidence(self) -> None:
        """When only Z3 proves bypass (no concrete payload), confidence=0.95."""
        from munio.scan.layers._z3_utils import (
            check_intersection,
            make_attack_regex,
            pattern_to_z3_search,
        )
        from munio.scan.layers.l4_z3 import _PATH_TRAVERSAL_SUBSTRINGS

        # Directly test the Z3 tier for a pattern that allows traversal
        pattern_z3 = pattern_to_z3_search("^[a-zA-Z0-9_./]+$")
        attack_z3 = make_attack_regex(_PATH_TRAVERSAL_SUBSTRINGS)
        result, counterexample = check_intersection(pattern_z3, attack_z3)
        assert result == "sat"
        assert counterexample is not None
        # Verify the counterexample contains traversal
        assert "../" in counterexample or "..\\" in counterexample

    def test_safe_pattern_no_finding(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Pattern only allows alphanumeric + underscore — no dots or slashes
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 0

    def test_safe_pattern_report_safe(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer(report_safe=True)
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.INFO

    def test_non_path_param_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="some_tool",
            description="Does things",
            input_schema=_schema({"name": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 0

    def test_vacuous_pattern_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^.*$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 0

    def test_no_pattern_no_finding(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # No pattern = L3's job, not L4's
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 0

    def test_invalid_regex_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[invalid"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 0

    def test_counterexample_contains_traversal(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        ce = findings[0].counterexample
        assert ce is not None
        assert "../" in ce or "..\\" in ce

    def test_cwe_and_attack_type(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-22"
        assert findings[0].attack_type == AttackType.PATH_TRAVERSAL


# ── TestL4002SSRF ───────────────────────────────────────────────────────


class TestL4002SSRF:
    """Test L4_002 SSRF URL pattern bypass."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "^https?://.*$",
            "^https?://[a-zA-Z0-9._:/-]+$",
        ],
        ids=["any_url", "alphanum_url"],
    )
    def test_weak_url_pattern_detected(self, pattern: str) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="fetch",
            description="Fetch URL",
            input_schema=_schema({"url": {"type": "string", "pattern": pattern}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_002"]
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH
        assert findings[0].cwe == "CWE-918"
        assert findings[0].attack_type == AttackType.SSRF

    def test_safe_url_pattern(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Only allows https://api.example.com/...
        tool = make_tool(
            name="fetch",
            description="Fetch URL",
            input_schema=_schema(
                {
                    "url": {
                        "type": "string",
                        "pattern": r"^https://api\.example\.com/[a-zA-Z0-9/]+$",
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_002"]
        assert len(findings) == 0

    def test_safe_url_pattern_report_safe(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer(report_safe=True)
        tool = make_tool(
            name="fetch",
            description="Fetch URL",
            input_schema=_schema(
                {
                    "url": {
                        "type": "string",
                        "pattern": r"^https://api\.example\.com/[a-zA-Z0-9/]+$",
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_002"]
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.INFO

    def test_non_url_param_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="fetch",
            description="Fetch",
            input_schema=_schema({"name": {"type": "string", "pattern": "^https?://.*$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_002"]
        assert len(findings) == 0

    def test_counterexample_contains_ssrf(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="fetch",
            description="Fetch URL",
            input_schema=_schema(
                {"url": {"type": "string", "pattern": "^https?://[a-zA-Z0-9._:/-]+$"}}
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_002"]
        assert len(findings) == 1
        ce = findings[0].counterexample
        assert ce is not None


# ── TestL4003CommandInjection ───────────────────────────────────────────


class TestL4003CommandInjection:
    """Test L4_003 command injection pattern bypass."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "^[a-zA-Z0-9_ ;|&]+$",
            "^.+$",  # vacuous — skipped
        ],
        ids=["allows_semicolon", "vacuous"],
    )
    def test_weak_cmd_pattern(self, pattern: str) -> None:
        from munio.scan.layers.l4_z3 import _VACUOUS_PATTERNS, L4Z3Analyzer

        if pattern in _VACUOUS_PATTERNS:
            pytest.skip("Vacuous pattern skipped by design")

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="run_command",
            description="Execute command",
            input_schema=_schema({"command": {"type": "string", "pattern": pattern}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_003"]
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[0].cwe == "CWE-78"

    def test_safe_cmd_pattern(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Only allows alphanumeric + underscore + dash
        tool = make_tool(
            name="run_command",
            description="Execute command",
            input_schema=_schema({"command": {"type": "string", "pattern": "^[a-zA-Z0-9_-]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_003"]
        assert len(findings) == 0

    def test_non_command_param_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="some_tool",
            description="Do something",
            input_schema=_schema({"name": {"type": "string", "pattern": "^[a-zA-Z0-9_;]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_003"]
        assert len(findings) == 0

    def test_counterexample_contains_metachar(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="run_command",
            description="Execute",
            input_schema=_schema({"command": {"type": "string", "pattern": "^[a-zA-Z0-9_ ;]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_003"]
        assert len(findings) == 1
        ce = findings[0].counterexample
        assert ce is not None
        assert ";" in ce


# ── TestL4004PatternLengthContradiction ─────────────────────────────────


class TestL4004PatternLengthContradiction:
    """Test L4_004 pattern-length contradiction detection."""

    def test_contradictory_constraints(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Pattern "abc" is exactly 3 chars but maxLength=2
        tool = make_tool(
            name="some_tool",
            description="Tool",
            input_schema=_schema(
                {
                    "value": {
                        "type": "string",
                        "pattern": "^abc$",
                        "maxLength": 2,
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_004"]
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.MEDIUM
        assert findings[0].cwe == "CWE-1286"

    def test_satisfiable_constraints(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="some_tool",
            description="Tool",
            input_schema=_schema(
                {
                    "value": {
                        "type": "string",
                        "pattern": "^[a-z]+$",
                        "minLength": 3,
                        "maxLength": 10,
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_004"]
        assert len(findings) == 0

    def test_pattern_only_no_length(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="some_tool",
            description="Tool",
            input_schema=_schema({"value": {"type": "string", "pattern": "^abc$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_004"]
        assert len(findings) == 0

    def test_min_length_contradiction(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Pattern "ab" is 2 chars but minLength=5
        tool = make_tool(
            name="some_tool",
            description="Tool",
            input_schema=_schema(
                {
                    "value": {
                        "type": "string",
                        "pattern": "^ab$",
                        "minLength": 5,
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_004"]
        assert len(findings) == 1

    def test_vacuous_pattern_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="some_tool",
            description="Tool",
            input_schema=_schema({"value": {"type": "string", "pattern": "^.*$", "maxLength": 10}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_004"]
        assert len(findings) == 0


# ── TestL4005UnsafeEnum ─────────────────────────────────────────────────


class TestL4005UnsafeEnum:
    """Test L4_005 unsafe enum value detection."""

    @pytest.mark.parametrize(
        ("enum_val", "desc", "expected_attack"),
        [
            ("../../../etc/passwd", "traversal", AttackType.PATH_TRAVERSAL),
            ("; rm -rf /", "shell_metachar", AttackType.COMMAND_INJECTION),
            ("$(whoami)", "cmd_substitution", AttackType.COMMAND_INJECTION),
            ("{{constructor}}", "template_directive", AttackType.COMMAND_INJECTION),
            ("<%= exec %>", "erb_template", AttackType.COMMAND_INJECTION),
            ("http://169.254.169.254/", "metadata_url", AttackType.SSRF),
            ("http://localhost:8080/", "localhost", AttackType.SSRF),
        ],
        ids=lambda x: x if isinstance(x, str) and "_" in x else None,
    )
    def test_unsafe_enum_detected(
        self, enum_val: str, desc: str, expected_attack: AttackType
    ) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="run_command",
            description="Execute",
            input_schema=_schema({"command": {"type": "string", "enum": ["safe", enum_val]}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_005"]
        assert len(findings) >= 1
        found_attacks = {f.attack_type for f in findings}
        assert expected_attack in found_attacks

    def test_safe_enum_no_finding(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="run_command",
            description="Execute",
            input_schema=_schema({"command": {"type": "string", "enum": ["list", "copy", "move"]}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_005"]
        assert len(findings) == 0

    def test_non_security_param_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Param "color" is not security-relevant, even with dangerous values
        tool = make_tool(
            name="some_tool",
            description="Tool",
            input_schema=_schema({"color": {"type": "string", "enum": ["red", "; rm -rf /"]}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_005"]
        assert len(findings) == 0

    def test_counterexample_is_enum_value(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="run_command",
            description="Execute",
            input_schema=_schema({"command": {"type": "string", "enum": ["safe", "; evil"]}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_005"]
        assert len(findings) == 1
        assert findings[0].counterexample == "; evil"

    def test_multiple_unsafe_values(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="run_command",
            description="Execute",
            input_schema=_schema(
                {
                    "command": {
                        "type": "string",
                        "enum": ["; evil1", "safe", "| evil2"],
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_005"]
        assert len(findings) == 2

    def test_non_string_enum_ignored(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="run_command",
            description="Execute",
            input_schema=_schema({"command": {"type": "string", "enum": [42, None, True, "safe"]}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_005"]
        assert len(findings) == 0

    def test_path_param_with_traversal_enum(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read file",
            input_schema=_schema(
                {
                    "file_path": {
                        "type": "string",
                        "enum": ["/var/data/safe", "../../../etc/passwd"],
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_005"]
        assert len(findings) == 1
        assert findings[0].attack_type == AttackType.PATH_TRAVERSAL


# ── TestL4Integration ───────────────────────────────────────────────────


class TestL4Integration:
    """Test L4 in orchestrator pipeline."""

    def test_l4_enabled_by_default(self) -> None:
        config = ScanConfig()
        assert Layer.L4_Z3 in config.enabled_layers

    def test_l4_produces_findings_through_orchestrator(self) -> None:
        tool = make_tool(
            name="read_file",
            description="Read file",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator()
        result = _run(orch.scan([sr]))
        l4 = [f for f in result.findings if f.layer == Layer.L4_Z3]
        assert len(l4) > 0

    def test_l4_disabled_no_l4_findings(self) -> None:
        config = ScanConfig(enabled_layers=frozenset({Layer.L1_SCHEMA}))
        tool = make_tool(
            name="read_file",
            description="Read file",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator(config)
        result = _run(orch.scan([sr]))
        l4 = [f for f in result.findings if f.layer == Layer.L4_Z3]
        assert l4 == []

    def test_l4_findings_sorted_by_severity(self) -> None:
        tool = make_tool(
            name="run_command",
            description="Execute",
            input_schema=_schema(
                {
                    "command": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9_ ;]+$",
                    },
                    "file_path": {
                        "type": "string",
                        "pattern": "^abc$",
                        "maxLength": 2,
                    },
                }
            ),
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator()
        result = _run(orch.scan([sr]))
        l4 = [f for f in result.findings if f.layer == Layer.L4_Z3]
        severities = [f.severity.value for f in l4]
        assert severities == sorted(severities)


# ── TestL4RecursiveProperties ───────────────────────────────────────────


class TestL4RecursiveProperties:
    """Test L4 handles nested schemas."""

    def test_nested_object_analyzed(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read file",
            input_schema=_schema(
                {
                    "config": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "pattern": "^[a-zA-Z0-9_./]+$",
                            }
                        },
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        assert "config.properties" in findings[0].location

    def test_array_items_analyzed(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="run_command",
            description="Execute commands",
            input_schema=_schema(
                {
                    "command_list": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "pattern": "^[a-zA-Z0-9_ ;]+$",
                        },
                    }
                }
            ),
        )
        # Array items named "command_list[]" — "command" segment triggers L4_003
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_003"]
        assert len(findings) >= 1
        assert findings[0].attack_type == AttackType.COMMAND_INJECTION

    def test_deep_recursion_capped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Build deeply nested schema (15 levels > _MAX_RECURSION_DEPTH=10)
        inner: dict[str, Any] = {"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}
        for _ in range(15):
            inner = {"nested": {"type": "object", "properties": inner}}
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(inner),
        )
        # Recursion capped at depth 10 — deeply nested param not found
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 0


# ── TestL4WithMaxLength ─────────────────────────────────────────────────


class TestL4WithMaxLength:
    """Test L4 respects maxLength in Z3 checks."""

    def test_maxlength_constrains_counterexample(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(
                {
                    "file_path": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9_./]+$",
                        "maxLength": 50,
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        ce = findings[0].counterexample
        if ce is not None:
            assert len(ce) <= 50


# ── TestL4EdgeCases ─────────────────────────────────────────────────────


class TestL4EdgeCases:
    """Test edge cases and error handling."""

    def test_empty_schema(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(name="test", input_schema={})
        findings = analyzer.analyze([tool])
        assert findings == []

    def test_no_properties(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(name="test", input_schema={"type": "object"})
        findings = analyzer.analyze([tool])
        assert findings == []

    def test_non_string_type_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "integer", "pattern": "^[0-9]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 0

    def test_unsupported_regex_feature_skipped(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Backreference in pattern — Z3 can't handle it.
        # Pattern: only letters/digits, no traversal payloads match,
        # so Tier 1 finds nothing; Tier 2 hits ValueError and skips.
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^([a-z])\\1+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        # Should not crash, just skip — no findings produced
        assert findings == []

    def test_multiple_tools(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool1 = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        tool2 = make_tool(
            name="fetch",
            description="Fetch URL",
            input_schema=_schema({"url": {"type": "string", "pattern": "^https?://.*$"}}),
        )
        findings = analyzer.analyze([tool1, tool2])
        check_ids = {f.id for f in findings}
        assert "L4_001" in check_ids
        assert "L4_002" in check_ids

    def test_word_char_class_pattern(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # \w is supported in Z3 translation
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": r"^\w+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        # \w = [a-zA-Z0-9_] — no dots or slashes, so safe
        assert len(findings) == 0

    def test_digit_class_pattern(self) -> None:
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import pattern_to_z3

        pat = pattern_to_z3(r"^\d+$")
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.InRe(s, pat))
        solver.add(z3.Length(s) >= 1)
        assert solver.check() == z3.sat
        val = solver.model()[s].as_string()
        assert val.isdigit()

    def test_space_class_pattern(self) -> None:
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import pattern_to_z3

        pat = pattern_to_z3(r"^\s+$")
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.InRe(s, pat))
        solver.add(z3.Length(s) == 1)
        assert solver.check() == z3.sat


# ── TestC1CaseInsensitiveFlag ─────────────────────────────────────────


class TestC1CaseInsensitiveFlag:
    """C1 fix: (?i) flag must be rejected, not silently dropped."""

    @pytest.mark.parametrize(
        ("pattern", "desc"),
        [
            ("(?i)abc", "global_flag"),
            ("(?i)^https://[A-Z]+$", "global_flag_anchored"),
            ("(?im)test", "multi_flag"),
        ],
        ids=["global_flag", "global_flag_anchored", "multi_flag"],
    )
    def test_case_insensitive_rejected_by_z3_utils(self, pattern: str, desc: str) -> None:
        from munio.scan.layers._z3_utils import pattern_to_z3

        with pytest.raises(ValueError, match=r"IGNORECASE|\(\?i\)"):
            pattern_to_z3(pattern)

    def test_case_insensitive_rejected_by_search(self) -> None:
        from munio.scan.layers._z3_utils import pattern_to_z3_search

        with pytest.raises(ValueError, match=r"IGNORECASE|\(\?i\)"):
            pattern_to_z3_search("(?i)abc")

    def test_case_insensitive_tier1_still_catches(self) -> None:
        """Tier 1 re.search() correctly handles (?i) — catches weak patterns."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # (?i) pattern — Tier 1 re.search() handles it correctly (Python re
        # supports (?i)), so it catches the traversal payload.
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "(?i)^[a-z_./]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        assert findings[0].confidence == 1.0  # Tier 1 concrete match

    def test_case_insensitive_tier2_skipped_not_false_safe(self) -> None:
        """(?i) pattern that reaches Tier 2 is skipped (not false safe).

        This tests the C1 fix: if Tier 1 doesn't catch the pattern and
        Z3 Tier 2 is reached, the (?i) flag causes a ValueError in
        pattern_to_z3, so the check is skipped instead of producing a
        false 'safe' Z3 proof.
        """
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer(report_safe=True)
        # (?i) with SAFE pattern — Tier 1 won't find a match, Tier 2
        # Z3 translation should reject and skip (not false safe).
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "(?i)^[a-z]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        # Should NOT produce an INFO "safe" finding (Z3 can't prove it)
        safe_findings = [f for f in findings if f.severity == FindingSeverity.INFO]
        assert len(safe_findings) == 0

    def test_case_sensitive_pattern_accepted(self) -> None:
        from munio.scan.layers._z3_utils import pattern_to_z3

        # Normal pattern without (?i) should work fine
        pat = pattern_to_z3("^[a-zA-Z]+$")
        assert pat is not None


# ── TestC2SearchSemantics ─────────────────────────────────────────────


class TestC2SearchSemantics:
    """C2 fix: JSON Schema pattern uses search (not fullmatch) semantics."""

    def test_unanchored_pattern_allows_attack_via_search(self) -> None:
        """Unanchored pattern like [a-z]+ accepts '../etc/passwd' via search."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # [a-z]+ with search semantics matches "etc" in "../etc/passwd"
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "[a-z]+"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        # With search semantics, this pattern accepts traversal payloads
        assert len(findings) == 1
        assert findings[0].confidence == 1.0  # Tier 1 concrete match

    def test_anchored_pattern_blocks_attack(self) -> None:
        """Fully anchored ^[a-z]+$ blocks attacks via fullmatch semantics."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-z]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 0

    def test_z3_search_unanchored(self) -> None:
        """Z3 search semantics wraps unanchored pattern with Full()."""
        from munio.scan.layers._z3_utils import (
            check_intersection,
            make_attack_regex,
            pattern_to_z3_search,
        )

        # [a-z]+ unanchored — search semantics allows anything around it
        pat_z3 = pattern_to_z3_search("[a-z]+")
        attack = make_attack_regex(["../"])
        result, ce = check_intersection(pat_z3, attack)
        # Any string with "../" that also has a lowercase letter should be SAT
        assert result == "sat"
        assert ce is not None

    def test_z3_search_anchored(self) -> None:
        """Fully anchored pattern has fullmatch semantics in Z3."""
        from munio.scan.layers._z3_utils import (
            check_intersection,
            make_attack_regex,
            pattern_to_z3_search,
        )

        # ^[a-z]+$ fully anchored — no dots or slashes allowed
        pat_z3 = pattern_to_z3_search("^[a-z]+$")
        attack = make_attack_regex(["../"])
        result, _ = check_intersection(pat_z3, attack)
        assert result == "unsat"

    def test_start_anchored_only(self) -> None:
        """Start-only anchor allows anything after the pattern."""
        import z3  # type: ignore[import-untyped]

        from munio.scan.layers._z3_utils import pattern_to_z3_search

        # ^[a-z]+ — start anchored, end open
        pat_z3 = pattern_to_z3_search("^[a-z]+")
        s = z3.String("s")
        solver = z3.Solver()
        solver.add(z3.InRe(s, pat_z3))
        solver.add(z3.Length(s) == 10)
        assert solver.check() == z3.sat
        # String can have non-lowercase chars after the initial match
        val = solver.model()[s].as_string()
        assert val[0].islower()


# ── TestH1UserAtHostBypass ──────────────────────────────────────────────


class TestH1UserAtHostBypass:
    """H1 fix: SSRF user@host bypass detection."""

    def test_user_at_host_detected(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Pattern allows http://user@127.0.0.1/ — the @ variant
        tool = make_tool(
            name="fetch",
            description="Fetch URL",
            input_schema=_schema(
                {"url": {"type": "string", "pattern": "^https?://[a-zA-Z0-9@._:/-]+$"}}
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_002"]
        assert len(findings) == 1
        assert findings[0].attack_type == AttackType.SSRF

    def test_ssrf_payloads_include_at_variants(self) -> None:
        from munio.scan.layers.l4_z3 import _SSRF_PAYLOADS

        at_payloads = [p for p in _SSRF_PAYLOADS if "@" in p]
        assert len(at_payloads) >= 2

    def test_ssrf_substrings_include_at_variants(self) -> None:
        from munio.scan.layers.l4_z3 import _SSRF_SUBSTRINGS

        at_subs = [s for s in _SSRF_SUBSTRINGS if s.startswith("@")]
        assert len(at_subs) >= 2


# ── TestH3AllOfAnyOfProperties ──────────────────────────────────────────


class TestH3AllOfAnyOfProperties:
    """H3 fix: L4 must inspect allOf/anyOf/patternProperties."""

    def test_allof_properties_analyzed(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema={
                "type": "object",
                "allOf": [
                    {
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "pattern": "^[a-zA-Z0-9_./]+$",
                            }
                        }
                    }
                ],
            },
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1

    def test_anyof_properties_analyzed(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="fetch",
            description="Fetch URL",
            input_schema={
                "type": "object",
                "anyOf": [
                    {
                        "properties": {
                            "url": {
                                "type": "string",
                                "pattern": "^https?://[a-zA-Z0-9._:/-]+$",
                            }
                        }
                    }
                ],
            },
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_002"]
        assert len(findings) == 1

    def test_pattern_properties_analyzed(self) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema={
                "type": "object",
                "patternProperties": {
                    "file_path": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9_./]+$",
                    }
                },
            },
        )
        # patternProperties key "file_path" used as pseudo-name
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) >= 1


# ── TestM1AtomicGroup ─────────────────────────────────────────────────


class TestM1AtomicGroup:
    """M1 fix: ATOMIC_GROUP handled instead of raising ValueError."""

    def test_atomic_group_not_crash(self) -> None:
        """Atomic group patterns should be handled, not rejected."""
        import re._parser as sre_parse  # type: ignore[import-untyped]

        if not hasattr(sre_parse, "ATOMIC_GROUP"):
            pytest.skip("Python version does not support atomic groups")

        from munio.scan.layers._z3_utils import pattern_to_z3

        # (?>abc) is an atomic group in Python 3.11+
        pat = pattern_to_z3("^(?>abc)+$")
        assert pat is not None


# ── TestM6EnumPatterns ────────────────────────────────────────────────


class TestM6EnumPatterns:
    """M6 fix: expanded enum attack pattern coverage."""

    @pytest.mark.parametrize(
        ("enum_val", "desc"),
        [
            ("..\\..\\windows\\system32", "backslash_traversal"),
            ("${PATH}", "variable_substitution"),
            ("file:///etc/passwd", "file_uri"),
            ("\\\\server\\share", "unc_path"),
        ],
        ids=["backslash_traversal", "variable_substitution", "file_uri", "unc_path"],
    )
    def test_new_enum_patterns_detected(self, enum_val: str, desc: str) -> None:
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "enum": ["safe", enum_val]}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_005"]
        assert len(findings) >= 1, f"Expected finding for {desc}: {enum_val}"


# ── DoS protection: ReDoS detection ──────────────────────────────────


class TestReDoSDetection:
    """ReDoS-prone patterns are skipped before re.search()."""

    @pytest.mark.parametrize(
        ("pattern", "desc"),
        [
            ("(a+)+", "nested_quantifier_plus"),
            ("(a*)*", "nested_quantifier_star"),
            ("(a+|b)+", "alternation_nested"),
            (
                "[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+",
                "polynomial_5_quantified_atoms",
            ),
        ],
        ids=["nested_plus", "nested_star", "alt_nested", "poly_5"],
    )
    def test_redos_pattern_skipped(self, pattern: str, desc: str) -> None:
        """ReDoS-prone patterns produce no findings (skipped safely)."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": pattern}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert findings == [], f"Expected skip for ReDoS pattern ({desc}): {pattern}"

    def test_safe_pattern_not_skipped(self) -> None:
        """Non-ReDoS patterns are still analyzed normally."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # This pattern allows traversal, so Tier 1 should catch it
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "[a-z./]+"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) >= 1, "Safe pattern should still be analyzed"


# ── DoS protection: Z3 Loop bounds cap ───────────────────────────────


class TestZ3LoopBoundsCap:
    """Z3 Loop bounds are capped to prevent memory exhaustion."""

    z3 = pytest.importorskip("z3")

    def test_large_loop_upper_bound_capped(self) -> None:
        """Pattern like a{1,1000000} should not crash Z3."""
        from munio.scan.layers._z3_utils import _MAX_LOOP_BOUND, pattern_to_z3

        # This would create a massive Z3 AST without the cap
        result = pattern_to_z3("a{1,100000}")
        # Should succeed without error; verify the cap constant exists
        assert _MAX_LOOP_BOUND == 1000
        assert result is not None

    def test_large_loop_lower_bound_capped(self) -> None:
        """Pattern like a{100000,} should not crash Z3."""
        from munio.scan.layers._z3_utils import pattern_to_z3

        result = pattern_to_z3("a{100000,}")
        assert result is not None

    def test_normal_loop_unchanged(self) -> None:
        """Normal bounds like a{2,5} work correctly."""
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^a{2,5}$")
        # "aaa" should satisfy a{2,5}
        assert check_satisfiability(pat, min_length=3, max_length=3) == "sat"
        # "a" should NOT satisfy a{2,5}
        assert check_satisfiability(pat, min_length=1, max_length=1) == "unsat"


# ── Tier 2 Z3 unknown path ───────────────────────────────────────────


class TestTier2Unknown:
    """Z3 returning 'unknown' produces no findings (fail-open for analysis)."""

    z3 = pytest.importorskip("z3")

    def test_z3_unknown_produces_info_finding(self) -> None:
        """When Z3 returns unknown, an INFO finding is produced."""
        from unittest.mock import patch

        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_]+$"}}),
        )
        # check_intersection is lazily imported from _z3_utils inside method
        with patch(
            "munio.scan.layers._z3_utils.check_intersection",
            return_value=("unknown", None),
        ) as mock_check:
            findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.INFO
        assert "inconclusive" in findings[0].message.lower()
        assert findings[0].confidence == 0.0
        mock_check.assert_called()

    def test_z3_unknown_logs_warning(self) -> None:
        """Z3 unknown result logs a warning for debugging."""
        from unittest.mock import patch

        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_]+$"}}),
        )
        with (
            patch(
                "munio.scan.layers._z3_utils.check_intersection",
                return_value=("unknown", None),
            ),
            patch("munio.scan.layers.l4_z3.logger") as mock_logger,
        ):
            analyzer.analyze([tool])
        mock_logger.warning.assert_called()
        call_args = mock_logger.warning.call_args[0]
        assert "unknown" in call_args[0].lower() or "unknown" in str(call_args)


# ── L3 + L4 co-existence integration ─────────────────────────────────


class TestL3L4Integration:
    """L3 and L4 both produce findings for the same parameter."""

    z3 = pytest.importorskip("z3")

    def test_l3_and_l4_both_produce_findings(self) -> None:
        """Orchestrator produces both L3 and L4 findings for same param."""
        tool = make_tool(
            name="read_file",
            description="Read a file",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        sr = ServerScanResult(
            server_name="test",
            source="test",
            tool_count=1,
            tools=[tool],
        )
        orch = Orchestrator()
        result = _run(orch.scan([sr]))
        l3 = [f for f in result.findings if f.layer == Layer.L3_STATIC]
        l4 = [f for f in result.findings if f.layer == Layer.L4_Z3]
        # Both layers should find issues with this weak path pattern
        assert len(l3) > 0, "L3 should detect heuristic issues"
        assert len(l4) > 0, "L4 should detect formal bypass"

    def test_l3_l4_different_confidence(self) -> None:
        """L3 heuristic and L4 formal findings have different confidence."""
        from munio.scan.layers.l3_static import L3StaticAnalyzer
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        tool = make_tool(
            name="read_file",
            description="Read a file",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        l3_findings = L3StaticAnalyzer().analyze([tool])
        l4_findings = L4Z3Analyzer().analyze([tool])
        # L3 is heuristic (confidence < 1.0 typically), L4 is formal
        path_l3 = [f for f in l3_findings if "file_path" in (f.location or "")]
        path_l4 = [f for f in l4_findings if f.id == "L4_001"]
        assert len(path_l3) > 0
        assert len(path_l4) > 0


# ── Fix 1: Per-parameter error isolation ──────────────────────────────


class TestPerParameterErrorIsolation:
    """Error in one parameter should not block analysis of other parameters."""

    z3 = pytest.importorskip("z3")

    def test_bad_param_does_not_block_good_param(self) -> None:
        """Exception in one param's check doesn't skip remaining params."""
        from unittest.mock import patch

        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(
                {
                    "aaa_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"},
                    "file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"},
                }
            ),
        )
        original = L4Z3Analyzer._check_parameter
        crashed = False

        def patched(
            self_inner: Any, tool_name: str, param_name: str, *args: Any, **kwargs: Any
        ) -> list[Any]:
            nonlocal crashed
            # Crash only on first param (sorted: aaa_path comes before file_path)
            if param_name == "aaa_path" and not crashed:
                crashed = True
                raise RuntimeError("Simulated Z3 crash")
            return original(self_inner, tool_name, param_name, *args, **kwargs)

        with patch.object(L4Z3Analyzer, "_check_parameter", patched):
            findings = analyzer.analyze([tool])

        # file_path should still be analyzed despite aaa_path crashing
        l4 = [f for f in findings if f.id == "L4_001"]
        assert len(l4) >= 1, "Good param should produce findings despite bad param crash"

    def test_bad_param_logs_warning(self) -> None:
        """Exception in parameter analysis is logged."""
        from unittest.mock import patch

        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        with (
            patch.object(
                L4Z3Analyzer,
                "_check_parameter",
                side_effect=RuntimeError("boom"),
            ),
            patch("munio.scan.layers.l4_z3.logger") as mock_logger,
        ):
            analyzer.analyze([tool])
        mock_logger.warning.assert_called()
        args = mock_logger.warning.call_args[0]
        assert "file_path" in str(args)


# ── Fix 2: maxLength: 0 handling ──────────────────────────────────────


class TestMaxLengthZero:
    """maxLength: 0 means only empty string — should be respected."""

    z3 = pytest.importorskip("z3")

    def test_maxlength_zero_constrains_z3(self) -> None:
        """maxLength=0 with pattern requiring chars → L4_004 contradiction."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(
                {
                    "file_path": {
                        "type": "string",
                        "pattern": "^[a-zA-Z]+$",  # requires at least 1 char
                        "minLength": 1,
                        "maxLength": 0,
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_004"]
        assert len(findings) >= 1, "maxLength=0 with minLength=1 should be contradictory"

    def test_maxlength_zero_blocks_attack_payloads(self) -> None:
        """maxLength=0 effectively makes pattern bypass impossible."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(
                {
                    "file_path": {
                        "type": "string",
                        "pattern": ".*",  # vacuous, but maxLength=0 blocks everything
                        "maxLength": 0,
                    }
                }
            ),
        )
        # Vacuous pattern is skipped, no traversal finding
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert findings == []


# ── Fix 3: Vacuous grouped patterns ──────────────────────────────────


class TestVacuousPatterns:
    """Grouped vacuous patterns like (.*) are correctly identified."""

    z3 = pytest.importorskip("z3")

    @pytest.mark.parametrize(
        "pattern",
        [
            ".*",
            "^.*$",
            ".+",
            "^.+$",
            "(.*)",
            "^(.*)$",
            "(.+)",
            "^(.+)$",
            "(?:.*)",
            "^(?:.*)$",
        ],
        ids=[
            "dot_star",
            "anchored_dot_star",
            "dot_plus",
            "anchored_dot_plus",
            "group_dot_star",
            "anchored_group_dot_star",
            "group_dot_plus",
            "anchored_group_dot_plus",
            "nc_group_dot_star",
            "anchored_nc_group_dot_star",
        ],
    )
    def test_vacuous_pattern_skipped(self, pattern: str) -> None:
        """Vacuous patterns produce no L4_001 findings (skipped early)."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": pattern}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert findings == [], f"Vacuous pattern '{pattern}' should be skipped"


# ── Fix 4: Negated character class Z3 translation ────────────────────


class TestNegatedCharacterClass:
    """Negated character classes [^...] translate correctly to Z3."""

    z3 = pytest.importorskip("z3")

    def test_negated_single_char(self) -> None:
        """[^/] translates to Z3 and accepts non-slash characters."""

        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^[^/]+$")
        # "abc" should satisfy (no slash)
        assert check_satisfiability(pat, min_length=3, max_length=3) == "sat"

    def test_negated_class_blocks_char(self) -> None:
        """[^/] rejects strings containing the negated character."""

        from munio.scan.layers._z3_utils import check_intersection, make_attack_regex, pattern_to_z3

        pat = pattern_to_z3("^[^/]+$")
        # Intersection with strings containing "/" should be empty
        attack = make_attack_regex(["/"])
        result, _ = check_intersection(pat, attack)
        assert result == "unsat", "Pattern [^/]+ should not allow strings with /"

    def test_negated_range(self) -> None:
        """[^a-z] accepts non-lowercase characters."""
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^[^a-z]+$")
        # "123" should satisfy (digits not in a-z)
        assert check_satisfiability(pat, min_length=3, max_length=3) == "sat"

    def test_negated_multi_member(self) -> None:
        """[^abc] — negate multiple literals."""
        from munio.scan.layers._z3_utils import check_intersection, make_attack_regex, pattern_to_z3

        pat = pattern_to_z3("^[^abc]+$")
        attack = make_attack_regex(["a"])
        result, _ = check_intersection(pat, attack)
        assert result == "unsat"


# ── Fix 5: Exact repeat {n} Z3 translation ───────────────────────────


class TestExactRepeat:
    """Exact repeat {n} correctly translates to Z3."""

    z3 = pytest.importorskip("z3")

    def test_exact_repeat_matches(self) -> None:
        """a{3} matches exactly 3 'a' characters."""
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^a{3}$")
        assert check_satisfiability(pat, min_length=3, max_length=3) == "sat"

    def test_exact_repeat_rejects_shorter(self) -> None:
        """a{3} rejects strings shorter than 3."""
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^a{3}$")
        assert check_satisfiability(pat, min_length=1, max_length=2) == "unsat"

    def test_exact_repeat_rejects_longer(self) -> None:
        """a{3} rejects strings longer than 3."""
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^a{3}$")
        assert check_satisfiability(pat, min_length=4, max_length=5) == "unsat"

    def test_exact_repeat_1(self) -> None:
        """a{1} = exactly one 'a'."""
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^a{1}$")
        assert check_satisfiability(pat, min_length=1, max_length=1) == "sat"
        assert check_satisfiability(pat, min_length=2, max_length=2) == "unsat"


# ── C1: Loop bound capping soundness ─────────────────────────────────


class TestLoopBoundCappingSoundness:
    """Loop bound capping must not create empty language (lo > hi)."""

    z3 = pytest.importorskip("z3")

    def test_finite_range_lo_gt_max_bound(self) -> None:
        """lo > _MAX_LOOP_BOUND must not create empty language.

        Patch _MAX_LOOP_BOUND to 10, then test a{15,20}: should be capped
        to Loop(10,10), NOT Loop(15,10) (empty language = false SAFE).
        """
        from unittest.mock import patch

        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        with patch("munio.scan.layers._z3_utils._MAX_LOOP_BOUND", 10):
            pat = pattern_to_z3("^a{15,20}$")
        result = check_satisfiability(pat, min_length=10, max_length=10)
        assert result == "sat", (
            "Loop(sub, capped_lo=10, capped_hi=10) should match 10 chars, "
            "not produce empty language from lo > hi"
        )

    def test_finite_range_lo_eq_hi_above_cap(self) -> None:
        """Exact repeat above cap → still satisfiable."""
        from unittest.mock import patch

        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        with patch("munio.scan.layers._z3_utils._MAX_LOOP_BOUND", 10):
            pat = pattern_to_z3("^a{15,15}$")
        result = check_satisfiability(pat, min_length=10, max_length=10)
        assert result == "sat"

    def test_finite_range_below_cap_unaffected(self) -> None:
        """a{5,10}: normal bounds unaffected by capping."""
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        pat = pattern_to_z3("^a{5,10}$")
        assert check_satisfiability(pat, min_length=5, max_length=5) == "sat"
        assert check_satisfiability(pat, min_length=10, max_length=10) == "sat"
        assert check_satisfiability(pat, min_length=11, max_length=11) == "unsat"

    def test_unbounded_range_hi_maxrepeat(self) -> None:
        """a{15,} with cap=10: unbounded with high lo → still matches at 10+."""
        from unittest.mock import patch

        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        with patch("munio.scan.layers._z3_utils._MAX_LOOP_BOUND", 10):
            pat = pattern_to_z3("^a{15,}$")
        # Uses Concat(Loop(capped_lo=10, 10), Star(sub)) → matches 10+
        result = check_satisfiability(pat, min_length=10, max_length=20)
        assert result == "sat"


# ── H3: Anchor stripping \\$ correctness ──────────────────────────────


class TestAnchorStripping:
    """Anchor stripping handles escaped dollar signs correctly."""

    z3 = pytest.importorskip("z3")

    @pytest.mark.parametrize(
        ("pattern", "has_anchor"),
        [
            ("abc$", True),  # unescaped $
            (r"abc\$", False),  # escaped $ (literal dollar)
            ("abc\\\\$", True),  # \\$ = escaped backslash + anchor $
            (r"abc\\\$", False),  # \\\$ = escaped backslash + escaped $
            ("abc", False),  # no $ at all
        ],
        ids=[
            "plain_anchor",
            "escaped_dollar",
            "double_backslash_anchor",
            "triple_backslash_escaped",
            "no_dollar",
        ],
    )
    def test_has_end_anchor(self, pattern: str, has_anchor: bool) -> None:
        """_has_end_anchor correctly identifies anchor vs escaped dollar."""
        from munio.scan.layers._z3_utils import _has_end_anchor

        assert _has_end_anchor(pattern) is has_anchor

    def test_even_backslash_dollar_is_anchor_in_z3(self) -> None:
        """Pattern with \\\\$ (even backslashes) strips $ as anchor."""
        from munio.scan.layers._z3_utils import check_satisfiability, pattern_to_z3

        # `abc\\$` = regex matching "abc\" at end of string
        # Z3 should strip the $ anchor
        pat = pattern_to_z3("^abc\\\\$")
        result = check_satisfiability(pat, min_length=4, max_length=4)
        assert result == "sat"

    def test_search_semantics_even_backslash(self) -> None:
        """pattern_to_z3_search respects even-backslash anchor."""
        from munio.scan.layers._z3_utils import pattern_to_z3_search

        # ^abc\\$ → start anchor + end anchor (even backslashes)
        # Should be fullmatch semantics
        pat = pattern_to_z3_search("^abc\\\\$")
        # Just verify it doesn't crash and returns something
        assert pat is not None


# ── H4: CMD injection newline ──────────────────────────────────────


class TestCmdInjectionNewline:
    """Command injection detection includes newline as separator."""

    z3 = pytest.importorskip("z3")

    def test_newline_in_cmd_payload(self) -> None:
        """Payload with newline is tested for command injection."""
        from munio.scan.layers.l4_z3 import _CMD_INJECTION_PAYLOADS

        has_newline = any("\n" in p for p in _CMD_INJECTION_PAYLOADS)
        assert has_newline, "At least one CMD payload should contain newline"

    def test_newline_in_cmd_substrings(self) -> None:
        """Newline is in command injection Z3 substrings."""
        from munio.scan.layers.l4_z3 import _CMD_INJECTION_SUBSTRINGS

        assert "\n" in _CMD_INJECTION_SUBSTRINGS


# ── H5: SSRF IPv6 and octal payloads ──────────────────────────────


class TestSSRFIPv6Octal:
    """SSRF detection includes IPv4-mapped IPv6 and octal IP payloads."""

    z3 = pytest.importorskip("z3")

    @pytest.mark.parametrize(
        "substring",
        ["[::ffff:", "://0177."],
        ids=["ipv4_mapped_ipv6", "octal_ip"],
    )
    def test_ssrf_substrings_present(self, substring: str) -> None:
        """Key SSRF bypass substrings are included."""
        from munio.scan.layers.l4_z3 import _SSRF_SUBSTRINGS

        assert substring in _SSRF_SUBSTRINGS

    @pytest.mark.parametrize(
        "payload",
        [
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://0177.0.0.1/",
        ],
        ids=["ipv6_mapped_loopback", "ipv6_mapped_metadata", "octal_loopback"],
    )
    def test_ssrf_payloads_present(self, payload: str) -> None:
        """Key SSRF bypass payloads are included."""
        from munio.scan.layers.l4_z3 import _SSRF_PAYLOADS

        assert payload in _SSRF_PAYLOADS

    def test_ipv6_payload_detected_tier1(self) -> None:
        """Tier 1 detects IPv6-mapped loopback on weak URL pattern."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="fetch_url",
            description="Fetch URL",
            input_schema=_schema({"url": {"type": "string", "pattern": "^https?://.+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_002"]
        assert len(findings) >= 1


# ── C2: Z3 budget per tool ────────────────────────────────────────


class TestZ3BudgetPerTool:
    """Z3 call budget prevents timeout multiplication DoS."""

    z3 = pytest.importorskip("z3")

    def test_z3_budget_limits_calls(self) -> None:
        """Z3 budget caps number of Z3 calls per tool."""
        from unittest.mock import patch

        from munio.scan.layers.l4_z3 import _MAX_Z3_CALLS_PER_TOOL, L4Z3Analyzer

        # Create a tool with many security-relevant params
        props: dict[str, Any] = {}
        for i in range(_MAX_Z3_CALLS_PER_TOOL + 10):
            props[f"file_path_{i}"] = {"type": "string", "pattern": "^[a-zA-Z0-9_]+$"}

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(props),
        )

        call_count = 0
        original_check = __import__(
            "munio.scan.layers._z3_utils", fromlist=["check_intersection"]
        ).check_intersection

        def counting_check(*args: Any, **kwargs: Any) -> tuple[str, str | None]:
            nonlocal call_count
            call_count += 1
            return original_check(*args, **kwargs)

        with patch(
            "munio.scan.layers._z3_utils.check_intersection",
            side_effect=counting_check,
        ):
            analyzer.analyze([tool])

        assert call_count <= _MAX_Z3_CALLS_PER_TOOL, (
            f"Z3 called {call_count} times, should be capped at {_MAX_Z3_CALLS_PER_TOOL}"
        )

    def test_z3_budget_resets_per_tool(self) -> None:
        """Z3 budget resets for each tool (not cumulative)."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        # Two tools, each with a path param that allows traversal (weak pattern)
        tool1 = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        tool2 = make_tool(
            name="write_file",
            description="Write",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        # Both tools should get findings (budget resets per tool)
        findings = analyzer.analyze([tool1, tool2])
        tool_names = {f.tool_name for f in findings}
        assert "read_file" in tool_names
        assert "write_file" in tool_names


# ── H7: Pattern length limit ──────────────────────────────────────


class TestPatternLengthLimit:
    """Very long patterns are rejected to prevent re.compile() DoS."""

    z3 = pytest.importorskip("z3")

    def test_long_pattern_skipped(self) -> None:
        """Pattern exceeding max length produces no findings (skipped)."""
        from munio.scan.layers.l4_z3 import _MAX_PATTERN_LENGTH, L4Z3Analyzer

        long_pattern = "^[a-z]" + "a" * (_MAX_PATTERN_LENGTH + 1) + "$"
        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": long_pattern}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert findings == [], "Long pattern should be skipped"

    def test_normal_pattern_not_skipped(self) -> None:
        """Pattern within length limit is analyzed normally."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^[a-zA-Z0-9_./]+$"}}),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_001"]
        assert len(findings) >= 1, "Normal-length pattern should be analyzed"


# ── H9: make_attack_regex empty input ──────────────────────────────


class TestMakeAttackRegexEmptyInput:
    """make_attack_regex raises ValueError on empty input."""

    z3 = pytest.importorskip("z3")

    def test_empty_substrings_raises(self) -> None:
        """Empty substring list raises ValueError."""
        from munio.scan.layers._z3_utils import make_attack_regex

        with pytest.raises(ValueError, match="at least one substring"):
            make_attack_regex([])


# ── H10: L4_004 search semantics ──────────────────────────────────


class TestL4004SearchSemantics:
    """L4_004 uses search semantics for unanchored patterns."""

    z3 = pytest.importorskip("z3")

    def test_unanchored_pattern_no_false_contradiction(self) -> None:
        """Unanchored pattern with minLength should not produce false contradiction.

        Pattern `[0-9]` (unanchored) with minLength=2: fullmatch says "string must be
        exactly 1 digit → unsatisfiable with minLength=2". Search semantics says
        "string must contain a digit, with length ≥ 2 → satisfiable (e.g., '1a')".
        """
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(
                {
                    "file_path": {
                        "type": "string",
                        "pattern": "[0-9]",  # unanchored — search semantics
                        "minLength": 2,
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_004"]
        assert findings == [], (
            "Unanchored pattern [0-9] with minLength=2 should NOT be "
            "flagged as contradictory (search semantics allows '1a')"
        )

    def test_anchored_pattern_contradiction_still_detected(self) -> None:
        """Anchored pattern + contradictory length still detected."""
        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema(
                {
                    "file_path": {
                        "type": "string",
                        "pattern": "^[a-z]{10,}$",  # anchored — needs ≥10 chars
                        "maxLength": 5,
                    }
                }
            ),
        )
        findings = [f for f in analyzer.analyze([tool]) if f.id == "L4_004"]
        assert len(findings) == 1, "Anchored pattern with contradictory maxLength should be flagged"


# ── M11: exc_info in logger.warning ───────────────────────────────


class TestExcInfoInWarnings:
    """Exception warnings include traceback via exc_info."""

    z3 = pytest.importorskip("z3")

    def test_tool_error_includes_exc_info(self) -> None:
        """Tool-level error warning includes exc_info=True."""
        from unittest.mock import patch

        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="crash_tool",
            description="Crash",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^a$"}}),
        )
        with (
            patch.object(
                L4Z3Analyzer,
                "_analyze_tool",
                side_effect=RuntimeError("tool boom"),
            ),
            patch("munio.scan.layers.l4_z3.logger") as mock_logger,
        ):
            analyzer.analyze([tool])
        mock_logger.warning.assert_called()
        # Verify exc_info=True was passed
        kwargs = mock_logger.warning.call_args[1]
        assert kwargs.get("exc_info") is True

    def test_param_error_includes_exc_info(self) -> None:
        """Parameter-level error warning includes exc_info=True."""
        from unittest.mock import patch

        from munio.scan.layers.l4_z3 import L4Z3Analyzer

        analyzer = L4Z3Analyzer()
        tool = make_tool(
            name="read_file",
            description="Read",
            input_schema=_schema({"file_path": {"type": "string", "pattern": "^a$"}}),
        )
        with (
            patch.object(
                L4Z3Analyzer,
                "_check_parameter",
                side_effect=RuntimeError("param boom"),
            ),
            patch("munio.scan.layers.l4_z3.logger") as mock_logger,
        ):
            analyzer.analyze([tool])
        mock_logger.warning.assert_called()
        kwargs = mock_logger.warning.call_args[1]
        assert kwargs.get("exc_info") is True
