"""Tests for L3+L7 schema-source correlation."""

from __future__ import annotations

import pytest

from munio.scan.models import AttackType, Finding, FindingSeverity, Layer


def _l3(tool: str, cwe: str, confidence: float = 0.80) -> Finding:
    return Finding(
        id="L3_001",
        layer=Layer.L3_STATIC,
        severity=FindingSeverity.HIGH,
        tool_name=tool,
        message=f"Schema risk: {cwe}",
        cwe=cwe,
        location="inputSchema.properties.path",
        confidence=confidence,
    )


def _l7(tool: str, cwe: str, confidence: float = 0.85, location: str = "file:index.ts:42") -> Finding:
    return Finding(
        id="L7_001",
        layer=Layer.L7_SOURCE,
        severity=FindingSeverity.CRITICAL,
        tool_name=tool,
        message=f"Non-literal arg: {cwe}",
        cwe=cwe,
        location=location,
        confidence=confidence,
    )


class TestCorrelation:
    """Test L3+L7 finding correlation."""

    def _correlate(self, findings: list[Finding]) -> list[Finding]:
        from munio.scan.layers.correlation import correlate_findings
        return correlate_findings(findings)

    def test_exact_tool_exact_cwe_confirmed(self) -> None:
        """L3(read_file, CWE-22) + L7(read_file, CWE-22) → both boosted."""
        findings = [_l3("read_file", "CWE-22", 0.80), _l7("read_file", "CWE-22", 0.85)]
        result = self._correlate(findings)
        assert len(result) == 2
        l3_result = [f for f in result if f.layer == Layer.L3_STATIC][0]
        l7_result = [f for f in result if f.layer == Layer.L7_SOURCE][0]
        assert l3_result.confidence > 0.80  # boosted
        assert l7_result.confidence > 0.85  # boosted
        assert "CONFIRMED" in l3_result.description
        assert "CONFIRMED" in l7_result.description

    def test_dispatch_tool_probable(self) -> None:
        """L3(run_cmd, CWE-78) + L7(<dispatch>, CWE-78) → probable."""
        findings = [_l3("run_cmd", "CWE-78"), _l7("<dispatch>", "CWE-78")]
        result = self._correlate(findings)
        l3_result = [f for f in result if f.layer == Layer.L3_STATIC][0]
        assert l3_result.confidence > 0.80
        assert "PROBABLE" in l3_result.description or "CONFIRMED" not in l3_result.description

    def test_file_sweep_weak(self) -> None:
        """L3(query, CWE-89) + L7(<file-sweep>, CWE-89) → weak boost."""
        findings = [_l3("query", "CWE-89", 0.75), _l7("<file-sweep>", "CWE-89", 0.60)]
        result = self._correlate(findings)
        l3_result = [f for f in result if f.layer == Layer.L3_STATIC][0]
        # Weak boost: +0.03
        assert l3_result.confidence >= 0.75 + 0.03 - 0.01  # small float tolerance

    def test_no_cwe_overlap_no_correlation(self) -> None:
        """Different CWE groups → no correlation."""
        findings = [_l3("tool", "CWE-400"), _l7("tool", "CWE-78")]
        result = self._correlate(findings)
        l3_result = [f for f in result if f.layer == Layer.L3_STATIC][0]
        assert l3_result.confidence == 0.80  # unchanged

    def test_l3_only_untouched(self) -> None:
        """L3 findings without L7 match → unchanged."""
        findings = [_l3("tool", "CWE-22")]
        result = self._correlate(findings)
        assert len(result) == 1
        assert result[0].confidence == 0.80

    def test_l7_only_untouched(self) -> None:
        """L7 findings without L3 match → unchanged."""
        findings = [_l7("tool", "CWE-78")]
        result = self._correlate(findings)
        assert len(result) == 1
        assert result[0].confidence == 0.85

    def test_cwe_group_match(self) -> None:
        """L3(CWE-78) + L7(CWE-94) → same injection group, boosted."""
        findings = [_l3("tool", "CWE-78"), _l7("tool", "CWE-94")]
        result = self._correlate(findings)
        l3_result = [f for f in result if f.layer == Layer.L3_STATIC][0]
        assert l3_result.confidence > 0.80  # boosted (group match)

    def test_confidence_capped_at_099(self) -> None:
        """High confidence findings don't exceed 0.99."""
        findings = [_l3("tool", "CWE-22", 0.95), _l7("tool", "CWE-22", 0.95)]
        result = self._correlate(findings)
        for f in result:
            assert f.confidence <= 0.99

    def test_empty_findings(self) -> None:
        """Empty list → empty result."""
        assert self._correlate([]) == []

    def test_non_l3_l7_findings_pass_through(self) -> None:
        """L1/L2/L5 findings pass through unchanged."""
        l1 = Finding(
            id="L1_001", layer=Layer.L1_SCHEMA, severity=FindingSeverity.LOW,
            tool_name="t", message="m", confidence=0.90,
        )
        result = self._correlate([l1])
        assert len(result) == 1
        assert result[0].confidence == 0.90
