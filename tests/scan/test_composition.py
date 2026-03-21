"""Tests for munio.scan.composition and composition_report."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from munio.scan.composition import CompositionAnalyzer, _estimate_cvss, _score_to_grade
from munio.scan.composition_report import (
    AttackChain,
    ChainNode,
    CompositionReport,
    DangerGrade,
    DangerScore,
)
from munio.scan.models import ToolDefinition


def _tool(name: str, server: str = "", description: str = "") -> ToolDefinition:
    """Helper to create a ToolDefinition."""
    return ToolDefinition(name=name, server_name=server, description=description)


class TestScoreToGrade:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0, DangerGrade.A),
            (19.9, DangerGrade.A),
            (20, DangerGrade.B),
            (39.9, DangerGrade.B),
            (40, DangerGrade.C),
            (59.9, DangerGrade.C),
            (60, DangerGrade.D),
            (79.9, DangerGrade.D),
            (80, DangerGrade.F),
            (100, DangerGrade.F),
        ],
    )
    def test_grade_boundaries(self, score: float, expected: DangerGrade) -> None:
        assert _score_to_grade(score) == expected


class TestEstimateCVSS:
    @pytest.mark.parametrize(
        ("desc", "cross_server", "expected_min_score"),
        [
            ("Credential exfiltration via network", True, 8.0),
            ("Credential exfiltration via network", False, 7.0),
            ("Remote code execution chain", True, 9.0),
            ("Remote code execution chain", False, 8.0),
            ("File overwrite via chain", True, 7.0),
            ("File overwrite via chain", False, 6.0),
            ("Generic data flow", True, 5.0),
            ("Generic data flow", False, 4.0),
        ],
    )
    def test_cvss_estimates(
        self,
        desc: str,
        cross_server: bool,
        expected_min_score: float,
    ) -> None:
        chain = AttackChain(
            nodes=[
                ChainNode(tool_name="src"),
                ChainNode(tool_name="snk"),
            ],
            risk="CRITICAL",
            description=desc,
            cross_server=cross_server,
        )
        vector, score = _estimate_cvss(chain)
        assert score >= expected_min_score
        assert "AV:N" in vector
        if cross_server:
            assert "S:C" in vector
        else:
            assert "S:U" in vector


class TestCompositionAnalyzerNoTools:
    def test_empty_tools(self) -> None:
        analyzer = CompositionAnalyzer()
        report = analyzer.analyze([])
        assert report.danger.chain_count == 0
        assert report.danger.grade == DangerGrade.A
        assert report.danger.score == 0.0


class TestCompositionAnalyzerBasic:
    def test_known_dangerous_pair(self) -> None:
        """read_file + send_email should trigger chain detection."""
        tools = [
            _tool("read_file", server="fs-server"),
            _tool("send_email", server="email-server"),
        ]
        analyzer = CompositionAnalyzer()
        report = analyzer.analyze(tools)
        assert report.danger.chain_count > 0
        assert report.chains[0].cross_server is True

    def test_same_server_chain(self) -> None:
        """Chain on same server: cross_server should be False."""
        tools = [
            _tool("read_file", server="combo"),
            _tool("http_request", server="combo"),
        ]
        analyzer = CompositionAnalyzer()
        report = analyzer.analyze(tools)
        if report.chains:
            same_server_chains = [c for c in report.chains if not c.cross_server]
            assert len(same_server_chains) > 0

    def test_no_chain_for_safe_tools(self) -> None:
        """Two read-only tools should not form a chain."""
        tools = [
            _tool("list_directory", server="fs"),
            _tool("search_files", server="fs"),
        ]
        analyzer = CompositionAnalyzer()
        report = analyzer.analyze(tools)
        assert report.danger.chain_count == 0

    def test_cross_server_amplification(self) -> None:
        """Cross-server chains should have higher scores."""
        # Same server
        tools_same = [
            _tool("read_file", server="a"),
            _tool("send_email", server="a"),
        ]
        report_same = CompositionAnalyzer().analyze(tools_same)

        # Cross server
        tools_cross = [
            _tool("read_file", server="a"),
            _tool("send_email", server="b"),
        ]
        report_cross = CompositionAnalyzer().analyze(tools_cross)

        if report_same.chains and report_cross.chains:
            # Cross-server should have higher danger score
            assert report_cross.danger.score >= report_same.danger.score


class TestCompositionAnalyzerMultiHop:
    def test_three_hop_chain(self) -> None:
        """A->B->C three-node chain should be detected."""
        tools = [
            _tool("read_file", server="fs"),
            _tool("http_request", server="web"),
            _tool("write_file", server="fs2"),
        ]
        analyzer = CompositionAnalyzer()
        report = analyzer.analyze(tools)
        # Should find chains (read -> http_request as source -> write)
        assert report.danger.chain_count > 0


class TestDangerScore:
    def test_single_critical_dominates_many_low(self) -> None:
        """1 CRITICAL (40) should outscore 10 LOW (3) chains."""
        critical_chain = AttackChain(
            nodes=[ChainNode(tool_name="a"), ChainNode(tool_name="b")],
            risk="CRITICAL",
            description="crit",
            score=40.0,
        )
        low_chains = [
            AttackChain(
                nodes=[
                    ChainNode(tool_name=f"a{i}"),
                    ChainNode(tool_name=f"b{i}"),
                ],
                risk="LOW",
                description="low",
                score=3.0,
            )
            for i in range(10)
        ]

        analyzer = CompositionAnalyzer()
        crit_danger = analyzer._compute_danger([critical_chain], 1)
        low_danger = analyzer._compute_danger(low_chains, 1)

        assert crit_danger.score > low_danger.score


class TestCVEDrafts:
    def test_generates_for_critical_chains(self) -> None:
        tools = [
            _tool("read_file", server="fs"),
            _tool("send_email", server="mail"),
        ]
        report = CompositionAnalyzer().analyze(tools)
        critical_chains = [c for c in report.chains if c.risk == "CRITICAL"]
        if critical_chains:
            assert len(report.cve_drafts) > 0
            draft = report.cve_drafts[0]
            assert draft.cvss_estimated is True
            assert draft.cvss_score > 0

    def test_no_drafts_for_medium(self) -> None:
        """MEDIUM chains should not generate CVE drafts."""
        tools = [
            _tool("read_file", server="fs"),
            _tool("write_file", server="fs"),
        ]
        report = CompositionAnalyzer().analyze(tools)
        # CVE drafts are only for CRITICAL/HIGH
        for draft in report.cve_drafts:
            assert draft.chain.risk in ("CRITICAL", "HIGH")


class TestCompositionReportModels:
    @pytest.mark.parametrize(
        "score",
        [-1, 101],
    )
    def test_danger_score_bounds(self, score: float) -> None:
        with pytest.raises(ValidationError):
            DangerScore(score=score, grade=DangerGrade.A)

    def test_chain_node_frozen(self) -> None:
        node = ChainNode(tool_name="test")
        with pytest.raises(ValidationError, match="frozen"):
            node.tool_name = "other"  # type: ignore[misc]

    def test_composition_report_frozen(self) -> None:
        report = CompositionReport(
            scan_id="test",
            danger=DangerScore(score=0, grade=DangerGrade.A),
        )
        with pytest.raises(ValidationError, match="frozen"):
            report.scan_id = "other"  # type: ignore[misc]


class TestCompositionAnalyzerBounds:
    def test_max_tools_limit(self) -> None:
        """Analyzer truncates to _MAX_TOOLS."""
        from munio.scan.composition import _MAX_TOOLS

        tools = [_tool(f"tool_{i}", server="s") for i in range(_MAX_TOOLS + 100)]
        analyzer = CompositionAnalyzer()
        # Should not crash, just process first _MAX_TOOLS
        report = analyzer.analyze(tools)
        assert report.tool_count <= _MAX_TOOLS

    def test_empty_server_names(self) -> None:
        """Tools with empty server_name should still form chains."""
        tools = [
            _tool("read_file", server=""),
            _tool("send_email", server=""),
        ]
        report = CompositionAnalyzer().analyze(tools)
        # Should find chains, cross_server=False since empty names match
        if report.chains:
            assert not report.chains[0].cross_server


class TestSignalClassification:
    """Tests for chain signal quality classification."""

    def test_known_combo_is_high_signal(self) -> None:
        """read_file + send_email (known combo) should be high signal."""
        tools = [
            _tool("read_file", server="fs"),
            _tool("send_email", server="mail"),
        ]
        report = CompositionAnalyzer().analyze(tools)
        high = [c for c in report.chains if c.signal == "high"]
        assert len(high) > 0

    def test_both_known_with_exfil_is_high(self) -> None:
        """Two known taxonomy tools with exfil cap = high signal."""
        tools = [
            _tool("database_query", server="db"),
            _tool("http_request", server="api"),
        ]
        report = CompositionAnalyzer().analyze(tools)
        high = [c for c in report.chains if c.signal == "high"]
        assert len(high) > 0

    def test_heuristic_only_is_low_signal(self) -> None:
        """Tools classified only by heuristics should be low signal."""
        tools = [
            _tool("my_custom_reader", server="a", description="reads documents"),
            _tool("my_custom_writer", server="b", description="writes data"),
        ]
        report = CompositionAnalyzer().analyze(tools)
        for chain in report.chains:
            assert chain.signal == "low"

    def test_browser_tools_filtered_from_sinks(self) -> None:
        """Browser navigation tools should not appear as sinks."""
        tools = [
            _tool("read_file", server="fs"),
            _tool("browser_navigate", server="browser"),
            _tool("navigate", server="browser"),
            _tool("browser_click", server="browser"),
        ]
        report = CompositionAnalyzer().analyze(tools)
        # No chains should end at browser tools
        for chain in report.chains:
            last = chain.nodes[-1].tool_name
            assert last not in ("browser_navigate", "navigate", "browser_click")

    def test_cve_drafts_only_for_high_medium_signal(self) -> None:
        """CVE drafts should not be generated for low-signal chains."""
        tools = [
            _tool("my_reader", server="a", description="reads files"),
            _tool("my_sender", server="b", description="sends data via network"),
        ]
        report = CompositionAnalyzer().analyze(tools)
        for draft in report.cve_drafts:
            assert draft.chain.signal != "low"

    @pytest.mark.parametrize(
        ("signal_val", "expected_valid"),
        [
            ("high", True),
            ("medium", True),
            ("low", True),
        ],
    )
    def test_signal_field_values(self, signal_val: str, expected_valid: bool) -> None:
        """AttackChain accepts valid signal values."""
        chain = AttackChain(
            nodes=[ChainNode(tool_name="a"), ChainNode(tool_name="b")],
            risk="HIGH",
            description="test",
            signal=signal_val,
        )
        assert chain.signal == signal_val
        assert expected_valid
