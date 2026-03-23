"""Tests for munio.scan.compose_cli."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

import re
from pathlib import Path as _Path

from click.exceptions import Exit as ClickExit

from munio.scan.compose_cli import (
    _format_compose_text,
    _format_markdown,
    run_compose,
)
from munio.scan.composition_report import (
    AttackChain,
    ChainNode,
    CompositionReport,
    CVEDraft,
    DangerGrade,
    DangerScore,
)


def _make_report(*, chains: list[AttackChain] | None = None) -> CompositionReport:
    """Create a test report."""
    chains = chains or []
    return CompositionReport(
        scan_id="test-123",
        server_count=2,
        tool_count=5,
        chains=chains,
        danger=DangerScore(
            score=45.0 if chains else 0.0,
            grade=DangerGrade.C if chains else DangerGrade.A,
            chain_count=len(chains),
            server_count=2,
        ),
        elapsed_ms=42.0,
    )


def _make_chain(
    *,
    risk: str = "CRITICAL",
    cross_server: bool = True,
    signal: str = "high",
) -> AttackChain:
    return AttackChain(
        nodes=[
            ChainNode(
                tool_name="read_file",
                server_name="fs",
                capabilities=["file_read"],
                role="P",
            ),
            ChainNode(
                tool_name="send_email",
                server_name="mail",
                capabilities=["email_send"],
                role="S",
            ),
        ],
        risk=risk,
        description="Credential exfiltration via email",
        cwe="CWE-200",
        cross_server=cross_server,
        score=60.0,
        signal=signal,
    )


class TestFormatComposeText:
    def test_no_chains(self) -> None:
        report = _make_report()
        text = _format_compose_text(report)
        assert "No dangerous chains" in text

    def test_with_chains(self) -> None:
        chain = _make_chain()
        report = _make_report(chains=[chain])
        text = _format_compose_text(report)
        assert "CRITICAL" in text
        assert "read_file" in text
        assert "send_email" in text
        assert "cross-server" in text

    def test_details_mode(self) -> None:
        chain = _make_chain()
        report = _make_report(chains=[chain])
        text = _format_compose_text(report, details=True)
        assert "file_read" in text

    def test_cve_candidates_shown(self) -> None:
        chain = _make_chain()
        draft = CVEDraft(
            title="Test CVE",
            affected_servers=["fs", "mail"],
            description="Test description",
            chain=chain,
            cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
            cvss_score=8.6,
        )
        report = CompositionReport(
            scan_id="test",
            server_count=2,
            tool_count=5,
            chains=[chain],
            danger=DangerScore(score=45, grade=DangerGrade.C, chain_count=1, server_count=2),
            cve_drafts=[draft],
            elapsed_ms=10,
        )
        text = _format_compose_text(report)
        assert "CVE candidates" in text
        assert "8.6" in text


class TestFormatMarkdown:
    def test_no_chains(self) -> None:
        report = _make_report()
        md = _format_markdown(report)
        assert "# Composition Analysis" in md
        assert "Danger Score" in md

    def test_with_cve_drafts(self) -> None:
        chain = _make_chain()
        draft = CVEDraft(
            title="Cross-server credential leak",
            affected_servers=["fs", "mail"],
            description="Test",
            chain=chain,
            cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
            cvss_score=8.6,
            poc_narrative="Step 1: read\nStep 2: send",
        )
        report = CompositionReport(
            scan_id="test",
            server_count=2,
            tool_count=5,
            chains=[chain],
            danger=DangerScore(score=45, grade=DangerGrade.C, chain_count=1, server_count=2),
            cve_drafts=[draft],
            elapsed_ms=10,
        )
        md = _format_markdown(report)
        assert "## CVE Candidates" in md
        assert "estimated" in md.lower()
        assert "Proof of Concept" in md


class TestRunComposeWithSchemas:
    def test_schemas_dir_not_found(self) -> None:
        """Non-existent schemas dir should exit with code 2."""

        with pytest.raises((SystemExit, ClickExit)) as exc_info:
            run_compose(schemas_dir="/nonexistent/path")
        exit_code = getattr(exc_info.value, "exit_code", getattr(exc_info.value, "code", None))
        assert exit_code == 2

    def test_schemas_dir_with_tools(self, tmp_path: Path) -> None:
        """Load tools from JSON files in schemas dir."""

        tools = [
            {"name": "read_file", "description": "Read a file"},
            {"name": "send_email", "description": "Send email"},
        ]
        _Path(str(tmp_path / "test.json")).write_text(json.dumps(tools))

        # Should run without error (will exit via typer.Exit)
        with pytest.raises((SystemExit, ClickExit)) as exc_info:
            run_compose(schemas_dir=str(tmp_path), output_format="json")
        # Exit code 0 or 1 (not 2 = error)
        exit_code = getattr(exc_info.value, "exit_code", getattr(exc_info.value, "code", None))
        assert exit_code in (0, 1)


class TestSignalDisplay:
    """Tests for signal quality display in CLI output."""

    def test_text_output_shows_signal_icons(self) -> None:
        """Signal indicators should appear in the risk column."""
        chain = _make_chain(signal="high")
        report = _make_report(chains=[chain])
        text = _format_compose_text(report)
        # High signal icon (filled circle)
        assert "\u25cf" in text

    def test_text_output_shows_signal_summary(self) -> None:
        """Signal summary line should appear after chain table."""

        chain = _make_chain(signal="high")
        report = _make_report(chains=[chain])
        text = _format_compose_text(report)
        assert "Signal:" in text
        # Strip ANSI codes for content check
        plain = re.sub(r"\x1b\[[0-9;]*m", "", text)
        assert "1 high" in plain

    @pytest.mark.parametrize(
        ("signal", "icon"),
        [
            ("high", "\u25cf"),
            ("medium", "\u25d0"),
            ("low", "\u25cb"),
        ],
    )
    def test_signal_icons_per_level(self, signal: str, icon: str) -> None:
        """Each signal level should use the correct icon."""
        chain = _make_chain(signal=signal)
        report = _make_report(chains=[chain])
        text = _format_compose_text(report)
        assert icon in text

    def test_markdown_shows_signal_quality(self) -> None:
        """Markdown output should include signal quality summary."""
        chain = _make_chain(signal="high")
        report = _make_report(chains=[chain])
        md = _format_markdown(report)
        assert "Signal quality:" in md
        assert "1 high" in md
