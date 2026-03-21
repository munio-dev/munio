"""CLI support for munio compose command."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from typing import Any

from munio.scan.models import OutputFormat

__all__ = ["run_compose"]


def _load_schema_file(json_file: Path, server_name: str) -> tuple[list[Any], str | None]:
    """Load a single schema file, returning (tools, error_message)."""
    from munio.scan.schema_loader import load_from_file

    try:
        loaded = load_from_file(json_file, server_name=server_name)
    except Exception as exc:
        return [], f"Warning: failed to load {json_file.name}: {exc}"
    return loaded, None


def run_compose(
    *,
    config: str | None = None,
    schemas_dir: str | None = None,
    output_format: str = "text",
    output_file: str | None = None,
    quiet: bool = False,
    details: bool = False,
) -> None:
    """Run composition analysis."""
    import typer

    from munio.scan.composition import CompositionAnalyzer
    from munio.scan.models import ToolDefinition

    tools: list[ToolDefinition] = []
    try:
        fmt = OutputFormat(output_format)
    except ValueError:
        typer.echo(
            f"Error: Invalid format '{output_format}'. Choose from: text, json, markdown",
            err=True,
        )
        raise typer.Exit(code=2) from None

    if schemas_dir is not None:
        # Offline mode: read pre-fetched JSON schemas
        schemas_path = Path(schemas_dir)
        if not schemas_path.is_dir():
            typer.echo(f"Error: Schemas directory not found: {schemas_dir}", err=True)
            raise typer.Exit(code=2)

        for json_file in sorted(schemas_path.glob("*.json")):
            loaded, err = _load_schema_file(json_file, json_file.stem)
            if err:
                typer.echo(err, err=True)
            tools.extend(loaded)

    elif config is not None:
        # Config mode: discover servers from config file and connect
        from munio.scan.config import ScanConfig
        from munio.scan.discovery import discover_from_file

        config_path = Path(config)
        try:
            servers = discover_from_file(config_path)
        except Exception:
            typer.echo("Error: Failed to parse config file", err=True)
            raise typer.Exit(code=2) from None

        if not servers:
            typer.echo(f"Error: No MCP servers found in {config}", err=True)
            raise typer.Exit(code=2)

        scan_config = ScanConfig()
        from munio.scan.cli import _connect_to_servers

        results = _connect_to_servers(servers, scan_config)
        for sr in results:
            tools.extend(sr.tools)

    else:
        # Auto-discover mode
        from munio.scan.config import ScanConfig
        from munio.scan.discovery import discover_servers

        servers = discover_servers()
        if not servers:
            typer.echo(
                "Error: No MCP servers discovered from IDE configurations.\n"
                "Try: munio compose --schemas-dir ./schemas\n"
                "  or: munio compose --config path/to/config.json",
                err=True,
            )
            raise typer.Exit(code=2)

        scan_config = ScanConfig()
        from munio.scan.cli import _connect_to_servers

        results = _connect_to_servers(servers, scan_config)
        for sr in results:
            tools.extend(sr.tools)

    if not tools:
        typer.echo("Error: No tools loaded for analysis", err=True)
        raise typer.Exit(code=2)

    # Run analysis
    analyzer = CompositionAnalyzer()
    report = analyzer.analyze(tools)

    # Output
    output_text: str | None = None

    if fmt == OutputFormat.JSON:
        output_text = json.dumps(
            report.model_dump(mode="json"),
            indent=2,
            default=str,
        )
    elif fmt == OutputFormat.MARKDOWN:
        output_text = _format_markdown(report)
    elif fmt == OutputFormat.SARIF:
        typer.echo("Error: SARIF output is not supported for compose. Use --format json.", err=True)
        raise typer.Exit(code=2)
    elif not quiet:
        output_text = _format_compose_text(report, details=details)

    if output_text:
        if output_file:
            out_path = Path(output_file)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output_text, encoding="utf-8")
        else:
            typer.echo(output_text)

    # Exit code: 1 if CRITICAL/HIGH chains, 0 otherwise
    has_critical = any(c.risk in ("CRITICAL", "HIGH") for c in report.chains)
    raise typer.Exit(code=1 if has_critical else 0)


def _grade_color(grade_val: str) -> str:
    """Map danger grade to Rich color."""
    return {
        "A": "green bold",
        "B": "green",
        "C": "yellow",
        "D": "red",
        "F": "red bold",
    }.get(grade_val, "white")


def _risk_color(risk: str) -> str:
    """Map risk level to Rich color."""
    return {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }.get(risk, "white")


def _format_compose_text(
    report: Any,
    *,
    details: bool = False,
) -> str:
    """Format CompositionReport as Rich text."""
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    buf = StringIO()
    console = Console(file=buf, force_terminal=True)

    # Header
    console.print(
        f"[bold]munio compose[/bold] -- {report.server_count} servers, {report.tool_count} tools\n"
    )

    # Danger score
    gc = _grade_color(report.danger.grade.value)
    console.print(
        f"Danger: [{gc}]{report.danger.grade.value}[/{gc}]"
        f" ({report.danger.score}/100)"
        f" [dim]({report.danger.chain_count} chains,"
        f" {report.danger.amplification:.1f}x amplification)[/dim]\n"
    )

    if not report.chains:
        console.print("[green]No dangerous chains detected.[/green]")
    else:
        # Chains table
        table = Table(show_header=True, header_style="bold", show_lines=True)
        table.add_column("Risk", width=10)
        table.add_column("Chain")
        table.add_column("Score", justify="right", width=6)

        for chain in report.chains:
            rc = _risk_color(chain.risk)
            chain_str = " -> ".join(
                f"{n.tool_name}" + (f"@{n.server_name}" if n.server_name else "")
                for n in chain.nodes
            )
            cross = " [cyan](cross-server)[/cyan]" if chain.cross_server else ""
            desc = escape(chain.description)

            sig_icon = {"high": " \u25cf", "medium": " \u25d0", "low": " \u25cb"}.get(
                chain.signal, ""
            )
            table.add_row(
                f"[{rc}]{chain.risk}[/{rc}]{sig_icon}",
                f"{escape(chain_str)}{cross}\n[dim]{desc}[/dim]",
                f"{chain.score:.0f}",
            )

            if details:
                detail_lines = []
                for i, node in enumerate(chain.nodes):
                    caps = ", ".join(node.capabilities[:5])
                    detail_lines.append(
                        f"[dim]{i + 1}. {escape(node.tool_name)} ({node.role}): {caps}[/dim]"
                    )
                if chain.cwe:
                    detail_lines.append(f"[dim]CWE: {chain.cwe}[/dim]")
                table.add_row("", "\n".join(detail_lines), "", end_section=True)

        console.print(table)

        # Signal quality summary
        high = sum(1 for c in report.chains if c.signal == "high")
        medium = sum(1 for c in report.chains if c.signal == "medium")
        low = sum(1 for c in report.chains if c.signal == "low")
        console.print(
            f"\nSignal: [green]{high} high[/green]"
            f"  [yellow]{medium} medium[/yellow]"
            f"  [dim]{low} low[/dim]"
        )

        # CVE candidates
        if report.cve_drafts:
            console.print(f"\n[bold]{len(report.cve_drafts)} CVE candidates[/bold]")
            for draft in report.cve_drafts:
                console.print(
                    f"  - {escape(draft.title)}"
                    f" [dim](CVSS {draft.cvss_score:.1f},"
                    f" {draft.cvss_vector})[/dim]"
                )

    # Cross-command hints
    console.print()
    console.print(
        "[dim]Run munio scan for schema analysis, munio config-scan for supply chain checks[/dim]"
    )

    console.print(f"\n{report.elapsed_ms:.0f}ms")
    return buf.getvalue()


def _format_markdown(report: Any) -> str:
    """Format CompositionReport as markdown for CVE filing."""
    lines: list[str] = []

    lines.append("# Composition Analysis Report\n")
    lines.append(f"**Danger Score:** {report.danger.grade.value} ({report.danger.score}/100)\n")
    lines.append(
        f"**Servers:** {report.server_count} | "
        f"**Tools:** {report.tool_count} | "
        f"**Chains:** {report.danger.chain_count}\n"
    )

    high = sum(1 for c in report.chains if c.signal == "high")
    medium = sum(1 for c in report.chains if c.signal == "medium")
    low = sum(1 for c in report.chains if c.signal == "low")
    lines.append(f"**Signal quality:** {high} high, {medium} medium, {low} low\n")

    if report.cve_drafts:
        lines.append("---\n")
        lines.append("## CVE Candidates\n")

        for i, draft in enumerate(report.cve_drafts, 1):
            lines.append(f"### {i}. {draft.title}\n")
            lines.append(f"**Affected servers:** {', '.join(draft.affected_servers)}\n")
            lines.append(f"{draft.description}\n")
            lines.append(f"**CVSS:** {draft.cvss_score:.1f} (`{draft.cvss_vector}`)\n")
            lines.append(
                "> **Note:** CVSS estimated based on chain properties. Verify before filing.\n"
            )
            if draft.poc_narrative:
                lines.append("**Proof of Concept:**\n")
                lines.append(f"```\n{draft.poc_narrative}\n```\n")

    elif report.chains:
        lines.append("---\n")
        lines.append("## Detected Chains\n")
        for chain in report.chains:
            chain_str = " -> ".join(
                f"`{n.tool_name}`" + (f"@{n.server_name}" if n.server_name else "")
                for n in chain.nodes
            )
            cross = " (cross-server)" if chain.cross_server else ""
            lines.append(f"- **{chain.risk}**: {chain_str}{cross} -- {chain.description}\n")

        lines.append(
            "\n> **Note:** Chains detected via automated analysis. "
            "Verify exploitability before reporting.\n"
        )

    return "\n".join(lines)
