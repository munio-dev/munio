"""munio scan CLI: MCP Security Scanner.

This module provides the scan CLI as both a standalone app (``create_app``)
and a reusable ``run_scan()`` function that the unified ``munio`` CLI imports.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from io import StringIO
from pathlib import Path
from typing import Any, NoReturn

from munio.scan.models import FindingSeverity, Layer, OutputFormat

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# ── Layer display names and install hints ────────────────────────────
_LAYER_DISPLAY: dict[Layer, str] = {
    Layer.L1_SCHEMA: "L1 Schema",
    Layer.L2_HEURISTIC: "L2 Heuristic",
    Layer.L2_CLASSIFIER: "L2.5 Classifier",
    Layer.L2_MULTILINGUAL: "L2.6 ML",
    Layer.L3_STATIC: "L3 Static",
    Layer.L4_Z3: "L4 Z3",
    Layer.L5_COMPOSITIONAL: "L5 Composition",
    Layer.L7_SOURCE: "L7 Source",
}

# Layers that are not in defaults but can be enabled — show as "available" hint
_OPT_IN_LAYERS: dict[Layer, str] = {
    Layer.L7_SOURCE: "pip install 'munio[source]', then use --source <dir>",
}

# Priority for the tip (higher = more impactful to highlight)
_LAYER_TIP_PRIORITY: dict[Layer, int] = {
    Layer.L7_SOURCE: 100,
    Layer.L4_Z3: 90,
    Layer.L2_MULTILINGUAL: 80,
    Layer.L2_CLASSIFIER: 60,
}

_NPM_PKG_RE = re.compile(r"^@?[a-z0-9][-a-z0-9]*/[a-z0-9][-a-z0-9._]*$|^[a-z0-9][-a-z0-9._]*$")

_app: Any = None


def _extract_npm_source(server_args: list[str], *, quiet: bool = False) -> Path | None:
    """Download and extract npm package source for L7 analysis.

    Returns path to extracted package/ directory, or None on failure.
    Caller must clean up the parent temp directory.
    """
    import shutil
    import subprocess
    import tarfile
    import tempfile

    # Find npm package name in args (@scope/pkg preferred, else bare pkg)
    scoped = [a for a in server_args if a.startswith("@") and "/" in a]
    pkg = scoped[0] if scoped else None
    if pkg is None:
        candidates = [a for a in server_args if not a.startswith("-") and not a.startswith("/")]
        pkg = candidates[0] if candidates else None
    if pkg is None or not _NPM_PKG_RE.match(pkg):
        return None

    tmpdir = Path(tempfile.mkdtemp(prefix="munio-src-"))
    try:
        if not quiet:
            import typer

            typer.echo(f"Downloading {pkg} source for L7 analysis...", err=True)

        result = subprocess.run(  # noqa: S603 — npm is a trusted system tool
            ["npm", "pack", pkg, "--pack-destination", str(tmpdir)],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            if not quiet:
                import typer

                typer.echo("Note: npm pack failed, L7 source analysis skipped", err=True)
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None

        tarballs = list(tmpdir.glob("*.tgz"))
        if not tarballs:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None

        # Extract with path traversal protection
        with tarfile.open(tarballs[0], "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    shutil.rmtree(tmpdir, ignore_errors=True)
                    return None
            tar.extractall(tmpdir)  # noqa: S202 — validated above

        pkg_dir = tmpdir / "package"
        return pkg_dir if pkg_dir.is_dir() else None

    except (subprocess.TimeoutExpired, OSError, tarfile.TarError):
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None


def _error_exit(message: str, code: int = 2) -> NoReturn:
    """Print error message to stderr and exit."""
    import typer

    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=code)


_L5_LOCATION_RE = re.compile(r"^source:(.+?)@(.+?) -> sink:(.+?)@(.+?)$")
_L5_FLOW_DESC_RE = re.compile(r"^Toxic flow: (.+?)\. Source:")
_QUOTED_PARAM_RE = re.compile(r" '[^']*'")


def _attack_type_label(attack_type: Any) -> str:
    """Convert AttackType enum to human-readable label."""
    return str(attack_type.name).replace("_", " ").title()


def _canonical_message(findings: list[Any]) -> str:
    """Extract short description from first finding, stripping first quoted param."""
    msg = findings[0].message
    return _QUOTED_PARAM_RE.sub("", msg, count=1)


def _cwe_tag(finding: Any) -> str:
    """Build '[CWE-22]' tag from finding, or empty string."""
    return f" [{finding.cwe}]" if finding.cwe else ""


def _l5_message(findings: list[Any]) -> tuple[str, int]:
    """Build deduped L5_002 message. Returns (message, flow_count)."""
    flow_groups: dict[str, tuple[set[str], set[str]]] = {}
    ungrouped = 0

    for f in findings:
        loc_match = _L5_LOCATION_RE.match(f.location)
        desc_match = _L5_FLOW_DESC_RE.match(f.message)
        if loc_match and desc_match:
            desc = desc_match.group(1)
            src_tool = loc_match.group(1)
            snk_tool = loc_match.group(3)
            if desc not in flow_groups:
                flow_groups[desc] = (set(), set())
            flow_groups[desc][0].add(src_tool)
            flow_groups[desc][1].add(snk_tool)
        else:
            ungrouped += 1

    if not flow_groups:
        return _canonical_message(findings), len(findings)

    total = len(findings) - ungrouped
    parts: list[str] = []
    for desc, (sources, sinks) in flow_groups.items():
        parts.append(f"{desc} — {len(sources)} sources -> {len(sinks)} sinks")
    return f"{total} toxic data flows: " + "; ".join(parts), total


def _score_to_grade(score: float) -> tuple[str, str]:
    """Convert 0-100 score to (letter_grade, rich_color)."""
    if score >= 90:
        return "A", "green bold"
    if score >= 80:
        return "B", "green"
    if score >= 70:
        return "C", "yellow"
    if score >= 60:
        return "D", "red"
    return "F", "red bold"


def _detail_block(check_id: str, findings: list[Any]) -> str:
    """Build detail text for a finding group (--details)."""
    from rich.markup import escape

    from munio.scan.recommendations import get_recommendation

    lines: list[str] = []

    # Affected tools
    tool_names = list(dict.fromkeys(f.tool_name for f in findings))
    if len(tool_names) <= 8:
        tools_str = ", ".join(escape(t) for t in tool_names)
    else:
        shown = ", ".join(escape(t) for t in tool_names[:6])
        tools_str = f"{shown}, +{len(tool_names) - 6} more"
    lines.append(f"[cyan]Tools:[/cyan] {tools_str}")

    # Recommendation
    rec = get_recommendation(check_id)
    if rec:
        prefix = "[green]Fix:[/green]" if rec.auto_fixable else "[dim]Review:[/dim]"
        lines.append(f"{prefix} {escape(rec.short)}")

    # Counterexample (L4 Z3 findings have concrete exploit payloads)
    cx = next((f.counterexample for f in findings if f.counterexample), None)
    if cx:
        lines.append(f"[dim]Proof:[/dim] {escape(cx)}")

    return "\n".join(lines)


def _format_layers_line(result: Any) -> str:
    """Build a compact layers status line with checkmarks and hints."""
    enabled: frozenset[Layer] = result.enabled_layers or frozenset()
    skipped_set = {s.layer for s in (result.skipped_layers or ())}

    parts: list[str] = []
    for layer in sorted(_LAYER_DISPLAY):
        name = _LAYER_DISPLAY[layer]
        if layer in enabled:
            if layer in skipped_set:
                parts.append(f"[red]{name} \u2717[/red]")
            else:
                parts.append(f"[green]{name} \u2713[/green]")
        elif layer in _OPT_IN_LAYERS:
            parts.append(f"[dim]{name} \u25cb[/dim]")

    return "  ".join(parts)


def _format_result_text(
    result: Any,
    *,
    verbose: bool = False,
    color: bool = True,
    details: bool = False,
) -> str:
    """Format a ScanResult as a grouped Rich table."""
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    from munio.scan import __version__

    buf = StringIO()
    console = Console(file=buf, force_terminal=color)

    # Header — use server name when single server
    total_tools = sum(sr.tool_count for sr in result.servers)
    if len(result.servers) == 1:
        srv_name = escape(result.servers[0].server_name)
        header = f"[bold]munio scan v{__version__}[/bold] — {srv_name}, {total_tools} tools\n"
    else:
        header = (
            f"[bold]munio scan v{__version__}[/bold]"
            f" — {len(result.servers)} servers, {total_tools} tools\n"
        )
    console.print(header)

    # Layers status line
    if result.enabled_layers:
        layers_line = _format_layers_line(result)
        console.print(f"[dim]Layers[/dim]  {layers_line}\n")

    if not result.findings:
        console.print("[green]No findings.[/green]")
    else:
        # Group findings: severity → check_id → list[Finding]
        grouped: dict[FindingSeverity, dict[str, list[Any]]] = {}
        for f in result.findings:
            grouped.setdefault(f.severity, {}).setdefault(f.id, []).append(f)

        # Build table
        table = Table(show_header=True, header_style="bold", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Finding")
        table.add_column("CWE", width=8)
        table.add_column("Tools", justify="right", width=6)

        for sev in FindingSeverity:
            checks = grouped.get(sev)
            if not checks:
                continue

            sev_color = _severity_color(sev)

            for check_id, findings in checks.items():
                representative = findings[0]

                # Message
                if check_id == "L5_002":
                    msg, _ = _l5_message(findings)
                else:
                    msg = _canonical_message(findings)

                # Tool count
                tool_names = list(dict.fromkeys(f.tool_name for f in findings))
                tool_count = str(len(tool_names))

                # CWE
                cwe = representative.cwe or ""

                table.add_row(
                    f"[{sev_color}]{sev.name}[/{sev_color}]",
                    escape(msg),
                    escape(cwe),
                    tool_count,
                )

                # Detail block (expanded row under --details)
                if details:
                    detail = _detail_block(check_id, findings)
                    table.add_row("", detail, "", "", end_section=True)

        console.print(table)

        # Summary line
        console.print()
        total_issues = sum(len(checks) for checks in grouped.values())
        severity_parts: list[str] = []
        for sev in FindingSeverity:
            checks = grouped.get(sev)
            if not checks:
                continue
            c = _severity_color(sev)
            severity_parts.append(f"[{c}]{sev.name}: {len(checks)}[/{c}]")
        console.print(
            f"{total_issues} issues across {total_tools} tools  " + "  ".join(severity_parts)
        )

    # Schema quality with letter grade
    if result.servers:
        console.print()
        servers_with_tools = [sr for sr in result.servers if sr.tools]
        if servers_with_tools:
            total_tool_count = sum(sr.tool_count for sr in servers_with_tools)
            scores = [sr.schema_completeness_avg for sr in servers_with_tools]
            avg = sum(scores) / len(scores) if scores else 0
            grade, grade_color = _score_to_grade(avg)
            console.print(
                f"Schema quality: [{grade_color}]{grade}[/{grade_color}]"
                f" ({avg:.0f}/100)"
                f" [dim](avg across {total_tool_count} tools)[/dim]"
            )
            for sr in servers_with_tools:
                console.print(f"  {escape(sr.server_name)}: {sr.schema_completeness_avg:.0f}/100")

    # Next steps hint (only when not already showing details)
    if result.findings and not details:
        console.print()
        console.print("[dim]Next: munio scan --details for affected tools and fixes[/dim]")

    # Skipped layers tip
    skipped = result.skipped_layers or ()
    # Also hint about opt-in layers that are not enabled
    enabled = result.enabled_layers or frozenset()
    opt_in_hints: list[tuple[int, str, str]] = []
    for layer, hint in _OPT_IN_LAYERS.items():
        if layer not in enabled and layer not in {s.layer for s in skipped}:
            prio = _LAYER_TIP_PRIORITY.get(layer, 0)
            name = _LAYER_DISPLAY.get(layer, layer.name)
            opt_in_hints.append((prio, name, hint))

    if skipped:
        best = max(skipped, key=lambda s: _LAYER_TIP_PRIORITY.get(s.layer, 0))
        name = _LAYER_DISPLAY.get(best.layer, best.layer.name)
        console.print()
        console.print(f"[dim]Tip: Enable {name} with: {escape(best.install_hint)}[/dim]")

    console.print(f"\n{result.elapsed_ms:.0f}ms")
    return buf.getvalue()


def _severity_color(severity: FindingSeverity) -> str:
    """Map severity to Rich color."""
    return {
        FindingSeverity.CRITICAL: "red bold",
        FindingSeverity.HIGH: "red",
        FindingSeverity.MEDIUM: "yellow",
        FindingSeverity.LOW: "blue",
        FindingSeverity.INFO: "dim",
    }.get(severity, "white")


def _connect_to_servers(servers: list[Any], config: Any) -> list[Any]:
    """Connect to MCP servers and list their tools."""
    from munio.scan.models import ScanConnectionError, ServerScanResult

    results: list[ServerScanResult] = []

    for server in servers:
        # Skip SSE/HTTP servers (no stdio command) — they need different transport
        if not server.command and server.url:
            results.append(
                ServerScanResult(
                    server_name=server.name,
                    source=server.source,
                    connected=False,
                    error="SSE/HTTP server (stdio scan not supported)",
                )
            )
            continue

        try:
            from munio.scan.mcp_client import connect_and_list_tools

            tools = asyncio.run(
                connect_and_list_tools(
                    server,
                    timeout=config.timeout_seconds,
                    max_tools=config.max_tools_per_server,
                )
            )
            results.append(
                ServerScanResult(
                    server_name=server.name,
                    source=server.source,
                    tool_count=len(tools),
                    tools=tools,
                )
            )
        except ScanConnectionError as exc:
            import typer

            typer.echo(f"Warning: {exc}", err=True)
            results.append(
                ServerScanResult(
                    server_name=server.name,
                    source=server.source,
                    connected=False,
                    error=str(exc),
                )
            )

    return results


# ── Reusable scan logic ────────────────────────────────────────────────


def _parse_server_command(command_str: str) -> Any:
    """Parse 'npx @foo/server --arg1 val1' into a ServerConfig."""
    import shlex

    from munio.scan.models import ServerConfig

    parts = shlex.split(command_str)
    if not parts:
        import typer

        typer.echo("Error: empty server command", err=True)
        raise typer.Exit(code=2)

    cmd = parts[0]
    args = parts[1:]

    # Derive server name from command arguments.
    # Priority: @scope/package arg > last non-flag non-path arg > command name
    non_flag = [p for p in args if not p.startswith("-")]
    scoped = [p for p in non_flag if "@" in p]  # @scope/pkg
    if scoped:
        raw = scoped[0]
    else:
        # Exclude absolute paths (/tmp, /home/...) — they're directory args, not names
        non_path = [p for p in non_flag if not p.startswith("/")]
        raw = non_path[-1] if non_path else (non_flag[-1] if non_flag else cmd)
    name = raw.split("/")[-1]  # @scope/name → name

    return ServerConfig(name=name, source="cli", command=cmd, args=args)


def run_scan(
    *,
    file: str | None = None,
    server: str | None = None,
    config: str | None = None,
    source: str | None = None,
    output_format: str = "text",
    timeout: float = 30.0,
    quiet: bool = False,
    verbose: bool = False,
    details: bool = False,
    output_file: str | None = None,
    trust_project: bool = False,
    no_classifier: bool = False,
    classifier_threshold: float = 0.5,
    no_auto_source: bool = False,
) -> None:
    """Run MCP security scan. Called by both standalone and unified CLI."""
    import shlex
    import shutil

    import typer

    from munio.scan.config import ScanConfig
    from munio.scan.models import DiscoveryError, Layer, SchemaLoadError, ServerScanResult
    from munio.scan.orchestrator import Orchestrator

    # Resolve output format from string
    try:
        fmt = OutputFormat(output_format)
    except ValueError:
        _error_exit(f"Invalid format '{output_format}'. Choose from: text, json, sarif")

    # Mutual exclusion
    sources = [x for x in (file, server, config) if x is not None]
    if len(sources) > 1:
        _error_exit("Options --file, --server, and --config are mutually exclusive")

    enabled = set(ScanConfig().enabled_layers)
    if no_classifier:
        enabled.discard(Layer.L2_CLASSIFIER)

    # Enable L7 source analysis when --source is provided
    source_dir: Path | None = None
    _auto_tmpdir: Path | None = None

    if source is not None:
        enabled.add(Layer.L7_SOURCE)
        source_dir = Path(source)
    elif server is not None and not no_auto_source:
        # Auto-extract npm package source for L7 analysis
        srv_parts = shlex.split(server)
        if srv_parts and srv_parts[0] in ("npx", "node", "bunx"):
            extracted = _extract_npm_source(srv_parts[1:], quiet=quiet)
            if extracted is not None:
                enabled.add(Layer.L7_SOURCE)
                source_dir = extracted
                _auto_tmpdir = extracted.parent

    scan_config = ScanConfig(
        timeout_seconds=timeout,
        output_format=fmt,
        enabled_layers=frozenset(enabled),
        classifier_threshold=classifier_threshold,
        source_dir=source_dir,
    )

    server_results: list[ServerScanResult] = []

    try:
        if file is not None:
            # Mode 1: Scan from JSON file (no MCP connection)
            from munio.scan.schema_loader import load_from_file

            file_path = Path(file)

            try:
                tools = load_from_file(file_path, server_name=file_path.stem)
            except SchemaLoadError as exc:
                _error_exit(str(exc))
            except Exception:
                _error_exit(f"Failed to load tool definitions from: {file}")

            server_results.append(
                ServerScanResult(
                    server_name=file_path.stem,
                    source="file",
                    tool_count=len(tools),
                    tools=tools,
                )
            )

        elif server is not None:
            # Mode 2: Scan from direct server command
            srv = _parse_server_command(server)
            server_results = _connect_to_servers([srv], scan_config)

        elif config is not None:
            # Mode 3: Scan from IDE config file
            from munio.scan.discovery import discover_from_file

            config_path = Path(config)

            try:
                servers = discover_from_file(config_path)
            except DiscoveryError as exc:
                _error_exit(str(exc))
            except Exception:
                _error_exit(f"Failed to parse config file: {config}")

            if not servers:
                _error_exit(f"No MCP servers found in: {config}")

            server_results = _connect_to_servers(servers, scan_config)

        else:
            # Mode 4: Auto-discover
            from munio.scan.discovery import discover_servers

            servers = discover_servers(include_project_level=trust_project)
            if not servers:
                _error_exit(
                    "No MCP servers discovered from IDE configurations.\n"
                    'Try: munio scan --server "npx @modelcontextprotocol/server-filesystem /tmp"\n'
                    "  or: munio scan --file tools.json\n"
                    "  or: munio scan --config path/to/config.json"
                )

            server_results = _connect_to_servers(servers, scan_config)

        # Run analysis
        orchestrator = Orchestrator(scan_config)
        result = asyncio.run(orchestrator.scan(server_results))

        # Output
        output_text: str | None = None

        if fmt == OutputFormat.SARIF:
            from munio.scan.sarif import scan_result_to_sarif

            output_text = json.dumps(scan_result_to_sarif(result), indent=2)
        elif fmt == OutputFormat.JSON:
            output_text = json.dumps(result.to_json_dict(), indent=2, default=str)
        elif not quiet:
            output_text = _format_result_text(
                result, verbose=verbose, color=not output_file, details=details
            )
        else:
            # Quiet mode: strip control chars to prevent ANSI injection
            lines = []
            for f in result.findings:
                safe_name = _CONTROL_CHARS_RE.sub("", f.tool_name)
                safe_msg = _CONTROL_CHARS_RE.sub("", f.message)
                lines.append(f"[{f.severity.name}] {safe_name}: {safe_msg}")
            output_text = "\n".join(lines) if lines else None

        if output_text:
            if output_file:
                out_path = Path(output_file)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(output_text, encoding="utf-8")
            else:
                typer.echo(output_text)

        # Exit code: 1 if CRITICAL or HIGH findings
        has_critical = any(
            f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) for f in result.findings
        )
        raise typer.Exit(code=1 if has_critical else 0)

    finally:
        if _auto_tmpdir is not None:
            shutil.rmtree(_auto_tmpdir, ignore_errors=True)


# ── Standalone app factory ─────────────────────────────────────────────


def create_app() -> Any:
    """Create and configure the standalone Typer CLI app."""
    import typer

    app = typer.Typer(
        name="munio-scan",
        help="MCP Security Scanner — analyze tool definitions for vulnerabilities.",
        no_args_is_help=True,
    )

    @app.command()
    def scan(
        file: str | None = typer.Option(None, "--file", "-f", help="Scan tools from a JSON file"),
        server: str | None = typer.Option(
            None, "--server", help="MCP server command to scan (e.g. 'npx @foo/mcp-server')"
        ),
        config: str | None = typer.Option(
            None, "--config", "-c", help="Scan servers from an IDE config file"
        ),
        output_format: OutputFormat = typer.Option(
            OutputFormat.TEXT, "--format", "-o", help="Output format: text or json"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", "-t", help="Connection timeout in seconds"
        ),
        quiet: bool = typer.Option(
            False, "--quiet", "-q", help="Only show findings, no header/footer"
        ),
        output_file: str | None = typer.Option(
            None, "--output", "-O", help="Write output to file instead of stdout"
        ),
        trust_project: bool = typer.Option(
            False,
            "--trust-project",
            help="Include project-level configs (.vscode/mcp.json, .claude/settings.json) in auto-discovery. "
            "WARNING: these files may contain untrusted commands from cloned repositories.",
        ),
        no_classifier: bool = typer.Option(
            False,
            "--no-classifier",
            help="Disable the ML classifier (L2.5) layer.",
        ),
        classifier_threshold: float = typer.Option(
            0.5,
            "--classifier-threshold",
            help="ML classifier minimum score to report (0.0-1.0).",
        ),
        source: str | None = typer.Option(
            None,
            "--source",
            "-s",
            help="Source code directory for L7 handler analysis (requires munio[source]).",
        ),
        no_auto_source: bool = typer.Option(
            False,
            "--no-source",
            help="Disable automatic npm package source extraction for L7.",
        ),
        verbose: bool = typer.Option(
            False,
            "--verbose",
            "-v",
            help="Show all findings including LOW/INFO details.",
        ),
        details: bool = typer.Option(
            False,
            "--details",
            "-d",
            help="Show affected tools, fix suggestions, and counterexamples.",
        ),
    ) -> None:
        """Scan MCP tool definitions for security issues."""
        run_scan(
            file=file,
            server=server,
            config=config,
            source=source,
            output_format=output_format.value,
            timeout=timeout,
            quiet=quiet,
            verbose=verbose,
            details=details,
            output_file=output_file,
            trust_project=trust_project,
            no_classifier=no_classifier,
            classifier_threshold=classifier_threshold,
            no_auto_source=no_auto_source,
        )

    @app.command()
    def version() -> None:
        """Print version and exit."""
        from munio.scan import __version__

        print(f"munio-scan {__version__}")

    return app


# ── Config scan logic ──────────────────────────────────────────────────


def run_config_scan(
    *,
    config_file: str | None = None,
    output_format: str = "text",
    output_file: str | None = None,
    trust_project: bool = False,
    details: bool = False,
    quiet: bool = False,
) -> None:
    """Run config file supply chain scan."""
    import uuid

    import typer

    from munio.scan.config_scanner import ConfigScanner
    from munio.scan.models import ConfigScanResult

    scanner = ConfigScanner()
    try:
        fmt = OutputFormat(output_format)
    except ValueError:
        _error_exit(f"Invalid format '{output_format}'. Choose from: text, json, sarif")

    if config_file is not None:
        path = Path(config_file)
        if not path.is_file():
            _error_exit(f"Config file not found: {config_file}")
        try:
            result_file = scanner.scan_file(path, ide="cli")
        except Exception:
            _error_exit("Failed to scan config file")
        # Wrap single file in ConfigScanResult
        result = ConfigScanResult(
            scan_id=str(uuid.uuid4()),
            files=[result_file],
        )
    else:
        try:
            result = scanner.scan_all(include_project_level=trust_project)
        except Exception:
            _error_exit("Config scan failed")

    if not result.files:
        _error_exit(
            "No MCP config files found.\n"
            "Searched: Claude Desktop, Cursor, Windsurf, Cline, Junie configs.\n"
            "Try: munio config-scan --config path/to/config.json"
        )

    # Output
    output_text: str | None = None

    if fmt == OutputFormat.JSON:
        from munio.scan.models import AttackType

        d = result.model_dump(mode="json")
        d["total_findings"] = result.total_findings
        d["by_severity"] = result.by_severity

        # Convert IntEnum values to names in nested findings
        _sev = {s.value: s.name for s in FindingSeverity}
        _lay = {lyr.value: lyr.name for lyr in Layer}
        _att = {a.value: a.name for a in AttackType}
        for file_entry in d.get("files", []):
            if isinstance(file_entry, dict):
                for f in file_entry.get("findings", []):
                    if isinstance(f, dict):
                        if isinstance(f.get("severity"), int):
                            f["severity"] = _sev.get(f["severity"], f["severity"])
                        if isinstance(f.get("layer"), int):
                            f["layer"] = _lay.get(f["layer"], f["layer"])
                        if isinstance(f.get("attack_type"), int):
                            f["attack_type"] = _att.get(f["attack_type"], f["attack_type"])

        output_text = json.dumps(d, indent=2, default=str)
    elif fmt == OutputFormat.SARIF:
        # Convert to ScanResult-compatible format for SARIF
        from munio.scan.models import ScanResult
        from munio.scan.sarif import scan_result_to_sarif

        compat = ScanResult(
            scan_id=result.scan_id,
            timestamp=result.timestamp,
            findings=result.all_findings,
            elapsed_ms=result.elapsed_ms,
            enabled_layers=frozenset({Layer.L0_CONFIG}),
        )
        output_text = json.dumps(scan_result_to_sarif(compat), indent=2)
    elif not quiet:
        output_text = _format_config_result_text(result, details=details)

    if output_text:
        if output_file:
            out_path = Path(output_file)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output_text, encoding="utf-8")
        else:
            typer.echo(output_text)

    # Exit code
    has_critical = any(
        f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) for f in result.all_findings
    )
    raise typer.Exit(code=1 if has_critical else 0)


def _format_config_result_text(
    result: Any,
    *,
    details: bool = False,
) -> str:
    """Format a ConfigScanResult as Rich text."""
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    from munio.scan import __version__

    buf = StringIO()
    console = Console(file=buf, force_terminal=True)

    # Header
    total_servers = sum(f.servers_count for f in result.files)
    console.print(
        f"[bold]munio config-scan v{__version__}[/bold]"
        f" -- {len(result.files)} config files, {total_servers} servers\n"
    )

    all_findings = result.all_findings
    if not all_findings:
        console.print("[green]No supply chain issues found.[/green]")
    else:
        # Group by severity -> check_id
        grouped: dict[FindingSeverity, dict[str, list[Any]]] = {}
        for f in all_findings:
            grouped.setdefault(f.severity, {}).setdefault(f.id, []).append(f)

        table = Table(show_header=True, header_style="bold", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Finding")
        table.add_column("CWE", width=10)
        table.add_column("Servers", justify="right", width=8)

        for sev in FindingSeverity:
            checks = grouped.get(sev)
            if not checks:
                continue
            sev_color = _severity_color(sev)
            for check_id, findings in checks.items():
                msg = _canonical_message(findings)
                server_names = list(dict.fromkeys(f.tool_name for f in findings))
                cwe = findings[0].cwe or ""
                table.add_row(
                    f"[{sev_color}]{sev.name}[/{sev_color}]",
                    escape(msg),
                    escape(cwe),
                    str(len(server_names)),
                )
                if details:
                    detail = _detail_block(check_id, findings)
                    table.add_row("", detail, "", "", end_section=True)

        console.print(table)

        # Summary
        console.print()
        total_issues = sum(len(checks) for checks in grouped.values())
        severity_parts: list[str] = []
        for sev in FindingSeverity:
            checks = grouped.get(sev)
            if not checks:
                continue
            c = _severity_color(sev)
            severity_parts.append(f"[{c}]{sev.name}: {len(checks)}[/{c}]")
        console.print(
            f"{total_issues} issues across {total_servers} servers  " + "  ".join(severity_parts)
        )

    # Cross-command hint
    console.print()
    console.print("[dim]Next: munio scan for deep schema analysis[/dim]")

    console.print(f"\n{result.elapsed_ms:.0f}ms")

    # Scanned files (dimmed, below findings)
    console.print()
    for fr in result.files:
        icon = "[green]+[/green]" if fr.findings else "[dim]o[/dim]"
        console.print(
            f"  {icon} [dim]{escape(fr.path)} ({fr.ide}, {fr.servers_count} servers)[/dim]"
        )
    return buf.getvalue()


def _get_app() -> Any:
    """Get or create the CLI app (cached)."""
    global _app
    if _app is None:
        _app = create_app()
    return _app


def main() -> None:  # pragma: no cover
    """CLI entrypoint."""
    try:
        app = _get_app()
    except ImportError:
        print(
            "Error: CLI dependencies not installed. Install with: pip install 'munio[all]'",
            file=sys.stderr,
        )
        sys.exit(1)
    app()
