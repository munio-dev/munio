"""munio gate CLI: MCP stdio proxy with constraint verification.

This module provides the gate CLI as both a standalone app (``app``)
and reusable ``run_*()`` functions that the unified ``munio`` CLI imports.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from munio.gate.models import InterceptionRecord

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from munio.gate import __version__

app = typer.Typer(
    name="munio-gate",
    help="MCP stdio proxy — runtime constraint verification for AI tool calls.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console(stderr=True)  # CLI output goes to stderr; stdout reserved for MCP protocol


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _resolve_constraints_dir(constraints_dir: str | None) -> Path | None:
    """Resolve constraints directory, defaulting to bundled generic pack.

    Priority order:
    1. Explicit ``--constraints-dir`` flag (user override)
    2. Bundled constraints shipped inside the wheel (``munio.gate/data/constraints/``)
    3. Repo-root constraints (development / editable installs)
    4. CWD ``constraints/`` directory (fallback)
    """
    if constraints_dir is not None:
        p = Path(constraints_dir)
        if not p.is_dir():
            # H2 fix: escape user-controlled path in Rich output
            console.print(f"[red]Constraints directory not found: {escape(str(p))}[/red]")
            raise typer.Exit(1)
        return p

    # B1 fix: Bundled constraints (always available after pip install).
    # importlib.resources works for both wheel installs and editable installs.
    from importlib.resources import files as _pkg_files

    try:
        bundled = _pkg_files("munio.gate").joinpath("data", "constraints")
        bundled_path = Path(str(bundled))
        if bundled_path.is_dir():
            return bundled_path
    except (ModuleNotFoundError, TypeError):
        pass

    # Dev fallback: repo root (editable installs where data/ doesn't exist yet)
    repo_root = Path(__file__).resolve().parent.parent.parent.parent.parent / "constraints"
    if repo_root.is_dir():
        return repo_root

    # Last resort: CWD
    cwd_candidate = Path.cwd() / "constraints"
    if cwd_candidate.is_dir():
        return cwd_candidate

    return None


def _load_config_file(path: Path) -> dict[str, Any]:
    """Load and validate a config file for init/restore commands.

    Returns parsed JSON dict. Exits with error on failure.
    """
    if not path.is_file():
        console.print(f"[red]Config file not found: {escape(str(path))}[/red]")
        raise typer.Exit(1)
    try:
        if path.stat().st_size > 1_048_576:
            console.print("[red]Config file too large (>1 MB).[/red]")
            raise typer.Exit(1)
    except OSError:
        console.print("[red]Cannot read config file.[/red]")
        raise typer.Exit(1)  # noqa: B904
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        console.print("[red]Cannot parse config file.[/red]")
        raise typer.Exit(1)  # noqa: B904
    if not isinstance(data, dict):
        console.print("[red]Config file is not a JSON object.[/red]")
        raise typer.Exit(1)
    return data


def _find_stdio_servers(data: dict[str, Any]) -> list[tuple[str, dict[str, dict[str, Any]]]]:
    """Find all keys with stdio MCP servers in a config dict."""
    results: list[tuple[str, dict[str, dict[str, Any]]]] = []
    for key in ("mcpServers", "servers"):
        servers = data.get(key, {})
        if isinstance(servers, dict) and servers:
            stdio_servers = {
                n: c
                for n, c in servers.items()
                if isinstance(c, dict) and isinstance(c.get("command"), str)
            }
            if stdio_servers:
                results.append((key, stdio_servers))
    return results


_STATUS_DISPLAY: dict[str, tuple[str, str]] = {
    # status -> (icon, label)
    "wrapped": ("[green]v[/green]", "wrapped"),
    "already_wrapped": ("[dim]-[/dim]", "already wrapped"),
    "restored": ("[green]v[/green]", "restored"),
    "not_wrapped": ("[dim]-[/dim]", "not wrapped"),
    "invalid_wrapper": ("[yellow]![/yellow]", "invalid wrapper (manual fix needed)"),
    "skipped": ("[dim]-[/dim]", "skipped"),
}


def _print_results(label: str, results: dict[str, str], *, dry_run: bool) -> None:
    if not results:
        return
    prefix = "[dim](dry run)[/dim] " if dry_run else ""
    console.print(f"\n{prefix}[bold]{escape(label)}[/bold]")
    for name, status in results.items():
        safe_name = escape(name)
        icon, desc = _STATUS_DISPLAY.get(status, ("[dim]-[/dim]", "skipped"))
        console.print(f"  {icon} {safe_name} - {desc}")


# ── Reusable command logic ─────────────────────────────────────────────


def run_gate(
    *,
    command_args: list[str],
    constraints_dir: str | None = None,
    packs: str | None = None,
    mode: str = "enforce",
    log_file: str | None = None,
    verbose: bool = False,
) -> None:
    """Run the MCP stdio proxy. Called by both standalone and unified CLI."""
    _setup_logging(verbose)

    if not command_args:
        console.print("[red]No server command specified.[/red]")
        console.print("Usage: munio gate -- npx @mcp/server-filesystem /tmp")
        raise typer.Exit(1)

    server_command = command_args[0]
    server_args = command_args[1:]

    # Resolve constraints
    cdir = _resolve_constraints_dir(constraints_dir)

    # H8 fix: Warn when no constraints directory found
    if cdir is None:
        console.print(
            "[yellow]Warning: No constraints directory found. "
            "All tool calls will be allowed.[/yellow]"
        )

    # Create Guard
    from munio._temporal import InMemoryTemporalStore
    from munio.guard import Guard
    from munio.models import VerificationMode

    temporal_store = InMemoryTemporalStore()

    # H9 fix: Validate mode and warn on non-enforce
    try:
        mode_enum = VerificationMode(mode)
    except ValueError:
        console.print(f"[red]Invalid mode: {escape(mode)}. Use: enforce, shadow, disabled[/red]")
        raise typer.Exit(1)  # noqa: B904

    if mode_enum != VerificationMode.ENFORCE:
        console.print(
            f"[yellow]Warning: Running in '{mode}' mode. Tool calls will NOT be blocked.[/yellow]"
        )

    pack_list = [p.strip() for p in packs.split(",") if p.strip()] if packs else None

    # R2-N2 fix: Guard(constraints=str) wraps it as [str], so passing list[str]
    # creates [[str]] (list of lists). Use ConstraintConfig directly for multi-pack.
    if pack_list and cdir:
        from munio.models import ConstraintConfig

        guard_config = ConstraintConfig(
            mode=mode_enum,
            constraint_packs=pack_list,
        )
        guard = Guard(
            config=guard_config,
            constraints_dir=cdir,
            temporal_store=temporal_store,
        )
    else:
        guard = Guard(
            constraints_dir=cdir,
            mode=mode_enum,
            temporal_store=temporal_store,
        )

    from munio.gate.interceptor import Interceptor
    from munio.gate.proxy import run_proxy

    interceptor = Interceptor(guard)

    # Optional log callback with proper resource management
    log_fh = None
    log_cb: Callable[[InterceptionRecord], None] | None = None
    if log_file:
        log_path = Path(log_file)
        if log_path.is_symlink():
            console.print("[red]Log file path is a symlink (refusing).[/red]")
            raise typer.Exit(1)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = log_path.open("a", encoding="utf-8")
        log_fh = fh

        def log_cb(record: InterceptionRecord) -> None:
            fh.write(record.model_dump_json() + "\n")
            fh.flush()

    # Run proxy
    try:
        exit_code = asyncio.run(
            run_proxy(
                server_command,
                server_args,
                interceptor,
                log_callback=log_cb,
            )
        )
    finally:
        # H4 fix: Always close log file handle
        if log_fh is not None:
            log_fh.close()

    raise typer.Exit(exit_code)


def run_init(*, dry_run: bool = False, config_path: str | None = None) -> None:
    """Run the init command logic. Called by both standalone and unified CLI."""
    from munio.gate.discovery import ConfigEntry, discover_configs, rewrite_config

    if config_path:
        path = Path(config_path)
        data = _load_config_file(path)
        found = _find_stdio_servers(data)
        if not found:
            console.print("[yellow]No stdio MCP servers found in config.[/yellow]")
            return
        for key, stdio_servers in found:
            entry = ConfigEntry(path.stem, path, key, stdio_servers)
            results = rewrite_config(entry, dry_run=dry_run)
            _print_results(path.name, results, dry_run=dry_run)
        return

    # Auto-discover all configs
    configs = discover_configs()
    if not configs:
        console.print("[yellow]No MCP config files found.[/yellow]")
        console.print("Searched: Claude Desktop, Cursor, VS Code, Windsurf, Cline, JetBrains.")
        return

    total_wrapped = 0
    for entry in configs:
        results = rewrite_config(entry, dry_run=dry_run)
        _print_results(f"{entry.source} ({entry.path.name})", results, dry_run=dry_run)
        total_wrapped += sum(1 for v in results.values() if v == "wrapped")

    if dry_run:
        console.print(f"\n[dim]Dry run: {total_wrapped} server(s) would be wrapped.[/dim]")
    elif total_wrapped > 0:
        console.print(f"\n[green]Wrapped {total_wrapped} server(s) with munio.[/green]")
    else:
        console.print("\n[dim]All servers already wrapped or skipped.[/dim]")

    # Warn if munio is in a venv (configs will break if venv deleted)
    if total_wrapped > 0:
        from munio.gate.discovery import _is_venv_path

        munio_bin = Path(sys.executable).parent / "munio"
        if munio_bin.exists() and _is_venv_path(munio_bin):
            console.print(
                f"\n[yellow]Warning: munio is in a virtual environment ({munio_bin.parent})[/yellow]"
                "\n[yellow]  Configs will break if this venv is deleted.[/yellow]"
                "\n[yellow]  For stable setup: pipx install munio[/yellow]"
            )


def run_status() -> None:
    """Run the status command logic. Called by both standalone and unified CLI."""
    from munio.gate.discovery import discover_configs

    configs = discover_configs()
    if not configs:
        console.print("[yellow]No MCP config files found.[/yellow]")
        return

    table = Table(title="MCP Server Configurations")
    table.add_column("Source", style="cyan")
    table.add_column("Server", style="white")
    table.add_column("Command", style="dim")
    table.add_column("Status", style="bold")

    for entry in configs:
        for name, cfg in entry.servers.items():
            command = cfg.get("command", "")
            is_wrapped = Path(str(command)).name == "munio"
            status_str = (
                "[green]protected[/green]" if is_wrapped else "[yellow]unprotected[/yellow]"
            )
            # H2 fix: escape user-controlled values in Rich table
            table.add_row(escape(entry.source), escape(name), escape(str(command)), status_str)

    console.print(table)


def run_restore(*, dry_run: bool = False, config_path: str | None = None) -> None:
    """Run the restore command logic. Called by both standalone and unified CLI."""
    from munio.gate.discovery import ConfigEntry, discover_configs, restore_config

    if config_path:
        path = Path(config_path)
        data = _load_config_file(path)
        found = _find_stdio_servers(data)
        if not found:
            console.print("[yellow]No stdio MCP servers found in config.[/yellow]")
            return
        for key, stdio_servers in found:
            entry = ConfigEntry(path.stem, path, key, stdio_servers)
            results = restore_config(entry, dry_run=dry_run)
            _print_results(path.name, results, dry_run=dry_run)
        return

    configs = discover_configs()
    if not configs:
        console.print("[yellow]No MCP config files found.[/yellow]")
        return

    total_restored = 0
    for entry in configs:
        results = restore_config(entry, dry_run=dry_run)
        _print_results(f"{entry.source} ({entry.path.name})", results, dry_run=dry_run)
        total_restored += sum(1 for v in results.values() if v == "restored")

    if dry_run:
        console.print(f"\n[dim]Dry run: {total_restored} server(s) would be restored.[/dim]")
    elif total_restored > 0:
        console.print(f"\n[green]Restored {total_restored} server(s) to original commands.[/green]")
    else:
        console.print("\n[dim]No wrapped servers found to restore.[/dim]")


def run_stats(*, log_file: str, top: int = 10, json_output: bool = False) -> None:
    """Run the stats command logic. Called by both standalone and unified CLI."""
    from munio.gate.stats import compute_stats, parse_log

    path = Path(log_file)
    if not path.is_file():
        console.print(f"[red]Log file not found: {escape(str(path))}[/red]")
        raise typer.Exit(1)

    try:
        records, parse_errors = parse_log(path)
    except OSError:
        console.print("[red]Cannot read log file.[/red]")
        raise typer.Exit(1)  # noqa: B904

    if not records and parse_errors == 0:
        if json_output:
            print("{}")
        else:
            console.print("[dim]Log file is empty.[/dim]")
        return

    if not records and parse_errors > 0:
        console.print(f"[red]No valid records found ({parse_errors} parse error(s)).[/red]")
        raise typer.Exit(1)

    result = compute_stats(records, top_n=top)
    result = result.model_copy(update={"parse_errors": parse_errors})

    if json_output:
        print(result.model_dump_json(indent=2))
        return

    # Rich output
    console.print(f"\n[bold]munio gate stats:[/bold] {escape(str(path))}")
    if result.first_timestamp and result.last_timestamp:
        first = result.first_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        last = result.last_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"[dim]{first} — {last}[/dim]")

    # Decisions table
    dec_table = Table(show_header=True, show_lines=False, pad_edge=False)
    dec_table.add_column("Decision", style="white")
    dec_table.add_column("Count", justify="right")
    dec_table.add_row("Allowed", f"[green]{result.allowed}[/green]")
    dec_table.add_row("Blocked", f"[red]{result.blocked}[/red]")
    if result.errors > 0:
        dec_table.add_row("Error", f"[yellow]{result.errors}[/yellow]")
    dec_table.add_row("[bold]Total[/bold]", f"[bold]{result.total}[/bold]")
    console.print(dec_table)

    # Latency table
    lat_table = Table(show_header=True, show_lines=False, pad_edge=False)
    lat_table.add_column("Latency", style="white")
    lat_table.add_column("ms", justify="right")
    lat_table.add_row("p50", f"{result.latency_p50_ms:.2f}")
    lat_table.add_row("p95", f"{result.latency_p95_ms:.2f}")
    lat_table.add_row("p99", f"{result.latency_p99_ms:.2f}")
    lat_table.add_row("max", f"{result.latency_max_ms:.2f}")
    console.print(lat_table)

    # Top blocked tools
    if result.top_blocked_tools:
        tool_table = Table(show_header=True, show_lines=False, pad_edge=False)
        tool_table.add_column("Blocked Tool", style="white")
        tool_table.add_column("Count", justify="right")
        for tool_name, count in result.top_blocked_tools:
            tool_table.add_row(escape(tool_name), str(count))
        console.print(tool_table)

    if parse_errors > 0:
        console.print(
            f"\n[yellow]Warning: {parse_errors} log line(s) could not be parsed.[/yellow]"
        )


# ── Standalone app commands ────────────────────────────────────────────


@app.command()
def run(
    command_args: Annotated[
        list[str],
        typer.Argument(help="Server command and args (after --)"),
    ],
    constraints_dir: Annotated[
        str | None,
        typer.Option("--constraints-dir", "-d", help="Path to constraints directory"),
    ] = None,
    packs: Annotated[
        str | None,
        typer.Option("--packs", "-p", help="Comma-separated constraint pack names"),
    ] = None,
    mode: Annotated[
        str,
        typer.Option("--mode", "-m", help="Verification mode: enforce, shadow, disabled"),
    ] = "enforce",
    log_file: Annotated[
        str | None,
        typer.Option("--log", "-l", help="Path to JSON lines log file"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable debug logging"),
    ] = False,
) -> None:
    """Run the MCP stdio proxy.

    Intercepts tool calls and verifies them against constraints.

    Usage: munio gate run -- npx @mcp/server-filesystem /tmp
    """
    run_gate(
        command_args=command_args,
        constraints_dir=constraints_dir,
        packs=packs,
        mode=mode,
        log_file=log_file,
        verbose=verbose,
    )


@app.command()
def init(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without writing"),
    ] = False,
    config_path: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to a specific config file"),
    ] = None,
) -> None:
    """Auto-detect MCP configs and wrap servers with munio gate.

    Discovers Claude Desktop, Cursor, VS Code, Windsurf, Cline, and other
    IDE configurations, then rewrites them to route MCP servers through
    munio for runtime constraint verification.
    """
    run_init(dry_run=dry_run, config_path=config_path)


@app.command()
def status() -> None:
    """Show discovered MCP configs and their munio gate status."""
    run_status()


@app.command()
def restore(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without writing"),
    ] = False,
    config_path: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to a specific config file"),
    ] = None,
) -> None:
    """Remove munio wrapper and restore original MCP server commands.

    Reverses `munio gate init` by extracting the original command and args
    from each wrapped server configuration.
    """
    run_restore(dry_run=dry_run, config_path=config_path)


@app.command()
def stats(
    log_file: Annotated[
        str,
        typer.Argument(help="Path to JSONL log file"),
    ],
    top: Annotated[
        int,
        typer.Option("--top", "-t", help="Number of top blocked tools to show"),
    ] = 10,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """Show interception statistics from a JSONL log file."""
    run_stats(log_file=log_file, top=top, json_output=json_output)


@app.command()
def version() -> None:
    """Show munio gate version."""
    print(f"munio-gate {__version__}")


def main() -> None:
    """Entry point for munio gate CLI."""
    app()
