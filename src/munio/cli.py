"""Unified CLI: munio — AI agent security toolkit.

Commands:
  munio scan [args]        Scan MCP servers for security issues
  munio check '{json}'     Verify a single action against constraints
  munio gate [args]        Run the MCP stdio proxy
  munio serve [args]       Start the HTTP API server
  munio policy [args]      Tier 4 deploy-time Z3 policy verification
  munio audit [args]       Audit constraints directory (statistics, issues)
  munio init [args]        Auto-wrap MCP configs with munio gate
  munio status [args]      Show MCP protection status
  munio restore [args]     Restore original MCP server commands
  munio stats [args]       Show gate interception statistics
  munio version            Show version and Z3 status

Output formats:
  --format text   Human-readable (default)
  --format json   Machine-readable JSON
  --format sarif  SARIF 2.1.0 (scan only)

Requires: pip install "munio[cli]" (typer + rich).
"""

from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path
from typing import Any, NoReturn

from munio.constraints import ConstraintLoadError, load_constraints_dir
from munio.guard import Guard
from munio.models import (
    ConstraintConfig,
    MunioError,
    OnViolation,
    PolicyResult,
    PolicyVerificationResult,
    VerificationMode,
    VerificationResult,
)
from munio.scan.models import OutputFormat

__all__: list[str] = []

_app = None

_MAX_STDIN_SIZE = 1_048_576  # 1MB, consistent with constraint file limits


# ── Formatting helpers ──────────────────────────────────────────────────


def _format_result_text(result: VerificationResult) -> str:
    """Format a VerificationResult as human-readable Rich text."""
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    buf = StringIO()
    console = Console(file=buf, force_terminal=False)

    if result.allowed:
        console.print("[green]ALLOWED[/green]")
    else:
        console.print("[red]BLOCKED[/red]")

    if result.violations:
        table = Table(title="Violations")
        table.add_column("Constraint", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Message")
        table.add_column("Field", style="dim")
        for v in result.violations:
            table.add_row(
                escape(v.constraint_name),
                escape(v.severity.value),
                escape(v.message),
                escape(v.field),
            )
        console.print(table)

    console.print(
        f"Mode: {result.mode.value} | "
        f"Checked: {result.checked_constraints} | "
        f"{result.elapsed_ms:.1f}ms"
    )
    if result.tier_breakdown:
        console.print(f"Tiers: {result.tier_breakdown}")

    return buf.getvalue()


def _format_result_json(result: VerificationResult) -> str:
    """Format a VerificationResult as JSON."""
    return result.model_dump_json(indent=2)


def _format_scan_text(stats: dict[str, Any]) -> str:
    """Format audit statistics as human-readable Rich text."""
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    buf = StringIO()
    console = Console(file=buf, force_terminal=False)

    console.print(f"[bold]Constraints: {stats['total']}[/bold]")

    if stats.get("tiers"):
        table = Table(title="Tier Breakdown")
        table.add_column("Tier", style="cyan")
        table.add_column("Count", justify="right")
        for tier, count in sorted(stats["tiers"].items()):
            table.add_row(escape(tier), str(count))
        console.print(table)

    if stats.get("check_types"):
        table = Table(title="Check Types")
        table.add_column("Type", style="cyan")
        table.add_column("Count", justify="right")
        for ctype, count in sorted(stats["check_types"].items()):
            table.add_row(escape(ctype), str(count))
        console.print(table)

    if stats.get("actions"):
        console.print(f"Action patterns: {escape(', '.join(sorted(stats['actions'])))}")

    if stats.get("issues"):
        console.print(f"\n[yellow]Issues ({len(stats['issues'])}):[/yellow]")
        for issue in stats["issues"]:
            console.print(f"  - {escape(issue)}")

    return buf.getvalue()


def _format_scan_json(stats: dict[str, Any]) -> str:
    """Format audit statistics as JSON."""
    return json.dumps(stats, indent=2)


def _format_policy_text(result: PolicyVerificationResult) -> str:
    """Format a PolicyVerificationResult as human-readable Rich text."""
    from rich.console import Console
    from rich.markup import escape

    buf = StringIO()
    console = Console(file=buf, force_terminal=False)

    if result.result == PolicyResult.SAFE:
        console.print("[green]SAFE[/green] — Policy verified mathematically safe")
    elif result.result == PolicyResult.UNSAFE:
        console.print("[red]UNSAFE[/red] — Policy violation found")
    elif result.result == PolicyResult.TIMEOUT:
        console.print("[yellow]TIMEOUT[/yellow] — Z3 solver timed out")
    elif result.result == PolicyResult.UNKNOWN:
        console.print("[yellow]UNKNOWN[/yellow] — Z3 returned unknown")
    else:
        console.print("[red]ERROR[/red] — Verification failed")

    if result.check_type:
        console.print(f"Check: {escape(result.check_type.value)}")

    if result.details:
        for key, value in result.details.items():
            console.print(f"  {escape(key)}: {escape(str(value))}")

    console.print(f"{result.elapsed_ms:.1f}ms")
    if result.constraints_checked:
        console.print(f"Constraints: {escape(', '.join(result.constraints_checked))}")

    return buf.getvalue()


def _format_policy_json(result: PolicyVerificationResult) -> str:
    """Format a PolicyVerificationResult as JSON."""
    return result.model_dump_json(indent=2)


def _error_exit(message: str, code: int = 2) -> NoReturn:
    """Print error message to stderr and exit."""
    import typer

    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=code)


def _resolve_dir(constraints_dir: str) -> Path:
    """Resolve and validate constraints directory (fail-closed).

    Falls back to bundled constraints if the specified directory doesn't exist.
    """
    dir_path = Path(constraints_dir)
    if not dir_path.is_absolute():
        dir_path = Path.cwd() / dir_path
    if dir_path.is_dir():
        return dir_path

    # Fallback to bundled constraints
    for candidate in (
        Path(__file__).resolve().parent / "gate" / "data" / "constraints",  # installed wheel
        Path(__file__).resolve().parents[2] / "constraints",  # dev mode (src/ layout)
    ):
        if candidate.is_dir():
            return candidate

    _error_exit(f"Constraints directory not found: {constraints_dir}")


def _read_stdin() -> str:
    """Read action JSON from stdin with size limit and TTY warning."""
    import typer

    if sys.stdin.isatty():
        typer.echo("Reading action JSON from stdin (Ctrl+D to end)...", err=True)
    raw = sys.stdin.read(_MAX_STDIN_SIZE + 1)
    if len(raw) > _MAX_STDIN_SIZE:
        _error_exit("stdin input exceeds 1MB limit")
    return raw


# ── App factory ─────────────────────────────────────────────────────────


def create_app() -> Any:
    """Create and configure the unified Typer CLI app.

    Raises ImportError if typer is not installed.
    """
    import typer

    app = typer.Typer(
        name="munio",
        help="AI agent security toolkit — scan MCP servers, guard tool calls.",
        no_args_is_help=True,
    )

    # ── scan (from scan/cli.py) ────────────────────────────────────────

    @app.command()
    def scan(
        file: str | None = typer.Option(None, "--file", "-f", help="Scan tools from a JSON file"),
        server: str | None = typer.Option(
            None, "--server", help="MCP server command to scan (e.g. 'npx @foo/mcp-server')"
        ),
        config: str | None = typer.Option(
            None, "--config", "-c", help="Scan servers from an IDE config file"
        ),
        output_format: str = typer.Option(
            "text", "--format", "-o", help="Output format: text, json, or sarif"
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
            help="Disable automatic npm source extraction for L7.",
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
            help="Show affected tools, fix suggestions, and counterexamples.",
        ),
    ) -> None:
        """Scan MCP tool definitions for security issues."""
        from munio.scan.cli import run_scan

        run_scan(
            file=file,
            server=server,
            config=config,
            source=source,
            output_format=output_format,
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

    # ── config-scan ───────────────────────────────────────────────────

    @app.command(name="config-scan")
    def config_scan(
        config_file: str | None = typer.Option(
            None, "--config", "-c", help="Scan a specific config file"
        ),
        output_format: str = typer.Option(
            "text", "--format", "-o", help="Output format: text, json, or sarif"
        ),
        output_file: str | None = typer.Option(
            None, "--output", "-O", help="Write output to file instead of stdout"
        ),
        trust_project: bool = typer.Option(
            False,
            "--trust-project",
            help="Include project-level configs in auto-discovery.",
        ),
        details: bool = typer.Option(
            False, "--details", "-d", help="Show affected servers and fix suggestions."
        ),
        quiet: bool = typer.Option(
            False, "--quiet", "-q", help="Only show findings, no header/footer"
        ),
    ) -> None:
        """Scan MCP config files for supply chain security issues."""
        from munio.scan.cli import run_config_scan

        run_config_scan(
            config_file=config_file,
            output_format=output_format,
            output_file=output_file,
            trust_project=trust_project,
            details=details,
            quiet=quiet,
        )

    # ── compose ───────────────────────────────────────────────────────

    @app.command()
    def compose(
        config: str | None = typer.Option(
            None, "--config", "-c", help="Config file with MCP server definitions"
        ),
        schemas_dir: str | None = typer.Option(
            None,
            "--schemas-dir",
            "-s",
            help="Directory with pre-fetched tool schema JSON files",
        ),
        output_format: str = typer.Option(
            "text", "--format", "-o", help="Output format: text, json, or markdown"
        ),
        output_file: str | None = typer.Option(
            None, "--output", "-O", help="Write output to file instead of stdout"
        ),
        quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
        details: bool = typer.Option(
            False, "--details", "-d", help="Show chain details and capabilities"
        ),
    ) -> None:
        """Analyze multi-server MCP configs for dangerous attack chains."""
        from munio.scan.compose_cli import run_compose

        run_compose(
            config=config,
            schemas_dir=schemas_dir,
            output_format=output_format,
            output_file=output_file,
            quiet=quiet,
            details=details,
        )

    # ── gate (from gate/cli.py) ────────────────────────────────────────

    @app.command()
    def gate(
        command_args: list[str] = typer.Argument(help="Server command and args (after --)"),
        constraints_dir: str | None = typer.Option(
            None, "--constraints-dir", "-d", help="Path to constraints directory"
        ),
        packs: str | None = typer.Option(
            None, "--packs", "-p", help="Comma-separated constraint pack names"
        ),
        mode: str = typer.Option(
            "enforce", "--mode", "-m", help="Verification mode: enforce, shadow, disabled"
        ),
        log_file: str | None = typer.Option(
            None, "--log", "-l", help="Path to JSON lines log file"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    ) -> None:
        """Run the MCP stdio proxy with runtime constraint verification.

        Usage: munio gate -- npx @mcp/server-filesystem /tmp
        """
        from munio.gate.cli import run_gate

        run_gate(
            command_args=command_args,
            constraints_dir=constraints_dir,
            packs=packs,
            mode=mode,
            log_file=log_file,
            verbose=verbose,
        )

    # ── init (from gate/cli.py) ────────────────────────────────────────

    @app.command()
    def init(
        dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
        config_path: str | None = typer.Option(
            None, "--config", "-c", help="Path to a specific config file"
        ),
    ) -> None:
        """Auto-detect MCP configs and wrap servers with munio gate."""
        from munio.gate.cli import run_init

        run_init(dry_run=dry_run, config_path=config_path)

    # ── status (from gate/cli.py) ──────────────────────────────────────

    @app.command()
    def status() -> None:
        """Show discovered MCP configs and their munio gate status."""
        from munio.gate.cli import run_status

        run_status()

    # ── restore (from gate/cli.py) ─────────────────────────────────────

    @app.command()
    def restore(
        dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
        config_path: str | None = typer.Option(
            None, "--config", "-c", help="Path to a specific config file"
        ),
    ) -> None:
        """Remove munio wrapper and restore original MCP server commands."""
        from munio.gate.cli import run_restore

        run_restore(dry_run=dry_run, config_path=config_path)

    # ── stats (from gate/cli.py) ───────────────────────────────────────

    @app.command()
    def stats(
        log_file: str = typer.Argument(help="Path to JSONL log file"),
        top: int = typer.Option(10, "--top", "-t", help="Number of top blocked tools to show"),
        json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    ) -> None:
        """Show interception statistics from a JSONL log file."""
        from munio.gate.cli import run_stats

        run_stats(log_file=log_file, top=top, json_output=json_output)

    # ── check (was verify) ─────────────────────────────────────────────

    @app.command()
    def check(
        action_json: str = typer.Argument(
            ...,
            help="Action as JSON string or '-' for stdin",
        ),
        constraints: str = typer.Option(
            "generic",
            "--constraints",
            "-c",
            help="Constraint pack name",
        ),
        mode: VerificationMode = typer.Option(
            VerificationMode.ENFORCE,
            "--mode",
            "-m",
            help="Verification mode",
        ),
        constraints_dir: str = typer.Option(
            "constraints",
            "--constraints-dir",
            "-d",
            help="Constraints directory path",
        ),
        output_format: OutputFormat = typer.Option(
            OutputFormat.TEXT,
            "--format",
            "-f",
            help="Output format",
        ),
        include_values: bool = typer.Option(
            True,
            "--include-values/--no-values",
            help="Include actual values in violations",
        ),
        quiet: bool = typer.Option(
            False,
            "--quiet",
            "-q",
            help="Exit code only, no output",
        ),
    ) -> None:
        """Verify a single action against constraints."""
        # 1. Read input
        if action_json == "-":
            action_json = _read_stdin()

        # 2. Parse JSON
        try:
            action_dict = json.loads(action_json)
        except json.JSONDecodeError as exc:
            _error_exit(f"Invalid JSON: {exc}")

        if not isinstance(action_dict, dict):
            _error_exit(f"JSON must be an object, got {type(action_dict).__name__}")

        # 3. Validate directory
        dir_path = _resolve_dir(constraints_dir)

        # 4. Validate required fields
        if "tool" not in action_dict:
            _error_exit("JSON must contain a 'tool' field")

        # 5. Build Guard and verify
        try:
            config = ConstraintConfig(
                mode=mode,
                constraint_packs=[constraints],
                include_violation_values=include_values,
            )
            guard = Guard(config=config, constraints_dir=dir_path)
            result = guard.check(action_dict)
        except MunioError as exc:
            _error_exit(str(exc))
        except Exception:
            _error_exit("Invalid action format")

        # 6. Output
        if not quiet:
            if output_format == OutputFormat.JSON:
                typer.echo(_format_result_json(result))
            else:
                typer.echo(_format_result_text(result))

        # 7. Exit code
        raise typer.Exit(code=0 if result.allowed else 1)

    # ── serve ──────────────────────────────────────────────────────────

    @app.command()
    def serve(
        host: str = typer.Option("127.0.0.1", "--host", "-H", help="Bind address"),
        port: int = typer.Option(8080, "--port", "-p", help="Bind port"),
        constraints_dir: str = typer.Option(
            "constraints", "--constraints-dir", "-d", help="Constraints directory path"
        ),
        packs: list[str] | None = typer.Option(
            None, "--pack", help="Default constraint packs (default: generic)"
        ),
        mode: VerificationMode = typer.Option(
            VerificationMode.ENFORCE, "--mode", "-m", help="Verification mode"
        ),
        workers: int = typer.Option(1, "--workers", "-w", help="Uvicorn worker count"),
        cors_origins: str = typer.Option(
            "", "--cors-origins", help="CORS allowed origins (comma-separated, empty=none)"
        ),
        log_level: str = typer.Option("info", "--log-level", help="Log level"),
    ) -> None:
        """Start the HTTP API server for remote verification."""
        try:
            from munio.server import ServerConfig, create_server
        except ImportError:
            _error_exit('Server dependencies not installed.\nRun: pip install "munio[server]"')

        try:
            import uvicorn
        except ImportError:
            _error_exit('uvicorn not installed.\nRun: pip install "munio[server]"')

        origins = [o.strip() for o in cors_origins.split(",") if o.strip()]
        if "*" in origins:
            print(
                "WARNING: CORS wildcard '*' allows any origin — use explicit origins in production",
                file=sys.stderr,
            )
        default_packs = packs if packs else ["generic"]

        config = ServerConfig(
            constraints_dir=constraints_dir,
            default_packs=default_packs,
            mode=mode,
            cors_origins=origins,
        )

        server_app = create_server(config)

        print(f"Starting munio server on {host}:{port}")
        print(f"  Constraints: {constraints_dir}")
        print(f"  Packs: {default_packs}")
        print(f"  Mode: {mode.value}")

        uvicorn.run(server_app, host=host, port=port, workers=workers, log_level=log_level)

    # ── policy (was policy-check) ──────────────────────────────────────

    @app.command()
    def policy(
        constraint_file: str | None = typer.Option(
            None,
            "--constraint-file",
            "-f",
            help="Path to a Tier 4 YAML constraint file",
        ),
        check_name: str | None = typer.Option(
            None,
            "--check-name",
            "-n",
            help="Name of a Tier 4 constraint from loaded registry",
        ),
        constraints_dir: str = typer.Option(
            "constraints",
            "--constraints-dir",
            "-d",
            help="Constraints directory path",
        ),
        packs: list[str] | None = typer.Option(
            None,
            "--pack",
            "-p",
            help="Constraint packs to load (default: all)",
        ),
        output_format: OutputFormat = typer.Option(
            OutputFormat.TEXT,
            "--format",
            help="Output format",
        ),
    ) -> None:
        """Run Tier 4 deploy-time Z3 policy verification."""
        from munio._policy_verifier import PolicyVerifier
        from munio.models import Constraint, DeployCheck, Tier

        if constraint_file is None and check_name is None:
            _error_exit("Specify --constraint-file or --check-name")

        # Load all constraints
        dir_path = _resolve_dir(constraints_dir)
        try:
            registry = load_constraints_dir(dir_path, packs=packs)
        except ConstraintLoadError as exc:
            _error_exit(str(exc))

        all_constraints = list(registry)

        # Find the Tier 4 constraint
        tier4_constraint: Constraint | None = None

        if constraint_file is not None:
            import yaml

            file_path = Path(constraint_file)
            if not file_path.exists():
                _error_exit(f"Constraint file not found: {constraint_file}")
            try:
                raw = file_path.read_text(encoding="utf-8")
                data = yaml.safe_load(raw)
                if not isinstance(data, dict):
                    _error_exit(f"Invalid YAML in {constraint_file}")
                tier4_constraint = Constraint(**data)
            except Exception as exc:
                _error_exit(f"Failed to load {constraint_file}: {exc}")
        else:
            # Search by name in loaded registry
            for c in all_constraints:
                if c.name == check_name and c.tier == Tier.TIER_4:
                    tier4_constraint = c
                    break
            if tier4_constraint is None:
                _error_exit(f"Tier 4 constraint '{check_name}' not found in registry")

        if tier4_constraint.tier != Tier.TIER_4:
            _error_exit(
                f"Constraint '{tier4_constraint.name}' is Tier {tier4_constraint.tier.value}, not Tier 4"
            )
        if tier4_constraint.deploy_check is None:
            _error_exit(f"Constraint '{tier4_constraint.name}' has no deploy_check")

        deploy_check: DeployCheck = tier4_constraint.deploy_check

        # Run verification
        verifier = PolicyVerifier()
        result = verifier.verify(
            deploy_check.type,
            all_constraints,
            deploy_check=deploy_check,
        )

        # Output
        if output_format == OutputFormat.JSON:
            typer.echo(_format_policy_json(result))
        else:
            typer.echo(_format_policy_text(result))

        # Exit code: 0=SAFE, 1=UNSAFE, 2=ERROR/UNKNOWN/TIMEOUT
        if result.result == PolicyResult.SAFE:
            raise typer.Exit(code=0)
        if result.result == PolicyResult.UNSAFE:
            raise typer.Exit(code=1)
        raise typer.Exit(code=2)

    # ── audit (was scan) ───────────────────────────────────────────────

    @app.command()
    def audit(
        constraints_dir: str = typer.Option(
            "constraints",
            "--constraints-dir",
            "-d",
            help="Constraints directory path",
        ),
        packs: list[str] | None = typer.Option(
            None,
            "--pack",
            "-p",
            help="Specific packs to scan (default: all)",
        ),
        output_format: OutputFormat = typer.Option(
            OutputFormat.TEXT,
            "--format",
            "-f",
            help="Output format",
        ),
        strict: bool = typer.Option(
            False,
            "--strict",
            help="Exit 1 if issues detected (for CI)",
        ),
    ) -> None:
        """Audit constraints directory for statistics and issues."""
        # 1. Validate directory
        dir_path = _resolve_dir(constraints_dir)

        # 2. Load constraints
        try:
            registry = load_constraints_dir(dir_path, packs=packs)
        except ConstraintLoadError as exc:
            _error_exit(str(exc))

        # 3. Gather statistics
        all_constraints = list(registry)
        tiers: dict[str, int] = {}
        check_types: dict[str, int] = {}
        actions: set[str] = set()
        issues: list[str] = []

        for c in all_constraints:
            tier_key = f"tier_{c.tier.value}"
            tiers[tier_key] = tiers.get(tier_key, 0) + 1

            if c.check is not None:
                ct = c.check.type.value
                check_types[ct] = check_types.get(ct, 0) + 1

            actions.add(c.action)

            if not c.enabled:
                issues.append(f"'{c.name}' is disabled")
            if c.on_violation == OnViolation.SHADOW:
                issues.append(f"'{c.name}' has on_violation=shadow")

        stats: dict[str, Any] = {
            "total": len(all_constraints),
            "tiers": tiers,
            "check_types": check_types,
            "actions": sorted(actions),
            "issues": issues,
        }

        # 4. Output
        if output_format == OutputFormat.JSON:
            typer.echo(_format_scan_json(stats))
        else:
            typer.echo(_format_scan_text(stats))

        # 5. Exit code
        if strict and issues:
            raise typer.Exit(code=1)

    # ── download-models ───────────────────────────────────────────────

    @app.command(name="download-models")
    def download_models(
        tier: str | None = typer.Option(
            None, "--tier", help="Download only models for a specific tier (l2.5, l2.6)"
        ),
        model: str | None = typer.Option(None, "--model", help="Download a specific model by name"),
        models_dir: str | None = typer.Option(
            None, "--models-dir", help="Custom directory for model storage"
        ),
        force: bool = typer.Option(False, "--force", help="Re-download even if already installed"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be downloaded"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed progress"),
        list_models: bool = typer.Option(False, "--list", help="List installed models"),
    ) -> None:
        """Download ML classifier models for enhanced detection."""
        from pathlib import Path as _Path

        from munio.downloader import (
            MODEL_REGISTRY,
            download_all,
            download_model,
            list_installed_models,
        )

        mdir = _Path(models_dir) if models_dir else None

        if list_models:
            installed = list_installed_models(mdir)
            if not installed:
                typer.echo("No models installed.")
                typer.echo("Run: munio download-models")
            else:
                typer.echo("Installed models:")
                for m in installed:
                    verified = "verified" if m.get("sha256_ok") else "unverified"
                    typer.echo(f"  {m['name']}: {m['size_mb']:.1f} MB ({verified})")
            raise typer.Exit(0)

        if model:
            if model not in MODEL_REGISTRY:
                typer.echo(
                    f"Error: Unknown model '{model}'. "
                    f"Available: {', '.join(MODEL_REGISTRY.keys())}",
                    err=True,
                )
                raise typer.Exit(2)
            ok = download_model(
                model, models_dir=mdir, force=force, dry_run=dry_run, verbose=verbose
            )
            raise typer.Exit(0 if ok else 1)

        # Download all (or filtered by tier)
        results = download_all(
            tier=tier, models_dir=mdir, force=force, dry_run=dry_run, verbose=verbose
        )

        if not results:
            typer.echo(
                f"No models match tier '{tier}'." if tier else "No models to download.",
                err=True,
            )
            raise typer.Exit(2)

        ok_count = sum(1 for v in results.values() if v)
        total = len(results)

        if dry_run:
            typer.echo(f"[dry-run] Would download {total} model(s)")
        else:
            typer.echo(f"Downloaded {ok_count}/{total} model(s)")

        raise typer.Exit(0 if ok_count == total else 1)

    # ── version ────────────────────────────────────────────────────────

    @app.command()
    def version() -> None:
        """Show munio version and Z3 availability."""
        from munio import __version__

        print(f"munio v{__version__}")

        try:
            import z3  # type: ignore[import-untyped]

            print(f"z3-solver  {z3.get_version_string()}")
        except ImportError:
            print("z3-solver  not installed (Tier 1 only)")
            print('  Install with: pip install "munio[z3]"')

    return app


def _get_app() -> Any:
    """Get or create the CLI app (cached)."""
    global _app
    if _app is None:
        _app = create_app()  # raises ImportError if typer missing
    return _app


def main() -> None:
    """CLI entrypoint with user-friendly error message."""
    # Smart default: `munio` with no args runs config-scan
    if len(sys.argv) == 1:
        import contextlib

        from munio.scan.cli import run_config_scan

        with contextlib.suppress(SystemExit, Exception):
            run_config_scan(output_format="text")
        return

    try:
        app = _get_app()
    except ImportError:
        print(
            'Error: CLI dependencies not installed.\nRun: pip install "munio[cli]"',
            file=sys.stderr,
        )
        sys.exit(1)
    app()


def __getattr__(name: str) -> Any:
    """Lazy module-level ``app`` access for programmatic use.

    Raises ImportError (not sys.exit) — safe for library code.
    """
    if name == "app":
        return _get_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
