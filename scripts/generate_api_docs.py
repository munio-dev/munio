"""Generate API reference Markdown from Python source code using griffe.

Usage:
    python scripts/generate_api_docs.py          # generate all
    python scripts/generate_api_docs.py guard     # generate one module

Output goes to docs/reference/*.md (overwrites auto-generated sections,
preserves hand-written intros).
"""

from __future__ import annotations

import sys
from pathlib import Path

import griffe

SRC = Path(__file__).resolve().parent.parent / "src"
DOCS = Path(__file__).resolve().parent.parent / "docs" / "reference"

# ── What to document ─────────────────────────────────────────────────

MODULES: dict[str, dict] = {
    "guard": {
        "file": "guard.md",
        "title": "Guard",
        "intro": "High-level verification API. Wraps the constraint engine with a simple check/block interface.",
        "module": "munio.guard",
        "members": ["Guard", "ActionBlockedError"],
    },
    "models": {
        "file": "models.md",
        "title": "Models",
        "intro": "Core data models for actions, constraints, and verification results. All models are Pydantic v2 with `frozen=True`.",
        "module": "munio.models",
        "members": [
            "Action", "Constraint", "ConstraintConfig", "ConstraintCheck",
            "VerificationResult", "Violation",
            "OnViolation", "VerificationMode", "Tier",
        ],
    },
    "verifier": {
        "file": "verifier.md",
        "title": "Verifier",
        "intro": "Async verification pipeline with shadow mode and fail-closed behavior.",
        "module": "munio.verifier",
        "members": ["Verifier"],
    },
    "constraints": {
        "file": "constraints.md",
        "title": "Constraints",
        "intro": "YAML constraint loader, registry, and tier auto-detection.",
        "module": "munio.constraints",
        "members": ["load_constraints_dir", "load_constraints", "ConstraintRegistry", "ConstraintLoadError"],
    },
    "solver": {
        "file": "solver.md",
        "title": "Solver",
        "intro": "Tier 1 (Python) and Tier 2-4 (Z3) constraint evaluation engine.",
        "module": "munio.solver",
        "members": ["Tier1Solver"],
    },
    "server": {
        "file": "server.md",
        "title": "Server",
        "intro": "HTTP API server (FastAPI) for remote verification.",
        "module": "munio.server",
        "members": ["create_server", "ServerConfig"],
    },
    "scan-models": {
        "file": "scan-models.md",
        "title": "Scan Models",
        "intro": "Data models for the MCP security scanner.",
        "module": "munio.scan.models",
        "members": [
            "Finding", "ScanResult", "ToolDefinition", "ServerConfig",
            "Layer", "FindingSeverity", "AttackType", "OutputFormat",
            "ConfigScanResult", "ConfigFileResult", "ConfigPermissions",
        ],
    },
    "config-scanner": {
        "file": "config-scanner.md",
        "title": "Config Scanner",
        "intro": "Supply chain security scanner for MCP config files.",
        "module": "munio.scan.config_scanner",
        "members": ["ConfigScanner"],
    },
    "composition": {
        "file": "composition.md",
        "title": "Composition Analyzer",
        "intro": "Multi-server attack chain detection and danger scoring.",
        "module": "munio.scan.composition",
        "members": ["CompositionAnalyzer"],
    },
}


# ── Rendering ────────────────────────────────────────────────────────


def _render_param(p: griffe.Parameter) -> str:
    """Render a single parameter as table row."""
    annotation = ""
    if p.annotation is not None:
        annotation = _expr_to_str(p.annotation)
    default = ""
    if p.default is not None:
        default = _expr_to_str(p.default)
    return f"| `{p.name}` | `{annotation}` | {default} |"


def _expr_to_str(expr: str | griffe.Expr | None) -> str:
    """Convert griffe expression to readable string."""
    if expr is None:
        return ""
    if isinstance(expr, str):
        return expr
    try:
        return str(expr)
    except Exception:
        return repr(expr)


def _render_class(obj: griffe.Class) -> list[str]:
    """Render a class as Markdown."""
    lines: list[str] = []
    lines.append(f"### `{obj.name}`")
    lines.append("")

    # Docstring
    if obj.docstring:
        lines.append(obj.docstring.value.strip())
        lines.append("")

    # Constructor parameters (from __init__)
    init = obj.members.get("__init__")
    if init and hasattr(init, "parameters"):
        params = [p for p in init.parameters if p.name not in ("self", "cls")]
        if params:
            lines.append("**Parameters:**")
            lines.append("")
            lines.append("| Name | Type | Default |")
            lines.append("|------|------|---------|")
            for p in params:
                lines.append(_render_param(p))
            lines.append("")

    # Fields (for Pydantic models — class-level attributes)
    fields = [
        m for m in obj.members.values()
        if m.kind.value == "attribute"
        and not m.name.startswith("_")
        and m.name != "model_config"
    ]
    if fields:
        lines.append("**Fields:**")
        lines.append("")
        lines.append("| Name | Type | Description |")
        lines.append("|------|------|-------------|")
        for f in fields:
            ftype = _expr_to_str(f.annotation) if f.annotation else ""
            fdoc = f.docstring.value.strip() if f.docstring else ""
            lines.append(f"| `{f.name}` | `{ftype}` | {fdoc} |")
        lines.append("")

    # Enum members
    if any(
        base
        for base in (obj.bases or [])
        if "Enum" in str(base) or "IntEnum" in str(base)
    ):
        enum_members = [
            m for m in obj.members.values()
            if m.kind.value == "attribute"
            and not m.name.startswith("_")
            and m.name.isupper()
        ]
        if enum_members:
            lines.append("**Values:**")
            lines.append("")
            for em in enum_members:
                val = _expr_to_str(em.value) if hasattr(em, "value") and em.value else ""
                lines.append(f"- `{em.name}` = `{val}`")
            lines.append("")

    # Public methods
    methods = [
        m for m in obj.members.values()
        if m.kind.value == "function"
        and not m.name.startswith("_")
        and m.name != "__init__"
    ]
    if methods:
        lines.append("**Methods:**")
        lines.append("")
        for m in methods:
            params = [p for p in m.parameters if p.name not in ("self", "cls")]
            sig = ", ".join(p.name for p in params)
            ret = ""
            if m.returns:
                ret = f" -> {_expr_to_str(m.returns)}"
            lines.append(f"- `{m.name}({sig}){ret}`")
            if m.docstring:
                first_line = m.docstring.value.strip().split("\n")[0]
                lines.append(f"  {first_line}")
        lines.append("")

    return lines


def _render_function(obj: griffe.Function) -> list[str]:
    """Render a function as Markdown."""
    lines: list[str] = []

    params = [p for p in obj.parameters if p.name not in ("self", "cls")]
    sig = ", ".join(p.name for p in params)
    ret = f" -> {_expr_to_str(obj.returns)}" if obj.returns else ""
    lines.append(f"### `{obj.name}({sig}){ret}`")
    lines.append("")

    if obj.docstring:
        lines.append(obj.docstring.value.strip())
        lines.append("")

    if params:
        lines.append("**Parameters:**")
        lines.append("")
        lines.append("| Name | Type | Default |")
        lines.append("|------|------|---------|")
        for p in params:
            lines.append(_render_param(p))
        lines.append("")

    return lines


def _render_member(obj: griffe.Object) -> list[str]:
    """Render any griffe object."""
    if obj.kind.value == "class":
        return _render_class(obj)  # type: ignore[arg-type]
    if obj.kind.value == "function":
        return _render_function(obj)  # type: ignore[arg-type]
    return [f"### `{obj.name}`", "", obj.docstring.value.strip() if obj.docstring else "", ""]


# ── Main ─────────────────────────────────────────────────────────────


def generate(module_key: str) -> None:
    """Generate docs for a single module config."""
    config = MODULES[module_key]
    mod = griffe.load(config["module"], search_paths=[str(SRC)], resolve_aliases=False)

    lines: list[str] = []

    # Header
    lines.append(f"# {config['title']}")
    lines.append("")
    lines.append(config["intro"])
    lines.append("")
    lines.append(f"**Module:** `{config['module']}`")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Render each member
    for name in config["members"]:
        if name not in mod.members:
            lines.append(f"### `{name}`")
            lines.append("")
            lines.append(f"*Not found in module `{config['module']}`.*")
            lines.append("")
            continue
        obj = mod.members[name]
        lines.extend(_render_member(obj))

    # Footer
    lines.append("---")
    lines.append("")
    lines.append(f"*Auto-generated from source code. Do not edit manually.*")
    lines.append("")

    # Write
    out_path = DOCS / config["file"]
    out_path.write_text("\n".join(lines), encoding="utf-8")
    member_count = len(config["members"])
    print(f"  {config['file']}: {len(lines)} lines, {member_count} members")


def main() -> None:
    """Generate all or specific module docs."""
    DOCS.mkdir(parents=True, exist_ok=True)

    if len(sys.argv) > 1:
        keys = sys.argv[1:]
    else:
        keys = list(MODULES.keys())

    print(f"Generating API docs for {len(keys)} modules...")
    for key in keys:
        if key not in MODULES:
            print(f"  SKIP: unknown module '{key}'")
            continue
        generate(key)
    print("Done.")


if __name__ == "__main__":
    main()
