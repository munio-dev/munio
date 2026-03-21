"""L7 Source Analysis — tree-sitter AST taint tracking for MCP handlers.

Detects vulnerabilities by tracing tool parameters to dangerous sinks
in handler source code. Supports JS/TS and Python MCP SDKs.

Checks:
  L7_001: Command injection (CWE-78)
  L7_002: SQL injection (CWE-89)
  L7_003: Path traversal (CWE-22)
  L7_004: SSRF (CWE-918)
  L7_005: Code injection (CWE-94)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NamedTuple

from munio.scan.models import (
    AttackType,
    Finding,
    FindingSeverity,
    Layer,
    ToolDefinition,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from tree_sitter import Node

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────

_MAX_FILES = 500
_MAX_FILE_SIZE = 512_000  # 500KB
_MAX_TOTAL_BYTES = 50_000_000  # 50MB
_MAX_WALK_DEPTH = 20
_MAX_IMPORT_DEPTH = 2
_MAX_FINDINGS_PER_HANDLER = 50
_SKIP_DIRS = frozenset(
    {
        "node_modules",
        "__pycache__",
        ".git",
        "build",
        ".venv",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)
_MIN_AVG_LINE_LEN_MINIFIED = 200


# ── Sink patterns ────────────────────────────────────────────────


class SinkPattern(NamedTuple):
    """A known dangerous function call pattern."""

    func_name: str
    receiver: str | None  # None = builtin/global; "a|b" = any of a, b
    cwe: str
    severity: FindingSeverity
    rule_id: str
    attack_type: AttackType


_JS_SINKS: tuple[SinkPattern, ...] = (
    # CWE-78: Command injection
    SinkPattern(
        "exec",
        "child_process",
        "CWE-78",
        FindingSeverity.CRITICAL,
        "L7_001",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "execSync",
        "child_process",
        "CWE-78",
        FindingSeverity.CRITICAL,
        "L7_001",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "spawn",
        "child_process",
        "CWE-78",
        FindingSeverity.CRITICAL,
        "L7_001",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "execFile",
        "child_process",
        "CWE-78",
        FindingSeverity.CRITICAL,
        "L7_001",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "execa", "execa", "CWE-78", FindingSeverity.CRITICAL, "L7_001", AttackType.COMMAND_INJECTION
    ),
    # CWE-89: SQL injection
    SinkPattern(
        "query",
        "db|conn|connection|pool|knex|prisma|sequelize|client",
        "CWE-89",
        FindingSeverity.CRITICAL,
        "L7_002",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "execute",
        "cursor|conn|connection|db|client",
        "CWE-89",
        FindingSeverity.CRITICAL,
        "L7_002",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "raw",
        "knex|prisma|sequelize",
        "CWE-89",
        FindingSeverity.CRITICAL,
        "L7_002",
        AttackType.COMMAND_INJECTION,
    ),
    # CWE-22: Path traversal
    SinkPattern(
        "readFile",
        "fs|fsPromises",
        "CWE-22",
        FindingSeverity.CRITICAL,
        "L7_003",
        AttackType.PATH_TRAVERSAL,
    ),
    SinkPattern(
        "readFileSync",
        "fs",
        "CWE-22",
        FindingSeverity.CRITICAL,
        "L7_003",
        AttackType.PATH_TRAVERSAL,
    ),
    SinkPattern(
        "writeFile",
        "fs|fsPromises",
        "CWE-22",
        FindingSeverity.CRITICAL,
        "L7_003",
        AttackType.PATH_TRAVERSAL,
    ),
    SinkPattern(
        "writeFileSync",
        "fs",
        "CWE-22",
        FindingSeverity.CRITICAL,
        "L7_003",
        AttackType.PATH_TRAVERSAL,
    ),
    SinkPattern(
        "open",
        "fs|fsPromises",
        "CWE-22",
        FindingSeverity.CRITICAL,
        "L7_003",
        AttackType.PATH_TRAVERSAL,
    ),
    SinkPattern(
        "unlink",
        "fs|fsPromises",
        "CWE-22",
        FindingSeverity.CRITICAL,
        "L7_003",
        AttackType.PATH_TRAVERSAL,
    ),
    # CWE-918: SSRF — bare fetch() REMOVED (29% FP rate: every API client triggers it)
    # Only flag receiver-qualified HTTP calls where import source confirms the library
    SinkPattern(
        "get",
        "axios|http|https|got|undici",
        "CWE-918",
        FindingSeverity.HIGH,
        "L7_004",
        AttackType.SSRF,
    ),
    SinkPattern(
        "post",
        "axios|http|https|got|undici",
        "CWE-918",
        FindingSeverity.HIGH,
        "L7_004",
        AttackType.SSRF,
    ),
    # CWE-94: Code injection
    SinkPattern(
        "eval", None, "CWE-94", FindingSeverity.CRITICAL, "L7_005", AttackType.COMMAND_INJECTION
    ),
    SinkPattern(
        "Function", None, "CWE-94", FindingSeverity.CRITICAL, "L7_005", AttackType.COMMAND_INJECTION
    ),
)

_PY_SINKS: tuple[SinkPattern, ...] = (
    # CWE-78: Command injection
    SinkPattern(
        "system", "os", "CWE-78", FindingSeverity.CRITICAL, "L7_001", AttackType.COMMAND_INJECTION
    ),
    SinkPattern(
        "popen", "os", "CWE-78", FindingSeverity.CRITICAL, "L7_001", AttackType.COMMAND_INJECTION
    ),
    SinkPattern(
        "run",
        "subprocess",
        "CWE-78",
        FindingSeverity.CRITICAL,
        "L7_001",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "call",
        "subprocess",
        "CWE-78",
        FindingSeverity.CRITICAL,
        "L7_001",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "Popen",
        "subprocess",
        "CWE-78",
        FindingSeverity.CRITICAL,
        "L7_001",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "check_output",
        "subprocess",
        "CWE-78",
        FindingSeverity.CRITICAL,
        "L7_001",
        AttackType.COMMAND_INJECTION,
    ),
    # CWE-89: SQL injection
    SinkPattern(
        "execute",
        "cursor",
        "CWE-89",
        FindingSeverity.CRITICAL,
        "L7_002",
        AttackType.COMMAND_INJECTION,
    ),
    SinkPattern(
        "executemany",
        "cursor",
        "CWE-89",
        FindingSeverity.CRITICAL,
        "L7_002",
        AttackType.COMMAND_INJECTION,
    ),
    # CWE-22: Path traversal
    SinkPattern(
        "open", None, "CWE-22", FindingSeverity.MEDIUM, "L7_003", AttackType.PATH_TRAVERSAL
    ),
    SinkPattern(
        "read_text", "Path", "CWE-22", FindingSeverity.CRITICAL, "L7_003", AttackType.PATH_TRAVERSAL
    ),
    # CWE-918: SSRF
    SinkPattern(
        "get", "requests|httpx", "CWE-918", FindingSeverity.HIGH, "L7_004", AttackType.SSRF
    ),
    SinkPattern(
        "post", "requests|httpx", "CWE-918", FindingSeverity.HIGH, "L7_004", AttackType.SSRF
    ),
    SinkPattern(
        "urlopen",
        "urllib.request|urllib",
        "CWE-918",
        FindingSeverity.CRITICAL,
        "L7_004",
        AttackType.SSRF,
    ),
    # CWE-94: Code injection (Python builtins, NOT subprocess)
    SinkPattern(
        "eval", None, "CWE-94", FindingSeverity.CRITICAL, "L7_005", AttackType.COMMAND_INJECTION
    ),
    SinkPattern(
        "exec", None, "CWE-94", FindingSeverity.CRITICAL, "L7_005", AttackType.COMMAND_INJECTION
    ),
)

# CWE-specific sanitizer patterns
_CWE78_SANITIZERS = frozenset({"quote", "shlex.quote", "shlex.join"})
_CWE89_PLACEHOLDERS = frozenset({"?", "$1", "$2", "$3", "%s", ":name", ":param"})


# ── Data structures ──────────────────────────────────────────────


@dataclass(frozen=True)
class Handler:
    """A detected MCP tool handler."""

    tool_name: str
    param_names: list[str]
    body_node: Node
    file_path: Path
    line_start: int
    file_source: bytes = b""
    imports: dict[str, str] = field(default_factory=dict)  # local_name → module source


# ── Main analyzer ────────────────────────────────────────────────


class L7SourceAnalyzer:
    """L7 Source Analysis layer — tree-sitter taint tracking."""

    def __init__(self, source_dir: Path | None = None) -> None:
        self._source_dir = source_dir
        self._ready = False

        if source_dir is None or not source_dir.exists():
            return

        try:
            from munio.scan.layers._ts_utils import (
                ImportResolver,
                ParsedFile,
                create_parser,
                detect_language,
                tree_sitter_available,
            )

            if not tree_sitter_available():
                return
        except ImportError:
            return

        self._create_parser = create_parser
        self._detect_language = detect_language
        self._ParsedFile = ParsedFile
        self._ImportResolver = ImportResolver
        self._ready = True

    @property
    def layer(self) -> Layer:
        return Layer.L7_SOURCE

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]:
        """Analyze source code for taint flows from tool params to sinks."""
        if not self._ready or self._source_dir is None:
            return []

        # 1. Discover and parse files
        parsed = self._parse_all_files()
        if not parsed:
            return []

        # 2. Build import resolver
        self._ImportResolver(parsed)  # side-effect: validates imports

        # 3. Detect handlers across all files
        handlers: list[Handler] = []
        for path, pf in parsed.items():
            try:
                handlers.extend(self._detect_handlers(pf.tree, pf.language, pf.source, path))
            except Exception:  # noqa: PERF203 — fail-closed per tool
                logger.warning("L7 handler detection failed for %s, skipping", path)

        # 4. Find dangerous patterns in each handler
        findings: list[Finding] = []
        for handler in handlers:
            try:
                lang = self._detect_language(handler.file_path) or "javascript"
                hfindings = self._find_dangerous_patterns(handler, lang)
                findings.extend(hfindings[:_MAX_FINDINGS_PER_HANDLER])
            except Exception:  # noqa: PERF203 — fail-closed per handler
                logger.warning(
                    "L7 analysis failed for handler '%s' in %s, skipping",
                    handler.tool_name,
                    handler.file_path,
                )

        # 5. File-level sweep — only for SQL injection (keeps postgres CVE detection).
        # Restricted: only fires when NO handlers detected in the file (fallback mode).
        for path, pf in parsed.items():
            # Only sweep files where NO handlers were detected (fallback for setRequestHandler etc.)
            file_has_handlers = any(h.file_path == path for h in handlers)
            if file_has_handlers:
                continue  # Handler-scoped analysis already covered this file
            try:
                sweep = self._file_sweep(pf.source, pf.language, path)
                findings.extend(sweep)
            except Exception:  # noqa: S110 — best-effort file sweep, non-critical
                pass

        # 6. Deduplicate by (rule_id, location) — keep highest confidence
        seen: dict[tuple[str, str], Finding] = {}
        for f in findings:
            key = (f.id, f.location)
            if key not in seen or f.confidence > seen[key].confidence:
                seen[key] = f
        return sorted(seen.values(), key=lambda f: f.severity)

    # ── File discovery & parsing ─────────────────────────────────

    def _parse_all_files(self) -> dict[Path, object]:
        """Discover and parse all source files in source_dir."""
        from munio.scan.layers._ts_utils import _ALL_EXTENSIONS

        assert self._source_dir is not None  # noqa: S101 — internal invariant, set in analyze()
        files: list[Path] = []
        total_bytes = 0

        for p in sorted(self._source_dir.rglob("*")):
            if len(files) >= _MAX_FILES:
                break
            if not p.is_file():
                continue
            if p.suffix.lower() not in _ALL_EXTENSIONS:
                continue
            if any(skip in p.parts for skip in _SKIP_DIRS):
                continue
            size = p.stat().st_size
            if size > _MAX_FILE_SIZE or size == 0:
                continue
            total_bytes += size
            if total_bytes > _MAX_TOTAL_BYTES:
                break
            files.append(p)

        # Parse each file
        parsed: dict[Path, object] = {}
        parsers: dict[str, object] = {}

        for fp in files:
            lang = self._detect_language(fp)
            if lang is None:
                continue

            try:
                source = fp.read_bytes()
            except OSError:
                continue

            # Skip minified files
            if self._is_minified(source):
                logger.debug("Skipping minified file: %s", fp)
                continue

            # Get or create parser for this language
            if lang not in parsers:
                try:
                    parsers[lang] = self._create_parser(lang)
                except Exception:  # noqa: S112 — skip unsupported language parsers
                    continue

            parser = parsers[lang]
            try:
                tree = parser.parse(source)  # type: ignore[union-attr]
            except Exception:  # noqa: S112 — skip unparseable files
                continue

            parsed[fp] = self._ParsedFile(tree=tree, source=source, language=lang, path=fp)

        return parsed  # type: ignore[return-value]

    @staticmethod
    def _is_minified(source: bytes) -> bool:
        """Detect minified files by average line length."""
        lines = source.split(b"\n")
        if len(lines) < 3:
            return False
        total_len = sum(len(line) for line in lines)
        avg = total_len / len(lines)
        return avg > _MIN_AVG_LINE_LEN_MINIFIED

    # ── Handler detection ────────────────────────────────────────

    def _detect_handlers(
        self, tree: object, language: str, source: bytes, file_path: Path
    ) -> list[Handler]:
        """Detect MCP tool handler registrations in source code."""
        root = tree.root_node  # type: ignore[union-attr]
        if language in ("javascript", "typescript", "tsx"):
            return self._detect_js_handlers(root, source, file_path)
        if language == "python":
            return self._detect_py_handlers(root, source, file_path)
        return []

    def _detect_js_handlers(self, root: Node, source: bytes, file_path: Path) -> list[Handler]:
        """Detect server.tool() / server.registerTool() in JS/TS."""
        handlers: list[Handler] = []
        imports = self._collect_js_imports(root, source)

        for node in self._walk_descendants(root):
            if node.type != "call_expression":
                continue

            func = node.child_by_field_name("function")
            if func is None or func.type != "member_expression":
                continue

            prop = func.child_by_field_name("property")
            if prop is None:
                continue
            method = self._text(prop, source)
            if method not in ("tool", "registerTool", "setRequestHandler"):
                continue

            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                continue

            children = [c for c in args_node.children if c.is_named]

            # setRequestHandler pattern: (CallToolRequestSchema, handler)
            if method == "setRequestHandler":
                if len(children) < 2:
                    continue
                schema_text = self._text(children[0], source)
                if "CallTool" not in schema_text:
                    continue  # Skip ListTools, etc.
                handler_node = children[-1]
                param_names: list[str] = []
                body_node = None
                if handler_node.type in ("arrow_function", "function_expression"):
                    param_names = self._extract_js_params(handler_node, source)
                    body_node = handler_node.child_by_field_name("body")
                if body_node is not None:
                    handlers.append(
                        Handler(
                            tool_name="<dispatch>",
                            param_names=param_names,
                            body_node=body_node,
                            file_path=file_path,
                            line_start=node.start_point[0] + 1,
                            file_source=source,
                            imports=imports,
                        )
                    )
                continue

            # Extract tool name (first string arg) and handler (last function arg)
            children = [c for c in args_node.children if c.is_named]
            if len(children) < 2:
                continue

            # First named child should be string (tool name)
            name_node = children[0]
            if name_node.type != "string":
                continue
            tool_name = self._text(name_node, source).strip("'\"")

            # Last child should be handler (arrow_function, function_expression, or identifier)
            handler_node = children[-1]
            param_names: list[str] = []
            body_node: Node | None = None

            if handler_node.type in ("arrow_function", "function_expression"):
                param_names = self._extract_js_params(handler_node, source)
                body_node = handler_node.child_by_field_name("body")
            elif handler_node.type == "identifier":
                # Handler is a reference — find the function in this file
                ref_name = self._text(handler_node, source)
                from munio.scan.layers._ts_utils import find_local_function

                func_node = find_local_function(root, ref_name, source)
                if func_node is not None:
                    param_names = self._extract_js_params(func_node, source)
                    body_node = func_node.child_by_field_name("body")

            if body_node is not None:
                handlers.append(
                    Handler(
                        tool_name=tool_name,
                        param_names=param_names,
                        body_node=body_node,
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        file_source=source,
                        imports=imports,
                    )
                )

        return handlers

    def _detect_py_handlers(self, root: Node, source: bytes, file_path: Path) -> list[Handler]:
        """Detect @mcp.tool() decorated functions in Python."""
        handlers: list[Handler] = []
        imports = self._collect_py_imports(root, source)

        for node in root.children:
            if node.type != "decorated_definition":
                continue

            # Check decorators for .tool()
            is_tool = False
            for child in node.children:
                if child.type == "decorator":
                    dec_text = self._text(child, source)
                    if ".tool" in dec_text:
                        is_tool = True
                        break

            if not is_tool:
                continue

            defn = node.child_by_field_name("definition")
            if defn is None or defn.type != "function_definition":
                continue

            name_node = defn.child_by_field_name("name")
            if name_node is None:
                continue
            tool_name = self._text(name_node, source)

            # Check decorator for explicit name= kwarg: @mcp.tool(name="custom_name")
            for child in node.children:
                if child.type == "decorator":
                    for dchild in self._walk_descendants(child):
                        if dchild.type == "keyword_argument":
                            key = dchild.child_by_field_name("name")
                            val = dchild.child_by_field_name("value")
                            if key and self._text(key, source) == "name" and val:
                                explicit = self._text(val, source).strip("'\"")
                                if explicit:
                                    tool_name = explicit

            params_node = defn.child_by_field_name("parameters")
            param_names = self._extract_py_params(params_node, source) if params_node else []

            body_node = defn.child_by_field_name("body")
            if body_node is not None:
                handlers.append(
                    Handler(
                        tool_name=tool_name,
                        param_names=param_names,
                        body_node=body_node,
                        file_path=file_path,
                        line_start=defn.start_point[0] + 1,
                        file_source=source,
                        imports=imports,
                    )
                )

        return handlers

    # ── Import collection ────────────────────────────────────────

    def _collect_js_imports(self, root: Node, source: bytes) -> dict[str, str]:
        """Collect import mappings: local_name → module_source."""
        imports: dict[str, str] = {}
        for node in root.children:
            # ESM: import { name } from 'module'
            if node.type == "import_statement":
                src = node.child_by_field_name("source")
                if src is None:
                    continue
                module = self._text(src, source).strip("'\"")
                # Check for type-only import (skip)
                if any(c.type == "type" for c in node.children if not c.is_named):
                    continue
                clause = None
                for c in node.children:
                    if c.type == "import_clause":
                        clause = c
                        break
                if clause is None:
                    continue
                for c in clause.children:
                    if c.type == "named_imports":
                        for spec in c.children:
                            if spec.type == "import_specifier":
                                name = spec.child_by_field_name("name")
                                if name:
                                    local = spec.child_by_field_name("alias") or name
                                    imports[self._text(local, source)] = module
                    elif c.type == "identifier":
                        # default import
                        imports[self._text(c, source)] = module

            # CommonJS: const { name } = require('module')
            if node.type in ("lexical_declaration", "variable_declaration"):
                for decl in node.children:
                    if decl.type != "variable_declarator":
                        continue
                    value = decl.child_by_field_name("value")
                    if value is None or value.type != "call_expression":
                        continue
                    func = value.child_by_field_name("function")
                    if func is None or self._text(func, source) != "require":
                        continue
                    args = value.child_by_field_name("arguments")
                    if args is None:
                        continue
                    arg_children = [c for c in args.children if c.is_named]
                    if not arg_children or arg_children[0].type != "string":
                        continue
                    module = self._text(arg_children[0], source).strip("'\"")

                    name_node = decl.child_by_field_name("name")
                    if name_node is None:
                        continue
                    if name_node.type == "object_pattern":
                        for prop in name_node.children:
                            if prop.type == "shorthand_property_identifier_pattern":
                                imports[self._text(prop, source)] = module
                            elif prop.type == "pair_pattern":
                                val = prop.child_by_field_name("value")
                                if val:
                                    imports[self._text(val, source)] = module
                    elif name_node.type == "identifier":
                        imports[self._text(name_node, source)] = module

        return imports

    def _collect_py_imports(self, root: Node, source: bytes) -> dict[str, str]:
        """Collect Python import mappings: local_name → module_source."""
        imports: dict[str, str] = {}
        for node in root.children:
            if node.type == "import_statement":
                # import os, import subprocess
                for c in node.children:
                    if c.type == "dotted_name":
                        name = self._text(c, source)
                        imports[name] = name
                    elif c.type == "aliased_import":
                        alias = c.child_by_field_name("alias")
                        name = c.child_by_field_name("name")
                        if alias and name:
                            imports[self._text(alias, source)] = self._text(name, source)
            elif node.type == "import_from_statement":
                # from os import system, from subprocess import run
                module_node = node.child_by_field_name("module_name")
                module = self._text(module_node, source) if module_node else ""
                for c in node.children:
                    if c.type == "dotted_name" and c != module_node:
                        imports[self._text(c, source)] = module
                    elif c.type == "aliased_import":
                        alias = c.child_by_field_name("alias")
                        name = c.child_by_field_name("name")
                        if alias and name:
                            imports[self._text(alias, source)] = module
                        elif name:
                            imports[self._text(name, source)] = module
        return imports

    # ── Pattern-based analysis (replaces taint tracking) ────────

    _SQL_RE = None  # lazy compiled

    @classmethod
    def _get_sql_re(cls):
        """Lazy-compile SQL keyword regex."""
        if cls._SQL_RE is None:
            import re

            cls._SQL_RE = re.compile(
                r"(select\s+.{0,40}\s+from\s|insert\s+into\s|update\s+.{0,40}\s+set\s|delete\s+from\s|"
                r"drop\s+table|drop\s+database|alter\s+user|create\s+user|grant\s|truncate\s)",
                re.IGNORECASE,
            )
        return cls._SQL_RE

    def _find_dangerous_patterns(self, handler: Handler, lang: str) -> list[Finding]:
        """Find dangerous function calls with non-literal arguments in handler body."""
        findings: list[Finding] = []
        file_source = handler.file_source

        # Build sanitizer map: var_name → True if assigned from sanitizer
        sanitized_vars = self._collect_sanitized_vars(handler.body_node, file_source)

        # Walk ALL descendants in handler body
        for node in self._walk_descendants(handler.body_node):
            if len(findings) >= _MAX_FINDINGS_PER_HANDLER:
                break

            # Check 1: sink call with non-literal arg
            if node.type in ("call_expression", "call"):
                finding = self._check_sink_call(node, lang, handler, file_source, sanitized_vars)
                if finding:
                    findings.append(finding)
                else:
                    # Not a direct sink — check if it's a helper with sinks inside
                    helper_findings = self._check_helper_for_sinks(
                        node, lang, handler, file_source, sanitized_vars
                    )
                    findings.extend(helper_findings)

            # Check 2: SQL keywords in interpolated strings (Bandit-style)
            if node.type in ("template_string", "string"):
                finding = self._check_sql_interpolation(node, handler, file_source)
                if finding:
                    findings.append(finding)

        return findings

    def _check_helper_for_sinks(
        self,
        call_node: Node,
        lang: str,
        handler: Handler,
        source: bytes,
        sanitized_vars: set[str],
    ) -> list[Finding]:
        """Check if a function call leads to a helper with dangerous patterns."""
        func_node = call_node.child_by_field_name("function")
        if func_node is None or func_node.type != "identifier":
            return []

        func_name = self._text(func_node, source)

        # Check if any argument is non-literal (only follow if we're passing dynamic data)
        args_node = call_node.child_by_field_name("arguments") or call_node.child_by_field_name(
            "argument_list"
        )
        if args_node is None:
            return []
        arg_children = [c for c in args_node.children if c.is_named]
        has_non_literal = any(not self._is_static_expression(a, source) for a in arg_children)
        if not has_non_literal:
            return []

        # Find helper function in same file
        root = handler.body_node
        while root.parent is not None:
            root = root.parent

        from munio.scan.layers._ts_utils import find_local_function

        helper_node = find_local_function(root, func_name, source)
        if helper_node is None:
            return []

        body = helper_node.child_by_field_name("body")
        if body is None:
            return []

        # Get helper's parameter names — only report sinks that use these params
        if lang in ("javascript", "typescript", "tsx"):
            helper_params = set(self._extract_js_params(helper_node, source))
        else:
            params_node = helper_node.child_by_field_name("parameters")
            helper_params = (
                set(self._extract_py_params(params_node, source)) if params_node else set()
            )

        if not helper_params:
            return []  # No params = no taint from caller

        # Scan helper body for dangerous patterns
        findings: list[Finding] = []
        helper_sanitized = self._collect_sanitized_vars(body, source)
        all_sanitized = sanitized_vars | helper_sanitized

        for node in self._walk_descendants(body):
            if node.type in ("call_expression", "call"):
                finding = self._check_sink_call(node, lang, handler, source, all_sanitized)
                if finding:
                    # Only report if sink uses helper params (not internal constants)
                    sink_text = self._text(node, source)
                    if not any(p in sink_text for p in helper_params):
                        continue
                    # Lower confidence for helper-hop findings
                    findings.append(
                        self._finding(
                            finding_id=finding.id,
                            tool_name=finding.tool_name,
                            severity=finding.severity,
                            message=finding.message + " (via helper function)",
                            location=finding.location,
                            attack_type=finding.attack_type,
                            cwe=finding.cwe,
                            confidence=max(0.5, finding.confidence - 0.15),
                        )
                    )
            if node.type in ("template_string", "string"):
                finding = self._check_sql_interpolation(node, handler, source)
                if finding:
                    findings.append(finding)

        return findings[:5]  # Cap helper findings

    def _collect_sanitized_vars(self, body_node: Node, source: bytes) -> set[str]:
        """Collect variable names assigned from sanitizer calls (one-step backward look)."""
        sanitized: set[str] = set()
        for node in self._walk_descendants(body_node):
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if (
                    name_node
                    and value_node
                    and name_node.type == "identifier"
                    and self._is_sanitizer_call(value_node, source)
                ):
                    sanitized.add(self._text(name_node, source))
            # Python: x = shlex.quote(y)
            if node.type == "assignment":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if (
                    left
                    and right
                    and left.type == "identifier"
                    and self._is_sanitizer_call(right, source)
                ):
                    sanitized.add(self._text(left, source))
        return sanitized

    def _check_sink_call(
        self,
        node: Node,
        lang: str,
        handler: Handler,
        source: bytes,
        sanitized_vars: set[str],
    ) -> Finding | None:
        """Check if a call is a sink with non-literal first argument."""
        func_node = node.child_by_field_name("function")
        if func_node is None:
            return None

        func_name: str | None = None
        receiver: str | None = None

        if func_node.type in ("member_expression", "attribute"):
            prop = func_node.child_by_field_name("property") or func_node.child_by_field_name(
                "attribute"
            )
            obj = func_node.child_by_field_name("object")
            if prop is None:
                return None
            func_name = self._text(prop, source)
            if obj is not None:
                if obj.type == "regex":
                    return None  # regex.exec() — NOT a sink
                receiver = self._text(obj, source)
        elif func_node.type == "identifier":
            func_name = self._text(func_node, source)
        else:
            return None

        if func_name is None:
            return None

        sink = self._match_sink(func_name, receiver, lang, handler.imports)
        if sink is None:
            return None

        # Get arguments
        args_node = node.child_by_field_name("arguments") or node.child_by_field_name(
            "argument_list"
        )
        if args_node is None:
            return None

        arg_children = [c for c in args_node.children if c.is_named]
        if not arg_children:
            return None

        first_arg = arg_children[0]

        # KEY CHECK: is first argument a static literal?
        if self._is_static_expression(first_arg, source):
            return None  # Safe: exec("ls"), db.query("SELECT 1")

        # SSRF-specific: template literal with http constant base = low risk
        if sink.cwe == "CWE-918" and self._is_safe_url_template(first_arg, source):
            return None

        # Check if the argument is a sanitized variable
        if first_arg.type == "identifier" and self._text(first_arg, source) in sanitized_vars:
            return None  # Assigned from sanitizer call

        # Check specific sanitizer patterns (parameterized queries, array args)
        if self._is_sanitized(node, sink.cwe, arg_children, source, lang):
            return None

        confidence = 0.85
        # SSRF sinks have lower base confidence (fetch is commonly used safely)
        if sink.cwe == "CWE-918":
            confidence = 0.70
            # Template literal URL = even lower (constructed from base + path)
            if first_arg.type == "template_string":
                confidence = 0.55
        if handler.body_node.has_error:
            confidence -= 0.10

        rel_path = handler.file_path.name
        line = node.start_point[0] + 1

        return self._finding(
            finding_id=sink.rule_id,
            tool_name=handler.tool_name,
            severity=sink.severity,
            message=f"Non-literal argument to {func_name}() — potential {sink.cwe}",
            location=f"file:{rel_path}:{line}",
            attack_type=sink.attack_type,
            cwe=sink.cwe,
            confidence=confidence,
        )

    def _is_static_expression(self, node: Node, source: bytes) -> bool:
        """Returns True if expression is a compile-time constant (literal)."""
        # String literals (but NOT f-strings with interpolation)
        if node.type == "string":
            return all(child.type != "interpolation" for child in node.children)

        # Template literals with no substitutions = static
        if node.type == "template_string":
            return not any(c.type == "template_substitution" for c in node.children)

        # Number, boolean, null/None/undefined
        if node.type in (
            "number",
            "integer",
            "float",
            "true",
            "false",
            "null",
            "none",
            "undefined",
        ):
            return True

        # Array of all literals
        if node.type in ("array", "list"):
            return all(self._is_static_expression(c, source) for c in node.children if c.is_named)

        # Everything else (identifiers, member access, calls, binary ops) = NOT static
        return False

    def _check_sql_interpolation(
        self, node: Node, handler: Handler, source: bytes
    ) -> Finding | None:
        """Bandit-style: find SQL keywords in interpolated strings."""
        has_interpolation = False

        if node.type == "template_string":
            has_interpolation = any(c.type == "template_substitution" for c in node.children)
        elif node.type == "string":
            has_interpolation = any(c.type == "interpolation" for c in node.children)

        if not has_interpolation:
            return None

        text = self._text(node, source)
        sql_re = self._get_sql_re()
        if not sql_re.search(text):
            return None

        rel_path = handler.file_path.name
        line = node.start_point[0] + 1

        return self._finding(
            finding_id="L7_002",
            tool_name=handler.tool_name,
            severity=FindingSeverity.CRITICAL,
            message="SQL keywords in interpolated string — potential SQL injection",
            location=f"file:{rel_path}:{line}",
            attack_type=AttackType.COMMAND_INJECTION,
            cwe="CWE-89",
            confidence=0.80,
        )

    @staticmethod
    def _bind_sweep_to_handlers(
        sweep_findings: list[Finding],
        handlers: list[Handler],
        sweep_path: Path,
    ) -> list[Finding]:
        """Bind file-sweep findings to handlers if they fall inside handler body."""
        if not handlers or not sweep_findings:
            return sweep_findings

        # Build handler line ranges for this file
        file_handlers: list[tuple[int, int, str]] = []  # (start, end, tool_name)
        for h in handlers:
            if h.file_path.name != sweep_path.name:
                continue
            start = h.body_node.start_point[0] + 1
            end = h.body_node.end_point[0] + 1
            if h.tool_name not in ("<dispatch>", "<file-sweep>"):
                file_handlers.append((start, end, h.tool_name))

        if not file_handlers:
            return sweep_findings

        result: list[Finding] = []
        for f in sweep_findings:
            # Parse line from location "file:name.ts:42"
            parts = f.location.split(":")
            line = int(parts[-1]) if len(parts) >= 3 and parts[-1].isdigit() else 0

            # Check if line falls inside any handler
            bound_name: str | None = None
            for start, end, tool_name in file_handlers:
                if start <= line <= end:
                    bound_name = tool_name
                    break

            if bound_name:
                result.append(
                    Finding(
                        id=f.id,
                        layer=f.layer,
                        severity=f.severity,
                        tool_name=bound_name,  # Replace <file-sweep> with handler name
                        message=f.message,
                        description=f.description,
                        attack_type=f.attack_type,
                        cwe=f.cwe,
                        location=f.location,
                        counterexample=f.counterexample,
                        confidence=min(0.99, f.confidence + 0.10),  # Boost for handler binding
                    )
                )
            else:
                result.append(f)

        return result

    def _file_sweep(self, source: bytes, lang: str, path: Path) -> list[Finding]:
        """Sweep entire file for dangerous patterns (not handler-scoped)."""

        findings: list[Finding] = []
        text = source.decode("utf-8", "replace")
        rel = path.name

        sql_re = self._get_sql_re()

        for i, line_text in enumerate(text.split("\n"), 1):
            # SQL interpolation in f-strings or template literals
            if ("${" in line_text or 'f"' in line_text or "f'" in line_text) and sql_re.search(
                line_text
            ):
                # Check it's actually interpolation, not just a comment
                stripped = line_text.strip()
                if stripped.startswith(("//", "#")):
                    continue
                findings.append(
                    self._finding(
                        finding_id="L7_002",
                        tool_name="<file-sweep>",
                        severity=FindingSeverity.HIGH,
                        message="SQL keywords in interpolated string",
                        location=f"file:{rel}:{i}",
                        attack_type=AttackType.COMMAND_INJECTION,
                        cwe="CWE-89",
                        confidence=0.60,
                    )
                )
                if len(findings) >= 10:
                    break

        return findings

    # ── Sink matching (kept from v1) ───────────────────────────

    def _match_sink(
        self, func_name: str, receiver: str | None, lang: str, imports: dict[str, str]
    ) -> SinkPattern | None:
        """Match a function call against the sink catalog."""
        effective_receiver = receiver
        if not receiver and func_name in imports:
            effective_receiver = imports[func_name]

        sinks = _JS_SINKS if lang in ("javascript", "typescript", "tsx") else _PY_SINKS

        for sink in sinks:
            if sink.func_name != func_name:
                continue
            if sink.receiver is None:
                if effective_receiver is None:
                    return sink
            elif effective_receiver and any(
                r == effective_receiver for r in sink.receiver.split("|")
            ):
                return sink
        return None

    def _is_safe_url_template(self, node: Node, source: bytes) -> bool:
        """Check if a template literal/f-string has a constant http base URL.

        Pattern: `${CONSTANT_BASE}/${variable}` or f"{BASE_URL}/{path}"
        When the base URL is a constant (UPPER_CASE identifier or string literal
        starting with http), the user can only control the path — not SSRF.
        """
        if node.type == "template_string":
            children = list(node.children)
            # First meaningful child should be string fragment starting with http
            # or an identifier that looks like a constant (UPPER_CASE)
            for child in children:
                if child.type == "string_fragment":
                    text = self._text(child, source)
                    if text.startswith(("http://", "https://")):
                        return True  # Hardcoded base URL
                    break
                if child.type == "template_substitution":
                    # First part is a variable — check if it's a constant
                    for sub in child.children:
                        if sub.type == "identifier":
                            name = self._text(sub, source)
                            if name.isupper() or name.endswith(("_URL", "_BASE")):
                                return True  # Constant base URL variable
                    break
        # Python f-string with http base
        if node.type == "string":
            text = self._text(node, source)
            if text.startswith(('f"http', "f'http", 'f"https', "f'https")):
                return True
        # Variable assigned from template with constant base
        if node.type == "identifier":
            # Can't resolve without taint tracking — skip
            pass
        return False

    def _is_sanitizer_call(self, node: Node, source: bytes) -> bool:
        """Check if a call expression is a known sanitizer that kills taint."""
        if node.type not in ("call_expression", "call"):
            return False
        func = node.child_by_field_name("function")
        if func is None:
            return False

        # Get full function name (e.g., "shlex.quote", "escape")
        func_text = self._text(func, source)

        # CWE-78 sanitizers
        if func_text in ("shlex.quote", "shlex.join", "shellescape"):
            return True
        # Attribute call: shlex.quote → func is attribute node
        if func.type in ("member_expression", "attribute"):
            prop = func.child_by_field_name("property") or func.child_by_field_name("attribute")
            if prop and self._text(prop, source) in ("quote", "join", "escape", "shellescape"):
                obj = func.child_by_field_name("object")
                if obj and self._text(obj, source) in ("shlex", "shell"):
                    return True

        return False

    def _is_sanitized(
        self,
        call_node: Node,
        cwe: str,
        args: list[Node],
        source: bytes,
        lang: str,
    ) -> bool:
        """Check if a sink call is sanitized."""
        if cwe == "CWE-78":
            # execFile/spawn with array args = safe
            func = call_node.child_by_field_name("function")
            if func:
                name = self._text(func.child_by_field_name("property") or func, source)
                if (
                    name in ("execFile", "execFileSync", "spawn", "spawnSync")
                    and len(args) >= 2
                    and args[1].type == "array"
                ):
                    return True  # Second arg is array = safe

            # Python: shlex.quote in taint chain (crude check)
            # Check if any variable in the call was assigned from shlex.quote
            # This is a simplification — we check the argument text
            if lang == "python":
                arg_text = self._text(args[0], source) if args else ""
                if "quote" in arg_text:
                    return True

        if cwe == "CWE-89" and len(args) >= 2 and args[1].type in ("array", "list"):
            # Parameterized query: query("SELECT $1", [param])
            first_arg_text = self._text(args[0], source)
            if any(ph in first_arg_text for ph in _CWE89_PLACEHOLDERS):
                return True

        return False

    # ── Helpers ──────────────────────────────────────────────────

    def _extract_js_params(self, func_node: Node, source: bytes) -> list[str]:
        """Extract parameter names from a JS/TS function."""
        params: list[str] = []
        # Arrow function with single param (no parens): (args) => or args =>
        param = func_node.child_by_field_name("parameter")
        if param and param.type == "identifier":
            params.append(self._text(param, source))
            return params

        params_node = func_node.child_by_field_name("parameters")
        if params_node is None:
            return params

        for child in params_node.children:
            if child.type == "identifier":
                params.append(self._text(child, source))
            elif child.type == "required_parameter" or child.type == "optional_parameter":
                pattern = child.child_by_field_name("pattern")
                if pattern and pattern.type == "identifier":
                    params.append(self._text(pattern, source))
        return params

    def _extract_py_params(self, params_node: Node, source: bytes) -> list[str]:
        """Extract parameter names from a Python function, excluding self/cls/ctx."""
        skip = {"self", "cls", "ctx", "context"}
        params: list[str] = []
        for child in params_node.children:
            name: str | None = None
            if child.type == "identifier":
                name = self._text(child, source)
            elif child.type == "typed_parameter":
                n = child.children[0] if child.children else None
                if n and n.type == "identifier":
                    name = self._text(n, source)
            elif child.type == "default_parameter":
                n = child.child_by_field_name("name")
                if n:
                    name = self._text(n, source)
            if name and name not in skip:
                params.append(name)
        return params

    @staticmethod
    def _text(node: Node | None, source: bytes) -> str:
        """Extract text from a tree-sitter node."""
        if node is None:
            return ""
        return source[node.start_byte : node.end_byte].decode("utf-8", "replace")

    @staticmethod
    def _walk_descendants(node: Node):
        """Yield all descendant nodes."""
        cursor = node.walk()
        visited = False
        while True:
            if not visited:
                yield cursor.node
                if cursor.goto_first_child():
                    continue
            if cursor.goto_next_sibling():
                visited = False
                continue
            if not cursor.goto_parent():
                break
            visited = True

    @staticmethod
    def _finding(
        finding_id: str,
        tool_name: str,
        severity: FindingSeverity,
        message: str,
        *,
        location: str = "",
        attack_type: AttackType | None = None,
        cwe: str | None = None,
        confidence: float = 0.90,
    ) -> Finding:
        return Finding(
            id=finding_id,
            layer=Layer.L7_SOURCE,
            severity=severity,
            tool_name=tool_name,
            message=message,
            location=location,
            attack_type=attack_type,
            cwe=cwe,
            confidence=confidence,
        )
