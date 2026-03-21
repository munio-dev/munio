"""Tree-sitter utilities for L7 source analysis.

Encapsulates tree-sitter availability check, parser creation,
language detection, and import resolution.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from pathlib import Path

    from tree_sitter import Node, Parser, Tree

logger = logging.getLogger(__name__)

# ── Availability ─────────────────────────────────────────────────

_JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx")
_TS_EXTENSIONS = (".ts", ".tsx")
_PY_EXTENSIONS = (".py", ".pyi")
_ALL_EXTENSIONS = frozenset(_JS_EXTENSIONS + _TS_EXTENSIONS + _PY_EXTENSIONS)

_FILE_RESOLUTION_ORDER = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_INDEX_FILES = tuple(f"index{ext}" for ext in _FILE_RESOLUTION_ORDER)


def tree_sitter_available() -> bool:
    """Return True if tree-sitter and language grammars are importable."""
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_javascript  # noqa: F401
        import tree_sitter_python  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
    except ImportError:
        return False
    return True


def detect_language(path: Path) -> str | None:
    """Detect language from file extension.

    Returns 'javascript', 'typescript', 'tsx', 'python', or None.
    """
    ext = path.suffix.lower()
    if ext in _JS_EXTENSIONS:
        return "javascript"
    if ext == ".ts":
        return "typescript"
    if ext == ".tsx":
        return "tsx"
    if ext in _PY_EXTENSIONS:
        return "python"
    return None


def create_parser(language: str) -> Parser:
    """Create a tree-sitter Parser for the given language."""
    from tree_sitter import Language, Parser

    lang_obj: Language
    if language == "javascript":
        import tree_sitter_javascript

        lang_obj = Language(tree_sitter_javascript.language())
    elif language in ("typescript", "tsx"):
        import tree_sitter_typescript

        if language == "tsx":
            lang_obj = Language(tree_sitter_typescript.language_tsx())
        else:
            lang_obj = Language(tree_sitter_typescript.language_typescript())
    elif language == "python":
        import tree_sitter_python

        lang_obj = Language(tree_sitter_python.language())
    else:
        msg = f"Unsupported language: {language}"
        raise ValueError(msg)

    return Parser(lang_obj)


# ── Parsed file storage ──────────────────────────────────────────


class ParsedFile(NamedTuple):
    """A parsed source file with its tree, source bytes, and language."""

    tree: Tree
    source: bytes
    language: str
    path: Path


# ── Import resolution ────────────────────────────────────────────


class ImportInfo(NamedTuple):
    """Information about an imported name."""

    source: str  # module specifier (e.g., 'child_process', './lib')
    original_name: str  # name in source module (may differ from local)
    kind: str  # 'named', 'default', 'namespace', 'require'


class ImportResolver:
    """Resolve cross-file imports for JS/TS and Python.

    Operates over a pre-parsed file set — no filesystem access after init.
    """

    _MAX_CHAIN_DEPTH: int = 3

    def __init__(self, parsed_files: dict[Path, ParsedFile]) -> None:
        self._files = parsed_files
        self._by_resolved: dict[Path, ParsedFile] = {
            p.resolve(): pf for p, pf in parsed_files.items()
        }

    def resolve(self, import_path: str, from_file: Path) -> Path | None:
        """Resolve an import specifier to an absolute file path."""
        raw = import_path.strip("'\"")
        if not raw.startswith("."):
            return None  # non-relative (npm, stdlib) — not resolved to file

        base_dir = from_file.resolve().parent

        # Exact match
        target = (base_dir / raw).resolve()
        if target in self._by_resolved:
            return target

        # Try extensions
        for ext in _FILE_RESOLUTION_ORDER:
            candidate = (base_dir / (raw + ext)).resolve()
            if candidate in self._by_resolved:
                return candidate

        # Try index files
        for idx in _INDEX_FILES:
            candidate = (base_dir / raw / idx).resolve()
            if candidate in self._by_resolved:
                return candidate

        return None

    def find_exported_function(
        self,
        name: str,
        file_path: Path,
        *,
        _depth: int = 0,
        _visited: frozenset[Path] | None = None,
    ) -> Node | None:
        """Find an exported function/variable by name in a file.

        Follows re-export chains up to _MAX_CHAIN_DEPTH.
        Uses _visited set to break circular imports.
        """
        if _visited is None:
            _visited = frozenset()
        resolved = file_path.resolve()
        if resolved in _visited or _depth > self._MAX_CHAIN_DEPTH:
            return None
        _visited = _visited | {resolved}

        pf = self._by_resolved.get(resolved)
        if pf is None:
            return None

        root = pf.tree.root_node

        # 1. Direct export: export function name() / export const name =
        for node in root.children:
            if node.type == "export_statement":
                decl = node.child_by_field_name("declaration")
                if decl and self._declaration_name(decl, pf.source) == name:
                    return decl

        # 2. Named re-export: export { name } from './other'
        for node in root.children:
            if node.type == "export_statement":
                source_node = node.child_by_field_name("source")
                if not source_node:
                    continue
                for child in node.children:
                    if child.type == "export_clause":
                        for spec in child.children:
                            if spec.type == "export_specifier":
                                spec_name = self._node_text(
                                    spec.child_by_field_name("name"), pf.source
                                )
                                if spec_name == name:
                                    target = self.resolve(
                                        self._node_text(source_node, pf.source), file_path
                                    )
                                    if target:
                                        return self.find_exported_function(
                                            name, target, _depth=_depth + 1, _visited=_visited
                                        )

        # 3. Star re-export: export * from './other'
        for node in root.children:
            if node.type == "export_statement":
                source_node = node.child_by_field_name("source")
                has_clause = any(c.type == "export_clause" for c in node.children)
                if source_node and not has_clause:
                    target = self.resolve(self._node_text(source_node, pf.source), file_path)
                    if target:
                        result = self.find_exported_function(
                            name, target, _depth=_depth + 1, _visited=_visited
                        )
                        if result:
                            return result

        # 4. Python: top-level function definition
        if pf.language == "python":
            return self._find_python_function(root, name, pf.source)

        # 5. Local function (JS) not exported but used internally
        return self._find_local_function(root, name, pf.source)

    def _find_python_function(self, root: Node, name: str, source: bytes) -> Node | None:
        """Find a top-level Python function definition by name."""
        for node in root.children:
            if node.type == "function_definition":
                fn_name = node.child_by_field_name("name")
                if fn_name and self._node_text(fn_name, source) == name:
                    return node
            if node.type == "decorated_definition":
                defn = node.child_by_field_name("definition")
                if defn and defn.type == "function_definition":
                    fn_name = defn.child_by_field_name("name")
                    if fn_name and self._node_text(fn_name, source) == name:
                        return defn
        return None

    @staticmethod
    def _declaration_name(node: Node, source: bytes) -> str | None:
        """Extract name from a declaration node."""
        if node.type in ("function_declaration", "class_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node:
                return source[name_node.start_byte : name_node.end_byte].decode("utf-8", "replace")
        if node.type in ("lexical_declaration", "variable_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    if name_node and name_node.type == "identifier":
                        return source[name_node.start_byte : name_node.end_byte].decode(
                            "utf-8", "replace"
                        )
        return None

    @staticmethod
    def _node_text(node: Node | None, source: bytes) -> str:
        """Extract text from a tree-sitter node."""
        if node is None:
            return ""
        return source[node.start_byte : node.end_byte].decode("utf-8", "replace")

    def _find_local_function(self, root: Node, name: str, source: bytes) -> Node | None:
        """Find a local (non-exported) function in JS/TS by name."""
        return find_local_function(root, name, source)


def find_local_function(root: Node, name: str, source: bytes) -> Node | None:
    """Find a local (non-exported) function in JS/TS by name (module-level)."""

    def _text(node: Node | None, src: bytes) -> str:
        if node is None:
            return ""
        return src[node.start_byte : node.end_byte].decode("utf-8", "replace")

    for node in root.children:
        if node.type in ("function_declaration", "generator_function_declaration"):
            fn_name = node.child_by_field_name("name")
            if fn_name and _text(fn_name, source) == name:
                return node
        if node.type in ("lexical_declaration", "variable_declaration"):
            for decl in node.children:
                if decl.type == "variable_declarator":
                    vname = decl.child_by_field_name("name")
                    value = decl.child_by_field_name("value")
                    if (
                        vname
                        and _text(vname, source) == name
                        and value
                        and value.type in ("arrow_function", "function_expression")
                    ):
                        return value
    return None
