"""YAML constraint parser, registry, and tier auto-detection.

Responsibilities:
- Load constraints from YAML files (single file or directory)
- Validate against Pydantic models (Constraint, ConstraintCheck, DeployCheck)
- Auto-detect tier from check type when not explicitly set
- Maintain a registry of loaded constraints for lookup by name/action
- Support constraint packs (generic, fintech, healthcare, etc.)

Design:
- YAML format mirrors Pydantic models exactly (no translation layer)
- Tier auto-detection: denylist/allowlist/threshold/regex -> Tier 1,
  deploy_check -> Tier 4, multiple numerical -> Tier 2
- Registry is immutable after loading (thread-safe reads)

SECURITY: All YAML parsing MUST use ``yaml.safe_load()`` exclusively.
Arbitrary YAML must never trigger code execution (no ``yaml.load()``).
"""

from __future__ import annotations

import fnmatch
import logging
import re
import types
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

from munio.models import Constraint, ProofAgentError, Tier

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

__all__ = [
    "ConstraintLoadError",
    "ConstraintRegistry",
    "load_constraints",
    "load_constraints_dir",
]

logger = logging.getLogger(__name__)

_MAX_FILE_SIZE = 1_048_576  # 1 MB
_MAX_CONSTRAINT_COUNT = 10_000
_PACK_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class ConstraintLoadError(ProofAgentError):
    """Error loading or parsing constraints.

    Wraps YAML syntax errors, Pydantic validation errors, and I/O errors
    with file-path context for actionable error messages.
    """


def load_constraints(path: Path | str) -> list[Constraint]:
    """Load constraints from a single YAML file.

    Uses ``yaml.safe_load()`` exclusively — never ``yaml.load()``.

    Args:
        path: Path to YAML constraint file.

    Returns:
        List of validated Constraint models.

    Raises:
        ConstraintLoadError: On any loading, parsing, or validation error.
    """
    p = Path(path)

    # Atomic read with size limit — eliminates TOCTOU between stat() and read().
    try:
        with p.open(encoding="utf-8") as f:
            raw = f.read(_MAX_FILE_SIZE + 1)
    except FileNotFoundError:
        msg = f"Constraint file not found: {p}"
        raise ConstraintLoadError(msg) from None
    except OSError as exc:
        msg = f"Cannot read constraint file {p}: {exc}"
        raise ConstraintLoadError(msg) from exc

    if len(raw) > _MAX_FILE_SIZE:
        msg = f"Constraint file too large: {p} (>{_MAX_FILE_SIZE} bytes, max {_MAX_FILE_SIZE})"
        raise ConstraintLoadError(msg)

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"Invalid YAML in {p}: {exc}"
        raise ConstraintLoadError(msg) from exc

    # Empty YAML (None) or comments-only
    if data is None:
        return []

    # Normalize to list
    if isinstance(data, dict):
        items: list[object] = [data]
    elif isinstance(data, list):
        items = data
    else:
        msg = f"Expected dict or list in {p}, got {type(data).__name__}"
        raise ConstraintLoadError(msg)

    # Alias amplification protection: cap top-level constraint count
    if len(items) > _MAX_CONSTRAINT_COUNT:
        msg = f"Constraint file {p} contains {len(items)} constraints, max {_MAX_CONSTRAINT_COUNT}"
        raise ConstraintLoadError(msg)

    constraints: list[Constraint] = []
    for i, item in enumerate(items):
        try:
            constraints.append(Constraint.model_validate(item))
        except ValidationError as exc:  # noqa: PERF203 — need per-item error reporting
            msg = f"Constraint validation failed in {p} (item {i}): {exc}"
            raise ConstraintLoadError(msg) from exc

    logger.debug("Loaded %d constraint(s) from %s", len(constraints), p)
    return constraints


def load_constraints_dir(
    directory: Path | str, packs: list[str] | None = None
) -> ConstraintRegistry:
    """Load all constraints from a directory (optionally filtered by packs).

    Uses ``yaml.safe_load()`` exclusively — never ``yaml.load()``.

    Args:
        directory: Path to constraints directory.
        packs: Optional list of constraint pack names to load.
            If None, discovers all subdirectories as packs.

    Returns:
        ConstraintRegistry with all loaded constraints.

    Raises:
        ConstraintLoadError: On duplicate constraint names or loading errors.
    """
    base = Path(directory)
    if not base.is_dir():
        return ConstraintRegistry(())

    resolved_base = base.resolve()

    if packs is None:
        pack_dirs = sorted(p for p in base.iterdir() if p.is_dir())
    else:
        for pack in packs:
            if not _PACK_NAME_RE.match(pack):
                msg = f"Invalid pack name {pack!r}: must match [a-zA-Z0-9][a-zA-Z0-9_-]*"
                raise ConstraintLoadError(msg)
        pack_dirs = [base / pack for pack in sorted(packs)]

    all_constraints: list[Constraint] = []
    # Track name -> source file for duplicate detection with file context
    name_to_file: dict[str, Path] = {}

    for pack_dir in pack_dirs:
        if not pack_dir.is_dir():
            continue

        # Collect YAML files in deterministic order
        yaml_files = sorted(
            [*pack_dir.rglob("*.yaml"), *pack_dir.rglob("*.yml")],
            key=lambda p: str(p.resolve()),
        )

        for yaml_file in yaml_files:
            # Symlink protection: resolved path must be under base directory
            resolved = yaml_file.resolve()
            if not resolved.is_relative_to(resolved_base):
                logger.warning("Skipping symlink outside base dir: %s", yaml_file)
                continue

            constraints = load_constraints(yaml_file)
            for constraint in constraints:
                if constraint.name in name_to_file:
                    msg = (
                        f"Duplicate constraint name {constraint.name!r} "
                        f"in {yaml_file} and {name_to_file[constraint.name]}"
                    )
                    raise ConstraintLoadError(msg)
                name_to_file[constraint.name] = yaml_file
                all_constraints.append(constraint)

    logger.info(
        "Loaded %d constraint(s) from %s (%d pack(s))",
        len(all_constraints),
        base,
        len([d for d in pack_dirs if d.is_dir()]),
    )
    return ConstraintRegistry(all_constraints)


class ConstraintRegistry:
    """Immutable registry of loaded constraints.

    Thread-safe after construction. Supports lookup by name,
    by action pattern, and by tier.

    Example::

        registry = load_constraints_dir("constraints/", packs=["generic"])
        constraint = registry["block-dangerous-urls"]
        applicable = registry.constraints_for("http_request")
    """

    __slots__ = ("_by_name", "_constraints")

    _constraints: tuple[Constraint, ...]
    _by_name: types.MappingProxyType[str, Constraint]

    def __init__(self, constraints: Sequence[Constraint]) -> None:
        by_name: dict[str, Constraint] = {}
        for c in constraints:
            if c.name in by_name:
                msg = f"Duplicate constraint name: {c.name!r}"
                raise ConstraintLoadError(msg)
            by_name[c.name] = c

        self._constraints = tuple(constraints)
        self._by_name = types.MappingProxyType(by_name)

    def get(self, name: str) -> Constraint | None:
        """Retrieve a constraint by name, returning None if not found."""
        return self._by_name.get(name)

    def __getitem__(self, name: str) -> Constraint:
        """Retrieve a constraint by name. Raises KeyError if not found."""
        try:
            return self._by_name[name]
        except KeyError:
            msg = f"No constraint named {name!r}"
            raise KeyError(msg) from None

    def constraints_for(self, tool_name: str) -> list[Constraint]:
        """Return all enabled constraints applicable to a tool name.

        Uses fnmatch.fnmatchcase for cross-platform case-sensitive matching.

        Args:
            tool_name: The tool name to match against constraint action patterns.

        Returns:
            List of enabled constraints whose action pattern matches.
        """
        # Casefold both sides: tool names are matched case-insensitively
        # to prevent bypass via case variants (e.g. "Exec" vs "exec").
        tool_cf = tool_name.casefold()
        return [
            c
            for c in self._constraints
            if c.enabled and fnmatch.fnmatchcase(tool_cf, c.action.casefold())
        ]

    def get_by_tier(self, tier: Tier) -> list[Constraint]:
        """Return all constraints of the specified tier."""
        return [c for c in self._constraints if c.tier == tier]

    def __len__(self) -> int:
        return len(self._constraints)

    def __iter__(self) -> Iterator[Constraint]:
        return iter(self._constraints)

    def __contains__(self, item: object) -> bool:
        if isinstance(item, str):
            return item in self._by_name
        return item in self._constraints

    def __repr__(self) -> str:
        return f"ConstraintRegistry({len(self._constraints)} constraints)"
