# Constraints

YAML constraint loader, registry, and tier auto-detection.

**Module:** `munio.constraints`

---

### `load_constraints_dir(directory, packs) -> ConstraintRegistry`

Load all constraints from a directory (optionally filtered by packs).

Uses ``yaml.safe_load()`` exclusively — never ``yaml.load()``.

Args:
    directory: Path to constraints directory.
    packs: Optional list of constraint pack names to load.
        If None, discovers all subdirectories as packs.

Returns:
    ConstraintRegistry with all loaded constraints.

Raises:
    ConstraintLoadError: On duplicate constraint names or loading errors.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `directory` | `Path | str` |  |
| `packs` | `list[str] | None` | None |

### `load_constraints(path) -> list[Constraint]`

Load constraints from a single YAML file.

Uses ``yaml.safe_load()`` exclusively — never ``yaml.load()``.

Args:
    path: Path to YAML constraint file.

Returns:
    List of validated Constraint models.

Raises:
    ConstraintLoadError: On any loading, parsing, or validation error.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `path` | `Path | str` |  |

### `ConstraintRegistry`

Immutable registry of loaded constraints.

Thread-safe after construction. Supports lookup by name,
by action pattern, and by tier.

Example::

    registry = load_constraints_dir("constraints/", packs=["generic"])
    constraint = registry["block-dangerous-urls"]
    applicable = registry.constraints_for("http_request")

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `constraints` | `Sequence[Constraint]` |  |

**Methods:**

- `get(name) -> Constraint | None`
  Retrieve a constraint by name, returning None if not found.
- `constraints_for(tool_name) -> list[Constraint]`
  Return all enabled constraints applicable to a tool name.
- `get_by_tier(tier) -> list[Constraint]`
  Return all constraints of the specified tier.

### `ConstraintLoadError`

Error loading or parsing constraints.

Wraps YAML syntax errors, Pydantic validation errors, and I/O errors
with file-path context for actionable error messages.

---

*Auto-generated from source code. Do not edit manually.*
