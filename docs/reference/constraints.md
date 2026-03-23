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

## Constraint Packs by Category

### ASI03: Privilege Abuse — Safety Control Tampering (SCT)

Safety Control Tampering detects tool calls that programmatically disable safety controls before executing malicious commands. This category covers 5 atomic SCT primitives:

- **DISABLE_APPROVAL** — turn off user confirmation requirements
- **WEAKEN_POLICY** — relax security mode or policy strictness
- **ESCAPE_SANDBOX** — break out of container/sandbox isolation
- **ELEVATE_PRIVILEGE** — gain host-level or root execution
- **BYPASS_VALIDATION** — skip input/origin validation checks

Maps to OWASP ASI03, CWE-269/863/346, MITRE ATLAS AML.T0054.

#### OpenClaw-specific constraints (`constraints/openclaw/asi03-privilege-abuse/`)

| Constraint | Primitive | Description |
|-----------|-----------|-------------|
| `openclaw-safety-disable-approvals` | DISABLE_APPROVAL | Blocks disabling execution approval via `exec.approvals.set` |
| `openclaw-safety-disable-security-mode` | WEAKEN_POLICY | Blocks weakening security approval mode |
| `openclaw-gateway-url-override` | BYPASS_VALIDATION | Blocks gateway URL changes redirecting to attacker servers |
| `openclaw-sandbox-escape-host-mode` | ESCAPE_SANDBOX | Blocks config changes escaping container to host execution |

Example constraint:

```yaml
name: openclaw-safety-disable-approvals
description: "Block disabling execution approval requirements (CVE-2026-25253 step 5)"
tier: 1
action: exec.approvals.set
check:
  type: denylist
  field: ask
  values: ["off", "false", "no", "never", "disable", "disabled", "none", "0"]
  match: exact
  case_sensitive: false
on_violation: block
severity: critical
```

#### Generic constraints (`constraints/generic/asi03-privilege-abuse/`)

| Constraint | Primitive | Description |
|-----------|-----------|-------------|
| `generic-safety-control-tampering` | DISABLE_APPROVAL, WEAKEN_POLICY | Detects any tool call that disables or weakens safety controls |
| `generic-safety-control-sequence` | DISABLE_APPROVAL + ELEVATE_PRIVILEGE | Detects multi-step bypass: config change followed by code execution |
| `generic-sandbox-escape-config` | ESCAPE_SANDBOX | Detects configuration changes that escape sandbox/isolation boundaries |

The generic constraints use `warn` severity and broad action patterns (wildcards) to catch SCT across any MCP server, not just OpenClaw.

---

*Auto-generated from source code. Do not edit manually.*
