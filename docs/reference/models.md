# Models

Core data models for actions, constraints, and verification results. All models are Pydantic v2 with `frozen=True`.

**Module:** `munio.models`

---

### `Action`

An agent tool call to be verified.

This is the input to the verification pipeline. Every framework adapter
(LangChain, CrewAI, ADK, MCP) normalizes its tool call into this model.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `tool` | `str` |  |
| `args` | `dict[str, Any]` |  |
| `agent_id` | `str | None` |  |
| `metadata` | `dict[str, Any]` |  |

### `Constraint`

A single safety constraint loaded from YAML.

Maps to OWASP Agentic Top 10 categories (ASI01-ASI10).
Tier is auto-detected from check type if not specified.

Action pattern matching uses fnmatch (glob) syntax:
- ``"*"`` matches any action (default).
- ``"http_request"`` matches exactly ``"http_request"``.
- ``"http_*"`` matches ``"http_request"``, ``"http_get"``, etc.
- ``"*.read"`` matches ``"db.read"``, ``"file.read"``, etc.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `name` | `str` |  |
| `description` | `str` |  |
| `category` | `str` |  |
| `tier` | `Tier` |  |
| `action` | `str` |  |
| `actions` | `list[str] | None` |  |
| `check` | `ConstraintCheck | None` |  |
| `deploy_check` | `DeployCheck | None` |  |
| `conditions` | `list[ConstraintCondition]` |  |
| `on_violation` | `OnViolation` |  |
| `severity` | `ViolationSeverity` |  |
| `enabled` | `bool` |  |

### `ConstraintConfig`

Top-level configuration for munio.

Loaded from .munio.yaml or CLI flags.
Use ``model_copy(update={...})`` to derive modified configs.

Mode vs on_violation resolution:
- DISABLED mode: skip all checks, return allowed=True immediately.
- SHADOW mode: run all checks, always return allowed=True (global override).
- ENFORCE mode: per-constraint ``on_violation`` applies:
  - BLOCK: violation blocks the action (allowed=False).
  - WARN: violation logged, action allowed (allowed=True).
  - SHADOW: same as WARN for that individual constraint.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `mode` | `VerificationMode` |  |
| `constraints_dir` | `Path` |  |
| `constraint_packs` | `list[str]` |  |
| `default_on_unmatched` | `OnViolation` |  |
| `solver` | `SolverConfig` |  |
| `include_violation_values` | `bool` |  |
| `max_violation_value_length` | `int` |  |

### `ConstraintCheck`

The check definition inside a constraint.

Determines WHAT to check and HOW.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `type` | `CheckType` |  |
| `field` | `str` |  |
| `values` | `list[str]` |  |
| `patterns` | `list[str]` |  |
| `match` | `MatchMode` |  |
| `case_sensitive` | `bool` |  |
| `min` | `float | None` |  |
| `max` | `float | None` |  |
| `unit` | `str | None` |  |
| `variables` | `dict[str, CompositeVariable]` |  |
| `expression` | `str` |  |
| `window_seconds` | `float | None` |  |
| `max_count` | `int | None` |  |
| `steps` | `list[str]` |  |
| `scope` | `Literal['global', 'agent']` |  |

### `VerificationResult`

Result of verifying an action against a constraint set.

This is the primary output of the verification pipeline.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `allowed` | `bool` |  |
| `mode` | `VerificationMode` |  |
| `violations` | `list[Violation]` |  |
| `checked_constraints` | `int` |  |
| `elapsed_ms` | `float` |  |
| `tier_breakdown` | `dict[str, int]` |  |
| `timestamp` | `datetime` |  |
| `has_violations` | `bool` | Whether any violations were found, regardless of mode. |

### `Violation`

A single constraint violation found during verification.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `constraint_name` | `str` |  |
| `constraint_category` | `str` |  |
| `severity` | `ViolationSeverity` |  |
| `message` | `str` |  |
| `field` | `str` |  |
| `actual_value` | `str` |  |
| `tier` | `Tier` |  |
| `source` | `ViolationSource` |  |

### `OnViolation`

What to do when a constraint is violated.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `BLOCK` | `` |  |
| `WARN` | `` |  |
| `SHADOW` | `` |  |

**Values:**

- `BLOCK` = `'block'`
- `WARN` = `'warn'`
- `SHADOW` = `'shadow'`

### `VerificationMode`

How the guard behaves on violation.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `ENFORCE` | `` |  |
| `SHADOW` | `` |  |
| `DISABLED` | `` |  |

**Values:**

- `ENFORCE` = `'enforce'`
- `SHADOW` = `'shadow'`
- `DISABLED` = `'disabled'`

### `Tier`

Verification tier — determines which backend handles the check.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `TIER_1` | `` |  |
| `TIER_2` | `` |  |
| `TIER_3` | `` |  |
| `TIER_4` | `` |  |

**Values:**

- `TIER_1` = `1`
- `TIER_2` = `2`
- `TIER_3` = `3`
- `TIER_4` = `4`

---

*Auto-generated from source code. Do not edit manually.*
