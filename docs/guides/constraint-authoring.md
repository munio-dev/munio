# Constraint Authoring Guide

How to write YAML constraint files for munio.

## Basic Structure

```yaml
name: my-constraint-name          # Unique identifier (required)
description: "What this checks"   # Human-readable description
category: ASI02                   # ASI category (optional)
tier: 1                           # 1-4, auto-detected from check type if omitted
action: http_request              # Tool name to match ("*" for all tools)
check:
  type: denylist                  # Check type (see below)
  field: url                      # Field path in action.args
  values:                         # Values for denylist/allowlist
    - "evil.com"
  match: contains                 # Match mode
  case_sensitive: false           # Case sensitivity
on_violation: block               # block | warn | shadow
severity: high                    # critical | high | medium | low | info
enabled: true                     # Set to false to disable without deleting
```

## Check Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `denylist` | Block if field matches any value | `values`, `match`, `case_sensitive` |
| `allowlist` | Block if field does NOT match any value | `values`, `match`, `case_sensitive` |
| `threshold` | Block if numeric field exceeds bounds | `min`, `max` |
| `regex_deny` | Block if field matches any regex pattern | `patterns`, `case_sensitive` |
| `regex_allow` | Block if field does NOT match any regex | `patterns`, `case_sensitive` |
| `composite` | Multi-variable arithmetic expressions | `variables`, `expression` |
| `rate_limit` | Sliding window call counting | `window_seconds`, `max_count`, `scope` |
| `sequence_deny` | Multi-step attack chain detection | `steps`, `window_seconds`, `scope` |

## Match Modes

| Mode | Behavior |
|------|----------|
| `exact` | Full string equality |
| `prefix` | Value starts with the list entry |
| `suffix` | Value ends with the list entry |
| `contains` | Value contains the list entry as substring |
| `regex` | Value matches the list entry as a regex pattern |
| `glob` | Value matches the list entry as a glob pattern |

## Field Paths

The `field` value specifies which argument to check:

- `field: url` checks `action.args["url"]`
- `field: headers.authorization` checks `action.args["headers"]["authorization"]` (dot-separated traversal)

**Important**: Flat keys with dots (e.g., `"db.host"` as a single key) are NOT addressable — the solver interprets dots as nesting separators.

## Conditions

Constraints can be conditionally applied based on other fields in the action:

```yaml
name: api-url-allowlist
action: http_request
conditions:
  - field: headers.authorization
    exists: true
check:
  type: allowlist
  field: url
  values: ["https://api.example.com"]
  match: prefix
on_violation: block
severity: high
```

| Condition Field | Type | Description |
|----------------|------|-------------|
| `field` | string | Field path to check (same dot-notation as `check.field`) |
| `exists` | bool | True = constraint applies only if field exists |
| `equals` | string | Constraint applies only if field equals this value |
| `not_equals` | string | Constraint applies only if field does NOT equal this value |

Multiple conditions are ANDed — all must be true for the constraint to apply.

## Gotchas

### Boolean Fields

`str(True)` produces `"True"` (capital T), not `"true"`. When checking boolean arguments:

```yaml
# CORRECT: case_sensitive: false catches both "True" and "true"
check:
  type: denylist
  field: elevated
  values: ["true"]
  match: exact
  case_sensitive: false

# WRONG: case_sensitive: true misses Python's True → "True"
```

### Empty Strings

Empty `""` in `values` is rejected at validation time because it matches everything for `contains`/`prefix`/`suffix` modes — a security risk.

### Regex Patterns

- Python `re` has **no timeout**. Patterns with nested quantifiers like `(a+)+` are rejected at validation time (ReDoS prevention).
- For case-insensitive matching, use `case_sensitive: false` in the check config. Do NOT use `(?i)` inline flags (they interact poorly with `casefold()`).

### Non-Scalar Arguments

If a tool argument is a list or dict (e.g., `{"urls": ["a.com", "b.com"]}`), the solver rejects it with a violation (fail-closed). Only `str`, `int`, `float`, `bool`, and `None` are valid scalar types.

### Threshold Checks

Operate directly on numeric values — no string coercion:
- `max: 300` blocks `timeout: 600` directly
- String values like `"300"` are parsed via `float()`
- Non-numeric strings produce a violation

### Contains Match Precision

`match: contains` checks substring inclusion. For URLs:
- `"localhost"` in values also matches `"notlocalhost.com"`
- Use `match: prefix` or `regex_deny` for precise URL matching

### Action Wildcards

`action: "*"` matches all tools. Use sparingly (e.g., cross-cutting security patterns like SQL injection detection).

### Size Limits

- Max **10,000** values per denylist/allowlist check
- Max **1,000** regex patterns per check
- Constraint YAML files limited to **1MB**

## Temporal Constraints

### RATE_LIMIT

Limit how often a tool can be called within a sliding time window.

```yaml
name: exec-rate-limit
description: "Max 10 exec calls per 60-second window per agent"
category: ASI02
tier: 1
action: exec
check:
  type: rate_limit
  field: "*"
  window_seconds: 60
  max_count: 10
  scope: agent
on_violation: block
severity: critical
```

| Field | Type | Description |
|-------|------|-------------|
| `window_seconds` | int | Sliding window duration (minimum 1 second) |
| `max_count` | int | Maximum calls allowed in window (max 1,000,000) |
| `scope` | enum | `agent` (per agent_id) or `global` (all agents) |

### SEQUENCE_DENY

Detect multi-step attack chains (e.g., read sensitive files then exfiltrate via HTTP).

```yaml
name: deny-cred-harvest
description: "Block reading multiple files then sending HTTP (credential harvesting)"
category: ASI02
tier: 1
action: "*"
check:
  type: sequence_deny
  field: "*"
  steps:
    - read_file
    - read_file
    - http_request
  window_seconds: 600
  scope: agent
on_violation: block
severity: critical
```

| Field | Type | Description |
|-------|------|-------------|
| `steps` | list[str] | Ordered tool names forming the denied sequence |
| `window_seconds` | int | Time window for the full sequence (minimum 1 second) |
| `scope` | enum | `agent` or `global` |

Steps are matched in order. If an agent calls `read_file`, `read_file`, then `http_request` within 600 seconds, the third call is blocked.

## Directory Structure

Constraints are organized into packs (top-level directories):

```
constraints/
├── generic/              # General-purpose pack
│   ├── asi02-tool-misuse/
│   │   ├── url-allowlist.yaml
│   │   └── sql-injection.yaml
│   └── asi05-code-execution/
│       └── path-traversal.yaml
└── openclaw/             # OpenClaw-specific pack
    ├── asi02-tool-misuse/
    │   ├── exec-command-denylist.yaml
    │   └── web-fetch-url-denylist.yaml
    └── ...
```

Subdirectories within a pack are for organization only — all YAML files are loaded recursively.

## Validation

Scan your constraints for issues:

```bash
munio audit --constraints-dir constraints --pack mypack --strict
```

The `--strict` flag exits with code 1 if any issues are found (useful for CI).
