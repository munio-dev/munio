# Scan Models

Data models for the MCP security scanner.

**Module:** `munio.scan.models`

---

### `Finding`

Single security finding from a scan layer.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `id` | `str` |  |
| `layer` | `Layer` |  |
| `severity` | `FindingSeverity` |  |
| `tool_name` | `str` |  |
| `message` | `str` |  |
| `description` | `str` |  |
| `attack_type` | `AttackType | None` |  |
| `cwe` | `str | None` |  |
| `location` | `str` |  |
| `counterexample` | `str | None` |  |
| `confidence` | `float` |  |

### `ScanResult`

Aggregate scan result across all servers/files.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `scan_id` | `str` |  |
| `timestamp` | `datetime` |  |
| `servers` | `list[ServerScanResult]` |  |
| `findings` | `list[Finding]` |  |
| `elapsed_ms` | `float` |  |
| `enabled_layers` | `frozenset[Layer]` |  |
| `skipped_layers` | `tuple[SkippedLayer, ...]` |  |
| `total_findings` | `int` | Total number of findings. |
| `by_severity` | `dict[str, int]` | Findings count grouped by severity name. |
| `by_layer` | `dict[str, int]` | Findings count grouped by layer name. |

**Methods:**

- `to_json_dict() -> dict[str, object]`
  Serialize to dict including computed properties (safe for JSON output).

### `ToolDefinition`

MCP tool definition with its JSON Schema.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `name` | `str` |  |
| `title` | `str` |  |
| `description` | `str` |  |
| `input_schema` | `dict[str, Any]` |  |
| `output_schema` | `dict[str, Any] | None` |  |
| `annotations` | `dict[str, Any] | None` |  |
| `server_name` | `str` |  |

### `ServerConfig`

Discovered MCP server configuration.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `name` | `str` |  |
| `source` | `str` |  |
| `command` | `str` |  |
| `args` | `list[str]` |  |
| `env` | `dict[str, str] | None` |  |
| `url` | `str | None` |  |
| `enabled` | `bool` |  |

### `Layer`

Analysis layer identifier (decade-spaced for future insertions).

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `L0_CONFIG` | `` |  |
| `L1_SCHEMA` | `` |  |
| `L2_HEURISTIC` | `` |  |
| `L2_CLASSIFIER` | `` |  |
| `L2_MULTILINGUAL` | `` |  |
| `L3_STATIC` | `` |  |
| `L4_Z3` | `` |  |
| `L5_COMPOSITIONAL` | `` |  |
| `L6_FUZZING` | `` |  |
| `L7_SOURCE` | `` |  |

**Values:**

- `L0_CONFIG` = `5`
- `L1_SCHEMA` = `10`
- `L2_HEURISTIC` = `20`
- `L2_CLASSIFIER` = `25`
- `L2_MULTILINGUAL` = `26`
- `L3_STATIC` = `30`
- `L4_Z3` = `40`
- `L5_COMPOSITIONAL` = `50`
- `L6_FUZZING` = `60`
- `L7_SOURCE` = `70`

### `FindingSeverity`

Finding severity level (ordered: CRITICAL=0 highest).

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `CRITICAL` | `` |  |
| `HIGH` | `` |  |
| `MEDIUM` | `` |  |
| `LOW` | `` |  |
| `INFO` | `` |  |

**Values:**

- `CRITICAL` = `0`
- `HIGH` = `1`
- `MEDIUM` = `2`
- `LOW` = `3`
- `INFO` = `4`

### `AttackType`

MCP attack type category.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `PROMPT_INJECTION` | `` |  |
| `DATA_EXFILTRATION` | `` |  |
| `COMMAND_INJECTION` | `` |  |
| `PATH_TRAVERSAL` | `` |  |
| `SSRF` | `` |  |
| `CREDENTIAL_EXPOSURE` | `` |  |
| `SYSTEM_PROMPT_EXTRACTION` | `` |  |
| `CROSS_SERVER_SHADOWING` | `` |  |
| `TOKEN_STUFFING` | `` |  |
| `SCHEMA_PERMISSIVENESS` | `` |  |
| `RUG_PULL` | `` |  |
| `AUTHORIZATION_BYPASS` | `` |  |
| `SUPPLY_CHAIN` | `` |  |
| `CONFIG_INJECTION` | `` |  |

**Values:**

- `PROMPT_INJECTION` = `1`
- `DATA_EXFILTRATION` = `2`
- `COMMAND_INJECTION` = `3`
- `PATH_TRAVERSAL` = `4`
- `SSRF` = `5`
- `CREDENTIAL_EXPOSURE` = `6`
- `SYSTEM_PROMPT_EXTRACTION` = `7`
- `CROSS_SERVER_SHADOWING` = `8`
- `TOKEN_STUFFING` = `9`
- `SCHEMA_PERMISSIVENESS` = `10`
- `RUG_PULL` = `11`
- `AUTHORIZATION_BYPASS` = `12`
- `SUPPLY_CHAIN` = `13`
- `CONFIG_INJECTION` = `14`

### `OutputFormat`

CLI output format.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `TEXT` | `` |  |
| `JSON` | `` |  |
| `SARIF` | `` |  |
| `MARKDOWN` | `` |  |

**Values:**

- `TEXT` = `'text'`
- `JSON` = `'json'`
- `SARIF` = `'sarif'`
- `MARKDOWN` = `'markdown'`

### `ConfigScanResult`

Aggregate config scan result across all discovered config files.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `scan_id` | `str` |  |
| `timestamp` | `datetime` |  |
| `files` | `list[ConfigFileResult]` |  |
| `elapsed_ms` | `float` |  |
| `total_findings` | `int` |  |
| `all_findings` | `list[Finding]` |  |
| `by_severity` | `dict[str, int]` |  |

### `ConfigFileResult`

Scan result for a single config file.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `path` | `str` |  |
| `ide` | `str` |  |
| `servers_count` | `int` |  |
| `findings` | `list[Finding]` |  |
| `permissions` | `ConfigPermissions | None` |  |

### `ConfigPermissions`

Unix file permission check result.

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `mode` | `int` |  |
| `world_readable` | `bool` |  |
| `world_writable` | `bool` |  |

---

*Auto-generated from source code. Do not edit manually.*
