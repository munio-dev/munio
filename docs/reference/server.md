# Server

HTTP API server (FastAPI) for remote verification.

**Module:** `munio.server`

---

### `create_server(config) -> Any`

Create and configure the FastAPI server.

Preloads all constraint packs at startup. Fails fatally on
invalid configuration (missing directory, invalid YAML, etc.).

Args:
    config: Server configuration. Defaults to ServerConfig().

Returns:
    FastAPI application instance.

Raises:
    ImportError: If fastapi is not installed.
    RuntimeError: If constraints directory is missing or empty.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `config` | `ServerConfig | None` | None |

### `ServerConfig`

Server configuration (frozen after construction).

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `constraints_dir` | `str` |  |
| `default_packs` | `list[str]` |  |
| `mode` | `VerificationMode` |  |
| `include_violation_values` | `bool` |  |
| `cors_origins` | `list[str]` |  |

---

*Auto-generated from source code. Do not edit manually.*
