# HTTP API Reference

munio exposes a REST API for language-agnostic tool call verification.

## Starting the Server

```bash
pip install "munio[server]"
munio serve --pack generic --pack openclaw --port 8080
```

All endpoints are under the `/v1/` prefix for API versioning.

## Endpoints

### `GET /v1/health`

Health check for load balancers and k8s probes.

```bash
curl http://localhost:8080/v1/health
```

**Response** (200):
```json
{
  "status": "ok",
  "version": "0.1.0",
  "constraint_count": 18
}
```

### `GET /v1/packs`

List available constraint packs with constraint counts.

```bash
curl http://localhost:8080/v1/packs
```

**Response** (200):
```json
{
  "packs": {
    "generic": 7,
    "openclaw": 11
  }
}
```

### `POST /v1/verify`

Universal action verification endpoint.

```bash
curl -X POST http://localhost:8080/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"tool":"exec","args":{"command":"rm -rf /"},"constraints":"openclaw"}'
```

**Request**:
```json
{
  "tool": "exec",
  "args": {"command": "rm -rf /"},
  "agent_id": "agent-1",
  "metadata": {},
  "constraints": "openclaw",
  "mode": "enforce"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | yes | Tool name |
| `args` | object | no | Tool call arguments (default: `{}`) |
| `agent_id` | string | no | Agent identifier |
| `metadata` | object | no | Additional metadata |
| `constraints` | string | no | Pack name override (default: server's default packs) |
| `mode` | string | no | Ignored (mode is server-side config only — mode override removed for security) |

**Response** (200): Full `VerificationResult` JSON:
```json
{
  "allowed": false,
  "mode": "enforce",
  "violations": [
    {
      "constraint_name": "openclaw-exec-command-denylist",
      "constraint_category": "ASI02",
      "severity": "critical",
      "message": "Field 'command' matched denied pattern: rm\\s+(-[a-zA-Z]*f...",
      "field": "command",
      "actual_value": "rm -rf /",
      "tier": 1
    }
  ],
  "checked_constraints": 3,
  "elapsed_ms": 0.234,
  "tier_breakdown": {"tier_1": 3}
}
```

### `POST /v1/openclaw/before-tool-call`

OpenClaw-native endpoint matching the `before_tool_call` hook format exactly.

```bash
curl -X POST http://localhost:8080/v1/openclaw/before-tool-call \
  -H "Content-Type: application/json" \
  -d '{"event":{"toolName":"exec","params":{"command":"ls -la"}},"ctx":{"toolName":"exec","agentId":"agent-1"}}'
```

**Request**:
```json
{
  "event": {
    "toolName": "exec",
    "params": {"command": "ls -la"}
  },
  "ctx": {
    "toolName": "exec",
    "agentId": "agent-1",
    "sessionKey": "sess-abc"
  }
}
```

**Response** (200):
```json
{
  "block": false,
  "blockReason": null
}
```

Or when blocked:
```json
{
  "block": true,
  "blockReason": "Field 'command' matched denied pattern"
}
```

## Error Responses

| Status | Error | When |
|--------|-------|------|
| 400 | Pack not found | Unknown constraint pack name |
| 413 | `payload_too_large` | Request body exceeds 1MB |
| 422 | Validation error | Missing/invalid fields (Pydantic) |
| 422 | `verification_error` | Internal verification error |
| 500 | `internal_error` | Unexpected server error |

## Forward Compatibility

All request models use `extra="ignore"` — unknown fields are silently discarded. This means:
- Future OpenClaw versions can add new fields to hook events without breaking the plugin
- Clients can send extra metadata without causing 422 errors

## Security

- **Bind address**: Default `127.0.0.1` (localhost only). For network deployment, use a reverse proxy with authentication.
- **CORS**: Configurable via `--cors-origins`. Default is empty (no cross-origin access).
- **Request size**: 1MB limit on request bodies.
- **Pack names**: Validated against `^[a-z0-9][a-z0-9_-]*$` regex — no path traversal.
- **No auth in v1**: Authentication should be handled by your reverse proxy (nginx, Caddy, etc.).
