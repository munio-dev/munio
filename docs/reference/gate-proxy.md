# Gate Proxy

Bidirectional MCP stdio proxy with JSON-RPC message interception and runtime constraint verification.

## How It Works

The gate proxy sits between the MCP client (IDE/agent) and the MCP server:

```
IDE/Agent <--stdin/stdout--> munio gate <--stdin/stdout--> MCP Server
```

1. **Spawn**: munio starts the real MCP server as a subprocess.
2. **Relay**: All JSON-RPC messages are relayed bidirectionally between client and server.
3. **Intercept**: `tools/call` requests are intercepted before forwarding to the server.
4. **Verify**: Each intercepted call is passed to `Guard.check()` for constraint evaluation.
5. **Decide**: If the check passes, the request is forwarded. If blocked, a JSON-RPC error response is returned to the client without ever reaching the server.

## Interception Flow

```
Client sends tools/call request
    |
    v
Extract tool_name and arguments
    |
    v
Guard.check(Action(tool=..., args=...))
    |
    +-- allowed --> forward request to server
    |
    +-- blocked --> return error to client
         "Blocked by munio: Policy violation"
```

Blocked responses use the MCP `isError: true` result format so the agent receives a clean error rather than a connection failure.

## CLI Usage

```bash
# Basic usage
munio gate -- npx @modelcontextprotocol/server-filesystem /tmp

# With custom constraints
munio gate --constraints-dir ./my-constraints --packs generic,fintech -- server-cmd

# Shadow mode (log but don't block)
munio gate --mode shadow --log ./gate.jsonl -- server-cmd

# Debug logging
munio gate --verbose --log ./gate.jsonl -- npx @scope/server
```

## Configuration

| Parameter | Flag | Default | Description |
|-----------|------|---------|-------------|
| Constraints dir | `--constraints-dir`, `-d` | bundled generic | Path to YAML constraints |
| Packs | `--packs`, `-p` | all in dir | Comma-separated pack names |
| Mode | `--mode`, `-m` | `enforce` | enforce, shadow, or disabled |
| Log file | `--log`, `-l` | none | JSONL file for interception records |
| Verbose | `--verbose`, `-v` | false | Debug-level stderr logging |

When no `--constraints-dir` is specified, the proxy uses bundled constraints shipped with the munio package. If none are found, all tool calls are allowed (with a warning).

## Log Format

Each interception is recorded as a JSON line in the log file:

```json
{
  "timestamp": "2026-03-20T12:00:00Z",
  "tool_name": "read_file",
  "arguments": {"path": "/etc/passwd"},
  "decision": "blocked",
  "violations": ["Path traversal: sensitive system file"],
  "elapsed_ms": 0.05
}
```

Use `munio stats <log-file>` to analyze interception logs.

## Auto-Setup

`munio init` rewrites IDE config files to route MCP servers through the gate:

```bash
# Preview changes
munio init --dry-run

# Apply
munio init

# Check status
munio status

# Undo
munio restore
```

## Security Properties

- **Fail-closed**: Guard errors (timeout, crash) result in blocking the tool call.
- **Guard timeout**: 30-second timeout on `Guard.check()` to prevent proxy hang.
- **No information leak**: blocked responses use generic messages without constraint details.
- **Batch support**: JSON-RPC batch arrays are supported (capped at 100 elements).
- **Non-finite ID safety**: NaN/Inf JSON-RPC IDs are normalized to null.

## See Also

- [Guard](guard.md) -- verification API used by the proxy
- [Gate Guide](../guides/gate.md) -- setup and usage guide
- [CLI Reference](cli.md) -- `munio gate`, `munio init`, `munio status`, `munio restore`
