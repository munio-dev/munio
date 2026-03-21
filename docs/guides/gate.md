# MCP Gate

**MCP stdio proxy** — runtime constraint verification for AI tool calls.

---

munio gate sits between your AI client (Claude Desktop, Cursor, etc.) and MCP servers. It intercepts `tools/call` requests, verifies them against safety constraints, and blocks dangerous calls before they reach the server.

## Why munio gate?

MCP servers execute tool calls from AI agents with no built-in safety checks. munio gate adds a verification layer:

```
Claude Desktop → munio gate → MCP Server
                     ↓
              Guard.check()
              (constraints)
```

- **Zero code changes** — works with any MCP server
- **Transparent** — passes through all non-tool traffic unchanged
- **Fail-closed** — blocks on verification errors
- **Built-in constraints** — ships with generic + OpenClaw constraint packs

## Quick Start

### 1. Install and auto-configure

```bash
pip install munio
munio init
```

This auto-detects MCP configs (Claude Desktop, Cursor, etc.) and wraps servers with munio gate. Use `--dry-run` to preview changes first.

### 2. Or configure Claude Desktop manually

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

**Before** (direct connection):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

**After** (through munio gate):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "munio",
      "args": [
        "gate", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

### 3. Restart Claude Desktop

munio gate now intercepts all tool calls to the filesystem server.

### 4. Check status

```bash
munio status
```

Shows discovered MCP configs and which servers are wrapped with munio gate.

## How It Works

1. Claude Desktop spawns `munio gate -- <server-command>`
2. munio gate starts the MCP server as a subprocess
3. All JSON-RPC messages flow through the async proxy
4. On `tools/call` requests:
   - Extract tool name and arguments
   - Run `Guard.check()` against loaded constraints
   - **ALLOWED**: forward request to server, return response to client
   - **BLOCKED**: return error response to client, never forward to server
5. All other messages (notifications, `tools/list`, etc.) pass through unchanged

## What Gets Checked

munio gate uses the constraint engine. Built-in packs include:

| Constraint | What it blocks |
|-----------|---------------|
| URL denylist | Internal IPs, metadata endpoints, `file://` URLs |
| SQL injection | `' OR 1=1 --` patterns in query fields |
| Command injection | `rm -rf`, `curl\|sh`, `chmod 777` |
| Path traversal | `../`, absolute paths, `~/.ssh/` |
| Credential harvesting | Reads of `.env`, `.aws/`, `.ssh/` |
| Spend limits | API calls exceeding cost thresholds |
| Rate limits | Too many calls in a time window |

## Configuration

### CLI Commands

#### `munio gate`

Start the stdio proxy wrapping an MCP server.

```bash
munio gate [OPTIONS] -- COMMAND [ARGS...]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--constraints-dir`, `-d` | path | bundled | Directory containing constraint YAML packs |
| `--packs`, `-p` | string | all found | Comma-separated constraint pack names |
| `--mode`, `-m` | enum | enforce | Verification mode: `enforce`, `shadow`, `disabled` |
| `--log`, `-l` | path | none | Path to JSON lines log file |
| `--verbose`, `-v` | flag | false | Enable debug logging |

**Example**:
```bash
munio gate \
    --packs generic \
    --mode enforce \
    --verbose \
    -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

#### `munio init`

Auto-detect MCP configs (Claude Desktop, Cursor, etc.) and wrap servers with munio gate.

```bash
munio init [--dry-run] [--config PATH]
```

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview changes without writing |
| `--config`, `-c` | Path to a specific config file |

#### `munio status`

Show discovered MCP configs and their munio gate status.

```bash
munio status
```

#### `munio restore`

Remove munio wrapper and restore original MCP server commands.

```bash
munio restore [--dry-run] [--config PATH]
```

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview changes without writing |
| `--config`, `-c` | Path to a specific config file |

#### `munio stats`

Show interception statistics from a JSONL log file.

```bash
munio stats LOG_FILE [--top N] [--json]
```

| Option | Default | Description |
|--------|---------|-------------|
| `LOG_FILE` | (required) | Path to JSONL log file |
| `--top`, `-t` | 10 | Number of top blocked tools to show |
| `--json`, `-j` | false | Output as JSON |

Output includes:
- Total requests intercepted
- Allowed / blocked counts
- Top violations by constraint name

### Verification Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **enforce** | Block violating tool calls, return error to client | Production |
| **shadow** | Log violations but allow all calls through | Testing, rollout |
| **disabled** | No verification, pure passthrough | Debugging |

### Logging

When a tool call is blocked, munio gate logs to stderr:

```
INFO: Blocked: exec — Field 'command' matched denied pattern (0.12ms)
```

In shadow mode:
```
WARNING: [SHADOW] Would block: exec — URL contains blocked domain (0.08ms)
```

Set `--verbose` for full JSON-RPC message tracing.

### Bundled Constraints

munio gate ships with built-in constraint packs:

- **generic/** — General-purpose constraints (URL denylist, SQL injection, path traversal, spend limits, rate limits)
- **openclaw/** — OpenClaw-specific constraints (exec, web_fetch, browser, read/write/edit path safety)

To use custom constraints, create a directory with YAML files and pass `--constraints-dir`:

```bash
munio gate --constraints-dir ./my-constraints -- npx server
```

See [Constraint Authoring](constraint-authoring.md) for the YAML format.
