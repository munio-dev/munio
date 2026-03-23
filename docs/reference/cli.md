# CLI Reference

Command-line interface for scanning, verification, gate proxy, and server management.

---

## munio scan

Scan MCP tool definitions for security issues.

| Option | Description |
|--------|-------------|
| `--server CMD` | MCP server command to scan (e.g., `"npx @scope/mcp-server"`) |
| `--file PATH`, `-f` | Scan tools from a JSON file (no server connection) |
| `--config PATH`, `-c` | Scan servers from an IDE config file |
| (none) | Auto-discover servers from IDE configs |
| `--details` | Show affected tools, fix suggestions, and counterexamples |
| `--format text\|json\|sarif`, `-o` | Output format (default: text) |
| `--output PATH`, `-O` | Write output to file instead of stdout |
| `--timeout SECS`, `-t` | Connection timeout in seconds (default: 30) |
| `--trust-project` | Include project-level configs in auto-discovery |
| `--no-classifier` | Disable the ML classifier (L2.5) layer |
| `--classifier-threshold FLOAT` | ML classifier minimum score, 0.0-1.0 (default: 0.5) |
| `--source DIR`, `-s` | Source code directory for L7 handler analysis |
| `--no-source` | Disable automatic npm source extraction for L7 |
| `--verbose`, `-v` | Show all findings including LOW/INFO |
| `--quiet`, `-q` | Only show findings, no header/footer |

Exit codes: 0 = no CRITICAL/HIGH findings, 1 = CRITICAL/HIGH found, 2 = error.

---

## munio config-scan

Scan MCP config files for supply chain security issues. No server connections needed.

| Option | Description |
|--------|-------------|
| `--config PATH`, `-c` | Scan a specific config file |
| (none) | Auto-discover all IDE config files |
| `--details`, `-d` | Show affected servers and fix suggestions |
| `--format text\|json\|sarif`, `-o` | Output format (default: text) |
| `--output PATH`, `-O` | Write output to file instead of stdout |
| `--trust-project` | Include project-level configs in auto-discovery |
| `--quiet`, `-q` | Only show findings, no header/footer |

Exit codes: 0 = no CRITICAL/HIGH findings, 1 = CRITICAL/HIGH found, 2 = error.

---

## munio compose

Analyze multi-server MCP configurations for dangerous attack chains.

| Option | Description |
|--------|-------------|
| `--config PATH`, `-c` | Config file with MCP server definitions |
| `--schemas-dir DIR`, `-s` | Directory with pre-fetched tool schema JSON files |
| (none) | Auto-discover servers from IDE configs |
| `--details`, `-d` | Show chain details and capabilities |
| `--format text\|json\|markdown`, `-o` | Output format (default: text) |
| `--output PATH`, `-O` | Write output to file instead of stdout |
| `--quiet`, `-q` | Minimal output |

Exit codes: 0 = no CRITICAL/HIGH chains, 1 = CRITICAL/HIGH found, 2 = error.

---

## munio check

Verify a single action against constraints.

| Option | Description |
|--------|-------------|
| `ACTION_JSON` (argument) | Action as JSON string, or `-` for stdin |
| `--constraints NAME`, `-c` | Constraint pack name (default: generic) |
| `--mode enforce\|shadow\|disabled`, `-m` | Verification mode (default: enforce) |
| `--constraints-dir DIR`, `-d` | Constraints directory path (default: constraints) |
| `--format text\|json`, `-f` | Output format (default: text) |
| `--include-values/--no-values` | Include actual values in violations (default: on) |
| `--quiet`, `-q` | Exit code only, no output |

Exit codes: 0 = allowed, 1 = blocked, 2 = error.

Example:

```bash
munio check '{"tool": "http_request", "args": {"url": "http://evil.com"}}'
```

---

## munio gate

Run the MCP stdio proxy with runtime constraint verification.

| Option | Description |
|--------|-------------|
| `COMMAND ARGS...` (argument) | Server command and args (after `--`) |
| `--constraints-dir DIR`, `-d` | Path to constraints directory |
| `--packs NAMES`, `-p` | Comma-separated constraint pack names |
| `--mode enforce\|shadow\|disabled`, `-m` | Verification mode (default: enforce) |
| `--log PATH`, `-l` | Path to JSONL log file |
| `--verbose`, `-v` | Enable debug logging |

Example:

```bash
munio gate -- npx @modelcontextprotocol/server-filesystem /tmp
```

---

## munio init

Auto-detect MCP configs and wrap servers with munio gate.

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview changes without writing |
| `--config PATH`, `-c` | Path to a specific config file |

Discovers Claude Desktop, Cursor, VS Code, Windsurf, Cline, and JetBrains configs.

---

## munio status

Show discovered MCP configs and their munio gate protection status.

No options. Displays a table of all discovered servers with their wrapped/unprotected status.

---

## munio restore

Remove munio wrapper and restore original MCP server commands.

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview changes without writing |
| `--config PATH`, `-c` | Path to a specific config file |

---

## munio stats

Show interception statistics from a gate JSONL log file.

| Option | Description |
|--------|-------------|
| `LOG_FILE` (argument) | Path to JSONL log file |
| `--top N`, `-t` | Number of top blocked tools to show (default: 10) |
| `--json`, `-j` | Output as JSON |

---

## munio serve

Start the HTTP API server for remote verification.

| Option | Description |
|--------|-------------|
| `--host ADDR`, `-H` | Bind address (default: 127.0.0.1) |
| `--port PORT`, `-p` | Bind port (default: 8080) |
| `--constraints-dir DIR`, `-d` | Constraints directory path |
| `--pack NAME` | Default constraint packs (repeatable, default: generic) |
| `--mode enforce\|shadow\|disabled`, `-m` | Verification mode (default: enforce) |
| `--workers N`, `-w` | Uvicorn worker count (default: 1) |
| `--cors-origins ORIGINS` | CORS allowed origins, comma-separated (default: none) |
| `--log-level LEVEL` | Log level (default: info) |

Requires: `pip install "munio[server]"` (fastapi + uvicorn).

---

## munio policy

Run Tier 4 deploy-time Z3 policy verification.

| Option | Description |
|--------|-------------|
| `--constraint-file PATH`, `-f` | Path to a Tier 4 YAML constraint file |
| `--check-name NAME`, `-n` | Name of a Tier 4 constraint from the registry |
| `--constraints-dir DIR`, `-d` | Constraints directory path |
| `--pack NAME`, `-p` | Constraint packs to load (repeatable) |
| `--format text\|json` | Output format (default: text) |

Exit codes: 0 = SAFE, 1 = UNSAFE, 2 = ERROR/UNKNOWN/TIMEOUT.

Requires: `pip install "munio[z3]"`.

---

## munio audit

Audit constraints directory for statistics and issues.

| Option | Description |
|--------|-------------|
| `--constraints-dir DIR`, `-d` | Constraints directory path (default: constraints) |
| `--pack NAME`, `-p` | Specific packs to audit (repeatable, default: all) |
| `--format text\|json`, `-f` | Output format (default: text) |
| `--strict` | Exit 1 if issues detected (for CI) |

---

## munio version

Show munio version and Z3 availability. No options.
