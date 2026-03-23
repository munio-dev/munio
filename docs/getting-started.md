# Getting Started

Pick your use case -- each takes under 5 minutes.

---

## A. Scan MCP servers for vulnerabilities (munio scan)

```bash
pipx install munio
```

### Scan a server by command

```bash
munio scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

8 scan layers (L1 schema, L2 heuristic, L2.5/L2.6 ML classifiers, L3 static, L4 Z3 formal, L5 compositional, L7 source) detect prompt injection, path traversal, SSRF, command injection, and cross-tool data flows.

### Scan from a config file

```bash
munio scan --config ~/.cursor/mcp.json
```

### Auto-discover configs

```bash
munio scan    # Discovers configs from Claude Desktop, Cursor, Windsurf, VS Code
```

### Machine-readable output

```bash
# JSON
munio scan --server "..." --format json

# SARIF 2.1.0 (GitHub Code Scanning, VS Code SARIF Viewer)
munio scan --server "..." --format sarif -O report.sarif
```

### Detailed findings

```bash
munio scan --server "..." --details    # Tool names, fixes, Z3 counterexamples
```

---

## B. Scan configs for supply chain risks (munio config-scan)

Static analysis of MCP config files -- no server connections needed.

```bash
munio config-scan
```

Auto-discovers configs from known client locations. Or scan a specific file:

```bash
munio config-scan --config ~/.cursor/mcp.json
```

### What it finds

10 checks (SC_001 through SC_010):

| Check | Risk |
|-------|------|
| SC_001 | Unpinned npm/bunx packages (dependency hijack) |
| SC_002 | Dangerous environment variables |
| SC_003 | Typosquatting of known MCP packages |
| SC_004 | Unscoped npm packages (higher hijack risk) |
| SC_005 | Shell metacharacters in command arguments |
| SC_006 | Absolute path binaries in command |
| SC_007 | Unencrypted HTTP URLs |
| SC_008 | Docker images without digest pinning |
| SC_009 | Hardcoded credentials in env values |
| SC_010 | Insecure file permissions |

```bash
munio config-scan --details                              # Fix suggestions per server
munio config-scan --trust-project                        # Include project-level configs
munio config-scan --format sarif -O config-report.sarif  # SARIF output
```

---

## C. Analyze cross-server attack chains (munio compose)

Detect multi-hop attack chains that span MCP server boundaries.

```bash
# From pre-fetched schemas
munio compose --schemas-dir ./schemas

# From a config file (connects to servers)
munio compose --config ~/.cursor/mcp.json
```

### Output formats

```bash
munio compose --schemas-dir ./schemas --format markdown   # For PRs/issues
munio compose --schemas-dir ./schemas --format json -O chains.json
```

### Signal quality

Findings include signal quality: **high** (confirmed dangerous data flow), **medium** (plausible chain), **low** (theoretical). Use `--details` to see chain details and capability classifications.

---

## D. Protect at runtime (munio gate)

Add a verification proxy between your MCP client and any MCP server. Zero code changes.

### Auto-wrap with munio init

```bash
# See current MCP server status
munio status

# Auto-wrap all discovered servers
munio init

# Undo changes
munio restore
```

`munio init` edits MCP client configs (Claude Desktop, Cursor, etc.) to route server commands through the munio gate proxy.

### Manual wrapping

Prefix the server command with `munio gate --` in your MCP client config:

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

Every `tools/call` is verified against YAML constraints. Dangerous calls are blocked. Safe calls pass through with sub-millisecond overhead.

### Gate options

```bash
munio gate --packs generic,filesystem -- npx @server     # Specific constraint packs
munio gate --mode shadow -- npx @server                   # Log only, do not block
munio gate --log /tmp/munio.jsonl -- npx @server          # JSON audit log
munio stats                                                # Runtime statistics
```

---

## E. Embed in code (Guard API)

### Python API

```python
from munio import Guard

guard = Guard(constraints="generic")

result = guard.check(tool="http_request", args={"url": "https://evil.com/steal"})
result.allowed     # False
result.violations  # [Violation(message="URL contains blocked domain", ...)]
```

### Framework adapters

Wrappers for LangChain, CrewAI, OpenAI Agents SDK, and MCP:

```python
from munio.adapters import langchain_tool_wrapper, crewai_tool_wrapper

safe_tool = langchain_tool_wrapper(my_tool, guard)
```

### CLI single-check

```bash
munio check '{"tool": "exec", "args": {"command": "rm -rf /"}}' -c generic
```

### HTTP API

```bash
munio serve --host 0.0.0.0 --port 8000
# POST /verify with {"tool": "exec", "arguments": {"command": "rm -rf /"}}
```

---

## F. Constraint format

All verification uses the same YAML constraint format:

```yaml
name: block-dangerous-urls
category: ASI02
action: http_request
check:
  type: denylist
  field: url
  values: ["evil.com", "169.254.169.254", "metadata.google.internal"]
  match: contains
on_violation: block
severity: critical
```

### Check types

| Type | Description |
|------|-------------|
| `denylist` | Block if field matches any value |
| `allowlist` | Block if field does NOT match any value |
| `threshold` | Block if numeric field exceeds bounds |
| `regex_deny` | Block if field matches regex pattern |
| `regex_allow` | Block if field does NOT match regex |
| `composite` | Multi-variable arithmetic expression |
| `rate_limit` | Block if call rate exceeds limit in time window |
| `sequence_deny` | Block if tool call sequence matches banned pattern |

See [Constraint Authoring](guides/constraint-authoring.md) for the full guide.

---

## Next steps

- [Scan Layers](reference/scan-layers.md) -- how the 8-layer analysis works
- [Gate Guide](guides/gate.md) -- all gate CLI and YAML options
- [Architecture](guides/architecture.md) -- verification pipeline design
- [Constraint Authoring](guides/constraint-authoring.md) -- write your own rules
- [Security Model](guides/security-model.md) -- threat model and hardening
- [CLI Reference](reference/cli.md) -- all commands and flags
