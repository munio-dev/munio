# OpenClaw Integration Guide

Integrate munio with [OpenClaw](https://github.com/openclaw/openclaw) for fine-grained tool call verification.

## Overview

OpenClaw's tool policy system handles **which tools** are allowed (coarse-grained allow/deny). munio complements it with **what arguments** are safe (fine-grained runtime verification).

```
Tool call → OpenClaw policy check → munio constraint check → Execute
             (allow/deny tool)        (verify arguments)
```

## Quick Start

### 1. Install and start munio

```bash
pip install "munio[server]"
munio serve --pack openclaw --port 8080
```

### 2. Install the OpenClaw plugin

```bash
cp -r examples/openclaw-plugin /path/to/openclaw/plugins/munio
```

### 3. Configure OpenClaw

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "munio": {
        "config": {
          "apiUrl": "http://localhost:8080",
          "timeoutMs": 5000,
          "failClosed": true
        }
      }
    }
  }
}
```

### 4. Verify it works

```bash
# Health check
curl http://localhost:8080/v1/health

# Test a blocked command
curl -X POST http://localhost:8080/v1/openclaw/before-tool-call \
  -H "Content-Type: application/json" \
  -d '{"event":{"toolName":"exec","params":{"command":"rm -rf /"}},"ctx":{"toolName":"exec"}}'
# → {"block":true,"blockReason":"Field 'command' matched denied pattern..."}
```

## Tool-to-Constraint Mapping

The `openclaw` constraint pack covers these tools:

| Tool | Constraint | What it checks |
|------|-----------|----------------|
| `exec` | `openclaw-exec-command-denylist` | Blocks `rm -rf`, `curl\|sh`, `chmod 777`, etc. |
| `exec` | `openclaw-exec-no-elevated` | Blocks `elevated: true` (root execution) |
| `exec` | `openclaw-exec-timeout-limit` | Caps timeout at 300 seconds |
| `web_fetch` | `openclaw-web-fetch-url-denylist` | Blocks internal IPs, metadata endpoints, `file://` |
| `web_fetch` | `openclaw-web-fetch-url-scheme` | Requires HTTPS |
| `browser` | `openclaw-browser-url-denylist` | Blocks internal URLs |
| `write` | `openclaw-write-path-traversal` | Blocks `../`, absolute paths, `~/` |
| `edit` | `openclaw-edit-path-traversal` | Blocks `../`, absolute paths, `~/` |
| `read` | `openclaw-read-path-traversal` | Blocks `../`, absolute paths, `~/` |
| `read` | `openclaw-read-path-denylist` | Blocks `/etc/shadow`, `.ssh/`, `.env`, `.aws/`, `.kube/`, `.docker/` |
| `web_search` | `openclaw-web-search-injection` | Detects prompt injection patterns (warn) |

## Safety Control Tampering (SCT) Protection

munio detects and blocks Safety Control Tampering -- attacks that programmatically disable safety controls before executing malicious commands. This was motivated by CVE-2026-25253 (OpenClaw 1-click RCE, CVSS 8.8), a 7-step attack chain where an attacker:

1. Overrides the gateway URL to a malicious WebSocket server
2. Sends crafted instructions via the hijacked connection
3. ...
4. ...
5. **Disables approval requirements** (`exec.approvals.set({ask: "off"})`)
6. **Escapes sandbox to host** (`config.patch({tools.exec.host: "gateway"})`)
7. Executes arbitrary commands on the host

Steps 5-6 are SCT primitives. munio blocks them with 4 OpenClaw-specific constraints:

| Constraint | CVE Step | What it blocks |
|-----------|----------|----------------|
| `openclaw-safety-disable-approvals` | Step 5 | Disabling execution approval requirements |
| `openclaw-safety-disable-security-mode` | Step 5 | Weakening security approval mode |
| `openclaw-gateway-url-override` | Step 1 | Gateway URL redirect to attacker server |
| `openclaw-sandbox-escape-host-mode` | Step 6 | Container escape to host execution |

### Example: blocking CVE-2026-25253

```bash
# Step 5 of the attack chain — munio blocks it
curl -X POST http://localhost:8080/v1/openclaw/before-tool-call \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "toolName": "exec.approvals.set",
      "params": {"ask": "off", "security": "full"}
    },
    "ctx": {"toolName": "exec.approvals.set"}
  }'
# → {"block":true,"blockReason":"Field 'ask' matched denied value: off"}

# Step 6 of the attack chain — munio blocks it
curl -X POST http://localhost:8080/v1/openclaw/before-tool-call \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "toolName": "config.patch",
      "params": {"patch": "tools.exec.host: gateway"}
    },
    "ctx": {"toolName": "config.patch"}
  }'
# → {"block":true,"blockReason":"Field matched denied pattern: host mode execution"}
```

The constraints are in `constraints/openclaw/asi03-privilege-abuse/`. Load them with:

```bash
munio serve --pack openclaw --port 8080
```

For broader SCT coverage across any MCP server, the `generic` pack includes 3 additional constraints that use wildcard action patterns to catch safety-disabling tool calls regardless of the server implementation. See [Constraints Reference](../reference/constraints.md) for the full list.

## Custom Constraints

Add your own constraints for OpenClaw tools:

```bash
mkdir -p constraints/openclaw/custom/
```

Create a YAML file (e.g., `constraints/openclaw/custom/my-rule.yaml`):

```yaml
name: my-custom-exec-rule
description: "Block npm publish commands"
category: ASI02
tier: 1
action: exec
check:
  type: regex_deny
  field: command
  patterns:
    - "npm\\s+publish"
  case_sensitive: false
on_violation: block
severity: high
```

Restart the server to pick up new constraints.

## Fail-Closed Design

The integration has two critical safety boundaries:

### 1. OpenClaw hooks are FAIL-OPEN

If the plugin handler throws an error, OpenClaw catches it, logs a warning, and allows the tool call. This is why the plugin wraps everything in try/catch.

### 2. Plugin is FAIL-CLOSED by default

On ANY error (network timeout, HTTP 500, DNS failure), the plugin returns `{block: true}`. Set `failClosed: false` only for testing/shadow mode.

## Shadow Mode

Test constraints without blocking:

```bash
# Server-side shadow mode
munio serve --pack openclaw --mode shadow

# Or client-side (failClosed: false in openclaw.json)
```

In shadow mode, violations are logged but all tool calls are allowed.

## Troubleshooting

### Plugin not loaded
- Check `openclaw.plugin.json` exists in the plugin directory
- Verify plugin is listed in `openclaw.json` → `plugins.entries`

### All tool calls blocked
- Check server health: `curl http://localhost:8080/v1/health`
- Verify constraints load: `munio audit -d constraints -p openclaw`
- Try shadow mode to see violations without blocking

### Latency concerns
- munio Tier 1 checks run in <1ms
- Network overhead depends on deployment (localhost ≈ 0.1ms, remote ≈ 1-10ms)
- Adjust `timeoutMs` if needed (default 5s is conservative)
