# munio OpenClaw Plugin

Pre-execution tool call verification for [OpenClaw](https://github.com/openclaw/openclaw) via the munio HTTP API.

## Quick Start

### 1. Start munio server

```bash
pip install "munio[server]"
munio serve --pack openclaw --port 8080
```

### 2. Install plugin

Copy this directory to your OpenClaw plugins folder:

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

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiUrl` | string | `http://localhost:8080` | munio HTTP API base URL |
| `timeoutMs` | number | `5000` | Request timeout in milliseconds |
| `failClosed` | boolean | `true` | Block tool calls when munio is unavailable |

## Fail-Closed Design

OpenClaw hooks are **fail-open**: if a hook handler throws an error, the tool call proceeds unchecked. This plugin handles this by:

1. Wrapping all logic in try/catch (never throws)
2. On ANY error (network, timeout, HTTP 500), returning `{block: true}` by default
3. Configurable via `failClosed: false` for shadow/testing mode

## Covered Tools

The `openclaw` constraint pack includes rules for:

| Tool | Rules | Coverage |
|------|-------|----------|
| `exec` | 3 | Dangerous commands, elevated execution, timeout limits |
| `web_fetch` | 2 | Internal URL blocking, HTTPS-only enforcement |
| `browser` | 1 | Internal URL blocking |
| `write` | 1 | Path traversal prevention |
| `edit` | 1 | Path traversal prevention |
| `read` | 1 | Sensitive file access blocking |
| `web_search` | 1 | Prompt injection detection |

## Troubleshooting

Check server health:
```bash
curl http://localhost:8080/v1/health
```

Test a tool call manually:
```bash
curl -X POST http://localhost:8080/v1/openclaw/before-tool-call \
  -H "Content-Type: application/json" \
  -d '{"event": {"toolName": "exec", "params": {"command": "ls"}}, "ctx": {"toolName": "exec"}}'
```

Run in shadow mode (log violations but allow all):
```bash
munio serve --pack openclaw --mode shadow
```
