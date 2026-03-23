<p align="center">
  <strong>[m] munio</strong><br>
  Security scanner and runtime guard for AI agent tool calls
</p>

<p align="center">
  <a href="https://github.com/munio-dev/munio/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <a href="https://python.org"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10+-blue"></a>
</p>

---

AI agents call external tools — MCP servers, OpenClaw skills, API endpoints. A malicious or poorly-written tool can exfiltrate your data, execute arbitrary commands, or chain actions into multi-step attacks. **munio** catches these issues before they reach your agent.

<p align="center">
  <img src="https://raw.githubusercontent.com/munio-dev/munio/main/assets/demo-scan.gif" alt="munio scan demo" width="800">
</p>

```bash
pipx install munio
munio config-scan
```

For deep tool schema analysis:

```bash
munio scan --server "npx @modelcontextprotocol/server-filesystem /tmp"
```

No MCP servers? Try the bundled example:

```bash
munio scan --file examples/vulnerable-server.json --details
```

## Why scan MCP servers?

The same vulnerability classes that led to [512 findings in Copilot extensions](https://www.legitsecurity.com/blog/legit-security-discovers-widespread-vulnerabilities-in-github-copilot-extensions) and [820+ malicious OpenClaw skills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) -- path traversal, command injection, SSRF, prompt injection -- exist in every AI tool-calling ecosystem. MCP servers, OpenClaw skills, and framework-integrated tools share the same attack surface.

munio was built by scanning 700+ public MCP servers and responsibly disclosing the vulnerabilities found. It works with MCP, OpenClaw, LangChain, CrewAI, and OpenAI Agents SDK.

## What it catches

| Category | Examples | How |
|----------|----------|-----|
| **Path traversal** | `../../etc/passwd` in file parameters | Schema analysis + Z3 formal proof |
| **SSRF** | `http://169.254.169.254` in URL parameters | Pattern matching + Z3 proof |
| **Command injection** | `; rm -rf /` in shell parameters | Denylist + regex + Z3 proof |
| **Prompt injection** | Hidden instructions in tool descriptions | ML classifier (188 languages) |
| **Data exfiltration** | `read_file` + `http_request` = stolen secrets | Compositional flow analysis |
| **Supply chain** | Unpinned npm deps, hardcoded API keys in config | Config file scanner |

## Installation

```bash
pipx install munio          # CLI (recommended)
pip install munio            # library
pip install "munio[z3]"      # with formal verification
pip install "munio[all]"     # everything
```

## Scan MCP servers

```bash
munio scan --server "npx @foo/mcp-server"       # scan a live server
munio scan --file tools.json                     # scan exported schemas
munio scan                                       # auto-discover from IDE configs
munio scan --details                             # show affected tools and fixes
munio scan --format sarif --output report.sarif  # SARIF 2.1.0 for CI
```

8 analysis layers: L1 Schema, L2 Heuristic, L2.5 ML Classifier, L2.6 Multilingual ML, L3 Static, L4 Z3 Formal, L5 Compositional, L7 Source.

## Scan config files

Finds hardcoded credentials, unpinned dependencies, and supply chain risks in Claude Desktop, Cursor, VS Code, Windsurf, Cline, and Junie configs. No server connections needed.

```bash
munio config-scan                    # auto-discover all IDE configs
munio config-scan --config file.json # scan a specific config
```

<p align="center">
  <img src="https://raw.githubusercontent.com/munio-dev/munio/main/assets/demo-config-scan.gif" alt="munio config-scan demo" width="800">
</p>

## Detect cross-server attack chains

```bash
munio compose --schemas-dir ./schemas  # analyze pre-fetched schemas
munio compose --format markdown        # generate CVE filing drafts
```

## Protect at runtime

Intercept every tool call before execution. No code changes.

```bash
munio init      # wrap all MCP servers in IDE configs
munio status    # check protection status
munio restore   # remove wrapper
```

After `munio init`, every `tools/call` is verified against YAML constraints. Dangerous calls are blocked before reaching the server.

### Constraint example

```yaml
name: block-dangerous-urls
action: http_request
check:
  type: denylist
  field: url
  values: ["evil.com", "169.254.169.254"]
  match: contains
on_violation: block
severity: critical
```

8 check types: `denylist`, `allowlist`, `threshold`, `regex_deny`, `regex_allow`, `composite`, `rate_limit`, `sequence_deny`.

## Python API

```python
from munio import Guard

guard = Guard(constraints="generic")
result = guard.check({"tool": "http_request", "args": {"url": "https://evil.com"}})
# result.allowed = False
```

Adapters for LangChain, CrewAI, OpenAI Agents SDK, and MCP. [See docs.](https://munio.dev)

## How it works

| Tier | What | Backend | Latency |
|------|------|---------|---------|
| **1** | Denylists, allowlists, regex, thresholds | Pure Python | <0.01ms |
| **2** | Multi-variable arithmetic | Z3 subprocess | 5-100ms |
| **3** | Complex constraints | Z3 full | 100ms-5s |
| **4** | Deploy-time policy verification | Z3 offline | per deploy |

Tier 1 handles 90-95% of constraints. Z3 is optional (`pip install "munio[z3]"`).

## All commands

| Command | What |
|---------|------|
| `munio scan` | Scan MCP server tool schemas |
| `munio config-scan` | Scan config files for supply chain risks |
| `munio compose` | Detect cross-server attack chains |
| `munio init` / `status` / `restore` | Manage runtime protection |
| `munio gate -- CMD` | Proxy a single MCP server |
| `munio check JSON` | Verify a single action |
| `munio serve` | HTTP API server |
| `munio policy` | Deploy-time Z3 policy verification |
| `munio download-models` | Download ML classifier models |

## Development

```bash
git clone https://github.com/munio-dev/munio.git && cd munio
make install    # uv sync + pre-commit hooks
make test       # 3900+ tests
make ci         # lint + typecheck + tests + coverage
```

## License

[Apache 2.0](LICENSE)
