# Scanner

**MCP Security Scanner** -- 8-layer analysis for AI tool definitions.

---

munio scan analyzes MCP (Model Context Protocol) server tool definitions for security vulnerabilities *before* they reach your AI agent. It catches prompt injection, path traversal, SSRF, command injection, and cross-tool attack chains -- all offline, deterministic, and in under 100ms.

## Why munio scan?

MCP servers expose tools to AI agents. A malicious or poorly-written tool description can:

- Inject instructions into the agent via prompt injection in tool descriptions
- Trick the agent into exfiltrating data through crafted parameter schemas
- Create cross-tool attack chains (read credentials -> send via HTTP)
- Hide attacks in non-English text that other scanners miss

**munio scan catches these at definition time** -- before any tool call happens.

## 8-Layer Analysis Pipeline

| Layer | Name | Technique | Latency |
|-------|------|-----------|---------|
| **L0** | Config Analysis | Supply chain checks on config files | <0.5ms |
| **L1** | Schema Analysis | JSON Schema validation, missing fields | <0.1ms |
| **L2** | Heuristic + Pinning | Pattern matching, keyword detection | <0.5ms |
| **L2.5** | ML Classifier | E5-small-v2 English classifier (F1=0.995) | ~12ms |
| **L2.6** | Multilingual ML | sklearn char n-gram, 188 languages | <0.3ms |
| **L3** | Static Analysis | 10 semantic checks (path traversal, SSRF, SQLi, etc.) | <1ms |
| **L4** | Z3 Verification | Formal proofs via Z3 SMT solver (optional) | ~50ms |
| **L5** | Compositional | Cross-tool P/U/S taint flow analysis | <5ms |
| **L7** | Source Analysis | tree-sitter AST taint tracking (optional) | ~200ms |

Layers run in sequence. Each finding includes confidence score, attack type, CWE mapping, and remediation guidance.

## Quick Start

```bash
pip install munio

# Scan a single MCP server
munio scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Scan from Claude Desktop config
munio scan --config ~/.config/claude/claude_desktop_config.json

# JSON output for CI
munio scan --server "..." --format json

# SARIF output for GitHub Code Scanning
munio scan --server "..." --format sarif -O results.sarif
```

## Output Formats

- **Rich CLI** -- colored terminal output with severity indicators
- **JSON** -- machine-readable for CI/CD pipelines
- **SARIF 2.1.0** -- GitHub Code Scanning, VS Code SARIF Viewer, Azure DevOps

## What It Detects

| Attack Type | Example | Layer |
|-------------|---------|-------|
| Prompt injection | "Ignore previous instructions..." in tool description | L2, L2.5, L2.6 |
| Path traversal | `../../etc/passwd` in default values | L3, L4, L7 |
| SSRF | `http://169.254.169.254` in URL parameters | L3, L4, L7 |
| Command injection | `; rm -rf /` patterns in string fields | L3, L7 |
| SQL injection | `' OR 1=1 --` in query parameters | L3, L7 |
| Cross-tool chains | read_file -> send_http data exfiltration | L5 |
| Multilingual attacks | Non-English prompt injection (Chinese, Arabic, etc.) | L2.6 |
| Schema abuse | Missing bounds, overly permissive types | L1, L3 |
| Supply chain | Unpinned deps, typosquatting, hardcoded creds | L0 |

## Orchestrator

The scan orchestrator runs all enabled layers in sequence and merges findings:

1. Running all enabled layers in sequence
2. Deduplicating findings with same tool + attack type
3. Taking the highest confidence when duplicates exist
4. Sorting by severity (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO)

## Related Commands

- **`munio config-scan`** -- supply chain analysis of MCP config files (L0 checks). See [Config Scan Guide](../guides/config-scan.md).
- **`munio compose`** -- cross-server composition analysis for attack chains. See [Compose Guide](../guides/compose.md).

## See Also

- [Scan Layers](scan-layers.md) -- detailed description of each analysis layer
- [Models](models.md) -- data models including scan findings and results
- [CLI Reference](cli.md) -- full command-line option listing
