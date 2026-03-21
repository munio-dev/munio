# munio

**Agent Safety Platform** -- pre-execution verification for AI agents.

*From guardrails to guarantees.*

---

## What munio does

- **Scan** -- static analysis of MCP server tool definitions, config files, and cross-server attack chains. No server connections required for config analysis.
- **Guard** -- runtime verification of every tool call against YAML constraints. Blocks dangerous calls before they reach the server.
- **Compose** -- cross-server compositional analysis that detects multi-hop attack chains across MCP server boundaries.

## Install

```bash
pipx install munio                 # Recommended: isolated CLI
pip install munio                  # Core library only
pip install "munio[all]"           # Everything: Z3, HTTP server, adapters
```

## Core capabilities

| Command | What it does |
|---------|-------------|
| `munio scan` | 8-layer MCP server analysis (L1-L5, L7 + ML classifiers) |
| `munio config-scan` | Supply chain risk detection in MCP config files (10 checks) |
| `munio compose` | Cross-server attack chain analysis |
| `munio gate` | MCP stdio proxy with runtime constraint enforcement |
| `munio check` | Verify a single tool call from CLI |
| `munio serve` | HTTP API server for remote verification |
| `munio policy` | Deploy-time policy verification (Z3 formal proofs) |
| `munio audit` | Audit constraint pack changes |
| `munio init` | Auto-wrap MCP servers in client configs |
| `munio status` | Show MCP server protection status |
| `munio restore` | Undo munio init changes |
| `munio stats` | Gate runtime statistics |
| `munio version` | Print version |

## 4-tier verification

| Tier | Engine | Latency | Use case |
|------|--------|---------|----------|
| 1 | Python | <0.01ms | Denylist, allowlist, regex, threshold, rate limit, sequence |
| 2 | Z3 subprocess | ~10ms | Multi-variable arithmetic (COMPOSITE expressions) |
| 3 | Z3 subprocess | ~50ms | Complex temporal/resource constraints |
| 4 | Z3 (deploy-time) | N/A | Static policy verification (NO_NEW_ACCESS, DATA_FLOW, etc.) |

Tier 1 covers ~90% of real-world constraints. Z3 tiers are opt-in via `pip install "munio[z3]"`.

## Constraint types

| Type | Description |
|------|-------------|
| `denylist` | Block if field matches any value |
| `allowlist` | Block if field does NOT match any value |
| `threshold` | Block if numeric field exceeds bounds |
| `regex_deny` | Block if field matches regex pattern |
| `regex_allow` | Block if field does NOT match regex |
| `composite` | Multi-variable arithmetic expression check |
| `rate_limit` | Block if call rate exceeds limit in time window |
| `sequence_deny` | Block if tool call sequence matches a banned pattern |

## Scan layers

| Layer | Name | Method |
|-------|------|--------|
| L1 | Schema | JSON Schema completeness and structural validation |
| L2 | Heuristic | Keyword and pattern-based prompt injection detection |
| L2.5 | Classifier | English ML classifier (char n-gram + logistic regression) |
| L2.6 | Multilingual | 188-language ML classifier (0.31% FPR) |
| L3 | Static | 10 semantic checks (path traversal, SSRF, SQL injection, etc.) |
| L4 | Z3 Formal | Z3 constraint solving with counterexample extraction |
| L5 | Compositional | Cross-tool data flow and capability analysis |
| L7 | Source | Source-level analysis (when available) |

## Quick links

- [Getting Started](getting-started.md) -- install and use in 5 minutes
- [Architecture](guides/architecture.md) -- verification pipeline design
- [Constraint Authoring](guides/constraint-authoring.md) -- write your own safety rules
- [Security Model](guides/security-model.md) -- threat model and design principles
- [Scanner Reference](reference/scanner.md) -- scan layer details
- [Gate Guide](guides/gate.md) -- MCP stdio proxy setup
- [CLI Reference](reference/cli.md) -- all commands and flags
