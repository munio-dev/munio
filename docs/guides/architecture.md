# Architecture

munio is a 4-tier verification engine that checks AI agent tool calls before execution.

## Pipeline Flow

```
Agent → Action → Guard.check() → Verifier → Solver(s) → VerificationResult
                                      ↓
                               ConstraintRegistry
                               (loaded from YAML)
```

## Tier System

| Tier | Engine | Latency | Use Case |
|------|--------|---------|----------|
| **1** | Python | <0.01ms | Denylist, allowlist, regex, threshold checks |
| **2** | Z3 subprocess | ~10ms | Multi-constraint satisfiability |
| **3** | Z3 subprocess | ~50ms | Complex temporal/resource constraints |
| **4** | Z3 (deploy-time) | N/A | Static policy verification at deploy time |

Tier 1 covers ~90% of real-world constraints. Z3 tiers are opt-in (`pip install "munio[z3]"`).

## Package Structure

The project is a single package with submodules:

```
src/munio/
├── models.py         Pydantic v2 data models
├── constraints.py    YAML loader, registry
├── solver.py         Facade: Tier 1 solver + Z3 subprocess pool
├── _matching.py      String matching logic
├── _composite.py     COMPOSITE expression evaluation
├── _z3_runtime.py    Z3 subprocess worker
├── _z3_regex.py      sre_parse → Z3 regex translator
├── _policy_verifier.py  Deploy-time policy verification
├── verifier.py       Orchestration: match → solve → aggregate
├── guard.py          High-level API: Guard class + decorators
├── server.py         HTTP API server (FastAPI)
├── cli.py            CLI interface (Typer)
├── scan/             MCP security scanner (8-layer analysis)
│   ├── layers/       L0 config, L1 schema, L2 heuristic, L2.5 ML,
│   │                 L2.6 multilingual, L3 static, L4 Z3, L5 compositional,
│   │                 L7 source
│   ├── orchestrator.py       Async scan pipeline
│   ├── config_scanner.py     Supply chain config scanning
│   ├── composition.py        Multi-server composition analysis
│   └── cli.py                CLI: munio scan/config-scan/compose
└── gate/             MCP stdio proxy
    ├── proxy.py          Async stdio proxy (JSON-RPC interception)
    ├── interceptor.py    Guard integration for tool calls
    └── cli.py            CLI: munio gate/init/status/restore/stats
```

## Key Design Decisions

### Frozen Models
All Pydantic models use `ConfigDict(frozen=True, extra="forbid")`. This prevents mutation after construction (TOCTOU safety) and rejects unknown fields (fail-closed).

**Exception**: HTTP API request models use `extra="ignore"` to remain forward-compatible with external callers (e.g., OpenClaw adding new fields to hook events).

### Fail-Closed by Default
- Unmatched actions produce warnings by default (`default_on_unmatched=warn`); configurable to `block` for strict environments
- Invalid inputs produce violations (not silent passes)
- Z3 errors produce system violations (not allowed results)

### Constraint Packs
Constraints are organized into packs (directories): `generic/`, `openclaw/`, `fintech/`, etc. Each pack can be loaded independently or combined.

### Guard Preloading (Server)
The HTTP server preloads all constraint packs at startup. Per-request pack selection uses the preloaded set — never touches the filesystem at runtime. This prevents:
- DoS via constraint loading (disk I/O per request)
- Path traversal attacks via pack names
- Silent fail-open on missing packs

## Verification Modes

| Mode | Behavior |
|------|----------|
| **ENFORCE** | Block on violation (return `allowed=false`) |
| **SHADOW** | Log violations but allow (return `allowed=true`) |
| **DISABLED** | Skip verification entirely |

## HTTP API

The server exposes a `/v1/` prefixed REST API:

```
POST /v1/verify                      Universal verification
POST /v1/openclaw/before-tool-call   OpenClaw-native hook format
GET  /v1/health                      Health check
GET  /v1/packs                       Available constraint packs
```

See [http-api.md](http-api.md) for details.

## Scan Architecture

The scanner uses 8 analysis layers (L0-L7), each progressively deeper:

| Layer | Name | Technique |
|-------|------|-----------|
| **L0** | Config | Supply chain checks on MCP config files |
| **L1** | Schema | JSON Schema validation (missing constraints) |
| **L2** | Heuristic | Keyword-based tool description analysis |
| **L2.5** | ML Classifier | Trained char n-gram + structural features |
| **L2.6** | Multilingual ML | Cross-language injection detection (188 languages) |
| **L3** | Static | Semantic checks (path traversal, SSRF, SQL/cmd injection) |
| **L4** | Z3 Formal | Z3 constraint solving (proves schema bypass is possible) |
| **L5** | Compositional | Cross-tool taint flow and toxic capability chains |
| **L7** | Source | Server source code analysis (planned) |

Additional scan commands:

- `munio config-scan` -- scans MCP config files (Claude Desktop, Cursor, etc.) for supply chain security issues such as unsigned packages, HTTP transport, and overly broad permissions.
- `munio compose` -- analyzes multi-server MCP configurations for dangerous cross-server attack chains (e.g., read + exfiltrate). Uses a signal quality system to rank findings by confidence and reduce false positives.
