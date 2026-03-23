# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-20

### Added

#### Scan (`munio scan`)
- 8-layer static analysis of MCP tool definitions (L1 Schema, L2 Heuristic, L2.5 ML Classifier, L2.6 Multilingual ML, L3 Static, L4 Z3 Formal, L5 Compositional, L7 Source)
- L1: JSON Schema validation (9 checks)
- L2: Heuristic prompt injection detection (8 checks)
- L2.6: Multilingual ML classifier (188 languages, 0.31% FPR)
- L3: Semantic static analysis (10 checks: path traversal, SSRF, SQL injection, command injection)
- L4: Z3 formal verification (5 checks with counterexample generation)
- L5: Compositional flow analysis (P/U/S taxonomy, 50-tool corpus, 13 toxic flow rules)
- L7: Source code handler analysis (tree-sitter JS/TS/Python)
- Auto-discovery of MCP servers from IDE configs (Claude Desktop, Cursor, VS Code, Windsurf, Cline, Junie)
- Direct server scanning via `--server "npx @scope/pkg"`
- SARIF 2.1.0 output for CI integration
- Schema quality letter grades (A-F)

#### Config Scanner (`munio config-scan`)
- 10 supply chain checks (SC_001-SC_010)
- Unpinned npm packages, typosquatting detection (Levenshtein), dangerous env vars
- Hardcoded credential detection (name-based + pattern-based)
- Docker images without digest pinning, shell metacharacters, HTTP URLs
- File permission checks (Unix)
- Auto-discovery of all IDE config files

#### Composition Analyzer (`munio compose`)
- Multi-server attack chain detection via BFS
- Danger scoring with cross-server amplification
- Signal quality classification (high/medium/low)
- CVE draft generation with CVSS estimates
- Markdown output for CVE filing

#### Guard (`munio gate`, `munio init`)
- MCP stdio proxy with YAML constraint enforcement
- Auto-wrapping of IDE configs (`munio init` / `munio restore` / `munio status`)
- 8 check types: DENYLIST, ALLOWLIST, THRESHOLD, REGEX_DENY, REGEX_ALLOW, COMPOSITE, RATE_LIMIT, SEQUENCE_DENY
- 4-tier constraint engine (Python fast path, Z3 subprocess, Z3 full, deploy-time)
- Temporal constraints (rate limiting, sequence denial)

#### HTTP API (`munio serve`)
- FastAPI server for remote verification
- OpenClaw constraint standard (10 built-in constraints)

#### Policy Verification (`munio policy`)
- 4 deploy-time Z3 checks: CONSISTENCY, NO_NEW_ACCESS, DATA_FLOW, FILTER_COMPLETENESS
- Formal regex-to-Z3 translator

#### Framework Adapters
- LangChain, CrewAI, OpenAI Agents SDK, MCP middleware

#### CLI
- Rich terminal output with grouped findings
- `--details` flag for affected tools and fix recommendations
- `--format text|json|sarif|markdown`
- `--output` for file output
- Cross-command hints

[0.1.0]: https://github.com/munio-dev/munio/releases/tag/v0.1.0
