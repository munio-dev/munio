# Scan Layers

munio scan uses 8 layers of analysis, each progressively deeper. Findings from all layers are aggregated into a single report.

## L0: Config Analysis

Static analysis of MCP configuration files for supply chain risks. Runs via `munio config-scan`.

- Unpinned npm packages, typosquatting, unscoped packages
- Dangerous environment variables (LD_PRELOAD, NODE_OPTIONS, etc.)
- Hardcoded credentials, shell metacharacters, HTTP URLs
- Docker images without digest, file permission issues

10 checks (SC_001 through SC_010). See [Config Scan Guide](../guides/config-scan.md) for details.

**Confidence**: 0.7-0.95

## L1: Schema Analysis

Validates the JSON Schema of tool input parameters.

- Missing `description` on tool or parameters
- Missing `type` annotations
- Overly permissive schemas (no constraints on strings, numbers)
- Empty or trivial enum values

**Confidence**: 0.5-0.7 (structural issues, not necessarily malicious)

## L2: Heuristic Detection

Pattern-based detection of known attack signatures.

- Keyword matching for dangerous patterns (e.g., `ignore previous`, `system prompt`)
- URL/IP detection in descriptions (potential SSRF/exfiltration)
- Path patterns (`../`, `/etc/`, `~/.ssh/`)
- Code execution indicators (`eval`, `exec`, `subprocess`)
- Pinning detection: hardcoded values that override user intent

**Confidence**: 0.6-0.85

## L2.5: ML Classifier (English)

Fine-tuned E5-small-v2 embedding model with logistic regression head.

- Trained on 2100+ malicious and 6000+ benign tool descriptions
- F1 = 0.995 on English prompt injection
- 12ms median inference on CPU
- Requires model download: `munio scan download-models`

**Confidence**: 0.8-0.99

## L2.6: Multilingual ML

sklearn char n-gram classifier for non-English attacks.

- HashingVectorizer with char n-grams (2-5) + 20 structural features
- Trained on 397K samples machine-translated to 188 languages
- <0.3ms inference, <5MB model, no PyTorch dependency
- Detects prompt injection in Chinese, Arabic, Russian, Korean, etc.

**Confidence**: 0.7-0.95

## L3: Static Analysis

10 semantic checks analyzing parameter schemas in context:

| Check | ID | Description |
|-------|-----|-------------|
| Path traversal | L3_001 | Unbounded string params that accept filesystem paths |
| URL injection | L3_002 | URL params without scheme/host validation |
| SQL injection | L3_003 | Query params without parameterization |
| Command injection | L3_004 | Command/shell params without allowlists |
| Array bomb | L3_005 | Unbounded arrays (missing maxItems) |
| Numeric overflow | L3_006 | Numbers without min/max bounds |
| Auth bypass | L3_007 | Authentication-related params with weak schemas |
| Code execution | L3_008 | Params that accept code/expressions |
| Secret exposure | L3_009 | Params named like credentials without writeOnly |
| Format bypass | L3_010 | String formats without pattern validation |

Uses word-segment matching (not substring) to minimize false positives. Context-aware: a `path` param on a filesystem tool is higher risk than on a browser tool.

**Confidence**: 0.75-0.95

## L4: Z3 Formal Verification

Optional layer using Z3 SMT solver for mathematical proofs.

```bash
pip install "munio[z3]"
```

5 formal checks:

| Check | ID | What it proves |
|-------|-----|----------------|
| Path traversal | L4_001 | Exists a string matching the schema that contains `../` |
| SSRF | L4_002 | Exists a URL matching the schema pointing to internal IPs |
| Command injection | L4_003 | Exists a string matching the schema containing shell metacharacters |
| Pattern contradiction | L4_004 | Pattern + maxLength are contradictory (no valid input exists) |
| Unsafe enum | L4_005 | Enum contains dangerous values (file://, ../,  etc.) |

Uses `z3.InRe(Intersect())` for regex intersection proofs. Two-tier: Python concrete payloads first (fast), Z3 formal proof second (thorough).

**Confidence**: 0.95-1.0 (mathematical proof)

## L5: Compositional Analysis

Cross-tool taint flow analysis using P/U/S (Provide/Use/Store) capability model.

- Classifies each tool into capability categories (FILE_READ, HTTP_SEND, CODE_EXEC, etc.)
- Builds a taint flow graph across all tools in the server
- Detects toxic flows: data from sensitive source to exfiltration sink
- 50-tool taxonomy, 16 capability categories, 13 toxic flow rules, 26 known dangerous combos
- Generates SARIF `codeFlows` with full taint path

Example toxic flow:
```
read_file (FILE_READ) -> send_email (MSG_SEND)
  Warning: Data from filesystem can be exfiltrated via email
```

**Confidence**: 0.7-0.9

## L7: Source Code Analysis

Optional layer using tree-sitter for AST-based taint tracking of MCP handler source code. Traces tool parameters through handler implementations to dangerous sinks.

```bash
pip install "munio[source]"
munio scan --server "npx @scope/server" --source ./server-src/
```

5 checks:

| Check | ID | CWE | What it detects |
|-------|-----|-----|-----------------|
| Command injection | L7_001 | CWE-78 | Tool params flowing to `exec`, `spawn`, `subprocess` calls |
| SQL injection | L7_002 | CWE-89 | Tool params concatenated into SQL query strings |
| Path traversal | L7_003 | CWE-22 | Tool params used in `readFile`, `open` without sanitization |
| SSRF | L7_004 | CWE-918 | Tool params passed to `fetch`, `request`, `urllib` without URL validation |
| Code injection | L7_005 | CWE-94 | Tool params flowing to `eval`, `Function()`, `exec()` calls |

Supports JavaScript/TypeScript and Python MCP server handlers. When scanning via `--server "npx @scope/pkg"`, munio automatically downloads and extracts the npm package source (disable with `--no-source`).

**Confidence**: 0.85-0.95

## Layer Interaction

Layers are independent -- each produces its own findings. The orchestrator merges them by:

1. Running all enabled layers in sequence
2. Deduplicating findings with same tool + attack type
3. Taking the highest confidence when duplicates exist
4. Sorting by severity (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO)
