# Scan Layers

munio scan uses 8 layers of analysis, each progressively deeper. Findings from all layers are aggregated into a single report.

## L0: Config Analysis

Static analysis of MCP configuration files for supply chain risks. Runs via `munio config-scan`.

- Unpinned npm packages, typosquatting, unscoped packages
- Dangerous environment variables (LD_PRELOAD, NODE_OPTIONS, etc.)
- Hardcoded credentials, shell metacharacters, HTTP URLs
- Docker images without digest, file permission issues

10 checks (SC_001 through SC_010) plus 3 Safety Control Tampering (SCT) checks:

| Check | ID | Description |
|-------|-----|-------------|
| Permissive approvals | SC_011 | MCP server config disables safety controls by default (env vars or args) |
| WebSocket without origin | SC_012 | WebSocket server has no origin validation — vulnerable to cross-site hijacking |
| Host-mode execution | SC_013 | MCP server tools run on host without sandbox isolation |

See [Config Scan Guide](../guides/config-scan.md) for details.

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

19 semantic checks analyzing parameter schemas in context:

| Check | ID | Description |
|-------|-----|-------------|
| Path traversal | L3_001 | Path/file params without traversal-rejecting pattern |
| SSRF/URL risk | L3_002 | URL/URI params without format or restrictive pattern |
| SQL injection | L3_003 | Query/SQL params in DB-context tools |
| Command injection | L3_004 | Command/script/exec params without enum |
| Unbounded array DoS | L3_005 | Array without maxItems |
| Boolean security bypass | L3_006 | force/unsafe/skip_auth boolean params |
| Weak regex constraint | L3_007 | Unanchored or overly broad pattern |
| Conflicting schema constraints | L3_008 | min>max, empty enum |
| Template injection | L3_009 | template/format_string/jinja params |
| Dangerous numeric param | L3_010 | limit/timeout/port without bounds |
| Schema poisoning | L3_011 | Tool descriptions with LLM manipulation instructions |
| Credential exposure | L3_012 | password/token/api_key params without writeOnly |
| Insecure defaults | L3_013 | Dangerous boolean defaults like recursive=true |
| Unconfirmed destructive ops | L3_014 | delete/drop/purge without confirmation param |
| Cross-tenant ID | L3_015 | user_id/tenant_id without UUID format validation |
| Mass assignment | L3_016 | additionalProperties allows arbitrary field injection |
| Raw infrastructure params | L3_017 | K8s/Docker/Terraform strings without constraints |
| Privilege escalation params | L3_018 | role/permission without enum |
| Unsafe deserialization | L3_019 | yaml/pickle/protobuf string params |

Uses word-segment matching (not substring) to minimize false positives. Context-aware: a `path` param on a filesystem tool is higher risk than on a browser tool.

Additionally, 1 safety control detection check:

| Check | ID | Description |
|-------|-----|-------------|
| Safety tool detection | L3_020 | Tools whose name matches safety-related segments (approval, guardrail, security, sandbox, etc.) are flagged as capable of modifying safety controls. Confidence is boosted when parameters contain on/off enum values. |

L3_020 produces findings with `SAFETY_TAMPERING` attack type and CWE-269.

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

- Classifies each tool into capability categories (FILE_READ, HTTP_SEND, CODE_EXEC, SAFETY_CONFIG, etc.)
- Builds a taint flow graph across all tools in the server
- Detects toxic flows: data from sensitive source to exfiltration sink
- 50-tool taxonomy, 17 capability categories, 16 toxic flow rules, 26 known dangerous combos
- Generates SARIF `codeFlows` with full taint path

The `SAFETY_CONFIG` capability identifies tools that modify safety controls (e.g., `exec.approvals.set`, `config.patch`, `security.set`, `guardrails.disable`, `sandbox.config`). Three SCT-specific toxic flow rules detect safety tampering chains:

| Source | Sink | Risk | Description |
|--------|------|------|-------------|
| FETCH_UNTRUSTED | SAFETY_CONFIG | CRITICAL | Untrusted external data can disable safety controls before exploitation |
| SAFETY_CONFIG | CODE_EXEC | CRITICAL | Safety controls can be weakened before code execution |
| CREDENTIAL_READ | SAFETY_CONFIG | HIGH | Stolen credentials can be used to modify safety configurations |

Flows involving `SAFETY_CONFIG` produce findings with `SAFETY_TAMPERING` attack type.

Example toxic flow:
```
read_file (FILE_READ) -> send_email (MSG_SEND)
  Warning: Data from filesystem can be exfiltrated via email
```

Example SCT toxic flow:
```
fetch_url (FETCH_UNTRUSTED) -> exec.approvals.set (SAFETY_CONFIG)
  CRITICAL: Untrusted external data can disable safety controls before exploitation
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
