# Security Model

munio's security architecture and the threat model it addresses.

## Design Principles

### Fail-Closed

Every ambiguous situation defaults to blocking:

- **Unmatched actions**: Warned by default (`default_on_unmatched=warn`); set to `block` for strict fail-closed behavior
- **Invalid inputs**: Produce violations, not silent passes
- **Z3 errors**: Generate `__system__` violations (blocking)
- **Non-scalar arguments**: Lists/dicts in tool args are rejected (not silently stringified)
- **Server errors**: OpenClaw plugin returns `{block: true}` on ANY error

### TOCTOU Prevention

All Pydantic models are frozen (`frozen=True`). Once an Action or Constraint is constructed, it cannot be mutated. This eliminates time-of-check-to-time-of-use vulnerabilities.

### Input Sanitization

Before constraint matching, string values undergo multi-stage sanitization:

1. **NFKC Unicode normalization** — collapses fullwidth characters (e.g., `ｒｍ` → `rm`), decomposes ligatures
2. **Zero-width character stripping** — U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM), U+00AD (soft hyphen), U+034F (combining grapheme joiner), U+2060-U+2064 (word joiner, invisible math operators), U+180E (Mongolian vowel separator)
3. **Variation selector stripping** — U+FE00-U+FE0F (invisible rendering modifiers, not removed by NFKC)
4. **Bidi control stripping** — U+200E/U+200F (LTR/RTL marks), U+202A-U+202E (embeddings/overrides), U+2066-U+2069 (isolates)
5. **Surrogate stripping** — U+D800-U+DFFF (invalid in UTF-8, can bypass matching via programmatic API)
6. **Control character stripping** — null byte (U+0000), ESC (U+001B, prevents ANSI injection)

This prevents bypass via invisible characters, terminal injection, and Unicode normalization tricks.

## Threat Model

### What munio protects against

| Threat | Mitigation |
|--------|------------|
| **SSRF** (Server-Side Request Forgery) | URL denylist: block internal IPs, metadata endpoints, non-HTTPS |
| **Command injection** | Regex deny: block `rm -rf`, `curl\|sh`, `chmod 777`, etc. |
| **Path traversal** | Regex deny: block `../`, absolute paths, `~/` |
| **Credential theft** | Denylist: block reads of `.ssh/`, `.env`, `.aws/` |
| **Resource exhaustion** | Threshold: cap timeouts, cost limits |
| **Privilege escalation** | Denylist: block `elevated: true`, `chown root` |
| **Prompt injection** | Regex deny: detect injection patterns in search queries |

### What munio does NOT protect against

- **LLM prompt/output safety**: Use Guardrails AI, NeMo Guardrails, or Lakera
- **Network-level security**: Use firewalls, network policies
- **Authentication/authorization**: Use your reverse proxy
- **Runtime sandboxing**: Use containers, gVisor, Firecracker

## Z3 Subprocess Isolation

Z3 solver operations run in isolated subprocesses (via `multiprocessing.get_context("spawn")`), not in the main process. This provides:

- **Memory limits**: Configurable `max_memory_mb` enforced via `resource.setrlimit` (on supported platforms).
- **Concurrency cap**: `BoundedSemaphore` limits the number of concurrent Z3 workers.
- **Crash isolation**: A Z3 worker crash produces a system violation (blocking) without affecting the main process.
- **Fork safety**: Spawn context avoids macOS fork-related hangs with Z3's internal threads.

## AST Security Invariant Tests

The test suite includes 12 AST-based security invariant tests (`tests/test_security_invariants.py`) that statically analyze the source code to enforce security rules:

- No `str(exc)` in HTTP-facing code (information leak prevention)
- Z3 worker calls division safety functions
- CORS default is empty (not `"*"`)
- Only `yaml.safe_load()` used (never `yaml.load()`)
- No raw values in system violation messages
- No broad `except: pass` patterns
- Bool-before-int guards in all `isinstance` checks (since `isinstance(True, int)` is `True`)

These tests run in CI and fail the build if any invariant is violated.

## YAML Safety

- **Only `yaml.safe_load()`** — never `yaml.load()`. This prevents arbitrary code execution via YAML deserialization.
- **NaN/Inf rejection**: `yaml.safe_load()` parses `.nan` and `.inf` as Python floats. Pydantic validators reject these in numeric fields.
- **File size limit**: 1MB per YAML file.

## ReDoS Prevention

Python's `re` module has no timeout mechanism. munio validates regex patterns at constraint load time and rejects patterns with nested quantifiers (e.g., `(a+)+`, `(a*)*`) that could cause catastrophic backtracking.

## HTTP API Security

### Forward Compatibility

API request models use `extra="ignore"` (not `extra="forbid"`). This is critical:
- OpenClaw may add new fields to hook events in future versions
- With `extra="forbid"`, new fields cause HTTP 422
- Plugin error in OpenClaw → **FAIL-OPEN** → all constraints silently disabled
- `extra="ignore"` safely discards unknown fields

Internal models keep `extra="forbid"` since we control both producer and consumer.

### Pack Name Validation

Pack names in API requests are validated against `^[a-z0-9][a-z0-9_-]*$`. This prevents:
- Path traversal (`../../etc/shadow`)
- Command injection
- Filesystem access outside the constraints directory

### Request Size Limits

1MB limit on HTTP request bodies (ASGI middleware). Prevents OOM from oversized `args` dicts.

### Startup Validation

The server refuses to start on:
- Missing constraints directory
- Empty constraints directory (0 packs)
- Invalid YAML in any constraint file
- Default pack(s) not found

This ensures the server never runs in an unconfigured state.

## Security Hardening History

The codebase has undergone 12 adversarial security review rounds (100+ fixes total), including:

- **Input sanitization**: NFKC, zero-width, bidi, surrogate, control char, URL percent-encoding bypass
- **Fail-closed everywhere**: server, adapters, solver, Z3 worker — all error paths block
- **ReDoS prevention**: nested quantifiers, polynomial patterns, alternation detection
- **Z3 soundness**: division-by-zero guards, Int→Real promotion, `{n,}` truncation fix, inline flag rejection
- **Resource limits**: BoundedSemaphore on Z3 workers, memory limits, request size caps
- **Information leak prevention**: no pack names in errors, no raw values in violations, no str(exc) in HTTP responses
- **CORS default**: empty list (not `"*"`)
- **Mode override removed**: server-side config only — HTTP callers cannot set mode
