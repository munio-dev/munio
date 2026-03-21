# Guard

High-level verification API. Wraps the constraint engine with a simple check/block interface.

**Module:** `munio.guard`

---

### `Guard`

Unified tool call security for Python agent frameworks.

Usage::

    guard = Guard(constraints="generic")

    # Check an action
    result = guard.check(Action(tool="http_request", args={"url": "..."}))


    # Universal decorator
    @guard.verify()
    def call_tool(url: str, method: str = "GET"):
        return requests.get(url)

Args:
    constraints: Constraint pack name (default: "generic").
    mode: Verification mode (enforce, shadow, disabled).
    config: Full ConstraintConfig (overrides constraints/mode if provided).
    registry: Pre-built ConstraintRegistry (for testing; skips disk loading).
    constraints_dir: Path to constraints directory (overrides config default).

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `constraints` | `str` | 'generic' |
| `mode` | `VerificationMode` | VerificationMode.ENFORCE |
| `config` | `ConstraintConfig | None` | None |
| `registry` | `ConstraintRegistry | None` | None |
| `constraints_dir` | `Path | str | None` | None |
| `temporal_store` | `TemporalStore | None` | None |

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `verifier` | `Verifier` | Access the underlying Verifier (for advanced use/testing). |

**Methods:**

- `check(action) -> VerificationResult`
  Verify an action and return the result (does not raise on violations).
- `acheck(action) -> VerificationResult`
  Verify an action asynchronously (does not raise).
- `verify(constraints) -> Callable[..., Any]`
  Universal decorator for verifying function calls.

### `ActionBlockedError`

Raised when a decorated function is blocked by constraint verification.

Attributes:
    result: The VerificationResult that caused the block.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `result` | `VerificationResult` |  |

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `result` | `` |  |

---

*Auto-generated from source code. Do not edit manually.*
