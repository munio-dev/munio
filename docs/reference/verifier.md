# Verifier

Async verification pipeline with shadow mode and fail-closed behavior.

**Module:** `munio.verifier`

---

### `Verifier`

Main verification engine.

Orchestrates constraint matching, tiered solving, and result aggregation.
Thread-safe for concurrent verification requests.

Args:
    registry: Pre-built constraint registry.
    config: Verification configuration. Defaults to ConstraintConfig().

Example::

    registry = load_constraints_dir("constraints/", packs=["generic"])
    verifier = Verifier(registry)
    result = verifier.verify(Action(tool="http_request", args={"url": "evil.com"}))

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `registry` | `ConstraintRegistry` |  |
| `config` | `ConstraintConfig | None` | None |
| `temporal_store` | `TemporalStore | None` | None |

**Fields:**

| Name | Type | Description |
|------|------|-------------|
| `registry` | `ConstraintRegistry` | The constraint registry used by this verifier. |

**Methods:**

- `verify(action) -> VerificationResult`
  Verify an action against the constraint registry.

---

*Auto-generated from source code. Do not edit manually.*
