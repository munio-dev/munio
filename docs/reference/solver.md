# Solver

Tier 1 (Python) and Tier 2-4 (Z3) constraint evaluation engine.

**Module:** `munio.solver`

---

### `Tier1Solver`

Pure Python solver for Tier 1 checks.

Handles: denylist, allowlist, threshold, regex_deny, regex_allow,
rate_limit, sequence_deny.
Target: <0.01ms per check.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `temporal_store` | `TemporalStore | None` | None |

**Methods:**

- `check(action, constraints) -> list[Violation]`
  Check an action against Tier 1 constraints.

---

*Auto-generated from source code. Do not edit manually.*
