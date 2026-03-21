"""Verification pipeline: constraint matching -> tiered solving -> result aggregation.

Pipeline stages:
1. Action -> match applicable constraints (by action pattern)
2. Group constraints by tier
3. Run Tier 1 checks (Python, sync, <0.01ms each)
4. If Tier 2-3 needed -> dispatch to Z3 subprocess pool
5. Aggregate results -> VerificationResult

Modes:
- ENFORCE: block on violation (return allowed=False)
- SHADOW: log violations but allow (return allowed=True, violations populated)
- DISABLED: skip verification entirely (return allowed=True, no checks)

Async support:
- verify_action() is sync (for simple use cases)
- averify_action() is async (uses asyncio.to_thread)
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from munio._temporal import InMemoryTemporalStore, TemporalStore
from munio._z3_runtime import Z3SubprocessPool
from munio.constraints import ConstraintRegistry, load_constraints_dir
from munio.models import (
    Action,
    ConstraintConfig,
    OnViolation,
    ProofAgentError,
    Tier,
    VerificationMode,
    VerificationResult,
    Violation,
    ViolationSeverity,
)
from munio.solver import Tier1Solver

if TYPE_CHECKING:
    from collections.abc import Sequence

    from munio.models import Constraint

__all__ = [
    "Verifier",
    "averify_action",
    "verify_action",
]

logger = logging.getLogger(__name__)


class Verifier:
    """Main verification engine.

    Orchestrates constraint matching, tiered solving, and result aggregation.
    Thread-safe for concurrent verification requests.

    Args:
        registry: Pre-built constraint registry.
        config: Verification configuration. Defaults to ConstraintConfig().

    Example::

        registry = load_constraints_dir("constraints/", packs=["generic"])
        verifier = Verifier(registry)
        result = verifier.verify(Action(tool="http_request", args={"url": "evil.com"}))
    """

    __slots__ = ("_config", "_registry", "_temporal_store", "_tier1", "_z3_lock", "_z3_pool")

    _config: ConstraintConfig
    _registry: ConstraintRegistry
    _temporal_store: TemporalStore
    _tier1: Tier1Solver
    _z3_lock: threading.Lock
    _z3_pool: Z3SubprocessPool | None

    def __init__(
        self,
        registry: ConstraintRegistry,
        config: ConstraintConfig | None = None,
        temporal_store: TemporalStore | None = None,
    ) -> None:
        self._registry = registry
        self._config = config or ConstraintConfig()
        # Always create a store — even for single-shot CLI mode.
        # Empty store is cheap. Without it, temporal constraints would
        # need to either fail-closed (blocking CLI) or fail-open (security gap).
        # First call always passes (empty history), which is expected.
        if temporal_store is not None:
            self._temporal_store = temporal_store
        else:
            self._temporal_store = InMemoryTemporalStore()
        self._tier1 = Tier1Solver(temporal_store=self._temporal_store)
        self._z3_pool = None
        self._z3_lock = threading.Lock()

    @property
    def registry(self) -> ConstraintRegistry:
        """The constraint registry used by this verifier."""
        return self._registry

    def verify(self, action: Action) -> VerificationResult:
        """Verify an action against the constraint registry.

        Thread-safe. Can be called concurrently from multiple threads.

        Args:
            action: The action to verify.

        Returns:
            VerificationResult with allowed status, violations, and timing.
        """
        start = time.monotonic()

        # 1. DISABLED mode: skip entirely
        if self._config.mode == VerificationMode.DISABLED:
            return VerificationResult(
                allowed=True,
                mode=VerificationMode.DISABLED,
                checked_constraints=0,
                elapsed_ms=0.0,
            )

        # 2. Match constraints for this action (sanitize tool name: strip
        # invisible chars, NFKC normalize — prevents zero-width / fullwidth bypass)
        from munio._matching import _sanitize_string

        sanitized_tool = _sanitize_string(action.tool)

        # 2b. Record tool call in temporal history BEFORE constraint matching.
        # Must be unconditional: sequence detection needs history of ALL tools,
        # including those matching no constraints (C2 fix: unmatched-tool bypass).
        san_tool = sanitized_tool.casefold()
        try:
            self._temporal_store.record_call("__global__", san_tool)
            # Always record to agent scope — use __anonymous__ when agent_id
            # is missing (C1 fix: solver resolves None to __anonymous__,
            # recording must match).
            agent_id = action.agent_id or "__anonymous__"
            agent_key = f"agent:{_sanitize_string(agent_id)[:128]}"
            self._temporal_store.record_call(agent_key, san_tool)
        except Exception:
            logger.warning("Failed to record temporal call for %s", action.tool)

        matched = self._registry.constraints_for(sanitized_tool)

        # 3. Handle unmatched actions
        if not matched:
            elapsed_ms = (time.monotonic() - start) * 1000
            return self._handle_unmatched(action, elapsed_ms)

        # 4. Group by tier (skip Tier 4 — deploy-time only)
        tier1 = [c for c in matched if c.tier == Tier.TIER_1]
        tier23 = [c for c in matched if c.tier in (Tier.TIER_2, Tier.TIER_3)]

        # 5. Run solvers
        all_violations: list[Violation] = []

        if tier1:
            all_violations.extend(self._tier1.check(action, tier1))

        if tier23:
            pool = self._get_z3_pool()
            all_violations.extend(pool.check(action, tier23))

        # 6. Post-process violations
        all_violations = self._postprocess_violations(all_violations)

        # 7. Build result
        elapsed_ms = (time.monotonic() - start) * 1000
        checked = len(tier1) + len(tier23)
        allowed = self._determine_allowed(all_violations, matched)
        tier_breakdown = _build_tier_breakdown(tier1, tier23)

        return VerificationResult(
            allowed=allowed,
            mode=self._config.mode,
            violations=all_violations,
            checked_constraints=checked,
            elapsed_ms=round(elapsed_ms, 3),
            tier_breakdown=tier_breakdown,
        )

    def _get_z3_pool(self) -> Z3SubprocessPool:
        """Lazily initialize the Z3 subprocess pool (thread-safe)."""
        if self._z3_pool is None:
            with self._z3_lock:
                if self._z3_pool is None:  # double-check after acquiring lock
                    self._z3_pool = Z3SubprocessPool(self._config.solver)
        return self._z3_pool

    def _determine_allowed(
        self,
        violations: list[Violation],
        matched: Sequence[Constraint],
    ) -> bool:
        """Determine if action is allowed based on mode and per-constraint on_violation."""
        # SHADOW mode: always allowed
        if self._config.mode == VerificationMode.SHADOW:
            return True

        # No violations: allowed
        if not violations:
            return True

        # ENFORCE mode: check per-constraint on_violation
        constraint_map = {c.name: c for c in matched}

        for violation in violations:
            # __system__ violations are always blocking (InputTooLargeError, Z3 errors)
            if violation.constraint_name == "__system__":
                return False

            # Unmatched-action violations: _handle_unmatched normally returns directly.
            # Defensive handling for future refactoring: defer to config intent.
            if violation.constraint_name == "__unmatched__":
                if self._config.default_on_unmatched == OnViolation.BLOCK:
                    return False
                continue

            constraint = constraint_map.get(violation.constraint_name)
            if constraint is None:
                # Unknown constraint violation — fail closed
                return False

            if constraint.on_violation == OnViolation.BLOCK:
                return False

        # All violations were WARN or SHADOW — action allowed
        return True

    def _handle_unmatched(self, action: Action, elapsed_ms: float) -> VerificationResult:
        """Handle actions matching no constraints based on default_on_unmatched."""
        on_unmatched = self._config.default_on_unmatched

        # Global SHADOW mode: always allowed, no violations
        if self._config.mode == VerificationMode.SHADOW:
            logger.debug("No constraints matched action %r (shadow mode)", action.tool)
            return VerificationResult(
                allowed=True,
                mode=VerificationMode.SHADOW,
                checked_constraints=0,
                elapsed_ms=round(elapsed_ms, 3),
            )

        # SHADOW on_unmatched: log only, no violation in result
        if on_unmatched == OnViolation.SHADOW:
            logger.debug("No constraints matched action %r", action.tool)
            return VerificationResult(
                allowed=True,
                mode=self._config.mode,
                checked_constraints=0,
                elapsed_ms=round(elapsed_ms, 3),
            )

        # WARN: INFO violation in result, allowed
        # BLOCK: HIGH violation, not allowed
        is_block = on_unmatched == OnViolation.BLOCK
        severity = ViolationSeverity.HIGH if is_block else ViolationSeverity.INFO
        violation = Violation(
            constraint_name="__unmatched__",
            constraint_category="",
            severity=severity,
            message=f"No constraints matched action {action.tool!r}",
            tier=Tier.TIER_1,
        )

        return VerificationResult(
            allowed=not is_block,
            mode=self._config.mode,
            violations=[violation],
            checked_constraints=0,
            elapsed_ms=round(elapsed_ms, 3),
        )

    def _postprocess_violations(self, violations: list[Violation]) -> list[Violation]:
        """Strip or truncate actual_value per config settings."""
        if not self._config.include_violation_values:
            return [v.model_copy(update={"actual_value": ""}) for v in violations]
        max_len = self._config.max_violation_value_length
        return [
            v.model_copy(update={"actual_value": v.actual_value[: max_len - 3] + "..."})
            if len(v.actual_value) > max_len
            else v
            for v in violations
        ]

    def __repr__(self) -> str:
        return f"Verifier(constraints={len(self._registry)}, mode={self._config.mode.value!r})"


def verify_action(
    action: Action | dict[str, Any],
    *,
    constraints: str = "generic",
    config: ConstraintConfig | None = None,
) -> VerificationResult:
    """Verify a single action against constraint set (sync API).

    Convenience function that loads constraints from disk, creates a Verifier,
    and runs verification. For repeated use, create a Verifier directly to
    avoid re-loading constraints on each call.

    .. warning::

        Creates a new Verifier (and InMemoryTemporalStore) per call.
        Temporal constraints (RATE_LIMIT, SEQUENCE_DENY) require persistent
        state across calls and will NOT trigger via this function. Use
        Guard or Verifier instances directly for temporal enforcement.

    Args:
        action: Action model or dict with 'tool', 'args', etc.
        constraints: Constraint pack name (default: "generic").
        config: Optional verification configuration.

    Returns:
        VerificationResult with allowed status, violations, and timing.
    """
    cfg = config or ConstraintConfig()
    if isinstance(action, dict):
        try:
            action = Action(**action)
        except Exception as exc:
            msg = f"Invalid action format: {exc}"
            raise ProofAgentError(msg) from exc

    constraints_dir = cfg.constraints_dir
    if not constraints_dir.is_absolute():
        constraints_dir = Path.cwd() / constraints_dir

    packs = cfg.constraint_packs if config is not None else [constraints]
    registry = load_constraints_dir(constraints_dir, packs=packs)
    verifier = Verifier(registry=registry, config=cfg)
    return verifier.verify(action)


async def averify_action(
    action: Action | dict[str, Any],
    *,
    constraints: str = "generic",
    config: ConstraintConfig | None = None,
) -> VerificationResult:
    """Verify a single action against constraint set (async API).

    Uses asyncio.to_thread to avoid blocking the event loop.
    Same semantics as verify_action.
    """
    return await asyncio.to_thread(
        verify_action,
        action,
        constraints=constraints,
        config=config,
    )


def _build_tier_breakdown(
    tier1: Sequence[Constraint],
    tier23: Sequence[Constraint],
) -> dict[str, int]:
    """Build tier breakdown dict for VerificationResult."""
    breakdown: dict[str, int] = {}
    if tier1:
        breakdown["tier_1"] = len(tier1)
    for c in tier23:
        key = f"tier_{c.tier.value}"
        breakdown[key] = breakdown.get(key, 0) + 1
    return breakdown
