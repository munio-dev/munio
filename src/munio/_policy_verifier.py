"""PolicyVerifier: Tier 4 deploy-time Z3 policy verification.

Four check types:
- CONSISTENCY: Detect arithmetic contradictions between threshold constraints.
- NO_NEW_ACCESS: Ensure new constraints are not more permissive than baseline.
- DATA_FLOW: Check data flow reachability (exfiltration path detection).
- FILTER_COMPLETENESS: Verify deny patterns catch all dangerous variants.

All Z3 usage is deploy-time only — no runtime latency pressure.
Runs in CI/CD pipelines with configurable timeout and rlimit.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

from munio._z3_regex import _regex_to_z3
from munio.models import (
    CheckType,
    Constraint,
    DeployCheck,
    DeployCheckType,
    MatchMode,
    OnViolation,
    PolicyResult,
    PolicyVerificationResult,
    SolverConfig,
)

__all__ = [
    "PolicyVerifier",
]

logger = logging.getLogger(__name__)


class PolicyVerifier:
    """Tier 4 deploy-time Z3 policy verification.

    Checks for arithmetic contradictions between threshold constraints.
    Does NOT check denylist/allowlist interactions (Phase 2: requires string reasoning).

    For CONSISTENCY: SAT = safe (constraints can coexist), UNSAT = contradictory.
    """

    __slots__ = ("_config",)

    def __init__(self, config: SolverConfig | None = None) -> None:
        self._config = config or SolverConfig()

    def verify(
        self,
        check_type: DeployCheckType,
        constraints: Sequence[Constraint],
        *,
        deploy_check: DeployCheck | None = None,
    ) -> PolicyVerificationResult:
        """Run a deploy-time policy verification.

        Args:
            check_type: Type of verification to perform.
            constraints: Constraints to verify.
            deploy_check: The DeployCheck specification (required for non-CONSISTENCY checks).

        Returns:
            PolicyVerificationResult with outcome and timing.
        """
        start = time.monotonic()
        constraint_names = [c.name for c in constraints]

        try:
            if check_type == DeployCheckType.CONSISTENCY:
                result = self._check_consistency(constraints)
            elif check_type == DeployCheckType.NO_NEW_ACCESS:
                if deploy_check is None:
                    msg = "NO_NEW_ACCESS requires deploy_check"
                    raise ValueError(msg)
                result = self._check_no_new_access(constraints, deploy_check)
            elif check_type == DeployCheckType.DATA_FLOW:
                if deploy_check is None:
                    msg = "DATA_FLOW requires deploy_check"
                    raise ValueError(msg)
                result = self._check_data_flow(deploy_check)
            elif check_type == DeployCheckType.FILTER_COMPLETENESS:
                if deploy_check is None:
                    msg = "FILTER_COMPLETENESS requires deploy_check"
                    raise ValueError(msg)
                result = self._check_filter_completeness(constraints, deploy_check)
            else:
                elapsed = (time.monotonic() - start) * 1000
                return PolicyVerificationResult(
                    result=PolicyResult.ERROR,
                    details={"error": f"Unknown check type: {check_type}"},
                    elapsed_ms=elapsed,
                    check_type=check_type,
                    constraints_checked=constraint_names,
                )
        except Exception:
            logger.exception("PolicyVerifier.verify failed for %s", check_type)
            elapsed = (time.monotonic() - start) * 1000
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": "internal verification error"},
                elapsed_ms=elapsed,
                check_type=check_type,
                constraints_checked=constraint_names,
            )

        elapsed = (time.monotonic() - start) * 1000
        return PolicyVerificationResult(
            result=result.result,
            details=result.details,
            elapsed_ms=elapsed,
            check_type=check_type,
            constraints_checked=constraint_names,
        )

    def _check_consistency(self, constraints: Sequence[Constraint]) -> PolicyVerificationResult:
        """Check threshold constraints for arithmetic contradictions.

        Encodes threshold min/max as Z3 QF_LIA constraints and checks
        satisfiability. SAT = consistent (safe), UNSAT = contradictory.
        """
        try:
            import z3  # type: ignore[import-untyped]
        except ImportError:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": "Z3 solver is not installed"},
            )

        # Collect threshold constraints
        threshold_constraints = [
            c
            for c in constraints
            if c.check is not None and c.check.type == CheckType.THRESHOLD and c.enabled
        ]

        if not threshold_constraints:
            return PolicyVerificationResult(
                result=PolicyResult.SAFE,
                details={"message": "No threshold constraints to check"},
            )

        solver = z3.Solver()
        solver.set("timeout", self._config.timeout_ms)
        solver.set("rlimit", self._config.rlimit)

        # Create Z3 variables and constraints
        z3_vars: dict[str, z3.ArithRef] = {}
        for constraint in threshold_constraints:
            if constraint.check is None:
                continue
            check = constraint.check
            field = check.field

            if field not in z3_vars:
                z3_vars[field] = z3.Real(field)

            var = z3_vars[field]
            if check.min is not None:
                solver.add(var >= z3.RealVal(check.min))
            if check.max is not None:
                solver.add(var <= z3.RealVal(check.max))

        result = solver.check()

        if result == z3.sat:
            return PolicyVerificationResult(
                result=PolicyResult.SAFE,
                details={"message": "All threshold constraints are consistent"},
            )
        if result == z3.unsat:
            return PolicyVerificationResult(
                result=PolicyResult.UNSAFE,
                details={"message": "Threshold constraints are contradictory"},
            )
        # z3.unknown
        return PolicyVerificationResult(
            result=PolicyResult.UNKNOWN,
            details={"message": "Z3 returned unknown"},
        )

    # ── NO_NEW_ACCESS ──────────────────────────────────────────────────

    def _check_no_new_access(
        self,
        constraints: Sequence[Constraint],
        deploy_check: DeployCheck,
    ) -> PolicyVerificationResult:
        """Check that new constraints are not more permissive than baseline.

        Hybrid approach:
        - Thresholds: Z3 QF_LRA — SAT(new_allows AND NOT old_allows) = UNSAFE
        - Denylists EXACT: Python set difference — removed entries = UNSAFE
        - Allowlists EXACT: Python set difference — added entries = UNSAFE
        """
        # Resolve constraint sets by name
        by_name = {c.name: c for c in constraints if c.enabled}
        new_constraints = [by_name[n] for n in deploy_check.constraints_ref if n in by_name]
        baseline_constraints = [
            by_name[n] for n in deploy_check.baseline_constraints_ref if n in by_name
        ]

        missing_new = set(deploy_check.constraints_ref) - set(by_name)
        missing_old = set(deploy_check.baseline_constraints_ref) - set(by_name)
        if missing_new or missing_old:
            missing = missing_new | missing_old
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": f"Referenced constraints not found: {sorted(missing)}"},
            )

        issues: list[str] = []

        # ── 1. Threshold sub-check (Z3 QF_LRA) ──────────────────────
        threshold_result = self._no_new_access_thresholds(baseline_constraints, new_constraints)
        if threshold_result is not None:
            if threshold_result.result == PolicyResult.ERROR:
                return threshold_result
            if threshold_result.result == PolicyResult.UNSAFE:
                issues.append(threshold_result.details.get("message", "threshold relaxed"))

        # ── 2. Denylist sub-check (Python sets) ──────────────────────
        deny_issues = self._no_new_access_denylists(baseline_constraints, new_constraints)
        issues.extend(deny_issues)

        # ── 3. Allowlist sub-check (Python sets) ─────────────────────
        allow_issues = self._no_new_access_allowlists(baseline_constraints, new_constraints)
        issues.extend(allow_issues)

        # ── 4. Structural sub-check ───────────────────────────────────
        structural_issues = self._no_new_access_structural(baseline_constraints, new_constraints)
        issues.extend(structural_issues)

        if issues:
            return PolicyVerificationResult(
                result=PolicyResult.UNSAFE,
                details={"message": "New constraints are more permissive", "issues": issues},
            )

        return PolicyVerificationResult(
            result=PolicyResult.SAFE,
            details={"message": "New constraints are not more permissive than baseline"},
        )

    def _no_new_access_thresholds(
        self,
        baseline: Sequence[Constraint],
        new: Sequence[Constraint],
    ) -> PolicyVerificationResult | None:
        """Compare threshold constraints via Z3. Returns None if no thresholds to compare."""
        old_thresholds = [
            c for c in baseline if c.check is not None and c.check.type == CheckType.THRESHOLD
        ]
        new_thresholds = [
            c for c in new if c.check is not None and c.check.type == CheckType.THRESHOLD
        ]

        if not old_thresholds and not new_thresholds:
            return None

        try:
            import z3
        except ImportError:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": "Z3 solver is not installed"},
            )

        # Collect all fields
        all_fields: set[str] = set()
        for c in old_thresholds + new_thresholds:
            if c.check is not None:
                all_fields.add(c.check.field)

        solver = z3.Solver()
        solver.set("timeout", self._config.timeout_ms)
        solver.set("rlimit", self._config.rlimit)

        z3_vars: dict[str, z3.ArithRef] = {}
        for field in all_fields:
            z3_vars[field] = z3.Real(field)

        # new_allows(x): all new bounds satisfied
        new_bounds = []
        for c in new_thresholds:
            if c.check is None:
                continue
            var = z3_vars[c.check.field]
            if c.check.min is not None:
                new_bounds.append(var >= z3.RealVal(c.check.min))
            if c.check.max is not None:
                new_bounds.append(var <= z3.RealVal(c.check.max))

        # old_allows(x): all old bounds satisfied
        old_bounds = []
        for c in old_thresholds:
            if c.check is None:
                continue
            var = z3_vars[c.check.field]
            if c.check.min is not None:
                old_bounds.append(var >= z3.RealVal(c.check.min))
            if c.check.max is not None:
                old_bounds.append(var <= z3.RealVal(c.check.max))

        # Query: SAT(new_allows AND NOT old_allows) → new allows something old didn't
        if new_bounds:
            solver.add(z3.And(*new_bounds))
        if old_bounds:
            solver.add(z3.Not(z3.And(*old_bounds)))
        else:
            # No old bounds = old allowed everything → new can't be MORE permissive
            return None

        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            counterexample = {str(var): str(model.evaluate(var)) for var in z3_vars.values()}
            return PolicyVerificationResult(
                result=PolicyResult.UNSAFE,
                details={
                    "message": "New thresholds allow values that baseline forbids",
                    "counterexample": counterexample,
                },
            )
        if result == z3.unsat:
            return PolicyVerificationResult(
                result=PolicyResult.SAFE,
                details={"message": "Threshold bounds are not relaxed"},
            )
        return PolicyVerificationResult(
            result=PolicyResult.UNKNOWN,
            details={"message": "Z3 returned unknown for threshold comparison"},
        )

    @staticmethod
    def _no_new_access_denylists(
        baseline: Sequence[Constraint],
        new: Sequence[Constraint],
    ) -> list[str]:
        """Compare denylist values grouped by (field, match_mode).

        Removed entries = more permissive.
        Entire group disappearing = more permissive.
        Match mode downgrade (CONTAINS→EXACT) = more permissive.
        """
        issues: list[str] = []

        deny_types = (CheckType.DENYLIST, CheckType.REGEX_DENY)
        broadness: dict[MatchMode, int] = {
            MatchMode.CONTAINS: 4,
            MatchMode.GLOB: 3,
            MatchMode.PREFIX: 2,
            MatchMode.SUFFIX: 2,
            MatchMode.EXACT: 1,
            MatchMode.REGEX: 0,  # incomparable — handled separately
        }

        # Group by (field, match_mode)
        old_groups: dict[tuple[str, MatchMode], set[str]] = {}
        for c in baseline:
            if c.check is not None and c.check.type in deny_types:
                key = (c.check.field, c.check.match)
                entries = (
                    c.check.patterns if c.check.type == CheckType.REGEX_DENY else c.check.values
                )
                old_groups.setdefault(key, set()).update(entries)

        new_groups: dict[tuple[str, MatchMode], set[str]] = {}
        for c in new:
            if c.check is not None and c.check.type in deny_types:
                key = (c.check.field, c.check.match)
                entries = (
                    c.check.patterns if c.check.type == CheckType.REGEX_DENY else c.check.values
                )
                new_groups.setdefault(key, set()).update(entries)

        for (field, mode), old_set in old_groups.items():
            new_set = new_groups.get((field, mode), set())
            removed = old_set - new_set
            if removed:
                issues.append(
                    f"Deny entries removed from field '{field}' ({mode.value}): {sorted(removed)}"
                )

        # Detect match mode downgrades per field (e.g. CONTAINS→EXACT)
        old_fields: dict[str, int] = {}
        for field, mode in old_groups:
            old_fields[field] = max(old_fields.get(field, 0), broadness.get(mode, 0))
        new_fields: dict[str, int] = {}
        for field, mode in new_groups:
            new_fields[field] = max(new_fields.get(field, 0), broadness.get(mode, 0))

        for field, old_broad in old_fields.items():
            new_broad = new_fields.get(field, 0)
            if new_broad < old_broad and old_broad > 0:
                issues.append(
                    f"Deny match mode narrowed for field '{field}' "
                    f"(broadness {old_broad}→{new_broad})"
                )

        return issues

    @staticmethod
    def _no_new_access_allowlists(
        baseline: Sequence[Constraint],
        new: Sequence[Constraint],
    ) -> list[str]:
        """Compare allowlist values grouped by (field, match_mode).

        Added entries = more permissive.
        Match mode upgrade (EXACT→CONTAINS) = more permissive.
        """
        issues: list[str] = []

        allow_types = (CheckType.ALLOWLIST, CheckType.REGEX_ALLOW)
        broadness: dict[MatchMode, int] = {
            MatchMode.CONTAINS: 4,
            MatchMode.GLOB: 3,
            MatchMode.PREFIX: 2,
            MatchMode.SUFFIX: 2,
            MatchMode.EXACT: 1,
            MatchMode.REGEX: 0,
        }

        old_groups: dict[tuple[str, MatchMode], set[str]] = {}
        for c in baseline:
            if c.check is not None and c.check.type in allow_types:
                key = (c.check.field, c.check.match)
                entries = (
                    c.check.patterns if c.check.type == CheckType.REGEX_ALLOW else c.check.values
                )
                old_groups.setdefault(key, set()).update(entries)

        new_groups: dict[tuple[str, MatchMode], set[str]] = {}
        for c in new:
            if c.check is not None and c.check.type in allow_types:
                key = (c.check.field, c.check.match)
                entries = (
                    c.check.patterns if c.check.type == CheckType.REGEX_ALLOW else c.check.values
                )
                new_groups.setdefault(key, set()).update(entries)

        for (field, mode), new_set in new_groups.items():
            old_set = old_groups.get((field, mode), set())
            added = new_set - old_set
            if added:
                issues.append(
                    f"Allow entries added to field '{field}' ({mode.value}): {sorted(added)}"
                )

        # Detect disappeared allowlist groups: old had allowlist, new removed it entirely.
        # Removing an allowlist = no longer restricting → more permissive.
        for (field, mode), old_set in old_groups.items():
            if (field, mode) not in new_groups:
                issues.append(
                    f"Allowlist removed from field '{field}' ({mode.value}): was {sorted(old_set)}"
                )

        # Detect match mode upgrades per field (EXACT→CONTAINS = more permissive)
        old_fields: dict[str, int] = {}
        for field, mode in old_groups:
            old_fields[field] = max(old_fields.get(field, 0), broadness.get(mode, 0))
        new_fields: dict[str, int] = {}
        for field, mode in new_groups:
            new_fields[field] = max(new_fields.get(field, 0), broadness.get(mode, 0))

        for field, new_broadness in new_fields.items():
            old_broadness = old_fields.get(field, 0)
            if new_broadness > old_broadness and new_broadness > 0:
                issues.append(
                    f"Allow match mode broadened for field '{field}' "
                    f"(broadness {old_broadness}→{new_broadness})"
                )

        return issues

    # ── Structural comparison ─────────────────────────────────────────

    @staticmethod
    def _no_new_access_structural(
        baseline: Sequence[Constraint],
        new: Sequence[Constraint],
    ) -> list[str]:
        """Detect structural permissiveness changes beyond value comparison.

        Checks per field:
        - on_violation downgrade (BLOCK → WARN/SHADOW)
        - Action scope narrowing (* → specific tool pattern)
        - Unconditional → conditional check change
        - COMPOSITE constraint type disappearance
        """
        issues: list[str] = []

        violation_rank = {
            OnViolation.BLOCK: 3,
            OnViolation.WARN: 2,
            OnViolation.SHADOW: 1,
        }

        # Group by check.field
        old_by_field: dict[str, list[Constraint]] = {}
        for c in baseline:
            if c.check is not None:
                old_by_field.setdefault(c.check.field, []).append(c)

        new_by_field: dict[str, list[Constraint]] = {}
        for c in new:
            if c.check is not None:
                new_by_field.setdefault(c.check.field, []).append(c)

        for field, old_constraints in old_by_field.items():
            new_constraints = new_by_field.get(field)

            if new_constraints is None:
                old_types = sorted({c.check.type.value for c in old_constraints if c.check})
                issues.append(f"Field '{field}' lost all checks (was: {', '.join(old_types)})")
                continue

            # on_violation: compare strictest enforcement level
            old_strictest = max(violation_rank.get(c.on_violation, 0) for c in old_constraints)
            new_strictest = max(violation_rank.get(c.on_violation, 0) for c in new_constraints)
            if new_strictest < old_strictest:
                issues.append(f"on_violation weakened for field '{field}'")

            # Action scope: if old had '*' and new doesn't → scope narrowed
            old_has_wildcard = any(c.action == "*" for c in old_constraints)
            new_has_wildcard = any(c.action == "*" for c in new_constraints)
            if old_has_wildcard and not new_has_wildcard:
                issues.append(
                    f"Action scope narrowed for field '{field}': was '*' (all tools), now limited"
                )

            # Conditions: if old had unconditioned checks, new should too
            old_unconditioned = any(not c.conditions for c in old_constraints)
            new_unconditioned = any(not c.conditions for c in new_constraints)
            if old_unconditioned and not new_unconditioned:
                issues.append(
                    f"All checks for field '{field}' now have conditions "
                    f"(baseline had unconditional checks)"
                )

            # Check type disappearance (COMPOSITE, RATE_LIMIT, SEQUENCE_DENY)
            old_check_types = {c.check.type for c in old_constraints if c.check}
            new_check_types = {c.check.type for c in new_constraints if c.check}
            issues.extend(
                f"{vt.value.upper()} check removed for field '{field}'"
                for vt in (CheckType.COMPOSITE, CheckType.RATE_LIMIT, CheckType.SEQUENCE_DENY)
                if vt in old_check_types and vt not in new_check_types
            )

        return issues

    # ── DATA_FLOW ──────────────────────────────────────────────────────

    def _check_data_flow(
        self,
        deploy_check: DeployCheck,
    ) -> PolicyVerificationResult:
        """Check data flow reachability using Z3 integer encoding.

        Without 'through': checks if ANY path exists source → forbidden_sink.
            SAT → UNSAFE (exfiltration path exists)
            UNSAT → SAFE (no path)

        With 'through': checks if a BYPASS path exists (not going through filter).
            SAT → UNSAFE (bypass exists)
            UNSAT → SAFE (all paths go through filter)
        """
        try:
            import z3
        except ImportError:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": "Z3 solver is not installed"},
            )

        source = deploy_check.source
        sink = deploy_check.forbidden_sink
        through = deploy_check.through

        if source is None or sink is None:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": "data_flow requires source and forbidden_sink"},
            )

        # Build directed graph
        nodes: set[str] = set()
        edges: list[tuple[str, str]] = []
        for edge in deploy_check.flow_edges:
            a, b = edge[0], edge[1]
            nodes.add(a)
            nodes.add(b)
            edges.append((a, b))

        if source not in nodes:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": f"Source '{source}' not found in flow_edges nodes"},
            )
        if sink not in nodes:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": f"Sink '{sink}' not found in flow_edges nodes"},
            )

        n = len(nodes)
        node_list = sorted(nodes)
        node_idx = {name: i for i, name in enumerate(node_list)}

        # Z3 Int variables: dist[i] = position on path (-1 = not on path)
        dist = [z3.Int(f"d_{name}") for name in node_list]

        solver = z3.Solver()
        solver.set("timeout", self._config.timeout_ms)
        solver.set("rlimit", self._config.rlimit)

        src_i = node_idx[source]
        sink_i = node_idx[sink]

        # Source at position 0
        solver.add(dist[src_i] == 0)
        # Sink is on the path (position > 0)
        solver.add(dist[sink_i] > 0)

        # All dist values are -1 (not on path) or in valid range
        # Source is at 0; non-source nodes must be > 0 if on path
        for i in range(n):
            if i == src_i:
                # Source already forced to 0
                continue
            solver.add(z3.Or(dist[i] == -1, z3.And(dist[i] > 0, dist[i] < n)))

        # For each node on the path (dist > 0), there must be a predecessor
        # with dist == current - 1 and an edge from predecessor to current
        for i in range(n):
            if i == src_i:
                continue
            # If node i is on path (dist[i] > 0), some predecessor j has
            # dist[j] == dist[i] - 1 and edge (j → i) exists
            predecessor_options = []
            for a, b in edges:
                if node_idx[b] == i:
                    j = node_idx[a]
                    predecessor_options.append(dist[j] == dist[i] - 1)

            if predecessor_options:
                solver.add(
                    z3.Implies(
                        dist[i] > 0,
                        z3.Or(*predecessor_options),
                    )
                )
            else:
                # No incoming edges → can't be on path
                solver.add(dist[i] == -1)

        # 'through' filter: if specified, require filter NOT on path
        if through is not None:
            if through not in node_idx:
                return PolicyVerificationResult(
                    result=PolicyResult.ERROR,
                    details={"error": f"Through node '{through}' not found in flow_edges nodes"},
                )
            solver.add(dist[node_idx[through]] == -1)

        result = solver.check()

        if result == z3.sat:
            model = solver.model()
            path_nodes = []
            for i, name in enumerate(node_list):
                d = model.evaluate(dist[i]).as_long()
                if d >= 0:
                    path_nodes.append((d, name))
            path_nodes.sort()
            path_str = " → ".join(name for _, name in path_nodes)

            msg = (
                f"Bypass path found (avoiding '{through}'): {path_str}"
                if through
                else f"Exfiltration path found: {path_str}"
            )
            return PolicyVerificationResult(
                result=PolicyResult.UNSAFE,
                details={"message": msg, "path": [name for _, name in path_nodes]},
            )

        if result == z3.unsat:
            msg = (
                f"All paths from '{source}' to '{sink}' go through '{through}'"
                if through
                else f"No path from '{source}' to '{sink}'"
            )
            return PolicyVerificationResult(
                result=PolicyResult.SAFE,
                details={"message": msg},
            )

        return PolicyVerificationResult(
            result=PolicyResult.UNKNOWN,
            details={"message": "Z3 returned unknown for data flow analysis"},
        )

    # ── FILTER_COMPLETENESS ────────────────────────────────────────────

    _MAX_DENY_PATTERNS = 8

    def _check_filter_completeness(
        self,
        constraints: Sequence[Constraint],
        deploy_check: DeployCheck,
    ) -> PolicyVerificationResult:
        """Check that deny patterns catch all variants of a dangerous concept.

        Uses Z3 string theory:
        - dangerous_pattern keywords → z3.Contains(s, keyword) for each
        - deny patterns → translated via _regex_to_z3(), combined into Union
        - Query: SAT(is_dangerous AND NOT caught_by_denies)
            SAT → UNSAFE + counterexample
            UNSAT → SAFE (all dangerous inputs caught)
        """
        try:
            import z3
        except ImportError:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": "Z3 solver is not installed"},
            )

        # Parse dangerous_pattern keywords
        if not deploy_check.dangerous_pattern:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": "dangerous_pattern is required"},
            )
        keywords = [k.strip() for k in deploy_check.dangerous_pattern.split(";") if k.strip()]
        if not keywords:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={"error": "dangerous_pattern must have at least one keyword"},
            )

        # Resolve deny patterns from referenced constraints
        by_name = {c.name: c for c in constraints if c.enabled}
        deny_patterns: list[str] = []

        for ref_name in deploy_check.constraints_ref:
            c = by_name.get(ref_name)
            if c is None:
                return PolicyVerificationResult(
                    result=PolicyResult.ERROR,
                    details={"error": f"Referenced constraint not found: {ref_name}"},
                )
            if c.check is None or c.check.type != CheckType.REGEX_DENY:
                return PolicyVerificationResult(
                    result=PolicyResult.ERROR,
                    details={
                        "error": f"Constraint '{ref_name}' must be regex_deny for filter_completeness"
                    },
                )
            deny_patterns.extend(c.check.patterns)

        if not deny_patterns:
            return PolicyVerificationResult(
                result=PolicyResult.UNSAFE,
                details={"message": "No deny patterns found — nothing catches the dangerous input"},
            )

        if len(deny_patterns) > self._MAX_DENY_PATTERNS:
            return PolicyVerificationResult(
                result=PolicyResult.ERROR,
                details={
                    "error": (
                        f"Too many deny patterns ({len(deny_patterns)}), "
                        f"max {self._MAX_DENY_PATTERNS} for reliable Z3 string solving"
                    )
                },
            )

        # Translate deny patterns to Z3 regex.
        # NOTE: InRe uses fullmatch semantics. Deny pattern authors MUST write
        # .*pattern.* to match anywhere in the string (simulating re.search).
        # Soundness of . → AllChar (matches \n): _sanitize_string() strips all
        # C0 controls including \n, so runtime inputs never contain \n.
        z3_regexes = []
        for pattern in deny_patterns:
            try:
                z3_re = _regex_to_z3(pattern)
                z3_regexes.append(z3_re)
            except ValueError as exc:  # noqa: PERF203 — fail-closed: abort on first bad regex
                return PolicyVerificationResult(
                    result=PolicyResult.ERROR,
                    details={"error": f"Unsupported regex feature in '{pattern}': {exc}"},
                )

        # Build Z3 query
        s = z3.String("s")
        solver = z3.Solver()
        solver.set("timeout", self._config.timeout_ms)
        solver.set("rlimit", self._config.rlimit)

        # String is dangerous: matches .*keyword.* for ALL keywords
        # Using InRe (not Contains) keeps everything in regex theory for Z3 performance
        full = z3.Full(z3.ReSort(z3.StringSort()))
        for keyword in keywords:
            keyword_re = z3.Concat(full, z3.Re(z3.StringVal(keyword)), full)
            solver.add(z3.InRe(s, keyword_re))

        # String is NOT caught by any deny pattern
        combined = z3_regexes[0] if len(z3_regexes) == 1 else z3.Union(*z3_regexes)
        solver.add(z3.Not(z3.InRe(s, combined)))

        # Bounded length for termination (configurable via deploy_check.max_string_length)
        solver.add(z3.Length(s) <= deploy_check.max_string_length)

        result = solver.check()

        if result == z3.sat:
            model = solver.model()
            counterexample = str(model.evaluate(s))
            return PolicyVerificationResult(
                result=PolicyResult.UNSAFE,
                details={
                    "message": "Deny patterns do not catch all dangerous variants",
                    "counterexample": counterexample,
                },
            )

        if result == z3.unsat:
            return PolicyVerificationResult(
                result=PolicyResult.SAFE,
                details={
                    "message": "All dangerous variants are caught by deny patterns",
                    "patterns_checked": len(deny_patterns),
                },
            )

        return PolicyVerificationResult(
            result=PolicyResult.UNKNOWN,
            details={"message": "Z3 returned unknown for filter completeness check"},
        )
