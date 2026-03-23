"""L5 Compositional Analysis: cross-server P/U/S taint flow detection.

Detects dangerous tool combinations by:
1. Classifying tools into capability categories (P/U/S + fine-grained)
2. Checking known dangerous source->sink pairs from vulnerability corpus
3. Matching toxic flow rules (capability-category combinations)
4. Detecting cross-server flows and the "lethal trifecta" (P+U+S)
5. Flagging unclassifiable tools (fail-closed)

Known-combo check is O(sources*sinks) but each pair is an O(1) dict lookup.
Toxic-rule check is O(N*K) where K is the number of rules (~16).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, NamedTuple

from munio.scan.layers.composition_taxonomy import (
    Capability,
    ToolRole,
    classify_tool,
    find_known_combo,
    match_toxic_rules,
)
from munio.scan.models import (
    AttackType,
    Finding,
    FindingSeverity,
    Layer,
)

# Capabilities that indicate safety control modification
_SAFETY_CONFIG_CAPS: frozenset[Capability] = frozenset({Capability.SAFETY_CONFIG})

if TYPE_CHECKING:
    from collections.abc import Sequence

    from munio.scan.layers.composition_taxonomy import DangerousCombo, ToxicFlowRule
    from munio.scan.models import ToolDefinition

__all__ = ["L5CompositionAnalyzer"]

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
}

# Capabilities that indicate untrusted input (U role) sources
_U_CAPS: frozenset[Capability] = frozenset({Capability.FETCH_UNTRUSTED})

# Capabilities associated with code execution sinks
_CODE_EXEC_CAPS: frozenset[Capability] = frozenset({Capability.CODE_EXEC})


class _ClassifiedTool(NamedTuple):
    """Tool with its P/U/S classification and capabilities."""

    tool: ToolDefinition
    role: ToolRole
    caps: frozenset[Capability]


def _normalize(name: str) -> str:
    """Normalize tool name for dedup consistency."""
    return name.lower().replace("-", "_")


def _format_location(src: _ClassifiedTool, snk: _ClassifiedTool) -> str:
    """Format source→sink location string."""
    return (
        f"source:{src.tool.name}@{src.tool.server_name} -> "
        f"sink:{snk.tool.name}@{snk.tool.server_name}"
    )


class L5CompositionAnalyzer:
    """L5 Compositional Analysis: cross-server P/U/S taint flow detection."""

    __slots__ = ()

    @property
    def layer(self) -> Layer:
        return Layer.L5_COMPOSITIONAL

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]:
        """Classify tools, match toxic flow rules, detect dangerous flows."""
        if len(tools) < 2:
            return []

        # Step 1: Classify all tools (outside try — classification errors are fatal)
        classified = [_ClassifiedTool(t, *classify_tool(t)) for t in tools]

        findings: list[Finding] = []

        # Per-phase exception handling: one phase failing doesn't silence others
        # Step 2: Known dangerous combos
        try:
            findings.extend(self._check_known_combos(classified))
        except Exception:
            logger.warning("L5 known-combo check failed", exc_info=True)

        # Step 3: Toxic flow rules
        try:
            findings.extend(self._check_toxic_rules(classified))
        except Exception:
            logger.warning("L5 toxic-rule check failed", exc_info=True)

        # Step 4: Lethal trifecta
        try:
            trifecta = self._check_lethal_trifecta(classified)
            if trifecta is not None:
                findings.append(trifecta)
        except Exception:
            logger.warning("L5 trifecta check failed", exc_info=True)

        # Step 5: Unclassifiable tools (fail-closed)
        try:
            findings.extend(self._check_unclassifiable(classified))
        except Exception:
            logger.warning("L5 unclassifiable check failed", exc_info=True)

        return findings

    def _check_known_combos(
        self,
        classified: list[_ClassifiedTool],
    ) -> list[Finding]:
        """Check for known dangerous source->sink pairs from corpus."""
        sources = [ct for ct in classified if ct.role & (ToolRole.P | ToolRole.U)]
        sinks = [ct for ct in classified if ct.role & ToolRole.S]

        if not sources or not sinks:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for src in sources:
            for snk in sinks:
                # Skip self-reference (same tool, same server)
                if src.tool.name == snk.tool.name and src.tool.server_name == snk.tool.server_name:
                    continue

                # Normalize for consistent dedup
                pair_key = (_normalize(src.tool.name), _normalize(snk.tool.name))
                if pair_key in seen:
                    continue

                combo = find_known_combo(src.tool.name, snk.tool.name)
                if combo is None:
                    continue

                seen.add(pair_key)
                findings.append(self._make_combo_finding(src, snk, combo))

                # Cross-server escalation
                if (
                    src.tool.server_name
                    and snk.tool.server_name
                    and src.tool.server_name != snk.tool.server_name
                ):
                    findings.append(self._make_cross_server_finding(src, snk, combo))

        return findings

    def _check_toxic_rules(
        self,
        classified: list[_ClassifiedTool],
    ) -> list[Finding]:
        """Match toxic flow rules against aggregated capabilities."""
        # Aggregate capabilities: source caps from P|U tools, sink caps from S tools.
        # Store ALL tools per capability (not just first) for cross-server detection.
        source_caps: set[Capability] = set()
        sink_caps: set[Capability] = set()
        source_tools: dict[Capability, list[_ClassifiedTool]] = {}
        sink_tools: dict[Capability, list[_ClassifiedTool]] = {}

        for ct in classified:
            if ct.role & (ToolRole.P | ToolRole.U):
                for cap in ct.caps:
                    source_caps.add(cap)
                    source_tools.setdefault(cap, []).append(ct)
            if ct.role & ToolRole.S:
                for cap in ct.caps:
                    sink_caps.add(cap)
                    sink_tools.setdefault(cap, []).append(ct)

        if not source_caps or not sink_caps:
            return []

        matched_rules = match_toxic_rules(frozenset(source_caps), frozenset(sink_caps))
        if not matched_rules:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for rule in matched_rules:
            # Find ALL source and sink tools for this rule
            src_list = self._find_all_representatives(source_tools, rule.source_caps)
            snk_list = self._find_all_representatives(sink_tools, rule.sink_caps)

            for src_tool in src_list:
                for snk_tool in snk_list:
                    # Self-reference guard
                    if (
                        src_tool.tool.name == snk_tool.tool.name
                        and src_tool.tool.server_name == snk_tool.tool.server_name
                    ):
                        continue

                    pair_key = (_normalize(src_tool.tool.name), _normalize(snk_tool.tool.name))
                    if pair_key in seen:
                        continue

                    # Skip if already reported as known combo
                    combo = find_known_combo(src_tool.tool.name, snk_tool.tool.name)
                    if combo is not None:
                        continue

                    seen.add(pair_key)
                    findings.append(self._make_rule_finding(src_tool, snk_tool, rule))

                    # Cross-server escalation
                    if (
                        src_tool.tool.server_name
                        and snk_tool.tool.server_name
                        and src_tool.tool.server_name != snk_tool.tool.server_name
                    ):
                        findings.append(
                            self._make_cross_server_rule_finding(src_tool, snk_tool, rule)
                        )

        return findings

    def _check_lethal_trifecta(
        self,
        classified: list[_ClassifiedTool],
    ) -> Finding | None:
        """Detect lethal trifecta: P + U + S all present from distinct tools."""
        p_names: set[str] = set()
        u_names: set[str] = set()
        s_names: set[str] = set()

        for ct in classified:
            if ct.role & ToolRole.P:
                p_names.add(ct.tool.name)
            if ct.role & ToolRole.U:
                u_names.add(ct.tool.name)
            if ct.role & ToolRole.S:
                s_names.add(ct.tool.name)

        if not p_names or not u_names or not s_names:
            return None

        # Require at least 2 distinct tool names across all roles to avoid
        # false positive from a single P|U|S tool
        all_names = p_names | u_names | s_names
        if len(all_names) < 2:
            return None

        p_repr = sorted(p_names)[0]
        u_repr = sorted(u_names)[0]
        s_repr = sorted(s_names)[0]

        return Finding(
            id="L5_004",
            layer=Layer.L5_COMPOSITIONAL,
            severity=FindingSeverity.CRITICAL,
            tool_name=s_repr,
            message=(
                f"Lethal trifecta: environment has private data sources ({p_repr}, ...), "
                f"untrusted inputs ({u_repr}, ...), and state-changing sinks ({s_repr}, ...). "
                f"Untrusted input can control how private data flows to external sinks."
            ),
            description=(
                f"Private sources: {', '.join(sorted(p_names)[:3])}. "
                f"Untrusted inputs: {', '.join(sorted(u_names)[:3])}. "
                f"Sinks: {', '.join(sorted(s_names)[:3])}."
            ),
            location=f"trifecta: P({len(p_names)}) + U({len(u_names)}) + S({len(s_names)})",
            attack_type=AttackType.DATA_EXFILTRATION,
            cwe="CWE-200",
            confidence=0.80,
        )

    @staticmethod
    def _check_unclassifiable(classified: list[_ClassifiedTool]) -> list[Finding]:
        """Emit L5_005 for tools that could not be classified (fail-closed)."""
        return [
            Finding(
                id="L5_005",
                layer=Layer.L5_COMPOSITIONAL,
                severity=FindingSeverity.INFO,
                tool_name=ct.tool.name,
                message=(
                    f"Tool '{ct.tool.name}' on server '{ct.tool.server_name}' "
                    f"could not be classified. Insufficient metadata for "
                    f"compositional safety analysis."
                ),
                attack_type=AttackType.DATA_EXFILTRATION,
                cwe="CWE-200",
                confidence=0.30,
            )
            for ct in classified
            if ct.role == ToolRole.NONE
        ]

    @staticmethod
    def _find_all_representatives(
        cap_to_tools: dict[Capability, list[_ClassifiedTool]],
        target_caps: frozenset[Capability],
    ) -> list[_ClassifiedTool]:
        """Find all unique tools that have any of the target capabilities."""
        seen_ids: set[tuple[str, str]] = set()
        result: list[_ClassifiedTool] = []
        for cap in target_caps:
            for ct in cap_to_tools.get(cap, []):
                key = (ct.tool.name, ct.tool.server_name)
                if key not in seen_ids:
                    seen_ids.add(key)
                    result.append(ct)
        return result

    @staticmethod
    def _make_combo_finding(
        src: _ClassifiedTool,
        snk: _ClassifiedTool,
        combo: DangerousCombo,
    ) -> Finding:
        """Create L5_001 finding for a known dangerous combo."""
        attack_type = AttackType.DATA_EXFILTRATION
        if combo.cwe == "CWE-94":
            attack_type = AttackType.COMMAND_INJECTION
        elif combo.cwe == "CWE-74":
            attack_type = AttackType.PROMPT_INJECTION

        return Finding(
            id="L5_001",
            layer=Layer.L5_COMPOSITIONAL,
            severity=_SEVERITY_MAP.get(combo.risk, FindingSeverity.HIGH),
            tool_name=snk.tool.name,
            message=(
                f"Known dangerous combination: {src.tool.name} ({src.tool.server_name}) "
                f"can flow data to {snk.tool.name} ({snk.tool.server_name}). "
                f"{combo.description}"
            ),
            description=f"Real-world: {combo.real_world}",
            attack_type=attack_type,
            cwe=combo.cwe,
            location=_format_location(src, snk),
            confidence=0.95 if combo.risk == "CRITICAL" else 0.90,
        )

    @staticmethod
    def _make_cross_server_finding(
        src: _ClassifiedTool,
        snk: _ClassifiedTool,
        combo: DangerousCombo,
    ) -> Finding:
        """Create L5_003 cross-server escalation for a known combo."""
        return Finding(
            id="L5_003",
            layer=Layer.L5_COMPOSITIONAL,
            severity=_SEVERITY_MAP.get(combo.risk, FindingSeverity.HIGH),
            tool_name=snk.tool.name,
            message=(
                f"Cross-server data flow: {src.tool.name} on server '{src.tool.server_name}' "
                f"can exfiltrate to {snk.tool.name} on server '{snk.tool.server_name}'"
            ),
            description="Cross-server flows bypass single-server authorization boundaries",
            attack_type=AttackType.DATA_EXFILTRATION,
            cwe=combo.cwe,
            location=_format_location(src, snk),
            confidence=0.90,
        )

    @staticmethod
    def _make_rule_finding(
        src: _ClassifiedTool,
        snk: _ClassifiedTool,
        rule: ToxicFlowRule,
    ) -> Finding:
        """Create L5_002 finding for a toxic flow rule match."""
        attack_type = AttackType.DATA_EXFILTRATION
        if (src.caps | snk.caps) & _SAFETY_CONFIG_CAPS:
            attack_type = AttackType.SAFETY_TAMPERING
        elif snk.caps & _CODE_EXEC_CAPS:
            attack_type = AttackType.COMMAND_INJECTION
        elif src.caps & _U_CAPS:
            attack_type = AttackType.PROMPT_INJECTION

        return Finding(
            id="L5_002",
            layer=Layer.L5_COMPOSITIONAL,
            severity=_SEVERITY_MAP.get(rule.risk, FindingSeverity.HIGH),
            tool_name=snk.tool.name,
            message=(
                f"Toxic flow: {rule.description}. "
                f"Source: {src.tool.name} ({src.tool.server_name}), "
                f"sink: {snk.tool.name} ({snk.tool.server_name})"
            ),
            attack_type=attack_type,
            cwe=rule.cwe,
            location=_format_location(src, snk),
            confidence=0.75,
        )

    @staticmethod
    def _make_cross_server_rule_finding(
        src: _ClassifiedTool,
        snk: _ClassifiedTool,
        rule: ToxicFlowRule,
    ) -> Finding:
        """Create L5_003 cross-server escalation for a rule match."""
        return Finding(
            id="L5_003",
            layer=Layer.L5_COMPOSITIONAL,
            severity=_SEVERITY_MAP.get(rule.risk, FindingSeverity.HIGH),
            tool_name=snk.tool.name,
            message=(
                f"Cross-server toxic flow: {src.tool.name} on server '{src.tool.server_name}' "
                f"to {snk.tool.name} on server '{snk.tool.server_name}'. {rule.description}"
            ),
            description="Cross-server flows bypass single-server authorization boundaries",
            attack_type=AttackType.DATA_EXFILTRATION,
            cwe=rule.cwe,
            location=_format_location(src, snk),
            confidence=0.85,
        )
