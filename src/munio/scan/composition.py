"""Multi-server composition analysis for attack chain detection.

Analyzes MCP tool configurations to find dangerous attack chains,
compute danger scores, and generate CVE filing drafts.
"""

from __future__ import annotations

import logging
import math
import time
import uuid
from collections import deque
from typing import TYPE_CHECKING

from munio.scan.composition_report import (
    AttackChain,
    ChainNode,
    CompositionReport,
    CVEDraft,
    DangerGrade,
    DangerScore,
)
from munio.scan.layers.composition_taxonomy import Capability

if TYPE_CHECKING:
    from munio.scan.layers.composition_taxonomy import ToolRole, ToxicFlowRule
    from munio.scan.models import ToolDefinition

__all__ = ["CompositionAnalyzer"]

logger = logging.getLogger(__name__)

# DoS bounds
_MAX_TOOLS = 1000
_MAX_CHAINS = 500
_MAX_HOPS = 3
_MAX_EDGES = 10000

# Danger score base values
_BASE_SCORES: dict[str, float] = {
    "CRITICAL": 40.0,
    "HIGH": 25.0,
    "MEDIUM": 10.0,
    "LOW": 3.0,
}

# Browser automation tools — navigation/clicks are by-design, not CVE material
_BROWSER_BY_DESIGN_TOOLS: frozenset[str] = frozenset(
    {
        "browser_navigate",
        "browser_click",
        "browser_fill_form",
        "browser_screenshot",
        "browser_go_back",
        "browser_go_forward",
        "browser_snapshot",
        "browser_hover",
        "browser_type",
        "browser_select_option",
        "browser_press_key",
        "browser_wait",
        "browser_drag",
        "browser_scroll",
        "browser_tab_list",
        "browser_close_tab",
        "navigate",
        "click",
        "screenshot",
        "fill",
        "select",
        "hover",
        "type",
        "press_key",
    }
)

# Capabilities that represent actual data exfiltration (data LEAVES victim's machine)
_EXFIL_CAPS: frozenset[Capability] = frozenset(
    {
        Capability.NETWORK_EXFIL,
        Capability.EMAIL_SEND,
        Capability.COMMS_SEND,
        Capability.VCS_PUSH,
    }
)


class _ClassifiedTool:
    """Internal helper: tool with its classification."""

    __slots__ = ("caps", "is_known", "role", "server_name", "tool")

    def __init__(
        self,
        tool: ToolDefinition,
        role: ToolRole,
        caps: frozenset[Capability],
        *,
        is_known: bool = False,
    ) -> None:
        self.tool = tool
        self.role = role
        self.caps = caps
        self.is_known = is_known
        self.server_name = tool.server_name


class _Edge:
    """Directed edge in the capability graph."""

    __slots__ = ("rules", "sink", "source")

    def __init__(
        self,
        source: _ClassifiedTool,
        sink: _ClassifiedTool,
        rules: list[ToxicFlowRule],
    ) -> None:
        self.source = source
        self.sink = sink
        self.rules = rules


class CompositionAnalyzer:
    """Analyze multi-server MCP configs for dangerous attack chains."""

    def analyze(self, tools: list[ToolDefinition]) -> CompositionReport:
        """Run full composition analysis on a set of tools."""
        start = time.monotonic()
        scan_id = str(uuid.uuid4())

        # Classify all tools (known taxonomy tools get priority over truncation)
        classified = self._classify_tools(tools)

        # Build capability graph
        edges = self._build_graph(classified)

        # Detect chains via BFS
        chains = self._detect_chains(classified, edges)

        # Compute danger score
        server_names = {t.server_name for t in classified if t.server_name}
        danger = self._compute_danger(chains, len(server_names))

        # Generate CVE drafts for high-severity chains
        cve_drafts = self._generate_cve_drafts(chains)

        elapsed = (time.monotonic() - start) * 1000

        return CompositionReport(
            scan_id=scan_id,
            server_count=len(server_names),
            tool_count=len(classified),
            chains=chains,
            danger=danger,
            cve_drafts=cve_drafts,
            elapsed_ms=elapsed,
        )

    def _classify_tools(self, tools: list[ToolDefinition]) -> list[_ClassifiedTool]:
        """Classify all tools using L5 taxonomy.

        Known taxonomy tools always included; heuristic tools truncated
        to _MAX_TOOLS to prevent DoS on large corpora.
        """
        from munio.scan.layers.composition_taxonomy import ToolRole, classify_tool_detailed

        known: list[_ClassifiedTool] = []
        heuristic: list[_ClassifiedTool] = []
        for tool in tools:
            role, caps, is_known = classify_tool_detailed(tool)
            if role == ToolRole.NONE:
                continue
            ct = _ClassifiedTool(tool, role, caps, is_known=is_known)
            if is_known:
                known.append(ct)
            else:
                heuristic.append(ct)

        # Known tools always included; fill remaining budget with heuristic
        budget = max(_MAX_TOOLS - len(known), 0)
        return known + heuristic[:budget]

    def _build_graph(self, classified: list[_ClassifiedTool]) -> list[_Edge]:
        """Build directed capability graph. Only edges with toxic flow matches.

        Known→known edges are built first to guarantee high-signal chains
        are discoverable before the edge budget is exhausted.
        """
        from munio.scan.layers.composition_taxonomy import ToolRole, match_toxic_rules

        # Sources: tools with P or U role
        sources = [t for t in classified if t.role & (ToolRole.P | ToolRole.U)]
        # Sinks: tools with S role, excluding browser-by-design tools
        sinks = [
            t
            for t in classified
            if t.role & ToolRole.S and t.tool.name not in _BROWSER_BY_DESIGN_TOOLS
        ]

        # Two-pass: known→known edges first, then the rest
        known_sources = [s for s in sources if s.is_known]
        known_sinks = [s for s in sinks if s.is_known]

        edges: list[_Edge] = []
        seen_pairs: set[tuple[str, str]] = set()

        def _add_edges(srcs: list[_ClassifiedTool], snks: list[_ClassifiedTool]) -> bool:
            """Add edges, return False if budget exhausted."""
            for src in srcs:
                for snk in snks:
                    pair = (
                        f"{src.tool.name}@{src.server_name}",
                        f"{snk.tool.name}@{snk.server_name}",
                    )
                    if pair in seen_pairs:
                        continue
                    if src.tool.name == snk.tool.name and src.server_name == snk.server_name:
                        continue
                    rules = match_toxic_rules(src.caps, snk.caps)
                    if rules:
                        edges.append(_Edge(src, snk, rules))
                        seen_pairs.add(pair)
                        if len(edges) >= _MAX_EDGES:
                            return False
            return True

        # Pass 1: known→known (highest signal)
        if not _add_edges(known_sources, known_sinks):
            return edges
        # Pass 2: known→heuristic + heuristic→known
        if not _add_edges(known_sources, sinks):
            return edges
        if not _add_edges(sources, known_sinks):
            return edges
        # Pass 3: heuristic→heuristic (lowest signal)
        _add_edges(sources, sinks)

        return edges

    def _detect_chains(
        self,
        classified: list[_ClassifiedTool],
        edges: list[_Edge],
    ) -> list[AttackChain]:
        """Detect attack chains via BFS from P|U nodes to S nodes."""
        from munio.scan.layers.composition_taxonomy import ToolRole

        chains: list[AttackChain] = []

        # Build adjacency list — sort edges: known sinks first for higher signal
        adj: dict[str, list[_Edge]] = {}
        for edge in edges:
            key = f"{edge.source.tool.name}@{edge.source.server_name}"
            adj.setdefault(key, []).append(edge)
        for key in adj:
            adj[key].sort(key=lambda e: not e.sink.is_known)

        # BFS from each source — known taxonomy tools first for higher signal
        sources = sorted(
            [t for t in classified if t.role & (ToolRole.P | ToolRole.U)],
            key=lambda t: (not t.is_known, t.tool.name),
        )
        seen_chains: set[str] = set()

        for src in sources:
            # BFS queue: (current_tool, path, depth)
            queue: deque[tuple[_ClassifiedTool, list[_ClassifiedTool], int]] = deque(
                [(src, [src], 0)]
            )

            while queue and len(chains) < _MAX_CHAINS:
                current, path, depth = queue.popleft()
                if depth >= _MAX_HOPS:
                    continue

                current_key = f"{current.tool.name}@{current.server_name}"
                for edge in adj.get(current_key, []):
                    sink = edge.sink
                    sink_key = f"{sink.tool.name}@{sink.server_name}"

                    # Avoid cycles
                    path_keys = {f"{p.tool.name}@{p.server_name}" for p in path}
                    if sink_key in path_keys:
                        continue

                    new_path = [*path, sink]

                    # Valid chain: ends at S node
                    if sink.role & ToolRole.S:
                        # Dedup by chain signature
                        chain_sig = " -> ".join(f"{n.tool.name}@{n.server_name}" for n in new_path)
                        if chain_sig in seen_chains:
                            continue
                        seen_chains.add(chain_sig)

                        # Use best (highest severity) rule
                        best_rule = max(
                            edge.rules,
                            key=lambda r: _BASE_SCORES.get(r.risk, 0),
                        )

                        servers_in_chain = {n.server_name for n in new_path if n.server_name}
                        cross_server = len(servers_in_chain) > 1

                        chain = self._build_chain(
                            new_path,
                            best_rule,
                            cross_server,
                        )
                        chains.append(chain)

                    # Continue BFS
                    if depth + 1 < _MAX_HOPS:
                        queue.append((sink, new_path, depth + 1))

        # Sort by score descending
        chains.sort(key=lambda c: c.score, reverse=True)
        return chains[:_MAX_CHAINS]

    def _build_chain(
        self,
        path: list[_ClassifiedTool],
        rule: ToxicFlowRule,
        cross_server: bool,
    ) -> AttackChain:
        """Build AttackChain from path and matching rule."""
        from munio.scan.layers.composition_taxonomy import ToolRole

        nodes: list[ChainNode] = []
        for ct in path:
            role_parts: list[str] = []
            if ct.role & ToolRole.P:
                role_parts.append("P")
            if ct.role & ToolRole.U:
                role_parts.append("U")
            if ct.role & ToolRole.S:
                role_parts.append("S")

            nodes.append(
                ChainNode(
                    tool_name=ct.tool.name,
                    server_name=ct.server_name,
                    capabilities=[c.value for c in ct.caps],
                    role="|".join(role_parts) if role_parts else "NONE",
                )
            )

        hops = len(path) - 1
        base = _BASE_SCORES.get(rule.risk, 10.0)
        score = base * (1.5 if cross_server else 1.0) * (1.0 + 0.2 * (hops - 1))

        signal = self._classify_signal(path, cross_server)

        return AttackChain(
            nodes=nodes,
            risk=rule.risk,
            description=rule.description,
            cwe=rule.cwe,
            cross_server=cross_server,
            score=score,
            signal=signal,
        )

    def _classify_signal(
        self,
        path: list[_ClassifiedTool],
        cross_server: bool,
    ) -> str:
        """Classify chain signal quality: high, medium, low.

        High: both endpoints from known taxonomy + cross-server + has exfil cap
        Medium: at least one known endpoint OR has known combo match
        Low: all heuristic-classified
        """
        from munio.scan.layers.composition_taxonomy import find_known_combo

        source = path[0]
        sink = path[-1]

        # Check for known combo match (highest signal)
        combo = find_known_combo(source.tool.name, sink.tool.name)
        if combo is not None:
            return "high"

        # Both endpoints from known taxonomy + actual exfil
        both_known = source.is_known and sink.is_known
        has_exfil = bool(sink.caps & _EXFIL_CAPS)

        if both_known and has_exfil and cross_server:
            return "high"

        if both_known or (source.is_known and has_exfil):
            return "medium"

        # At least one known endpoint with dangerous capability
        any_known = source.is_known or sink.is_known
        if any_known and (has_exfil or bool(sink.caps & frozenset({Capability.CODE_EXEC}))):
            return "medium"

        return "low"

    def _compute_danger(
        self,
        chains: list[AttackChain],
        server_count: int,
    ) -> DangerScore:
        """Compute aggregate danger score."""
        if not chains:
            return DangerScore(
                score=0.0,
                grade=DangerGrade.A,
                chain_count=0,
                server_count=server_count,
            )

        amplification = 1.0 + math.log2(max(server_count, 1))

        sorted_scores = sorted(
            [c.score for c in chains],
            reverse=True,
        )

        raw = sorted_scores[0] + 0.1 * sum(sorted_scores[1:])
        danger_score = min(raw * amplification, 100.0)

        grade = _score_to_grade(danger_score)

        return DangerScore(
            score=round(danger_score, 1),
            grade=grade,
            chain_count=len(chains),
            server_count=server_count,
            amplification=round(amplification, 2),
        )

    def _generate_cve_drafts(self, chains: list[AttackChain]) -> list[CVEDraft]:
        """Generate CVE filing drafts for high-signal CRITICAL/HIGH chains."""
        drafts: list[CVEDraft] = []
        seen_descriptions: set[str] = set()

        for chain in chains:
            if chain.risk not in ("CRITICAL", "HIGH"):
                continue
            # Only generate CVE drafts for high/medium signal chains
            if chain.signal == "low":
                continue
            # Dedup by description
            if chain.description in seen_descriptions:
                continue
            seen_descriptions.add(chain.description)

            servers = list(dict.fromkeys(n.server_name for n in chain.nodes if n.server_name))

            cvss_vector, cvss_score = _estimate_cvss(chain)

            source_name = chain.nodes[0].tool_name if chain.nodes else "unknown"
            sink_name = chain.nodes[-1].tool_name if chain.nodes else "unknown"

            title = f"Cross-server {chain.description}" if chain.cross_server else chain.description

            poc_parts = []
            for i, node in enumerate(chain.nodes):
                step = f"Step {i + 1}: Call `{node.tool_name}`"
                if node.server_name:
                    step += f" on server `{node.server_name}`"
                step += f" (role: {node.role})"
                poc_parts.append(step)

            drafts.append(
                CVEDraft(
                    title=title,
                    affected_servers=servers,
                    description=(
                        f"An attacker can chain {source_name} -> {sink_name} "
                        f"to achieve {chain.description.lower()}. "
                        f"This is a {'cross-server ' if chain.cross_server else ''}"
                        f"{'multi-hop ' if len(chain.nodes) > 2 else ''}"
                        f"attack chain with {chain.risk} severity."
                    ),
                    chain=chain,
                    cvss_vector=cvss_vector,
                    cvss_score=cvss_score,
                    cvss_estimated=True,
                    poc_narrative="\n".join(poc_parts),
                )
            )

        return drafts


def _score_to_grade(score: float) -> DangerGrade:
    """Convert numeric score to danger grade."""
    if score >= 80:
        return DangerGrade.F
    if score >= 60:
        return DangerGrade.D
    if score >= 40:
        return DangerGrade.C
    if score >= 20:
        return DangerGrade.B
    return DangerGrade.A


def _estimate_cvss(chain: AttackChain) -> tuple[str, float]:
    """Estimate CVSS vector and score based on chain properties.

    Returns (vector_string, numeric_score). All estimates are clearly
    template-based -- not authoritative CVSS calculations.
    """
    # Scope: cross-server = Changed, same-server = Unchanged
    scope = "S:C" if chain.cross_server else "S:U"

    desc_lower = chain.description.lower()

    # Template matching
    if "credential" in desc_lower or "exfil" in desc_lower or "secret" in desc_lower:
        # Data exfiltration
        vector = f"AV:N/AC:L/PR:N/UI:R/{scope}/C:H/I:N/A:N"
        score = 8.6 if chain.cross_server else 7.4
    elif (
        "code" in desc_lower
        or "exec" in desc_lower
        or "command" in desc_lower
        or "rce" in desc_lower
    ):
        # RCE chain
        vector = f"AV:N/AC:L/PR:N/UI:R/{scope}/C:H/I:H/A:N"
        score = 9.3 if chain.cross_server else 8.1
    elif "write" in desc_lower or "modify" in desc_lower or "overwrite" in desc_lower:
        # Data tampering
        vector = f"AV:N/AC:L/PR:N/UI:R/{scope}/C:N/I:H/A:N"
        score = 7.4 if chain.cross_server else 6.5
    else:
        # Generic
        vector = f"AV:N/AC:L/PR:N/UI:R/{scope}/C:L/I:L/A:N"
        score = 5.4 if chain.cross_server else 4.3

    return vector, score
