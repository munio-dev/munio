"""L3+L7 Schema-Source Correlation.

Post-processing module that matches L3 schema findings with L7 source
findings. When both layers flag the same tool + CWE, the finding is
boosted as a confirmed vulnerability with schema + source evidence.

This is munio's unique differentiator — no competitor correlates
structured schema analysis with deterministic source code analysis.
"""

from __future__ import annotations

from munio.scan.models import Finding, Layer

# ── CWE correlation groups ───────────────────────────────────────

_CWE_GROUPS: dict[str, frozenset[str]] = {
    "injection": frozenset({"CWE-78", "CWE-94"}),
    "sql": frozenset({"CWE-89"}),
    "path": frozenset({"CWE-22"}),
    "ssrf": frozenset({"CWE-918"}),
}

_CWE_TO_GROUP: dict[str, str] = {}
for _group, _cwes in _CWE_GROUPS.items():
    for _cwe in _cwes:
        _CWE_TO_GROUP[_cwe] = _group

# ── Confidence boosts per tier ───────────────────────────────────

_CONFIRMED_BOOST = 0.10  # exact tool + exact CWE
_STRONG_BOOST = 0.07  # exact tool + CWE group
_PROBABLE_BOOST = 0.08  # <dispatch> + exact CWE
_WEAK_BOOST = 0.03  # <file-sweep> + exact CWE
_MAX_CONFIDENCE = 0.99


# ── Core correlation ─────────────────────────────────────────────


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    """Correlate L3 schema findings with L7 source findings.

    When L3 flags a suspicious parameter AND L7 finds a dangerous sink
    for the same tool+CWE, both findings get boosted confidence and
    enriched descriptions marking them as confirmed.

    Returns a new list with correlated findings replaced.
    Unmatched findings pass through unchanged.
    """
    if not findings:
        return []

    l3 = [f for f in findings if f.layer == Layer.L3_STATIC]
    l7 = [f for f in findings if f.layer == Layer.L7_SOURCE]
    others = [f for f in findings if f.layer not in (Layer.L3_STATIC, Layer.L7_SOURCE)]

    if not l3 or not l7:
        return findings  # Nothing to correlate

    # Track which findings have been correlated
    l3_matched: dict[int, tuple[Finding, float, str]] = {}  # idx → (partner, boost, label)
    l7_matched: dict[int, tuple[Finding, float, str]] = {}

    for i, f3 in enumerate(l3):
        best_j: int | None = None
        best_boost = 0.0
        best_label = ""

        for j, f7 in enumerate(l7):
            if j in l7_matched:
                continue  # Already matched

            boost, label = _match(f3, f7)
            if boost > best_boost:
                best_boost = boost
                best_label = label
                best_j = j

        if best_j is not None and best_boost > 0:
            l3_matched[i] = (l7[best_j], best_boost, best_label)
            l7_matched[best_j] = (f3, best_boost, best_label)

    # Build result with boosted findings
    result: list[Finding] = list(others)

    for i, f3 in enumerate(l3):
        if i in l3_matched:
            partner, boost, label = l3_matched[i]
            result.append(_boost(f3, boost, label, partner))
        else:
            result.append(f3)

    for j, f7 in enumerate(l7):
        if j in l7_matched:
            partner, boost, label = l7_matched[j]
            result.append(_boost(f7, boost, label, partner))
        else:
            result.append(f7)

    return result


def _match(l3: Finding, l7: Finding) -> tuple[float, str]:
    """Determine correlation boost and label between L3 and L7 finding.

    Returns (boost, label). (0.0, "") if no correlation.
    """
    if l3.cwe is None or l7.cwe is None:
        return 0.0, ""

    exact_cwe = l3.cwe == l7.cwe
    group_cwe = (
        _CWE_TO_GROUP.get(l3.cwe) == _CWE_TO_GROUP.get(l7.cwe)
        and _CWE_TO_GROUP.get(l3.cwe) is not None
    )

    if not exact_cwe and not group_cwe:
        return 0.0, ""

    # Determine tier by tool name match (normalize: hyphens, underscores, case)
    def _norm(name: str) -> str:
        return name.lower().replace("-", "_").replace(" ", "_")

    exact_tool = _norm(l3.tool_name) == _norm(l7.tool_name)
    dispatch_tool = l7.tool_name == "<dispatch>"
    sweep_tool = l7.tool_name == "<file-sweep>"

    if exact_tool and exact_cwe:
        return _CONFIRMED_BOOST, "CONFIRMED"
    if exact_tool and group_cwe:
        return _STRONG_BOOST, "STRONG"
    if dispatch_tool and exact_cwe:
        return _PROBABLE_BOOST, "PROBABLE"
    if sweep_tool and exact_cwe:
        return _WEAK_BOOST, "WEAK"
    # Dispatch/sweep + group match — very weak, skip
    return 0.0, ""


def _boost(finding: Finding, boost: float, label: str, partner: Finding) -> Finding:
    """Create a new Finding with boosted confidence and enriched description."""
    new_confidence = min(_MAX_CONFIDENCE, finding.confidence + boost)

    partner_layer = "L7 source" if partner.layer == Layer.L7_SOURCE else "L3 schema"
    partner_info = f"{partner.tool_name} at {partner.location}"

    new_desc = finding.description or ""
    if new_desc:
        new_desc += " "
    new_desc += f"[{label} by {partner_layer} analysis: {partner_info}]"

    return Finding(
        id=finding.id,
        layer=finding.layer,
        severity=finding.severity,
        tool_name=finding.tool_name,
        message=finding.message,
        description=new_desc,
        attack_type=finding.attack_type,
        cwe=finding.cwe,
        location=finding.location,
        counterexample=finding.counterexample,
        confidence=new_confidence,
    )
