"""Recommendation registry for munio scan findings.

Maps check_id to actionable recommendation text. Queried at display time
by --details output. Separate from the frozen Finding model.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Recommendation:
    """Actionable recommendation for a finding type."""

    short: str
    auto_fixable: bool


_RECOMMENDATIONS: dict[str, Recommendation] = {
    # L1 Schema
    "L1_001": Recommendation(
        short="Add a description to this tool explaining what it does.",
        auto_fixable=False,
    ),
    "L1_002": Recommendation(
        short="Define inputSchema with typed properties for all parameters.",
        auto_fixable=False,
    ),
    "L1_003": Recommendation(
        short='Set "additionalProperties": false in inputSchema.',
        auto_fixable=True,
    ),
    "L1_004": Recommendation(
        short="Add the parameter to the required array if it is mandatory.",
        auto_fixable=False,
    ),
    "L1_005": Recommendation(
        short='Add "maxLength" or a restrictive "pattern" to this string parameter.',
        auto_fixable=True,
    ),
    "L1_006": Recommendation(
        short='Add "minimum" and "maximum" bounds to this numeric parameter.',
        auto_fixable=True,
    ),
    "L1_007": Recommendation(
        short="Rename this parameter or document its safe usage.",
        auto_fixable=False,
    ),
    "L1_009": Recommendation(
        short="Add a description to this parameter.",
        auto_fixable=False,
    ),
    # L2 Heuristic
    "L2_001": Recommendation(
        short="Rewrite the description to avoid imperative instructions to the LLM.",
        auto_fixable=False,
    ),
    "L2_002": Recommendation(
        short="Remove references to other tools from this tool's description.",
        auto_fixable=False,
    ),
    "L2_003": Recommendation(
        short="Remove data exfiltration patterns (URLs, emails) from the description.",
        auto_fixable=False,
    ),
    "L2_004": Recommendation(
        short="Remove persistence/scheduling instructions from the description.",
        auto_fixable=False,
    ),
    "L2_005": Recommendation(
        short="Remove override/ignore instructions from the description.",
        auto_fixable=False,
    ),
    "L2_006": Recommendation(
        short="Remove sensitive data patterns from the description.",
        auto_fixable=False,
    ),
    "L2_007": Recommendation(
        short="Remove pre/post-action data access instructions from the description.",
        auto_fixable=False,
    ),
    "L2_008": Recommendation(
        short="Remove stealth/evasion instructions from the description.",
        auto_fixable=False,
    ),
    # L3 Static
    "L3_001": Recommendation(
        short='Add "pattern" rejecting ../ sequences to this path parameter.',
        auto_fixable=True,
    ),
    "L3_002": Recommendation(
        short='Add "format": "uri" or a pattern restricting to https:// URLs.',
        auto_fixable=True,
    ),
    "L3_003": Recommendation(
        short="Use parameterized queries or restrict to an enum of allowed values.",
        auto_fixable=False,
    ),
    "L3_004": Recommendation(
        short="Restrict to an enum of allowed commands or add a strict pattern.",
        auto_fixable=False,
    ),
    "L3_005": Recommendation(
        short='Add "maxItems" to this array parameter.',
        auto_fixable=True,
    ),
    "L3_006": Recommendation(
        short="Review this boolean parameter for security bypass risk.",
        auto_fixable=False,
    ),
    "L3_007": Recommendation(
        short="Anchor the regex pattern with ^ and $ to prevent partial matches.",
        auto_fixable=False,
    ),
    "L3_008": Recommendation(
        short="Fix conflicting constraints (e.g. minimum > maximum).",
        auto_fixable=False,
    ),
    "L3_009": Recommendation(
        short="Restrict template parameters with an enum or strict pattern.",
        auto_fixable=False,
    ),
    "L3_010": Recommendation(
        short="Add bounds or pattern to this numeric identifier parameter.",
        auto_fixable=False,
    ),
    # L4 Z3 (formal verification — has counterexamples)
    "L4_001": Recommendation(
        short="Current pattern does not block path traversal. Use a stronger pattern.",
        auto_fixable=True,
    ),
    "L4_002": Recommendation(
        short="Current URL pattern admits SSRF payloads. Restrict to public HTTPS.",
        auto_fixable=True,
    ),
    "L4_003": Recommendation(
        short="Current pattern does not block command injection. Use an enum.",
        auto_fixable=False,
    ),
    "L4_004": Recommendation(
        short="Pattern and length constraints contradict — no valid input exists.",
        auto_fixable=False,
    ),
    "L4_005": Recommendation(
        short="Enum contains unsafe values (traversal, injection payloads). Remove them.",
        auto_fixable=False,
    ),
    # L5 Compositional
    "L5_001": Recommendation(
        short="Review this known dangerous tool combination.",
        auto_fixable=False,
    ),
    "L5_002": Recommendation(
        short="Add runtime constraints (munio gate) to block this data flow.",
        auto_fixable=False,
    ),
    "L5_003": Recommendation(
        short="Isolate these servers or add cross-server gate constraints.",
        auto_fixable=False,
    ),
    # SC Supply Chain (Config Scanner)
    "SC_001": Recommendation(
        short="Pin the npm package version: @scope/pkg@1.2.3.",
        auto_fixable=True,
    ),
    "SC_002": Recommendation(
        short="Remove dangerous environment variable from config.",
        auto_fixable=False,
    ),
    "SC_003": Recommendation(
        short="Verify package name -- potential typosquatting detected.",
        auto_fixable=False,
    ),
    "SC_004": Recommendation(
        short="Use scoped packages (@org/pkg) to reduce name hijacking risk.",
        auto_fixable=False,
    ),
    "SC_005": Recommendation(
        short="Remove shell metacharacters from arguments.",
        auto_fixable=False,
    ),
    "SC_006": Recommendation(
        short="Use PATH-relative binary name instead of absolute path.",
        auto_fixable=False,
    ),
    "SC_007": Recommendation(
        short="Use HTTPS URL instead of HTTP.",
        auto_fixable=True,
    ),
    "SC_008": Recommendation(
        short="Pin Docker image by digest: image@sha256:abc123...",
        auto_fixable=True,
    ),
    "SC_009": Recommendation(
        short="Move credentials to a secrets manager or .env file (not in config).",
        auto_fixable=False,
    ),
    "SC_010": Recommendation(
        short="Restrict file permissions: chmod 600 <config-file>.",
        auto_fixable=True,
    ),
}


def get_recommendation(check_id: str) -> Recommendation | None:
    """Look up recommendation by check_id."""
    return _RECOMMENDATIONS.get(check_id)
