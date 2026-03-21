"""SARIF 2.1.0 output builder for munio scan.

Converts ScanResult to a SARIF 2.1.0 dict suitable for GitHub Code Scanning
upload and other SARIF-compatible tools. Dict-based builder, no external deps.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Any

from munio.scan.models import FindingSeverity, Layer

if TYPE_CHECKING:
    from munio.scan.models import Finding, ScanResult

__all__ = ["scan_result_to_sarif"]

_MAX_RESULTS = 5000

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# L5 location format: "source:name@server -> sink:name@server"
_FLOW_RE = re.compile(
    r"source:(?P<src_tool>[^@]+)@(?P<src_srv>\S+)"
    r"\s*->\s*"
    r"sink:(?P<snk_tool>[^@]+)@(?P<snk_srv>\S+)"
)

_SEVERITY_MAP: dict[FindingSeverity, tuple[str, str]] = {
    FindingSeverity.CRITICAL: ("error", "9.5"),
    FindingSeverity.HIGH: ("error", "8.0"),
    FindingSeverity.MEDIUM: ("warning", "5.5"),
    FindingSeverity.LOW: ("note", "3.0"),
    FindingSeverity.INFO: ("note", "1.0"),
}

_LAYER_NAMES: dict[Layer, str] = {
    Layer.L0_CONFIG: "Config Analysis",
    Layer.L1_SCHEMA: "Schema Analysis",
    Layer.L2_HEURISTIC: "Heuristic Checks",
    Layer.L3_STATIC: "Static Analysis",
    Layer.L4_Z3: "Z3 Verification",
    Layer.L5_COMPOSITIONAL: "Compositional Analysis",
    Layer.L6_FUZZING: "Fuzzing",
}

# CWE names for taxonomy taxa entries (common ones used by munio scan).
_CWE_NAMES: dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-74": "Improper Neutralization of Special Elements in Output",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-185": "Incorrect Regular Expression",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-284": "Improper Access Control",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-497": "Exposure of Sensitive System Information",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-1286": "Improper Validation of Syntactic Correctness of Input",
    "CWE-1188": "Initialization with an Insecure Default",
    "CWE-1287": "Improper Validation of Specified Type of Input",
    "CWE-1336": "Improper Neutralization of Special Elements in Template Engine",
    # L3_014-L3_019 CWEs
    "CWE-269": "Improper Privilege Management",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-862": "Missing Authorization",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-426": "Untrusted Search Path",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-1104": "Use of Unmaintained Third Party Components",
}


def scan_result_to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a SARIF 2.1.0 dict.

    Returns a dict that can be serialized with json.dumps().
    """
    from munio.scan import __version__

    findings = result.findings[:_MAX_RESULTS]

    rules, id_to_index = _make_rules(findings)
    results = [_make_result(f, id_to_index[f.id]) for f in findings]
    taxonomies = _make_taxonomies(findings)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "munio",
                "version": __version__,
                "informationUri": "https://munio.dev",
                "rules": rules,
            },
        },
        "results": results,
    }

    if taxonomies:
        run["taxonomies"] = taxonomies

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


# ── Helpers ───────────────────────────────────────────────────────────


def _severity_to_sarif(severity: FindingSeverity) -> tuple[str, str]:
    """Map FindingSeverity to (SARIF level, security-severity string)."""
    return _SEVERITY_MAP.get(severity, ("note", "1.0"))


def _confidence_to_precision(confidence: float) -> str:
    """Map confidence score to SARIF precision label."""
    if confidence >= 0.9:
        return "very-high"
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


def _fingerprint(finding: Finding) -> str:
    """Generate a stable fingerprint for deduplication across runs."""
    key = f"{finding.id}:{finding.tool_name}:{finding.message}"
    return hashlib.sha256(key.encode()).hexdigest()


def _make_rules(findings: list[Finding]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build rules list and id→index mapping from findings.

    Groups findings by finding.id. Each unique ID becomes one rule.
    Returns (rules_list, {finding_id: rule_index}).
    """
    id_to_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    # Track first finding per ID for description/metadata
    id_to_first: dict[str, Finding] = {}

    for f in findings:
        if f.id not in id_to_first:
            id_to_first[f.id] = f

    for finding_id, first in id_to_first.items():
        idx = len(rules)
        id_to_index[finding_id] = idx

        level, sec_sev = _severity_to_sarif(first.severity)
        layer_name = _LAYER_NAMES.get(first.layer, first.layer.name)

        rule: dict[str, Any] = {
            "id": finding_id,
            "shortDescription": {"text": f"{first.layer.name}: {finding_id}"},
            "defaultConfiguration": {"level": level},
            "properties": {
                "security-severity": sec_sev,
                "precision": _confidence_to_precision(first.confidence),
                "tags": ["security"],
            },
        }

        if first.description:
            rule["fullDescription"] = {"text": first.description}
        else:
            rule["fullDescription"] = {"text": f"{layer_name} check {finding_id}"}

        # Attack type tag
        if first.attack_type is not None:
            rule["properties"]["tags"].append(first.attack_type.name)

        # CWE relationship
        if first.cwe:
            rule["relationships"] = [
                {
                    "target": {
                        "id": first.cwe,
                        "guid": first.cwe,
                        "toolComponent": {"name": "CWE", "index": 0},
                    },
                    "kinds": ["superset"],
                }
            ]

        rules.append(rule)

    return rules, id_to_index


def _make_result(finding: Finding, rule_index: int) -> dict[str, Any]:
    """Build a single SARIF result from a Finding."""
    level, sec_sev = _severity_to_sarif(finding.severity)

    # Server name from the finding's tool context
    server_name = ""
    for part in (finding.location, finding.tool_name):
        if "@" in part:
            server_name = part.split("@")[-1]
            break

    fqn = f"{server_name}/{finding.tool_name}" if server_name else finding.tool_name

    result: dict[str, Any] = {
        "ruleId": finding.id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": finding.message},
        "locations": [
            {
                "logicalLocations": [
                    {
                        "kind": "module",
                        "fullyQualifiedName": fqn,
                    }
                ],
            }
        ],
        "partialFingerprints": {
            "proofScanFinding/v1": _fingerprint(finding),
        },
        "properties": {
            "security-severity": sec_sev,
        },
    }

    # L5 compositional findings: add codeFlows for source→sink visualization
    code_flows = _make_code_flows(finding)
    if code_flows is not None:
        result["codeFlows"] = code_flows

    return result


def _make_code_flows(finding: Finding) -> list[dict[str, Any]] | None:
    """Build codeFlows for L5 findings with source→sink location."""
    if finding.layer != Layer.L5_COMPOSITIONAL:
        return None

    m = _FLOW_RE.search(finding.location)
    if m is None:
        return None

    src_tool = m.group("src_tool")
    src_srv = m.group("src_srv")
    snk_tool = m.group("snk_tool")
    snk_srv = m.group("snk_srv")

    return [
        {
            "threadFlows": [
                {
                    "locations": [
                        {
                            "location": {
                                "message": {"text": f"Source: {src_tool} on {src_srv}"},
                                "logicalLocations": [
                                    {
                                        "kind": "module",
                                        "fullyQualifiedName": f"{src_srv}/{src_tool}",
                                    }
                                ],
                            },
                        },
                        {
                            "location": {
                                "message": {"text": f"Sink: {snk_tool} on {snk_srv}"},
                                "logicalLocations": [
                                    {
                                        "kind": "module",
                                        "fullyQualifiedName": f"{snk_srv}/{snk_tool}",
                                    }
                                ],
                            },
                        },
                    ],
                }
            ],
        }
    ]


def _make_taxonomies(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build CWE taxonomy if any finding has a CWE reference."""
    cwes: dict[str, str] = {}
    for f in findings:
        if f.cwe and f.cwe not in cwes:
            cwes[f.cwe] = _CWE_NAMES.get(f.cwe, f.cwe)

    if not cwes:
        return []

    taxa = [{"id": cwe_id, "name": name} for cwe_id, name in cwes.items()]

    return [
        {
            "name": "CWE",
            "version": "4.x",
            "informationUri": "https://cwe.mitre.org/data/published/cwe_latest.pdf",
            "taxa": taxa,
        }
    ]
