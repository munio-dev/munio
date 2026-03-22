"""Cross-category blind spot detection for YAML constraints.

Architecture rule: if an attack pattern is dangerous through ANY tool type,
it MUST exist in a universal constraint (action: "*"). Capability-scoped
constraints (actions: [list]) add depth but cannot be the sole defense.

Problem this prevents: exec tool running `curl http://10.0.0.1` bypasses
web-network-safety (only fires for web tools). Without the same SSRF check
in universal, the attack succeeds.

This test maintains an explicit contract of patterns/values that MUST be
in universal constraints. If someone adds a critical pattern to a capability
constraint but forgets universal, this test fails.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_CONSTRAINTS_DIR = Path(__file__).resolve().parent.parent / "constraints" / "generic"
_UNIVERSAL_DIR = _CONSTRAINTS_DIR / "universal"
_CAPABILITY_DIR = _CONSTRAINTS_DIR / "capability"


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _collect_universal_patterns() -> dict[str, list[str]]:
    """Return {constraint_name: [patterns]} for all universal regex_deny constraints."""
    result: dict[str, list[str]] = {}
    for f in _UNIVERSAL_DIR.glob("*.yaml"):
        data = _load_yaml(f)
        if data.get("check", {}).get("type") == "regex_deny":
            result[data["name"]] = data["check"].get("patterns", [])
    return result


def _collect_universal_values() -> dict[str, list[str]]:
    """Return {constraint_name: [values]} for all universal denylist constraints."""
    result: dict[str, list[str]] = {}
    for f in _UNIVERSAL_DIR.glob("*.yaml"):
        data = _load_yaml(f)
        if data.get("check", {}).get("type") == "denylist":
            result[data["name"]] = data["check"].get("values", [])
    return result


def _all_patterns_flat(patterns_by_name: dict[str, list[str]]) -> list[str]:
    return [p for ps in patterns_by_name.values() for p in ps]


def _all_values_flat(values_by_name: dict[str, list[str]]) -> list[str]:
    return [v.lower() for vs in values_by_name.values() for v in vs]


# ── Contracts ────────────────────────────────────────────────────────────
# Each entry = (pattern_or_value, description).
# If this list grows stale, that's a FEATURE — it forces explicit review
# of whether new patterns belong in universal.

_CRITICAL_SSRF_PATTERNS = [
    ("169\\.254\\.169\\.254", "AWS/Azure metadata endpoint"),
    ("metadata\\.google\\.internal", "GCP metadata endpoint"),
    ("://127\\.0\\.0\\.", "loopback via URL"),
    ("://0\\.0\\.0\\.0", "unspecified address via URL"),
    ("://10\\.\\d", "private 10.x via URL"),
    ("://192\\.168\\.", "private 192.168.x via URL"),
    ("file://", "file:// scheme"),
    ("gopher://", "gopher:// scheme"),
    ("\\bdata:", "data: URI scheme"),
    ("kubernetes\\.default", "Kubernetes service discovery"),
    ("@10\\.\\d", "private 10.x via connection string"),
    ("@127\\.", "loopback via connection string"),
    ("@localhost\\b", "localhost via connection string"),
]

_CRITICAL_CREDENTIAL_DIRS = [
    (".ssh/", "SSH credentials directory"),
    (".aws/", "AWS credentials directory"),
    (".gnupg/", "GnuPG credentials directory"),
    ("/etc/shadow", "shadow password file"),
    ("/proc/self/", "process information"),
    (".env", "environment file"),
    (".kube/config", "Kubernetes config"),
    (".docker/config.json", "Docker config"),
    (".git-credentials", "Git credentials"),
]

_CRITICAL_COMMAND_PATTERNS = [
    ("\\|\\s*(ba|z|da|k|fi)?sh\\b", "pipe to shell"),
    ("/dev/tcp/", "reverse shell via /dev/tcp"),
    ("\\bsudo\\s+", "privilege escalation via sudo"),
    ("\\brm\\s+-[a-zA-Z]*r[a-zA-Z]*f", "recursive forced delete (rm -rf)"),
    ("\\brm\\s+.*--no-preserve-root", "rm --no-preserve-root"),
]


class TestUniversalSsrfCoverage:
    """SSRF patterns that are dangerous through ANY tool must be in universal."""

    @pytest.fixture(autouse=True)
    def _load(self) -> None:
        self.patterns = _all_patterns_flat(_collect_universal_patterns())

    @pytest.mark.parametrize(
        ("pattern", "desc"),
        _CRITICAL_SSRF_PATTERNS,
        ids=[d for _, d in _CRITICAL_SSRF_PATTERNS],
    )
    def test_ssrf_pattern_in_universal(self, pattern: str, desc: str) -> None:
        assert pattern in self.patterns, (
            f"SSRF pattern for '{desc}' ({pattern}) is missing from universal "
            f"ssrf-deny. This creates a blind spot: tools not matching "
            f"web-network-safety actions bypass this check."
        )


class TestUniversalCredentialCoverage:
    """Credential paths dangerous through ANY tool must be in universal."""

    @pytest.fixture(autouse=True)
    def _load(self) -> None:
        self.values = _all_values_flat(_collect_universal_values())

    @pytest.mark.parametrize(
        ("value", "desc"),
        _CRITICAL_CREDENTIAL_DIRS,
        ids=[d for _, d in _CRITICAL_CREDENTIAL_DIRS],
    )
    def test_credential_path_in_universal(self, value: str, desc: str) -> None:
        assert value.lower() in self.values, (
            f"Credential path for '{desc}' ({value}) is missing from universal "
            f"credential-paths. This creates a blind spot: exec/code-eval tools "
            f"can access this path without triggering file-ops-safety."
        )


class TestUniversalDangerousCommandCoverage:
    """Shell patterns dangerous through ANY tool must be in universal."""

    @pytest.fixture(autouse=True)
    def _load(self) -> None:
        self.patterns = _all_patterns_flat(_collect_universal_patterns())

    @pytest.mark.parametrize(
        ("pattern", "desc"),
        _CRITICAL_COMMAND_PATTERNS,
        ids=[d for _, d in _CRITICAL_COMMAND_PATTERNS],
    )
    def test_command_pattern_in_universal(self, pattern: str, desc: str) -> None:
        assert pattern in self.patterns, (
            f"Dangerous command pattern for '{desc}' ({pattern}) is missing "
            f"from universal dangerous-commands. Any tool could pass this "
            f"pattern to a shell/interpreter."
        )


class TestCapabilityConstraintsHaveActions:
    """All capability constraints must use actions (not action: '*').

    A capability constraint with action: '*' is architecturally wrong —
    it applies to all tools but has category-specific checks, creating
    false positives on unrelated tools.
    """

    def test_no_wildcard_action_in_capability(self) -> None:
        violations: list[str] = []
        for f in _CAPABILITY_DIR.glob("*.yaml"):
            data = _load_yaml(f)
            if data.get("action") == "*":
                violations.append(f"{f.name}: uses action='*' instead of actions list")
            if not data.get("actions"):
                violations.append(f"{f.name}: missing 'actions' field")
        assert not violations, (
            "Capability constraints must use 'actions: [list]', not 'action: \"*\"':\n"
            + "\n".join(f"  {v}" for v in violations)
        )


class TestUniversalConstraintsUseWildcard:
    """All universal constraints must use action: '*'.

    A universal constraint with actions list is architecturally wrong —
    it should apply to ALL tools unconditionally.
    """

    def test_all_universal_use_wildcard_action(self) -> None:
        violations: list[str] = []
        for f in _UNIVERSAL_DIR.glob("*.yaml"):
            data = _load_yaml(f)
            if data.get("action") != "*":
                violations.append(f"{f.name}: does not use action='*'")
        assert not violations, "Universal constraints must use 'action: \"*\"':\n" + "\n".join(
            f"  {v}" for v in violations
        )
