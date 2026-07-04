"""Root conftest.py — Hypothesis profile registration + marker auto-skip."""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, settings

collect_ignore_glob = ["tests/red_team/*"]


def _z3_available() -> bool:
    try:
        import z3  # noqa: F401

        return True
    except ImportError:
        return False


_HAS_Z3 = _z3_available()


def _real_mcp_enabled(config: pytest.Config) -> bool:
    """Real-server tests run only on explicit request: env flag or -m real_mcp."""
    if os.environ.get("MUNIO_REAL_MCP_TESTS"):
        return True
    return "real_mcp" in (config.getoption("-m") or "")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-skip @pytest.mark.z3 without Z3, and @pytest.mark.real_mcp unless requested."""
    if not _HAS_Z3:
        skip_z3 = pytest.mark.skip(reason="Z3 solver not installed")
        for item in items:
            if "z3" in item.keywords:
                item.add_marker(skip_z3)

    if not _real_mcp_enabled(config):
        skip_real_mcp = pytest.mark.skip(
            reason="needs npx + network; set MUNIO_REAL_MCP_TESTS=1 or run with -m real_mcp"
        )
        for item in items:
            if "real_mcp" in item.keywords:
                item.add_marker(skip_real_mcp)


# CI profile (default): balance thoroughness with CI time budget
settings.register_profile(
    "ci",
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)

# Dev profile: fast iteration during local development
settings.register_profile(
    "dev",
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)

# Deep profile: thorough fuzzing for pre-release verification
settings.register_profile(
    "deep",
    max_examples=2000,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)

settings.load_profile("ci")
