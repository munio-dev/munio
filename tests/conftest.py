"""Root conftest.py — Hypothesis profile registration + marker auto-skip."""

from __future__ import annotations

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


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Auto-skip tests marked with @pytest.mark.z3 when Z3 is not installed."""
    if _HAS_Z3:
        return
    skip_z3 = pytest.mark.skip(reason="Z3 solver not installed")
    for item in items:
        if "z3" in item.keywords:
            item.add_marker(skip_z3)


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
