"""Tests for munio.scan.__init__ lazy imports."""

from __future__ import annotations

import pytest

import munio.scan


class TestLazyImports:
    """Test lazy import mechanism."""

    @pytest.mark.parametrize(
        "attr_name",
        [
            "Finding",
            "FindingSeverity",
            "Layer",
            "OutputFormat",
            "ScanResult",
            "ServerConfig",
            "ToolDefinition",
            "ScanConfig",
        ],
    )
    def test_lazy_import_resolves(self, attr_name: str) -> None:
        """Lazy imports resolve to actual classes."""
        obj = getattr(munio.scan, attr_name)
        assert obj is not None

    def test_unknown_attribute_raises(self) -> None:
        """Unknown attributes raise AttributeError."""
        with pytest.raises(AttributeError, match="no attribute"):
            _ = munio.scan.NonExistentThing  # type: ignore[attr-defined]

    def test_version_is_string(self) -> None:
        """__version__ is a string."""
        assert isinstance(munio.scan.__version__, str)
        assert "0.1" in munio.scan.__version__
