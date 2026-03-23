"""Analysis layers for munio scan."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from munio.scan.models import Finding, Layer, ToolDefinition


@runtime_checkable
class AnalysisLayer(Protocol):
    """Protocol for scan analysis layers."""

    @property
    def layer(self) -> Layer: ...

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]: ...
