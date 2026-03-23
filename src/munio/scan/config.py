"""munio scan configuration."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from munio.scan.models import Layer, OutputFormat


def _default_storage_dir() -> Path:
    """Return the default storage directory."""
    return Path.home() / ".munio"


class ScanConfig(BaseModel):
    """Configuration for a munio scan run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    output_format: OutputFormat = OutputFormat.TEXT
    enabled_layers: frozenset[Layer] = Field(
        default_factory=lambda: frozenset(
            {
                Layer.L1_SCHEMA,
                Layer.L2_HEURISTIC,
                Layer.L2_MULTILINGUAL,
                Layer.L3_STATIC,
                Layer.L4_Z3,
                Layer.L5_COMPOSITIONAL,
            }
        )
    )
    max_tools_per_server: int = Field(default=500, ge=1, le=10_000)
    storage_dir: Path = Field(default_factory=_default_storage_dir)
    classifier_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    classifier_model_dir: Path | None = None
    multilingual_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    multilingual_model_dir: Path | None = None
    hidden_probe_model_dir: Path | None = None
    source_dir: Path | None = None
