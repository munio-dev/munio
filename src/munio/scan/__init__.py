"""munio scan: MCP Security Scanner — 6-layer analysis for AI tool definitions."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

__version__ = "0.1.0"

if TYPE_CHECKING:
    from munio.scan.composition import CompositionAnalyzer
    from munio.scan.composition_report import (
        AttackChain,
        ChainNode,
        CompositionReport,
        CVEDraft,
        DangerGrade,
        DangerScore,
    )
    from munio.scan.config import ScanConfig
    from munio.scan.config_scanner import ConfigScanner
    from munio.scan.models import (
        AttackType,
        ConfigFileResult,
        ConfigPermissions,
        ConfigScanResult,
        DiscoveryError,
        Finding,
        FindingSeverity,
        Layer,
        MunioScanError,
        OutputFormat,
        ScanConnectionError,
        ScanResult,
        SchemaLoadError,
        ServerConfig,
        ServerScanResult,
        SkippedLayer,
        ToolDefinition,
    )
    from munio.scan.sarif import scan_result_to_sarif

__all__ = [
    "AttackChain",
    "AttackType",
    "CVEDraft",
    "ChainNode",
    "CompositionAnalyzer",
    "CompositionReport",
    "ConfigFileResult",
    "ConfigPermissions",
    "ConfigScanResult",
    "ConfigScanner",
    "DangerGrade",
    "DangerScore",
    "DiscoveryError",
    "Finding",
    "FindingSeverity",
    "Layer",
    "MunioScanError",
    "OutputFormat",
    "ScanConfig",
    "ScanConnectionError",
    "ScanResult",
    "SchemaLoadError",
    "ServerConfig",
    "ServerScanResult",
    "SkippedLayer",
    "ToolDefinition",
    "__version__",
    "scan_result_to_sarif",
]

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "AttackChain": ("munio.scan.composition_report", "AttackChain"),
    "AttackType": ("munio.scan.models", "AttackType"),
    "CVEDraft": ("munio.scan.composition_report", "CVEDraft"),
    "ChainNode": ("munio.scan.composition_report", "ChainNode"),
    "CompositionAnalyzer": ("munio.scan.composition", "CompositionAnalyzer"),
    "CompositionReport": ("munio.scan.composition_report", "CompositionReport"),
    "ConfigFileResult": ("munio.scan.models", "ConfigFileResult"),
    "ConfigPermissions": ("munio.scan.models", "ConfigPermissions"),
    "ConfigScanResult": ("munio.scan.models", "ConfigScanResult"),
    "ConfigScanner": ("munio.scan.config_scanner", "ConfigScanner"),
    "DangerGrade": ("munio.scan.composition_report", "DangerGrade"),
    "DangerScore": ("munio.scan.composition_report", "DangerScore"),
    "DiscoveryError": ("munio.scan.models", "DiscoveryError"),
    "Finding": ("munio.scan.models", "Finding"),
    "FindingSeverity": ("munio.scan.models", "FindingSeverity"),
    "Layer": ("munio.scan.models", "Layer"),
    "MunioScanError": ("munio.scan.models", "MunioScanError"),
    "OutputFormat": ("munio.scan.models", "OutputFormat"),
    "ScanConfig": ("munio.scan.config", "ScanConfig"),
    "ScanConnectionError": ("munio.scan.models", "ScanConnectionError"),
    "ScanResult": ("munio.scan.models", "ScanResult"),
    "SchemaLoadError": ("munio.scan.models", "SchemaLoadError"),
    "ServerConfig": ("munio.scan.models", "ServerConfig"),
    "ServerScanResult": ("munio.scan.models", "ServerScanResult"),
    "SkippedLayer": ("munio.scan.models", "SkippedLayer"),
    "ToolDefinition": ("munio.scan.models", "ToolDefinition"),
    "scan_result_to_sarif": ("munio.scan.sarif", "scan_result_to_sarif"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        module = importlib.import_module(module_path)
        value = getattr(module, attr_name)
        globals()[name] = value
        return value
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
