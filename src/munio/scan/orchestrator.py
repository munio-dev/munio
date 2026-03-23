"""Async scan pipeline: orchestrate analysis layers on tool definitions."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

from munio.scan.config import ScanConfig
from munio.scan.layers.l1_schema import L1SchemaAnalyzer, schema_completeness_score
from munio.scan.layers.l2_heuristic import L2HeuristicAnalyzer
from munio.scan.layers.l3_static import L3StaticAnalyzer
from munio.scan.layers.l4_z3 import L4Z3Analyzer
from munio.scan.layers.l5_composition import L5CompositionAnalyzer

if TYPE_CHECKING:
    from collections.abc import Sequence

    from munio.scan.layers import AnalysisLayer
from munio.scan.models import (
    Finding,
    Layer,
    ScanResult,
    ServerScanResult,
    SkippedLayer,
    ToolDefinition,
)


class Orchestrator:
    """Async scan pipeline. Runs enabled analysis layers on tool definitions."""

    __slots__ = ("_config", "_layers", "_skipped")

    def __init__(self, config: ScanConfig | None = None) -> None:
        self._config = config or ScanConfig()
        self._layers: list[AnalysisLayer] = []
        self._skipped: list[SkippedLayer] = []

        if Layer.L1_SCHEMA in self._config.enabled_layers:
            self._layers.append(L1SchemaAnalyzer())
        if Layer.L2_HEURISTIC in self._config.enabled_layers:
            self._layers.append(L2HeuristicAnalyzer())
        if Layer.L2_CLASSIFIER in self._config.enabled_layers:
            try:
                from munio.scan.layers.l2_5_classifier import L25ClassifierAnalyzer

                self._layers.append(
                    L25ClassifierAnalyzer(
                        model_dir=self._config.classifier_model_dir,
                        threshold_high=self._config.classifier_threshold,
                    )
                )
            except ImportError:
                self._skipped.append(
                    SkippedLayer(
                        layer=Layer.L2_CLASSIFIER,
                        reason="transformers not installed",
                        install_hint="pip install 'munio[ml]'",
                    )
                )
        if Layer.L2_MULTILINGUAL in self._config.enabled_layers:
            try:
                from munio.scan.layers.l2_6_multilingual import L26MultilingualAnalyzer

                self._layers.append(
                    L26MultilingualAnalyzer(
                        model_dir=self._config.multilingual_model_dir,
                        threshold_high=self._config.multilingual_threshold,
                        hidden_probe_model_dir=self._config.hidden_probe_model_dir,
                    )
                )
            except ImportError:
                self._skipped.append(
                    SkippedLayer(
                        layer=Layer.L2_MULTILINGUAL,
                        reason="scikit-learn not installed",
                        install_hint="pip install 'munio[ml]'",
                    )
                )
        if Layer.L3_STATIC in self._config.enabled_layers:
            self._layers.append(L3StaticAnalyzer())
        if Layer.L4_Z3 in self._config.enabled_layers:
            z3_analyzer = L4Z3Analyzer()
            if z3_analyzer.available:
                self._layers.append(z3_analyzer)
            else:
                self._skipped.append(
                    SkippedLayer(
                        layer=Layer.L4_Z3,
                        reason="z3-solver not installed",
                        install_hint="pip install 'munio[z3]'",
                    )
                )
        if Layer.L5_COMPOSITIONAL in self._config.enabled_layers:
            self._layers.append(L5CompositionAnalyzer())
        if Layer.L7_SOURCE in self._config.enabled_layers:
            try:
                from munio.scan.layers.l7_source import L7SourceAnalyzer

                self._layers.append(L7SourceAnalyzer(source_dir=self._config.source_dir))
            except ImportError:
                self._skipped.append(
                    SkippedLayer(
                        layer=Layer.L7_SOURCE,
                        reason="tree-sitter not installed",
                        install_hint="pip install 'munio[source]'",
                    )
                )

    async def scan(
        self,
        server_results: Sequence[ServerScanResult],
    ) -> ScanResult:
        """Run all enabled layers on collected tools.

        Args:
            server_results: Results from server connections (tools already listed).

        Returns:
            Aggregate scan result with findings from all layers.
        """
        start = time.monotonic()
        all_tools: list[ToolDefinition] = []
        for sr in server_results:
            all_tools.extend(sr.tools)

        findings: list[Finding] = []

        # Phase 1: run all enabled layers
        for layer in self._layers:
            findings.extend(layer.analyze(all_tools))

        # Phase 2: cross-layer correlation (L3 schema + L7 source)
        from munio.scan.layers.correlation import correlate_findings

        findings = correlate_findings(findings)

        # Sort findings by severity (CRITICAL=0 first, INFO=4 last)
        findings.sort(key=lambda f: f.severity.value)

        # Compute schema completeness averages per server
        enriched_servers: list[ServerScanResult] = []
        for sr in server_results:
            if sr.tools:
                scores = [schema_completeness_score(t) for t in sr.tools]
                avg = round(sum(scores) / len(scores), 1)
            else:
                avg = 0.0
            enriched_servers.append(
                ServerScanResult(
                    server_name=sr.server_name,
                    source=sr.source,
                    tool_count=sr.tool_count,
                    tools=sr.tools,
                    connected=sr.connected,
                    error=sr.error,
                    schema_completeness_avg=avg,
                )
            )

        elapsed = (time.monotonic() - start) * 1000

        return ScanResult(
            scan_id=f"scan_{uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc),
            servers=enriched_servers,
            findings=findings,
            elapsed_ms=round(elapsed, 1),
            enabled_layers=self._config.enabled_layers,
            skipped_layers=tuple(self._skipped),
        )
