"""L2.5 ML Classifier: neural network detection of prompt injection in tool definitions.

Uses a fine-tuned transformer model (DeBERTa-xsmall or E5-small) to classify
tool definition text as benign or malicious.  Complements L2 heuristic patterns
with learned features that generalise to novel attack patterns.

Checks:
    L2_5_001  ML classifier detected prompt injection / tool poisoning
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from munio.scan.models import (
    AttackType,
    Finding,
    FindingSeverity,
    Layer,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from munio.scan.models import ToolDefinition

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────

_DEFAULT_MODEL_NAME = "deberta-v1"
_DEFAULT_THRESHOLD_CRITICAL = 0.8
_DEFAULT_THRESHOLD_HIGH = 0.5
_MAX_TEXT_LENGTH = 2048  # truncate before tokenisation to prevent DoS
_MODEL_CACHE_DIR = Path.home() / ".munio" / "models"


# ── Helpers ──────────────────────────────────────────────────────────────


def _is_transformers_available() -> bool:
    """Return *True* if ``transformers`` **and** ``torch`` are importable."""
    try:
        import torch  # type: ignore[import-not-found]  # noqa: F401
        import transformers  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False
    return True


def _extract_classifier_text(tool: ToolDefinition) -> str:
    """Build a flat string from all textual fields of *tool*.

    The format **must** mirror the one used during training data preparation
    (``scripts/prepare_dataset.py``) so that the model sees the same input
    distribution at inference time.
    """
    parts: list[str] = [f"TOOL: {tool.name}"]

    if tool.title.strip():
        parts.append(f"TITLE: {tool.title}")

    if tool.description.strip():
        parts.append(f"DESCRIPTION: {tool.description}")

    schema = tool.input_schema
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue
            line = f"PARAM {param_name}"
            desc = param_def.get("description", "")
            if isinstance(desc, str) and desc.strip():
                line += f": {desc}"
            default = param_def.get("default")
            if default is not None:
                line += f" [default: {default}]"
            enum_vals = param_def.get("enum")
            if isinstance(enum_vals, list):
                line += f" [enum: {', '.join(str(v) for v in enum_vals)}]"
            parts.append(line)

    return "\n".join(parts)


# ── Backend ──────────────────────────────────────────────────────────────


class _ClassifierBackend:
    """Lazy-loaded transformer model wrapper.

    Encapsulates model loading, tokenisation, and inference.  Thread-safe
    after ``__init__`` (model is read-only, ``torch.no_grad``).
    """

    __slots__ = ("_device", "_model", "_tokenizer")

    def __init__(self, model_dir: Path) -> None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._device = torch.device("cpu")
        self._tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
        self._model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
        self._model.eval()
        self._model.to(self._device)

    def predict_batch(self, texts: list[str]) -> list[float]:
        """Return per-text malicious probability (0.0 = benign, 1.0 = malicious)."""
        import torch

        truncated = [t[:_MAX_TEXT_LENGTH] for t in texts]
        inputs = self._tokenizer(
            truncated,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )
        inputs = {k: v.to(self._device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self._model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)
            # column 1 = malicious class
            return probs[:, 1].tolist()  # type: ignore[no-any-return]


# ── Analyser ─────────────────────────────────────────────────────────────


class L25ClassifierAnalyzer:
    """L2.5 ML Classifier: learned prompt-injection detection.

    Graceful degradation: if ``transformers`` is not installed or the model
    weights are not found, the layer silently produces zero findings.  L2
    heuristic patterns still cover known attack signatures.
    """

    __slots__ = (
        "_backend",
        "_model_dir",
        "_ready",
        "_threshold_critical",
        "_threshold_high",
    )

    def __init__(
        self,
        model_dir: Path | None = None,
        threshold_critical: float = _DEFAULT_THRESHOLD_CRITICAL,
        threshold_high: float = _DEFAULT_THRESHOLD_HIGH,
    ) -> None:
        self._threshold_critical = threshold_critical
        self._threshold_high = threshold_high
        self._model_dir = model_dir or (_MODEL_CACHE_DIR / _DEFAULT_MODEL_NAME)
        self._backend: _ClassifierBackend | None = None
        self._ready = False

        if not _is_transformers_available():
            logger.info(
                "L2.5 classifier skipped: transformers not installed. "
                "Install with: pip install 'munio[ml]'"
            )
            return

        if not self._model_dir.exists():
            logger.info(
                "L2.5 classifier skipped: model not found at %s",
                self._model_dir,
            )
            return

        try:
            self._backend = _ClassifierBackend(self._model_dir)
            self._ready = True
            logger.debug("L2.5 classifier loaded from %s", self._model_dir)
        except Exception:
            logger.warning(
                "L2.5 classifier failed to load from %s, skipping",
                self._model_dir,
                exc_info=True,
            )

    @property
    def layer(self) -> Layer:
        return Layer.L2_CLASSIFIER

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]:
        """Run the ML classifier on all tool definitions."""
        if not self._ready or self._backend is None:
            return []

        findings: list[Finding] = []

        # Extract text for batch prediction
        tool_texts: list[tuple[ToolDefinition, str]] = []
        for tool in tools:
            try:
                text = _extract_classifier_text(tool)
                if text.strip():
                    tool_texts.append((tool, text))
            except Exception:  # noqa: PERF203 — fail-closed per tool
                logger.warning(
                    "L2.5 text extraction failed for tool '%s', skipping",
                    tool.name,
                )

        if not tool_texts:
            return findings

        # Batch inference
        try:
            texts = [t[1] for t in tool_texts]
            scores = self._backend.predict_batch(texts)
        except Exception:
            logger.warning("L2.5 classifier inference failed, skipping", exc_info=True)
            return findings

        for (tool, _text), score in zip(tool_texts, scores, strict=True):
            if score >= self._threshold_critical:
                findings.append(self._make_finding(tool.name, FindingSeverity.CRITICAL, score))
            elif score >= self._threshold_high:
                findings.append(self._make_finding(tool.name, FindingSeverity.HIGH, score))

        return findings

    @staticmethod
    def _make_finding(
        tool_name: str,
        severity: FindingSeverity,
        score: float,
    ) -> Finding:
        return Finding(
            id="L2_5_001",
            layer=Layer.L2_CLASSIFIER,
            severity=severity,
            tool_name=tool_name,
            message=(
                f"ML classifier detected potential prompt injection (confidence: {score:.0%})"
            ),
            attack_type=AttackType.PROMPT_INJECTION,
            cwe="CWE-74",
            confidence=round(score, 3),
        )
