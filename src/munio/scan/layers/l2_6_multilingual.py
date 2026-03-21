"""L2.6 Multilingual ML Classifier: char n-gram + hidden-state probe detection.

Two-tier cascade pipeline:
  Tier A: Lightweight sklearn char n-gram + structural features (<0.3ms, no PyTorch)
  Tier B: Frozen multilingual-e5-small hidden-state probe (~12ms, requires torch)

Tier B is optional: if transformers/torch are not installed or the probe model
is not found, the layer gracefully degrades to Tier A only.

Cascade logic: Tier A runs first.  If score is confident (>=0.8 or <0.2),
we skip Tier B.  Otherwise, Tier B runs and we take max(A, B).

Checks:
    L2_6_001  Multilingual classifier detected prompt injection / tool poisoning
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
from scipy.sparse import csr_matrix, hstack

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

_DEFAULT_MODEL_NAME = "multilingual-v1"
_DEFAULT_HIDDEN_MODEL_NAME = "e5-hidden-probe-v1"
_DEFAULT_THRESHOLD_CRITICAL = 0.8
_DEFAULT_THRESHOLD_HIGH = 0.5
_CASCADE_CONFIDENT_HIGH = 0.8  # Tier A score >= this → skip Tier B (confident malicious)
_CASCADE_CONFIDENT_LOW = 0.2  # Tier A score < this → skip Tier B (confident benign)
_MAX_TEXT_LENGTH = 2048
_MODEL_CACHE_DIR = Path.home() / ".munio" / "models"
_N_STRUCTURAL = 20

# ── Structural feature patterns (language-agnostic) ─────────────────────

_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:~/\.ssh/|/\.ssh/|~/\.aws/|\.env\b|/etc/passwd|/etc/shadow"
    r"|~/\.kube/|~/\.gnupg/|api_keys?\.json|id_rsa|id_ed25519)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]|%2[eE]%2[eE]")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_CMD_INJECTION_RE = re.compile(
    r"(?:\$\(|`[^`]*`|\|\s*(?:grep|awk|bash|sh|python|curl|wget|nc)\b"
    r"|;\s*(?:rm|cat|curl|wget|bash|sh|exec|eval)\b)",
    re.IGNORECASE,
)
_DIRECTIVE_RE = re.compile(
    r"(?:<IMPORTANT\b|</IMPORTANT>|\[SYSTEM\s+OVERRIDE|\[ADMIN\s+MODE"
    r"|\[INST\]|<\|im_start\|>|<system>|<<SYS>>|NOTE_TO_(?:ASSISTANT|AI|LLM))",
    re.IGNORECASE,
)
_IMPERATIVE_RE = re.compile(
    r"\b(?:you\s+must|you\s+should|you\s+have\s+to|you\s+need\s+to"
    r"|ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:previous|prior)"
    r"|your\s+(?:new\s+)?task\s+is"
    r"|do\s+not\s+(?:inform|tell|mention)\s+(?:the\s+)?user"
    r"|the\s+assistant\s+must)\b",
    re.IGNORECASE,
)
_EXFIL_WORDS_RE = re.compile(r"\b(?:exfil|steal|leak|dump|harvest|upload\s+to)\b", re.IGNORECASE)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{30,}={0,2}")


# ── Helpers ──────────────────────────────────────────────────────────────


def _count_scripts(text: str) -> int:
    """Count distinct Unicode script blocks in text."""
    scripts: set[str] = set()
    for c in text:
        cp = ord(c)
        if cp < 0x0080:
            scripts.add("latin")
        elif 0x0400 <= cp <= 0x04FF:
            scripts.add("cyrillic")
        elif 0x0370 <= cp <= 0x03FF:
            scripts.add("greek")
        elif 0x0600 <= cp <= 0x06FF:
            scripts.add("arabic")
        elif 0x0900 <= cp <= 0x097F:
            scripts.add("devanagari")
        elif 0x0E00 <= cp <= 0x0E7F:
            scripts.add("thai")
        elif 0x3040 <= cp <= 0x309F:
            scripts.add("hiragana")
        elif 0x30A0 <= cp <= 0x30FF:
            scripts.add("katakana")
        elif 0x4E00 <= cp <= 0x9FFF:
            scripts.add("cjk")
        elif 0xAC00 <= cp <= 0xD7AF:
            scripts.add("hangul")
        elif 0x10A0 <= cp <= 0x10FF:
            scripts.add("georgian")
        elif 0x0530 <= cp <= 0x058F:
            scripts.add("armenian")
        elif 0x0980 <= cp <= 0x09FF:
            scripts.add("bengali")
        elif 0x0A80 <= cp <= 0x0AFF:
            scripts.add("gujarati")
        elif 0x0B80 <= cp <= 0x0BFF:
            scripts.add("tamil")
        elif 0x0C80 <= cp <= 0x0CFF:
            scripts.add("kannada")
        elif 0x0D00 <= cp <= 0x0D7F:
            scripts.add("malayalam")
        elif 0x1000 <= cp <= 0x109F:
            scripts.add("myanmar")
        elif 0x1780 <= cp <= 0x17FF:
            scripts.add("khmer")
        elif 0x0D80 <= cp <= 0x0DFF:
            scripts.add("sinhala")
        elif 0x0A00 <= cp <= 0x0A7F:
            scripts.add("gurmukhi")
        elif cp > 0x007F:
            scripts.add("other")
    return len(scripts)


def _extract_structural_features(text: str) -> list[float]:
    """Extract language-agnostic structural features from text."""
    length = len(text)
    if length == 0:
        return [0.0] * _N_STRUCTURAL

    ascii_chars = sum(1 for c in text if ord(c) < 128)
    digits = sum(1 for c in text if c.isdigit())
    uppers = sum(1 for c in text if c.isupper())
    specials = sum(1 for c in text if not c.isalnum() and not c.isspace())
    lines = text.split("\n")

    return [
        min(length / 2000.0, 5.0),
        float(len(_URL_RE.findall(text))),
        float(len(_SENSITIVE_PATH_RE.findall(text))),
        float(len(_EMAIL_RE.findall(text))),
        float(len(_IP_RE.findall(text))),
        float(len(_CMD_INJECTION_RE.findall(text))),
        1.0 if _DIRECTIVE_RE.search(text) else 0.0,
        1.0 if _BASE64_RE.search(text) else 0.0,
        1.0 if _IMPERATIVE_RE.search(text) else 0.0,
        1.0 if _EXFIL_WORDS_RE.search(text) else 0.0,
        1.0 if _PATH_TRAVERSAL_RE.search(text) else 0.0,
        ascii_chars / length,
        digits / length,
        uppers / length,
        specials / length,
        float(_count_scripts(text)),
        float(len(lines)),
        sum(len(ln) for ln in lines) / max(len(lines), 1) / 200.0,
        float(text.count("TOOL:")),
        float(text.count("PARAM")),
    ]


def _extract_classifier_text(tool: ToolDefinition) -> str:
    """Build a flat string from all textual fields of a tool definition.

    Must mirror the format used during training data preparation.
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


class _MultilingualBackend:
    """Lazy-loaded sklearn model wrapper."""

    __slots__ = ("_model", "_vectorizer")

    def __init__(self, model_dir: Path) -> None:
        import joblib

        model_path = model_dir / "model.joblib"
        vectorizer_path = model_dir / "vectorizer.joblib"

        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not vectorizer_path.exists():
            raise FileNotFoundError(f"Vectorizer not found: {vectorizer_path}")

        self._model = joblib.load(model_path)
        self._vectorizer = joblib.load(vectorizer_path)

    def predict_batch(self, texts: list[str]) -> list[float]:
        """Return per-text malicious probability (0.0 = benign, 1.0 = malicious)."""
        truncated = [t[:_MAX_TEXT_LENGTH] for t in texts]

        # Char n-gram features
        char_features = self._vectorizer.transform(truncated)

        # Structural features
        struct_list = [_extract_structural_features(t) for t in truncated]
        struct_matrix = csr_matrix(np.array(struct_list, dtype=np.float64))

        # Combine
        X = hstack([char_features, struct_matrix], format="csr")  # noqa: N806 — ML convention

        # Predict
        probs = self._model.predict_proba(X)
        return probs[:, 1].tolist()  # column 1 = malicious


class _HiddenStateBackend:
    """Frozen multilingual-e5-small hidden-state probe (InstructDetector approach).

    Extracts intermediate hidden states from a frozen encoder and classifies
    with a lightweight linear probe.  Optional — requires torch + transformers.
    """

    __slots__ = ("_layers", "_model", "_probe", "_tokenizer")

    def __init__(self, model_dir: Path) -> None:
        import joblib
        import torch  # noqa: F401
        from transformers import AutoModel, AutoTokenizer

        probe_path = model_dir / "probe.joblib"
        meta_path = model_dir / "meta.json"
        if not probe_path.exists():
            raise FileNotFoundError(f"Hidden probe not found: {probe_path}")

        self._probe = joblib.load(probe_path)
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        self._layers: list[int] = meta.get("layers", [6, 12])

        model_name = meta.get("model", "intfloat/multilingual-e5-small")
        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModel.from_pretrained(model_name, output_hidden_states=True)
        self._model.eval()

    def predict_batch(self, texts: list[str]) -> list[float]:
        """Return per-text malicious probability using hidden-state probe."""
        import torch

        results: list[float] = []
        batch_size = 32

        for start in range(0, len(texts), batch_size):
            batch = texts[start : start + batch_size]
            prefixed = [f"query: {t[:1024]}" for t in batch]

            encoded = self._tokenizer(
                prefixed,
                padding=True,
                truncation=True,
                max_length=256,
                return_tensors="pt",
            )

            with torch.no_grad():
                outputs = self._model(**encoded, output_hidden_states=True)

            mask = encoded["attention_mask"].unsqueeze(-1).float()
            feats = []
            for layer_idx in self._layers:
                hidden = outputs.hidden_states[layer_idx]
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
                feats.append(pooled.numpy())

            X = np.hstack(feats)  # noqa: N806 — ML convention
            probas = self._probe.predict_proba(X)[:, 1]
            results.extend(probas.tolist())

        return results


# ── Analyzer ─────────────────────────────────────────────────────────────


class L26MultilingualAnalyzer:
    """L2.6 Multilingual ML Classifier with optional cascade.

    Tier A (always): sklearn char n-gram + structural features (<0.3ms, no PyTorch).
    Tier B (optional): frozen E5 hidden-state probe (~12ms, requires torch).

    Cascade: Tier A runs first.  If the score is confident (high or low),
    Tier B is skipped.  For uncertain scores, Tier B runs and we take
    max(A, B).  This keeps average latency ~2-3ms while improving recall.

    Graceful degradation: if sklearn/joblib is not installed or the model
    weights are not found, the layer silently produces zero findings.
    If torch/transformers are not installed, Tier B is simply skipped.
    """

    __slots__ = (
        "_backend",
        "_hidden_backend",
        "_hidden_model_dir",
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
        hidden_probe_model_dir: Path | None = None,
    ) -> None:
        self._threshold_critical = threshold_critical
        self._threshold_high = threshold_high
        self._model_dir = model_dir or (_MODEL_CACHE_DIR / _DEFAULT_MODEL_NAME)
        self._hidden_model_dir = hidden_probe_model_dir or (
            _MODEL_CACHE_DIR / _DEFAULT_HIDDEN_MODEL_NAME
        )
        self._backend: _MultilingualBackend | None = None
        self._hidden_backend: _HiddenStateBackend | None = None
        self._ready = False

        try:
            import joblib  # noqa: F401
        except ImportError:
            logger.info(
                "L2.6 multilingual classifier skipped: joblib not installed. "
                "Install with: pip install joblib"
            )
            return

        if not self._model_dir.exists():
            logger.info(
                "L2.6 multilingual classifier skipped: model not found at %s",
                self._model_dir,
            )
            return

        try:
            self._backend = _MultilingualBackend(self._model_dir)
            self._ready = True
            logger.debug("L2.6 Tier A (char n-gram) loaded from %s", self._model_dir)
        except Exception:
            logger.warning(
                "L2.6 multilingual classifier failed to load from %s, skipping",
                self._model_dir,
                exc_info=True,
            )
            return

        # Try loading Tier B (hidden-state probe) — optional
        hidden_dir = self._hidden_model_dir
        try:
            self._hidden_backend = _HiddenStateBackend(hidden_dir)
            logger.debug("L2.6 Tier B (hidden-state probe) loaded from %s", hidden_dir)
        except Exception:
            logger.debug("L2.6 Tier B (hidden-state probe) not available, using Tier A only")

    @property
    def layer(self) -> Layer:
        return Layer.L2_MULTILINGUAL

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]:
        """Run the multilingual classifier on all tool definitions."""
        if not self._ready or self._backend is None:
            return []

        findings: list[Finding] = []

        tool_texts: list[tuple[ToolDefinition, str]] = []
        for tool in tools:
            try:
                text = _extract_classifier_text(tool)
                if text.strip():
                    tool_texts.append((tool, text))
            except Exception:  # noqa: PERF203 — fail-closed per tool
                logger.warning(
                    "L2.6 text extraction failed for tool '%s', skipping",
                    tool.name,
                )

        if not tool_texts:
            return findings

        # Tier A: char n-gram + structural (all texts)
        try:
            texts = [t[1] for t in tool_texts]
            scores_a = self._backend.predict_batch(texts)
        except Exception:
            logger.warning("L2.6 Tier A inference failed, skipping", exc_info=True)
            return findings

        # Tier B cascade: only for uncertain Tier A scores
        final_scores = list(scores_a)
        if self._hidden_backend is not None:
            uncertain_indices = [
                i
                for i, s in enumerate(scores_a)
                if _CASCADE_CONFIDENT_LOW <= s < _CASCADE_CONFIDENT_HIGH
            ]
            if uncertain_indices:
                uncertain_texts = [texts[i] for i in uncertain_indices]
                try:
                    scores_b = self._hidden_backend.predict_batch(uncertain_texts)
                    for idx, score_b in zip(uncertain_indices, scores_b, strict=True):
                        final_scores[idx] = max(final_scores[idx], score_b)
                except Exception:
                    logger.warning("L2.6 Tier B inference failed, using Tier A only", exc_info=True)

        for (tool, _text), score in zip(tool_texts, final_scores, strict=True):
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
            id="L2_6_001",
            layer=Layer.L2_MULTILINGUAL,
            severity=severity,
            tool_name=tool_name,
            message=(
                f"Multilingual classifier detected potential prompt injection "
                f"(confidence: {score:.0%})"
            ),
            attack_type=AttackType.PROMPT_INJECTION,
            cwe="CWE-74",
            confidence=round(score, 3),
        )
