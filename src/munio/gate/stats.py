"""Offline JSONL log analyzer for munio gate interception records."""

from __future__ import annotations

import logging
import math
import statistics
from datetime import datetime  # noqa: TC003 — Pydantic needs at runtime
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from munio.gate.models import InterceptionRecord

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

__all__ = ["LogStats", "compute_stats", "parse_log"]

logger = logging.getLogger(__name__)

# Cap input to prevent OOM on adversarial log files.
_MAX_LINES = 1_000_000


class LogStats(BaseModel):
    """Aggregate statistics from parsed interception records."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total: int = 0
    allowed: int = 0
    blocked: int = 0
    errors: int = 0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    latency_max_ms: float = 0.0
    top_blocked_tools: list[tuple[str, int]] = []
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    parse_errors: int = 0


def compute_stats(
    records: Sequence[InterceptionRecord],
    *,
    top_n: int = 10,
) -> LogStats:
    """Compute aggregate statistics from parsed interception records."""
    if not records:
        return LogStats()

    allowed = 0
    blocked = 0
    errors = 0
    latencies: list[float] = []
    blocked_tools: dict[str, int] = {}
    timestamps: list[datetime] = []

    for rec in records:
        if rec.decision == "allowed":
            allowed += 1
        elif rec.decision == "blocked":
            blocked += 1
            blocked_tools[rec.tool] = blocked_tools.get(rec.tool, 0) + 1
        else:
            errors += 1
        # Skip NaN/Inf latencies — they corrupt percentile calculations.
        if math.isfinite(rec.elapsed_ms):
            latencies.append(rec.elapsed_ms)
        timestamps.append(rec.timestamp)

    timestamps.sort()

    # Latency percentiles
    p50 = p95 = p99 = lat_max = 0.0
    if latencies:
        latencies_sorted = sorted(latencies)
        lat_max = latencies_sorted[-1]
        if len(latencies_sorted) >= 2:
            quantiles = statistics.quantiles(latencies_sorted, n=100, method="inclusive")
            p50 = quantiles[49]  # 50th percentile
            p95 = quantiles[94]  # 95th percentile
            p99 = quantiles[98]  # 99th percentile
        else:
            p50 = p95 = p99 = latencies_sorted[0]

    # Top blocked tools (negative top_n treated as 0)
    top_blocked = sorted(blocked_tools.items(), key=lambda x: x[1], reverse=True)
    top_blocked = top_blocked[: max(top_n, 0)]

    return LogStats(
        total=len(records),
        allowed=allowed,
        blocked=blocked,
        errors=errors,
        latency_p50_ms=round(p50, 2),
        latency_p95_ms=round(p95, 2),
        latency_p99_ms=round(p99, 2),
        latency_max_ms=round(lat_max, 2),
        top_blocked_tools=top_blocked,
        first_timestamp=timestamps[0] if timestamps else None,
        last_timestamp=timestamps[-1] if timestamps else None,
    )


def parse_log(
    path: Path,
    *,
    max_lines: int = _MAX_LINES,
) -> tuple[list[InterceptionRecord], int]:
    """Parse a JSONL log file into InterceptionRecord list.

    Returns (records, parse_error_count).
    """
    records: list[InterceptionRecord] = []
    parse_errors = 0
    count = 0

    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            if count >= max_lines:
                break
            count += 1
            try:
                records.append(InterceptionRecord.model_validate_json(stripped))
            except Exception:
                parse_errors += 1
                logger.debug("Failed to parse log line %d", count)

    return records, parse_errors
