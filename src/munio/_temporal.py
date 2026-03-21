"""In-memory temporal state for rate limiting and sequence detection.

Provides TemporalStore protocol and InMemoryTemporalStore implementation.
Used by Tier1Solver for RATE_LIMIT and SEQUENCE_DENY constraint checks.

Thread-safety: InMemoryTemporalStore uses a single threading.Lock for all
operations. Critical sections are microseconds (deque append/popleft), so
a global lock is sufficient for typical workloads.

Clock: time.monotonic() only — immune to NTP drift and system clock changes.
"""

from __future__ import annotations

import fnmatch
import logging
import threading
import time
from collections import deque
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "InMemoryTemporalStore",
    "TemporalStore",
]

logger = logging.getLogger(__name__)

# Memory bounds
_MAX_ENTRIES_PER_KEY = 10_000
_MAX_KEYS = 100_000

# Keys that are never evicted by the key-limit enforcement.
# Without this, an attacker creating 100K unique agent_ids could evict
# the __global__ key, breaking global rate limits.
_PROTECTED_KEYS = frozenset({"__global__"})


@runtime_checkable
class TemporalStore(Protocol):
    """Protocol for temporal state backends (rate limiting + sequence detection).

    Implementations must be thread-safe. All methods use monotonic time.
    """

    def check_and_record_rate(
        self,
        key: str,
        window_seconds: float,
        max_count: int,
        now: float | None = None,
    ) -> bool:
        """Atomically check rate limit and record if allowed.

        Returns True if the call is allowed (count < max_count within window).
        Returns False if rate limit exceeded (call is NOT recorded).
        """
        ...

    def check_sequence(
        self,
        scope_key: str,
        tool: str,
        steps: list[str],
        window_seconds: float,
        now: float | None = None,
    ) -> bool:
        """Check if the current tool call completes a denied sequence.

        Returns True if allowed (no denied sequence detected).
        Returns False if the denied sequence is detected.
        Read-only: does NOT record the call (use record_call for that).
        """
        ...

    def record_call(
        self,
        scope_key: str,
        tool: str,
        now: float | None = None,
    ) -> None:
        """Record a tool call in the sequence history.

        Called unconditionally after all checks, regardless of outcome.
        This ensures sequence detection sees all calls (even denied ones).
        """
        ...


class InMemoryTemporalStore:
    """In-memory temporal store with bounded memory and thread safety.

    Data structures:
    - _rate_data: per-constraint-key deque of timestamps (for rate limiting)
    - _sequence_data: per-scope-key deque of (timestamp, tool) pairs (for sequences)

    Memory bounds:
    - _MAX_ENTRIES_PER_KEY entries per key (FIFO eviction)
    - _MAX_KEYS total keys per data dict (FIFO eviction, __global__ protected)
    """

    __slots__ = (
        "_lock",
        "_rate_data",
        "_rate_key_order",
        "_sequence_data",
        "_sequence_key_order",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rate_data: dict[str, deque[float]] = {}
        self._rate_key_order: deque[str] = deque()
        self._sequence_data: dict[str, deque[tuple[float, str]]] = {}
        self._sequence_key_order: deque[str] = deque()

    def check_and_record_rate(
        self,
        key: str,
        window_seconds: float,
        max_count: int,
        now: float | None = None,
    ) -> bool:
        """Atomically check rate limit and record if allowed.

        Denied calls are NOT recorded — prevents permanent blocking when
        attacker floods after exhausting the limit. The window naturally
        expires after window_seconds from the last ALLOWED call.
        """
        ts = now if now is not None else time.monotonic()
        cutoff = ts - window_seconds

        with self._lock:
            entries = self._rate_data.get(key)
            if entries is None:
                entries = deque()
                self._rate_data[key] = entries
                self._rate_key_order.append(key)
                self._enforce_key_limit(self._rate_data, self._rate_key_order)

            # Prune expired entries (strict <: boundary event is INCLUDED)
            while entries and entries[0] < cutoff:
                entries.popleft()

            # Check limit
            if len(entries) >= max_count:
                return False

            # Record and allow
            entries.append(ts)

            # Enforce per-key entry limit
            while len(entries) > _MAX_ENTRIES_PER_KEY:
                entries.popleft()

            return True

    def check_sequence(
        self,
        scope_key: str,
        tool: str,
        steps: list[str],
        window_seconds: float,
        now: float | None = None,
    ) -> bool:
        """Check if current tool completes a denied sequence.

        Returns True if allowed, False if denied sequence detected.
        Optimization: checks if current tool matches the LAST step first
        (most calls won't match, skipping the O(N) history scan).
        """
        if not steps:
            return True

        # Quick check: does current tool match the last step?
        if not fnmatch.fnmatchcase(tool, steps[-1]):
            return True

        # Single-step sequence: current tool IS the full sequence
        if len(steps) == 1:
            return False

        ts = now if now is not None else time.monotonic()
        cutoff = ts - window_seconds

        with self._lock:
            entries = self._sequence_data.get(scope_key)
            if entries is None:
                return True

            # Prune expired entries
            while entries and entries[0][0] < cutoff:
                entries.popleft()

            # Extract tool names from history
            history = [t for _, t in entries]

            # Check if steps[:-1] is a subsequence of history
            return not _matches_subsequence(history, steps[:-1])

    def record_call(
        self,
        scope_key: str,
        tool: str,
        now: float | None = None,
    ) -> None:
        """Record a tool call in sequence history."""
        ts = now if now is not None else time.monotonic()

        with self._lock:
            entries = self._sequence_data.get(scope_key)
            if entries is None:
                entries = deque()
                self._sequence_data[scope_key] = entries
                self._sequence_key_order.append(scope_key)
                self._enforce_key_limit(self._sequence_data, self._sequence_key_order)

            entries.append((ts, tool))

            # Enforce per-key entry limit
            while len(entries) > _MAX_ENTRIES_PER_KEY:
                entries.popleft()

    @staticmethod
    def _enforce_key_limit(
        data: dict[str, Any],
        key_order: deque[str],
    ) -> None:
        """Evict oldest non-protected keys when exceeding _MAX_KEYS."""
        while len(data) > _MAX_KEYS:
            if not key_order:
                break
            oldest = key_order.popleft()
            # Protected keys are never evicted
            if oldest in _PROTECTED_KEYS:
                key_order.append(oldest)
                # If all remaining keys are protected, stop
                if len(key_order) <= len(_PROTECTED_KEYS):
                    break
                continue
            data.pop(oldest, None)


def _matches_subsequence(history: list[str], steps: list[str]) -> bool:
    """Check if steps appear as a subsequence in history (relaxed matching).

    Uses fnmatch.fnmatchcase for each step (supports glob patterns like "read_*").
    Steps are matched in order — interleaved non-matching calls are allowed.
    """
    step_idx = 0
    for tool in history:
        if fnmatch.fnmatchcase(tool, steps[step_idx]):
            step_idx += 1
            if step_idx >= len(steps):
                return True
    return False
