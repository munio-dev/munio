"""Tests for munio._temporal — InMemoryTemporalStore and helpers."""

from __future__ import annotations

import ast
import concurrent.futures
import inspect
import threading
from collections import deque
from pathlib import Path
from unittest.mock import patch

import pytest

from munio._temporal import (
    _MAX_ENTRIES_PER_KEY,
    _MAX_KEYS,
    _PROTECTED_KEYS,
    InMemoryTemporalStore,
    TemporalStore,
    _matches_subsequence,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_TIME = 1_000_000.0


def _make_store() -> InMemoryTemporalStore:
    return InMemoryTemporalStore()


# ── TestCheckAndRecordRate ─────────────────────────────────────────────────


class TestCheckAndRecordRate:
    """Tests for InMemoryTemporalStore.check_and_record_rate."""

    @pytest.mark.parametrize(
        ("calls_before", "max_count", "expected", "desc"),
        [
            (0, 3, True, "first call under limit"),
            (1, 3, True, "second call under limit"),
            (2, 3, True, "third call at limit boundary allowed"),
            (3, 3, False, "fourth call denied at limit"),
            (5, 3, False, "well over limit denied"),
        ],
    )
    def test_rate_limit_basic(
        self, calls_before: int, max_count: int, expected: bool, desc: str
    ) -> None:
        """Rate limit allows calls under max_count and denies at/over."""
        store = _make_store()
        key = "test_key"
        window = 60.0
        for i in range(calls_before):
            store.check_and_record_rate(key, window, max_count, now=BASE_TIME + i)
        result = store.check_and_record_rate(key, window, max_count, now=BASE_TIME + calls_before)
        assert result is expected, desc

    def test_window_expiry(self) -> None:
        """Calls outside the window do not count toward the rate limit."""
        store = _make_store()
        key = "expire_key"
        window = 10.0
        max_count = 2

        # Two calls at t=0 and t=1
        assert store.check_and_record_rate(key, window, max_count, now=BASE_TIME)
        assert store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 1)

        # Third call at t=2 denied (within window)
        assert not store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 2)

        # After window expires (t=11), first call expired, room for new
        assert store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 11)

    def test_boundary_event_included(self) -> None:
        """Event at exactly the boundary is INCLUDED (strict < cutoff).

        If window=10 and now=110, cutoff=100.
        An event at t=100 satisfies 100 < 100 = False, so it is NOT pruned.
        This is fail-closed: boundary events count toward the limit.
        """
        store = _make_store()
        key = "boundary"
        window = 10.0
        max_count = 1

        # Record at t=100
        assert store.check_and_record_rate(key, window, max_count, now=100.0)

        # At t=110, cutoff=100. Event at 100 is NOT pruned (100 < 100 is False).
        assert not store.check_and_record_rate(key, window, max_count, now=110.0)

        # At t=110.001, cutoff=100.001. Event at 100 IS pruned (100 < 100.001).
        assert store.check_and_record_rate(key, window, max_count, now=110.001)

    def test_denied_call_not_recorded(self) -> None:
        """A denied call must NOT be recorded, so it does not pollute the window."""
        store = _make_store()
        key = "no_record"
        window = 60.0
        max_count = 2

        # Fill up
        store.check_and_record_rate(key, window, max_count, now=BASE_TIME)
        store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 1)

        # Denied many times — should not inflate the count
        for i in range(10):
            assert not store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 2 + i)

        # After the window of the first allowed call expires, we should be allowed again
        # because only 1 allowed call remains (the one at t+1)
        assert store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 61)

    @pytest.mark.parametrize(
        ("key_a", "key_b"),
        [
            ("agent:alice", "agent:bob"),
            ("tool:read", "tool:write"),
        ],
    )
    def test_keys_isolated(self, key_a: str, key_b: str) -> None:
        """Different keys have independent rate limits."""
        store = _make_store()
        window = 60.0
        max_count = 1

        assert store.check_and_record_rate(key_a, window, max_count, now=BASE_TIME)
        assert not store.check_and_record_rate(key_a, window, max_count, now=BASE_TIME + 1)

        # key_b is still available
        assert store.check_and_record_rate(key_b, window, max_count, now=BASE_TIME + 2)

    def test_now_parameter_injection(self) -> None:
        """The now parameter overrides time.monotonic() for deterministic testing."""
        store = _make_store()
        key = "inject"
        window = 10.0
        max_count = 1

        # Use a specific timestamp
        assert store.check_and_record_rate(key, window, max_count, now=42.0)
        assert not store.check_and_record_rate(key, window, max_count, now=43.0)
        # Window expired
        assert store.check_and_record_rate(key, window, max_count, now=53.0)

    def test_per_key_entry_limit(self) -> None:
        """When entries exceed _MAX_ENTRIES_PER_KEY, oldest are pruned via FIFO."""
        store = _make_store()
        key = "overflow"
        window = float("inf")  # Never expire so we test FIFO eviction only
        max_count = _MAX_ENTRIES_PER_KEY + 100  # High enough to never block

        # Fill beyond limit
        for i in range(_MAX_ENTRIES_PER_KEY + 50):
            store.check_and_record_rate(key, window, max_count, now=BASE_TIME + i)

        # Internal deque should be capped
        entries = store._rate_data[key]
        assert len(entries) == _MAX_ENTRIES_PER_KEY

        # Oldest entry should be the 51st one (0-49 were evicted)
        assert entries[0] == BASE_TIME + 50

    def test_key_eviction_protects_global(self) -> None:
        """At _MAX_KEYS limit, __global__ key is never evicted."""
        store = _make_store()
        window = 60.0
        max_count = 100

        # Register __global__ key first
        store.check_and_record_rate("__global__", window, max_count, now=BASE_TIME)

        # Fill up to _MAX_KEYS with unique keys
        for i in range(_MAX_KEYS):
            store.check_and_record_rate(f"agent:{i}", window, max_count, now=BASE_TIME + i)

        # __global__ should still be present
        assert "__global__" in store._rate_data

    def test_max_count_one(self) -> None:
        """Rate limit of 1 allows exactly one call, then denies."""
        store = _make_store()
        assert store.check_and_record_rate("k", 60.0, 1, now=BASE_TIME)
        assert not store.check_and_record_rate("k", 60.0, 1, now=BASE_TIME + 1)

    def test_max_count_zero_always_denies(self) -> None:
        """Rate limit of 0 denies every call (0 >= 0 is True)."""
        store = _make_store()
        assert not store.check_and_record_rate("k", 60.0, 0, now=BASE_TIME)
        assert not store.check_and_record_rate("k", 60.0, 0, now=BASE_TIME + 1)

    def test_window_zero(self) -> None:
        """Window of 0 means only events at exactly `now` count."""
        store = _make_store()
        # First call allowed
        assert store.check_and_record_rate("k", 0.0, 1, now=100.0)
        # Immediately after: cutoff = now - 0 = now. Event at 100.0 < 100.0 is False
        # so the event is included, count = 1 >= 1 => denied
        assert not store.check_and_record_rate("k", 0.0, 1, now=100.0)
        # Any later time: cutoff = 100.001, event at 100.0 < 100.001 => pruned
        assert store.check_and_record_rate("k", 0.0, 1, now=100.001)


# ── TestCheckSequence ──────────────────────────────────────────────────────


class TestCheckSequence:
    """Tests for InMemoryTemporalStore.check_sequence."""

    def test_two_step_match(self) -> None:
        """Detects a 2-step denied sequence: read_file -> http_request."""
        store = _make_store()
        scope = "agent:alice"
        steps = ["read_file", "http_request"]
        window = 60.0

        store.record_call(scope, "read_file", now=BASE_TIME)
        # Current tool is http_request — completes the sequence
        assert not store.check_sequence(scope, "http_request", steps, window, now=BASE_TIME + 1)

    def test_three_step_match_with_interleaving(self) -> None:
        """Detects a 3-step sequence with benign calls interleaved."""
        store = _make_store()
        scope = "agent:bob"
        steps = ["read_file", "encode_data", "http_request"]
        window = 60.0

        store.record_call(scope, "read_file", now=BASE_TIME)
        store.record_call(scope, "list_files", now=BASE_TIME + 1)  # benign
        store.record_call(scope, "encode_data", now=BASE_TIME + 2)
        store.record_call(scope, "log_info", now=BASE_TIME + 3)  # benign

        # http_request completes the 3-step sequence
        assert not store.check_sequence(scope, "http_request", steps, window, now=BASE_TIME + 4)

    def test_wrong_order_three_step_no_match(self) -> None:
        """3-step sequence in wrong order does not match."""
        store = _make_store()
        scope = "agent:delta"
        steps = ["step_a", "step_b", "step_c"]
        window = 60.0

        # Record: step_b then step_a (reversed first two steps)
        store.record_call(scope, "step_b", now=BASE_TIME)
        store.record_call(scope, "step_a", now=BASE_TIME + 1)

        # step_c as current — steps[:-1] = [step_a, step_b]
        # History: [step_b, step_a]. Is [step_a, step_b] a subsequence?
        # step_a matches at index 1, then step_b must come AFTER index 1. No such.
        assert store.check_sequence(scope, "step_c", steps, window, now=BASE_TIME + 2)

    def test_outside_window_expired(self) -> None:
        """Calls outside the window are expired and do not count."""
        store = _make_store()
        scope = "agent:eve"
        steps = ["read_file", "http_request"]
        window = 10.0

        store.record_call(scope, "read_file", now=BASE_TIME)

        # After window expires
        assert store.check_sequence(scope, "http_request", steps, window, now=BASE_TIME + 20)

    def test_last_step_optimization_non_matching(self) -> None:
        """If current tool does not match the last step, return True immediately."""
        store = _make_store()
        scope = "agent:frank"
        steps = ["read_file", "http_request"]
        window = 60.0

        store.record_call(scope, "read_file", now=BASE_TIME)

        # Current tool is "list_files" — does not match last step "http_request"
        assert store.check_sequence(scope, "list_files", steps, window, now=BASE_TIME + 1)

    @pytest.mark.parametrize(
        ("step_pattern", "tool_name", "expected_match", "desc"),
        [
            ("read_*", "read_file", False, "wildcard matches read_file"),
            ("read_*", "read_db", False, "wildcard matches read_db"),
            ("read_*", "write_file", True, "wildcard does not match write_file"),
            ("*_request", "http_request", False, "suffix wildcard matches"),
            ("*_request", "http_response", True, "suffix wildcard does not match"),
        ],
    )
    def test_wildcard_patterns(
        self,
        step_pattern: str,
        tool_name: str,
        expected_match: bool,
        desc: str,
    ) -> None:
        """Steps support fnmatch glob patterns."""
        store = _make_store()
        scope = "agent:glob"
        # Single-step sequence: just the pattern
        steps = [step_pattern]
        window = 60.0

        result = store.check_sequence(scope, tool_name, steps, window, now=BASE_TIME)
        assert result is expected_match, desc

    def test_wildcard_in_multi_step(self) -> None:
        """Wildcard patterns work in multi-step sequences."""
        store = _make_store()
        scope = "agent:multi_glob"
        steps = ["read_*", "http_*"]
        window = 60.0

        store.record_call(scope, "read_config", now=BASE_TIME)
        assert not store.check_sequence(scope, "http_post", steps, window, now=BASE_TIME + 1)

    def test_self_loop_detection(self) -> None:
        """Detects repeated self-loop pattern [A, A, A]."""
        store = _make_store()
        scope = "agent:loop"
        steps = ["tool_a", "tool_a", "tool_a"]
        window = 60.0

        store.record_call(scope, "tool_a", now=BASE_TIME)
        store.record_call(scope, "tool_a", now=BASE_TIME + 1)

        # Third tool_a completes the 3-step self-loop
        assert not store.check_sequence(scope, "tool_a", steps, window, now=BASE_TIME + 2)

    def test_single_entry_history_two_step_no_match(self) -> None:
        """Single-entry history cannot satisfy a 2-step sequence."""
        store = _make_store()
        scope = "agent:short"
        steps = ["step_a", "step_b", "step_c"]
        window = 60.0

        store.record_call(scope, "step_a", now=BASE_TIME)

        # steps[:-1] = [step_a, step_b] — needs 2 matches in history of 1
        assert store.check_sequence(scope, "step_c", steps, window, now=BASE_TIME + 1)

    def test_empty_history_no_match(self) -> None:
        """Empty history cannot match any multi-step sequence."""
        store = _make_store()
        scope = "agent:empty"
        steps = ["read_file", "http_request"]
        window = 60.0

        # No record_call — empty history
        assert store.check_sequence(scope, "http_request", steps, window, now=BASE_TIME)

    def test_empty_steps_always_allowed(self) -> None:
        """Empty steps list means no sequence to deny, always allowed."""
        store = _make_store()
        store.record_call("scope", "any_tool", now=BASE_TIME)
        assert store.check_sequence("scope", "any_tool", [], 60.0, now=BASE_TIME + 1)

    def test_single_step_sequence(self) -> None:
        """Single-step sequence: current tool IS the full sequence, always denied."""
        store = _make_store()
        steps = ["dangerous_tool"]
        assert not store.check_sequence("scope", "dangerous_tool", steps, 60.0, now=BASE_TIME)

    def test_single_step_no_match(self) -> None:
        """Single-step sequence: non-matching tool is allowed."""
        store = _make_store()
        steps = ["dangerous_tool"]
        assert store.check_sequence("scope", "safe_tool", steps, 60.0, now=BASE_TIME)

    def test_different_scopes_isolated(self) -> None:
        """Sequence detection is scoped — different scope_keys do not interfere."""
        store = _make_store()
        steps = ["step_a", "step_b"]
        window = 60.0

        store.record_call("scope_1", "step_a", now=BASE_TIME)

        # step_b under scope_2 should not see scope_1's history
        assert store.check_sequence("scope_2", "step_b", steps, window, now=BASE_TIME + 1)

    def test_boundary_expiry_in_sequence(self) -> None:
        """Boundary event in sequence data: strict < cutoff (event at boundary NOT pruned)."""
        store = _make_store()
        scope = "boundary_seq"
        steps = ["step_a", "step_b"]
        window = 10.0

        store.record_call(scope, "step_a", now=100.0)

        # At now=110, cutoff=100. Event at 100.0 < 100.0 is False — NOT pruned.
        assert not store.check_sequence(scope, "step_b", steps, window, now=110.0)

        # At now=110.001, cutoff=100.001. Event at 100.0 IS pruned.
        assert store.check_sequence(scope, "step_b", steps, window, now=110.001)


# ── TestRecordCall ─────────────────────────────────────────────────────────


class TestRecordCall:
    """Tests for InMemoryTemporalStore.record_call."""

    def test_basic_recording_and_retrieval(self) -> None:
        """Recorded calls can be detected by check_sequence."""
        store = _make_store()
        scope = "agent:test"
        steps = ["step_a", "step_b"]
        window = 60.0

        store.record_call(scope, "step_a", now=BASE_TIME)

        # Without recording step_b, check_sequence should detect partial match
        assert not store.check_sequence(scope, "step_b", steps, window, now=BASE_TIME + 1)

    def test_per_key_entry_limit(self) -> None:
        """Entries exceeding _MAX_ENTRIES_PER_KEY are pruned (oldest first)."""
        store = _make_store()
        scope = "overflow"

        for i in range(_MAX_ENTRIES_PER_KEY + 100):
            store.record_call(scope, f"tool_{i}", now=BASE_TIME + i)

        entries = store._sequence_data[scope]
        assert len(entries) == _MAX_ENTRIES_PER_KEY

        # Oldest entry should be tool_100 (0-99 evicted)
        assert entries[0] == (BASE_TIME + 100, "tool_100")

    def test_scope_keys_isolated(self) -> None:
        """Different scope_keys maintain independent histories."""
        store = _make_store()
        store.record_call("scope_a", "tool_x", now=BASE_TIME)
        store.record_call("scope_b", "tool_y", now=BASE_TIME + 1)

        # scope_a only has tool_x
        entries_a = store._sequence_data["scope_a"]
        assert len(entries_a) == 1
        assert entries_a[0] == (BASE_TIME, "tool_x")

        # scope_b only has tool_y
        entries_b = store._sequence_data["scope_b"]
        assert len(entries_b) == 1
        assert entries_b[0] == (BASE_TIME + 1, "tool_y")

    def test_record_uses_monotonic_by_default(self) -> None:
        """When now=None, record_call uses time.monotonic()."""
        store = _make_store()
        with patch("munio._temporal.time.monotonic", return_value=999.0):
            store.record_call("scope", "tool", now=None)

        entries = store._sequence_data["scope"]
        assert entries[0][0] == 999.0

    def test_multiple_records_same_scope(self) -> None:
        """Multiple record_call invocations for the same scope build up history."""
        store = _make_store()
        scope = "accumulate"
        for i in range(5):
            store.record_call(scope, f"tool_{i}", now=BASE_TIME + i)

        entries = store._sequence_data[scope]
        assert len(entries) == 5
        assert [t for _, t in entries] == [f"tool_{i}" for i in range(5)]


# ── TestMatchesSubsequence ─────────────────────────────────────────────────


class TestMatchesSubsequence:
    """Tests for _matches_subsequence helper function."""

    @pytest.mark.parametrize(
        ("history", "steps", "expected", "desc"),
        [
            # Exact match
            (["a", "b", "c"], ["a", "b", "c"], True, "exact match"),
            # Subsequence with interleaving
            (["a", "x", "b", "y", "c"], ["a", "b", "c"], True, "interleaved"),
            # No match — wrong order
            (["c", "b", "a"], ["a", "b", "c"], False, "reversed order"),
            # No match — missing step
            (["a", "c"], ["a", "b", "c"], False, "missing middle step"),
            # Single step
            (["a", "b", "c"], ["b"], True, "single step present"),
            # Single step absent
            (["a", "b", "c"], ["d"], False, "single step absent"),
            # Empty history
            ([], ["a"], False, "empty history"),
            # Steps longer than history
            (["a"], ["a", "b"], False, "steps longer than history"),
            # Repeated elements
            (["a", "a", "a"], ["a", "a"], True, "repeated elements"),
            # Partial overlap
            (["a", "b"], ["a", "b", "c"], False, "partial overlap insufficient"),
        ],
    )
    def test_matches_subsequence(
        self,
        history: list[str],
        steps: list[str],
        expected: bool,
        desc: str,
    ) -> None:
        """Test subsequence matching with various inputs."""
        assert _matches_subsequence(history, steps) is expected, desc

    def test_fnmatch_wildcards(self) -> None:
        """_matches_subsequence uses fnmatch for glob-style matching."""
        history = ["read_file", "encode_data", "http_post"]
        steps = ["read_*", "http_*"]
        assert _matches_subsequence(history, steps) is True

    def test_fnmatch_no_wildcard_match(self) -> None:
        """Non-matching wildcard patterns return False."""
        history = ["write_file", "db_query"]
        steps = ["read_*"]
        assert _matches_subsequence(history, steps) is False

    @pytest.mark.parametrize(
        ("history", "steps", "expected", "desc"),
        [
            (["read_config", "read_secret"], ["read_*", "read_*"], True, "double wildcard match"),
            (
                ["read_config"],
                ["read_*", "read_*"],
                False,
                "not enough matches for double wildcard",
            ),
            (["a_1", "b_2", "a_3"], ["a_*", "a_*"], True, "wildcard with interleaving"),
        ],
    )
    def test_wildcards_parametrized(
        self,
        history: list[str],
        steps: list[str],
        expected: bool,
        desc: str,
    ) -> None:
        """Parametrized wildcard subsequence tests."""
        assert _matches_subsequence(history, steps) is expected, desc


# ── TestKeyEviction ────────────────────────────────────────────────────────


class TestKeyEviction:
    """Tests for key eviction logic (_enforce_key_limit)."""

    def test_rate_data_fifo_eviction(self) -> None:
        """Rate data keys are evicted in FIFO order when exceeding _MAX_KEYS."""
        store = _make_store()
        window = 60.0
        max_count = 100

        # Insert _MAX_KEYS + 10 keys
        for i in range(_MAX_KEYS + 10):
            store.check_and_record_rate(f"key_{i}", window, max_count, now=BASE_TIME)

        assert len(store._rate_data) <= _MAX_KEYS

        # First keys should have been evicted
        assert "key_0" not in store._rate_data
        assert "key_9" not in store._rate_data

        # Later keys should remain
        assert f"key_{_MAX_KEYS + 9}" in store._rate_data

    def test_sequence_data_fifo_eviction(self) -> None:
        """Sequence data keys are evicted in FIFO order when exceeding _MAX_KEYS."""
        store = _make_store()

        for i in range(_MAX_KEYS + 10):
            store.record_call(f"scope_{i}", "tool", now=BASE_TIME)

        assert len(store._sequence_data) <= _MAX_KEYS

        # First keys should have been evicted
        assert "scope_0" not in store._sequence_data
        assert "scope_9" not in store._sequence_data

    def test_global_protected_rate_eviction(self) -> None:
        """__global__ is never evicted from rate data even under pressure."""
        store = _make_store()
        window = 60.0
        max_count = 100

        # Seed __global__ first
        store.check_and_record_rate("__global__", window, max_count, now=BASE_TIME)

        # Fill up well beyond _MAX_KEYS
        for i in range(_MAX_KEYS + 50):
            store.check_and_record_rate(f"attacker_{i}", window, max_count, now=BASE_TIME + i)

        assert "__global__" in store._rate_data

    def test_global_protected_sequence_eviction(self) -> None:
        """__global__ is never evicted from sequence data."""
        store = _make_store()

        # Seed __global__
        store.record_call("__global__", "tool", now=BASE_TIME)

        # Fill beyond _MAX_KEYS
        for i in range(_MAX_KEYS + 50):
            store.record_call(f"attacker_{i}", "tool", now=BASE_TIME + i)

        assert "__global__" in store._sequence_data

    def test_enforce_key_limit_all_protected(self) -> None:
        """When all remaining keys are protected, eviction stops (no infinite loop).

        Uses _enforce_key_limit directly with a patched _MAX_KEYS to test
        the edge case where all keys in the order deque are protected.
        """
        data: dict[str, deque[float]] = {
            "__global__": deque([1.0]),
            "extra": deque([2.0]),
        }
        key_order: deque[str] = deque(["__global__", "extra"])

        # Patch _MAX_KEYS to 1 so the while condition fires
        with patch("munio._temporal._MAX_KEYS", 1):
            InMemoryTemporalStore._enforce_key_limit(data, key_order)

        # __global__ is protected, "extra" should be evicted
        assert "__global__" in data
        assert "extra" not in data

    def test_enforce_key_limit_only_protected_remaining(self) -> None:
        """When ONLY protected keys remain, eviction terminates without infinite loop."""
        data: dict[str, deque[float]] = {
            "__global__": deque([1.0]),
        }
        key_order: deque[str] = deque(["__global__"])

        # Even though len(data) > 0 (patched limit), loop terminates
        # because all keys are protected
        with patch("munio._temporal._MAX_KEYS", 0):
            InMemoryTemporalStore._enforce_key_limit(data, key_order)

        assert "__global__" in data

    def test_protected_keys_constant(self) -> None:
        """_PROTECTED_KEYS contains only __global__."""
        assert frozenset({"__global__"}) == _PROTECTED_KEYS

    def test_mixed_protected_and_normal_eviction(self) -> None:
        """Protected keys survive while normal keys are evicted in FIFO order."""
        store = _make_store()
        window = 60.0
        max_count = 100

        # Insert in order: key_0, __global__, key_1, ..., key_N
        store.check_and_record_rate("key_0", window, max_count, now=BASE_TIME)
        store.check_and_record_rate("__global__", window, max_count, now=BASE_TIME + 1)

        for i in range(1, _MAX_KEYS + 10):
            store.check_and_record_rate(f"key_{i}", window, max_count, now=BASE_TIME + i + 1)

        assert "__global__" in store._rate_data
        assert "key_0" not in store._rate_data  # FIFO: oldest normal key evicted


# ── TestProtocol ───────────────────────────────────────────────────────────


class TestProtocol:
    """Tests for TemporalStore protocol compliance."""

    def test_isinstance_check(self) -> None:
        """InMemoryTemporalStore satisfies the runtime_checkable TemporalStore protocol."""
        store = InMemoryTemporalStore()
        assert isinstance(store, TemporalStore)

    def test_protocol_is_runtime_checkable(self) -> None:
        """TemporalStore is decorated with @runtime_checkable."""
        assert hasattr(TemporalStore, "__protocol_attrs__") or hasattr(
            TemporalStore, "_is_runtime_protocol"
        )
        # The concrete check: isinstance works
        assert isinstance(InMemoryTemporalStore(), TemporalStore)

    def test_protocol_methods_exist(self) -> None:
        """InMemoryTemporalStore has all protocol methods with correct signatures."""
        store = InMemoryTemporalStore()
        assert callable(getattr(store, "check_and_record_rate", None))
        assert callable(getattr(store, "check_sequence", None))
        assert callable(getattr(store, "record_call", None))


# ── TestASTInvariant ───────────────────────────────────────────────────────


class TestASTInvariant:
    """AST-level invariant checks for _temporal.py."""

    def test_no_time_time_calls(self) -> None:
        """_temporal.py must only use time.monotonic(), never time.time().

        time.time() is vulnerable to NTP drift and system clock changes,
        which can cause security issues in rate limiting and sequence detection.
        """
        source_path = Path(inspect.getfile(InMemoryTemporalStore))
        source = source_path.read_text()
        tree = ast.parse(source)

        # Find ast.Call nodes where func is time.time (attribute "time" on module "time").
        # time.monotonic has attr "monotonic", so only time.time triggers this.
        calls_to_time_time = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "time"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "time"
        ]

        assert calls_to_time_time == [], (
            f"time.time() calls found at lines {calls_to_time_time}. Use time.monotonic() instead."
        )

    def test_no_sleep_calls(self) -> None:
        """_temporal.py must not use time.sleep() (would block under lock)."""
        source_path = Path(inspect.getfile(InMemoryTemporalStore))
        source = source_path.read_text()
        tree = ast.parse(source)

        sleep_calls: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "sleep"
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "time"
                ):
                    sleep_calls.append(node.lineno)

        assert sleep_calls == [], (
            f"time.sleep() calls found at lines {sleep_calls}. "
            "Never sleep inside lock-protected temporal operations."
        )


# ── TestConcurrency ────────────────────────────────────────────────────────


class TestConcurrency:
    """Thread safety tests for InMemoryTemporalStore."""

    def test_concurrent_rate_limiting(self) -> None:
        """Multiple threads calling check_and_record_rate see correct total count.

        With max_count=50 and 100 threads each making 1 call, exactly 50
        should be allowed and 50 denied.
        """
        store = _make_store()
        key = "concurrent"
        window = 600.0
        max_count = 50
        num_threads = 100
        results: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            result = store.check_and_record_rate(key, window, max_count)
            with lock:
                results.append(result)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(worker) for _ in range(num_threads)]
            concurrent.futures.wait(futures)
            # Raise any exceptions
            for f in futures:
                f.result()

        allowed = sum(1 for r in results if r)
        denied = sum(1 for r in results if not r)

        assert allowed == max_count
        assert denied == num_threads - max_count
        assert len(results) == num_threads

    def test_concurrent_record_call(self) -> None:
        """Multiple threads recording calls — all calls are persisted."""
        store = _make_store()
        scope = "concurrent_seq"
        num_threads = 100

        def worker(i: int) -> None:
            store.record_call(scope, f"tool_{i}", now=BASE_TIME + i)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(worker, i) for i in range(num_threads)]
            concurrent.futures.wait(futures)
            for f in futures:
                f.result()

        entries = store._sequence_data[scope]
        assert len(entries) == num_threads

    def test_concurrent_mixed_operations(self) -> None:
        """Mixed rate-check and record_call operations do not deadlock or corrupt."""
        store = _make_store()
        barrier = threading.Barrier(20)
        errors: list[Exception] = []

        def rate_worker() -> None:
            try:
                barrier.wait(timeout=5)
                for i in range(50):
                    store.check_and_record_rate("mixed_key", 60.0, 1000, now=BASE_TIME + i)
            except Exception as e:
                errors.append(e)

        def seq_worker() -> None:
            try:
                barrier.wait(timeout=5)
                for i in range(50):
                    store.record_call("mixed_scope", f"tool_{i}", now=BASE_TIME + i)
                    store.check_sequence(
                        "mixed_scope",
                        f"tool_{i}",
                        ["tool_0", "tool_1"],
                        60.0,
                        now=BASE_TIME + i,
                    )
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = []
            for _ in range(10):
                futures.append(pool.submit(rate_worker))
                futures.append(pool.submit(seq_worker))
            concurrent.futures.wait(futures)
            for f in futures:
                f.result()

        assert errors == [], f"Concurrent operations raised errors: {errors}"


# ── TestEdgeCases ──────────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge case tests for temporal store."""

    def test_very_large_window(self) -> None:
        """Very large window keeps all entries."""
        store = _make_store()
        window = 1e12  # ~31K years
        max_count = 5

        for i in range(5):
            assert store.check_and_record_rate("k", window, max_count, now=float(i))

        assert not store.check_and_record_rate("k", window, max_count, now=1e9)

    def test_very_small_window(self) -> None:
        """Very small (but positive) window expires quickly."""
        store = _make_store()
        window = 0.001
        max_count = 1

        assert store.check_and_record_rate("k", window, max_count, now=1.0)
        # 0.002 seconds later, window has expired
        assert store.check_and_record_rate("k", window, max_count, now=1.002)

    def test_rate_check_uses_monotonic_by_default(self) -> None:
        """When now=None, check_and_record_rate uses time.monotonic()."""
        store = _make_store()
        with patch("munio._temporal.time.monotonic", return_value=42.0):
            store.check_and_record_rate("k", 60.0, 10, now=None)

        entries = store._rate_data["k"]
        assert entries[0] == 42.0

    def test_sequence_check_uses_monotonic_by_default(self) -> None:
        """When now=None, check_sequence uses time.monotonic()."""
        store = _make_store()
        store.record_call("scope", "step_a", now=100.0)

        with patch("munio._temporal.time.monotonic", return_value=105.0):
            result = store.check_sequence("scope", "step_b", ["step_a", "step_b"], 10.0, now=None)

        assert result is False  # step_a is within window (105-10=95 < 100)

    @pytest.mark.parametrize(
        ("max_count", "num_calls", "expected_allowed"),
        [
            (1, 1, 1),
            (1, 5, 1),
            (10, 10, 10),
            (10, 15, 10),
            (100, 100, 100),
        ],
    )
    def test_exact_allowed_count(
        self, max_count: int, num_calls: int, expected_allowed: int
    ) -> None:
        """Exactly max_count calls are allowed, rest are denied."""
        store = _make_store()
        results = [
            store.check_and_record_rate("k", 600.0, max_count, now=BASE_TIME + i)
            for i in range(num_calls)
        ]
        assert sum(results) == expected_allowed

    def test_sequence_prunes_expired_on_check(self) -> None:
        """check_sequence prunes expired entries from the deque."""
        store = _make_store()
        scope = "prune_test"

        # Record old entries
        for i in range(10):
            store.record_call(scope, f"old_{i}", now=BASE_TIME + i)

        # Check with a small window that makes all old entries expire
        store.check_sequence(scope, "new_tool", ["step_a", "new_tool"], 1.0, now=BASE_TIME + 100)

        # All old entries should have been pruned
        entries = store._sequence_data[scope]
        assert len(entries) == 0

    def test_slots_defined(self) -> None:
        """InMemoryTemporalStore uses __slots__ for memory efficiency."""
        assert hasattr(InMemoryTemporalStore, "__slots__")
        expected_slots = {
            "_lock",
            "_rate_data",
            "_rate_key_order",
            "_sequence_data",
            "_sequence_key_order",
        }
        assert set(InMemoryTemporalStore.__slots__) == expected_slots

    def test_max_entries_per_key_constant(self) -> None:
        """_MAX_ENTRIES_PER_KEY is 10,000."""
        assert _MAX_ENTRIES_PER_KEY == 10_000

    def test_max_keys_constant(self) -> None:
        """_MAX_KEYS is 100,000."""
        assert _MAX_KEYS == 100_000

    def test_rate_data_new_key_creates_empty_deque(self) -> None:
        """First check_and_record_rate for a key creates the deque and records."""
        store = _make_store()
        assert store.check_and_record_rate("new_key", 60.0, 1, now=BASE_TIME)
        assert "new_key" in store._rate_data
        assert len(store._rate_data["new_key"]) == 1

    def test_record_call_new_scope_creates_deque(self) -> None:
        """First record_call for a scope creates the deque and records."""
        store = _make_store()
        store.record_call("new_scope", "tool", now=BASE_TIME)
        assert "new_scope" in store._sequence_data
        assert len(store._sequence_data["new_scope"]) == 1


# ── TestRateWindowSliding ──────────────────────────────────────────────────


class TestRateWindowSliding:
    """Tests for the sliding window behavior of rate limiting."""

    def test_sliding_window_gradual_expiry(self) -> None:
        """As time progresses, oldest entries expire one by one."""
        store = _make_store()
        key = "slide"
        window = 10.0
        max_count = 3

        # Record at t=0, t=1, t=2
        for i in range(3):
            assert store.check_and_record_rate(key, window, max_count, now=BASE_TIME + i)

        # At t=3, all 3 are in window -> denied
        assert not store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 3)

        # At t=10.001: entry at t=0 expires (0 < 0.001), 2 remain -> allowed
        assert store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 10.001)

        # Now 3 in window again (t=1, t=2, t=10.001) -> denied
        assert not store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 10.002)

    def test_burst_then_wait(self) -> None:
        """After a burst fills the limit, waiting for window clears all entries."""
        store = _make_store()
        key = "burst"
        window = 5.0
        max_count = 10

        # Burst: 10 calls in 1 second
        for i in range(10):
            assert store.check_and_record_rate(key, window, max_count, now=BASE_TIME + i * 0.1)

        # Denied immediately after burst
        assert not store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 1.0)

        # Wait for full window to expire (all entries < cutoff)
        # Latest entry was at BASE_TIME + 0.9, window=5, so at BASE_TIME + 5.901 all expire
        assert store.check_and_record_rate(key, window, max_count, now=BASE_TIME + 5.901)

    @pytest.mark.parametrize(
        ("window", "record_time", "check_time", "expected", "desc"),
        [
            (10.0, 100.0, 109.0, False, "within window: denied"),
            (10.0, 100.0, 110.0, False, "at exact boundary: denied (fail-closed)"),
            (10.0, 100.0, 110.001, True, "just past boundary: allowed"),
            (10.0, 100.0, 200.0, True, "well past window: allowed"),
            (0.5, 100.0, 100.4, False, "sub-second window: within"),
            (0.5, 100.0, 100.501, True, "sub-second window: expired"),
        ],
    )
    def test_window_boundary_parametrized(
        self,
        window: float,
        record_time: float,
        check_time: float,
        expected: bool,
        desc: str,
    ) -> None:
        """Parametrized window boundary tests."""
        store = _make_store()
        store.check_and_record_rate("k", window, 1, now=record_time)
        result = store.check_and_record_rate("k", window, 1, now=check_time)
        assert result is expected, desc


# ── TestSequenceComplexScenarios ───────────────────────────────────────────


class TestSequenceComplexScenarios:
    """Complex scenario tests for sequence detection."""

    def test_four_step_sequence(self) -> None:
        """4-step exfiltration pattern: discover -> read -> encode -> send."""
        store = _make_store()
        scope = "agent:exfil"
        steps = ["list_files", "read_file", "base64_encode", "http_post"]
        window = 120.0

        store.record_call(scope, "list_files", now=BASE_TIME)
        store.record_call(scope, "read_file", now=BASE_TIME + 10)
        store.record_call(scope, "base64_encode", now=BASE_TIME + 20)

        assert not store.check_sequence(scope, "http_post", steps, window, now=BASE_TIME + 30)

    def test_partial_sequence_not_denied(self) -> None:
        """Incomplete sequence (missing middle step) is allowed."""
        store = _make_store()
        scope = "agent:partial"
        steps = ["step_a", "step_b", "step_c"]
        window = 60.0

        store.record_call(scope, "step_a", now=BASE_TIME)
        # step_b never recorded

        assert store.check_sequence(scope, "step_c", steps, window, now=BASE_TIME + 1)

    def test_repeated_denied_sequence_detection(self) -> None:
        """Denied sequence is detected on every completion attempt."""
        store = _make_store()
        scope = "agent:repeat"
        steps = ["read_file", "http_post"]
        window = 60.0

        store.record_call(scope, "read_file", now=BASE_TIME)

        # First attempt: denied
        assert not store.check_sequence(scope, "http_post", steps, window, now=BASE_TIME + 1)

        # Second attempt: still denied (read_file still in history)
        assert not store.check_sequence(scope, "http_post", steps, window, now=BASE_TIME + 2)

    def test_sequence_with_many_benign_calls(self) -> None:
        """Denied sequence detected even with 100 benign calls interleaved."""
        store = _make_store()
        scope = "agent:noise"
        steps = ["read_secret", "exfil_data"]
        window = 600.0

        store.record_call(scope, "read_secret", now=BASE_TIME)

        # 100 benign calls
        for i in range(100):
            store.record_call(scope, f"benign_{i}", now=BASE_TIME + i + 1)

        assert not store.check_sequence(scope, "exfil_data", steps, window, now=BASE_TIME + 200)

    def test_multiple_sequences_same_scope(self) -> None:
        """Multiple denied sequences can be checked against the same history."""
        store = _make_store()
        scope = "agent:multi"
        window = 60.0

        store.record_call(scope, "read_file", now=BASE_TIME)
        store.record_call(scope, "encode_data", now=BASE_TIME + 1)

        # Sequence 1: [read_file, http_post] — denied
        assert not store.check_sequence(
            scope, "http_post", ["read_file", "http_post"], window, now=BASE_TIME + 2
        )

        # Sequence 2: [encode_data, http_post] — denied
        assert not store.check_sequence(
            scope, "http_post", ["encode_data", "http_post"], window, now=BASE_TIME + 2
        )

        # Sequence 3: [delete_file, http_post] — allowed (delete_file not in history)
        assert store.check_sequence(
            scope, "http_post", ["delete_file", "http_post"], window, now=BASE_TIME + 2
        )

    @pytest.mark.parametrize(
        ("history_tools", "steps", "current_tool", "expected", "desc"),
        [
            (["a"], ["a", "b"], "b", False, "minimal 2-step match"),
            (["a", "b"], ["a", "b", "c"], "c", False, "minimal 3-step match"),
            (["x", "a", "y", "b"], ["a", "b", "c"], "c", False, "interleaved 3-step"),
            (["b", "a"], ["a", "b", "c"], "c", True, "reversed order means no subsequence"),
            ([], ["a", "b"], "b", True, "empty history for 2-step"),
            (["c"], ["a", "b"], "b", True, "no matching history tool"),
        ],
    )
    def test_sequence_scenarios_parametrized(
        self,
        history_tools: list[str],
        steps: list[str],
        current_tool: str,
        expected: bool,
        desc: str,
    ) -> None:
        """Parametrized complex sequence scenarios."""
        store = _make_store()
        scope = "param_scope"
        window = 60.0

        for i, tool in enumerate(history_tools):
            store.record_call(scope, tool, now=BASE_TIME + i)

        result = store.check_sequence(
            scope, current_tool, steps, window, now=BASE_TIME + len(history_tools)
        )
        assert result is expected, desc


# ── TestRateAndSequenceIntegration ─────────────────────────────────────────


class TestRateAndSequenceIntegration:
    """Integration tests: rate limiting and sequence detection together."""

    def test_rate_and_sequence_independent_data(self) -> None:
        """Rate data and sequence data are completely independent."""
        store = _make_store()

        # Rate limit on key "tool:exec"
        store.check_and_record_rate("tool:exec", 60.0, 1, now=BASE_TIME)

        # Sequence on scope "agent:alice"
        store.record_call("agent:alice", "read_file", now=BASE_TIME)

        # Rate data has the key
        assert "tool:exec" in store._rate_data
        assert "tool:exec" not in store._sequence_data

        # Sequence data has the scope
        assert "agent:alice" in store._sequence_data
        assert "agent:alice" not in store._rate_data

    def test_shared_store_rate_then_sequence(self) -> None:
        """Using the same store for both rate limiting and sequence detection."""
        store = _make_store()

        # Rate limit allows first call
        assert store.check_and_record_rate("rate:exec", 60.0, 2, now=BASE_TIME)

        # Record call for sequence tracking
        store.record_call("agent:x", "exec", now=BASE_TIME)

        # Rate limit allows second call
        assert store.check_and_record_rate("rate:exec", 60.0, 2, now=BASE_TIME + 1)

        # Rate limit blocks third
        assert not store.check_and_record_rate("rate:exec", 60.0, 2, now=BASE_TIME + 2)

        # Sequence check still works independently
        assert not store.check_sequence(
            "agent:x", "http_post", ["exec", "http_post"], 60.0, now=BASE_TIME + 3
        )


# ── TestEnforceKeyLimitDirect ──────────────────────────────────────────────


class TestEnforceKeyLimitDirect:
    """Direct tests of the _enforce_key_limit static method."""

    def test_under_limit_no_eviction(self) -> None:
        """When under limit, no keys are evicted."""
        data: dict[str, deque[float]] = {
            "a": deque([1.0]),
            "b": deque([2.0]),
        }
        key_order: deque[str] = deque(["a", "b"])

        # _MAX_KEYS is 100K, far above 2 keys
        InMemoryTemporalStore._enforce_key_limit(data, key_order)

        assert "a" in data
        assert "b" in data

    def test_eviction_removes_oldest(self) -> None:
        """Oldest key in key_order is removed first."""
        data: dict[str, deque[float]] = {
            "first": deque([1.0]),
            "second": deque([2.0]),
            "third": deque([3.0]),
        }
        key_order: deque[str] = deque(["first", "second", "third"])

        with patch("munio._temporal._MAX_KEYS", 2):
            InMemoryTemporalStore._enforce_key_limit(data, key_order)

        assert "first" not in data
        assert "second" in data
        assert "third" in data

    def test_empty_key_order_breaks_loop(self) -> None:
        """If key_order is empty but data exceeds limit, loop breaks safely."""
        data: dict[str, deque[float]] = {
            "orphan": deque([1.0]),
            "orphan2": deque([2.0]),
        }
        key_order: deque[str] = deque()  # Empty!

        with patch("munio._temporal._MAX_KEYS", 1):
            # Should not infinite loop
            InMemoryTemporalStore._enforce_key_limit(data, key_order)

        # Data unchanged because key_order is empty (break condition)
        assert len(data) == 2

    def test_key_in_order_but_not_in_data(self) -> None:
        """data.pop(oldest, None) handles keys in order but not in data gracefully."""
        data: dict[str, deque[float]] = {
            "real_key": deque([1.0]),
            "another": deque([2.0]),
        }
        key_order: deque[str] = deque(["ghost_key", "real_key", "another"])

        with patch("munio._temporal._MAX_KEYS", 1):
            InMemoryTemporalStore._enforce_key_limit(data, key_order)

        # ghost_key popleft'd but pop from data returns None (no error)
        # real_key should be evicted to get to limit
        assert len(data) <= 1


# ── TestMatchesSubsequenceAdditional ───────────────────────────────────────


class TestMatchesSubsequenceAdditional:
    """Additional edge cases for _matches_subsequence."""

    @pytest.mark.parametrize(
        ("history", "steps", "expected", "desc"),
        [
            # Question mark wildcard
            (["tool_a"], ["tool_?"], True, "question mark matches single char"),
            (["tool_ab"], ["tool_?"], False, "question mark does not match two chars"),
            # Character set
            (["tool_a"], ["tool_[abc]"], True, "character set match"),
            (["tool_d"], ["tool_[abc]"], False, "character set no match"),
            # Negated character set
            (["tool_d"], ["tool_[!abc]"], True, "negated character set match"),
            (["tool_a"], ["tool_[!abc]"], False, "negated character set no match"),
            # Exact literal (no wildcards)
            (["exact_match"], ["exact_match"], True, "exact literal match"),
            (["exact_match"], ["exact_mismatch"], False, "exact literal no match"),
        ],
    )
    def test_fnmatch_patterns(
        self,
        history: list[str],
        steps: list[str],
        expected: bool,
        desc: str,
    ) -> None:
        """Test fnmatch pattern features (?, [], [!])."""
        assert _matches_subsequence(history, steps) is expected, desc

    def test_long_history_short_steps(self) -> None:
        """Steps found early in a long history."""
        history = [f"tool_{i}" for i in range(1000)]
        steps = ["tool_0", "tool_500"]
        assert _matches_subsequence(history, steps) is True

    def test_long_steps_not_in_history(self) -> None:
        """Many steps that don't all appear in history."""
        history = ["a", "b", "c"]
        steps = ["a", "b", "c", "d", "e"]
        assert _matches_subsequence(history, steps) is False

    def test_greedy_matching_does_not_skip(self) -> None:
        """Greedy left-to-right matching: first match is consumed.

        History: [a, a, b]. Steps: [a, b].
        First 'a' at index 0 matches, then 'b' at index 2 matches -> True.
        """
        assert _matches_subsequence(["a", "a", "b"], ["a", "b"]) is True

    def test_greedy_matching_failure(self) -> None:
        """Greedy matching can still succeed even with early consumption.

        History: [a, b, a]. Steps: [a, a].
        First 'a' at index 0, second 'a' at index 2 -> True.
        """
        assert _matches_subsequence(["a", "b", "a"], ["a", "a"]) is True

    def test_all_same_elements(self) -> None:
        """History and steps are all the same element."""
        assert _matches_subsequence(["x", "x", "x"], ["x", "x", "x"]) is True
        assert _matches_subsequence(["x", "x"], ["x", "x", "x"]) is False
