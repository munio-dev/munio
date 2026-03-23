"""Tests for proxy helper functions (no subprocess needed)."""

from __future__ import annotations

import json

import pytest

from munio.gate.proxy import (
    _MAX_BLOCKED_IDS,
    _add_blocked_id,
    _extract_tool_call,
    _make_blocked_response,
    _should_drop_response,
)


class TestExtractToolCall:
    """Test _extract_tool_call JSON-RPC parsing."""

    def test_valid_tools_call(self) -> None:
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "exec", "arguments": {"command": "ls"}},
        }
        result = _extract_tool_call(msg)
        assert result is not None
        name, args = result
        assert name == "exec"
        assert args == {"command": "ls"}

    def test_not_tools_call(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        assert _extract_tool_call(msg) is None

    def test_tools_list_not_intercepted(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        assert _extract_tool_call(msg) is None

    def test_notification_no_method(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 3, "result": {"tools": []}}
        assert _extract_tool_call(msg) is None

    def test_missing_params(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
        assert _extract_tool_call(msg) is None

    def test_missing_name(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {}}}
        assert _extract_tool_call(msg) is None

    def test_non_string_name(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": 42}}
        assert _extract_tool_call(msg) is None

    def test_missing_arguments_defaults_empty(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "ping"}}
        result = _extract_tool_call(msg)
        assert result is not None
        _, args = result
        assert args == {}

    @pytest.mark.parametrize(
        ("bad_arguments", "desc"),
        [
            ("bad", "string"),
            ([1, 2, 3], "list"),
            (42, "int"),
            (True, "bool"),
        ],
    )
    def test_non_dict_arguments_returns_none(self, bad_arguments: object, desc: str) -> None:
        """C1 fix: non-dict arguments → None (fail-closed), not silent coercion to {}."""
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ping", "arguments": bad_arguments},
        }
        assert _extract_tool_call(msg) is None


class TestMakeBlockedResponse:
    """Test JSON-RPC blocked response construction."""

    def test_response_format(self) -> None:
        data = _make_blocked_response(42, "Policy violation")
        parsed = json.loads(data)
        assert parsed["jsonrpc"] == "2.0"
        assert parsed["id"] == 42
        assert parsed["result"]["isError"] is True
        assert "munio" in parsed["result"]["content"][0]["text"].lower()

    def test_string_id(self) -> None:
        data = _make_blocked_response("req-abc", "Denied")
        parsed = json.loads(data)
        assert parsed["id"] == "req-abc"

    def test_null_id(self) -> None:
        data = _make_blocked_response(None, "Error")
        parsed = json.loads(data)
        assert parsed["id"] is None

    def test_ends_with_newline(self) -> None:
        data = _make_blocked_response(1, "x")
        assert data.endswith(b"\n")

    def test_reason_sanitized(self) -> None:
        """M1 fix: arbitrary violation details are replaced with generic message."""
        data = _make_blocked_response(1, "Command denied by denylist constraint 'exec-deny'")
        parsed = json.loads(data)
        text = parsed["result"]["content"][0]["text"].lower()
        # Should NOT contain internal constraint details
        assert "exec-deny" not in text
        # Should contain the generic sanitized message
        assert "blocked by policy" in text

    def test_known_reasons_preserved(self) -> None:
        """Known safe reason strings are preserved."""
        for reason in ("Malformed tools/call request", "Policy violation"):
            data = _make_blocked_response(1, reason)
            parsed = json.loads(data)
            assert reason in parsed["result"]["content"][0]["text"]


class TestAddBlockedId:
    """Tests for _add_blocked_id with FIFO dict-based tracking."""

    def test_add_int_id(self) -> None:
        blocked: dict[int | float | str, None] = {}
        _add_blocked_id(blocked, 42)
        assert 42 in blocked

    def test_none_skipped(self) -> None:
        """H4 fix: None is never added."""
        blocked: dict[int | float | str, None] = {}
        _add_blocked_id(blocked, None)
        assert len(blocked) == 0

    def test_bool_normalized_to_int(self) -> None:
        """M3 fix: True → 1, False → 0."""
        blocked: dict[int | float | str, None] = {}
        _add_blocked_id(blocked, True)
        assert 1 in blocked
        _add_blocked_id(blocked, False)
        assert 0 in blocked

    @pytest.mark.parametrize("bad_float", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_float_rejected(self, bad_float: float) -> None:
        """R2-H1 fix: NaN/Inf floats are rejected."""
        blocked: dict[int | float | str, None] = {}
        _add_blocked_id(blocked, bad_float)
        assert len(blocked) == 0

    @pytest.mark.parametrize(
        ("bad_id", "desc"),
        [
            ({"nested": "obj"}, "dict"),
            ([1, 2, 3], "list"),
        ],
    )
    def test_non_hashable_id_rejected(self, bad_id: object, desc: str) -> None:
        """R2-N1 fix: Non-hashable IDs (dict/list) are rejected without crash."""
        blocked: dict[int | float | str, None] = {}
        _add_blocked_id(blocked, bad_id)  # type: ignore[arg-type]
        assert len(blocked) == 0

    def test_fifo_eviction_order(self) -> None:
        """R2-L1 fix: Eviction removes oldest entries (insertion order)."""

        blocked: dict[int | float | str, None] = {}
        # Fill to capacity
        for i in range(_MAX_BLOCKED_IDS):
            _add_blocked_id(blocked, i)
        assert len(blocked) == _MAX_BLOCKED_IDS

        # Adding one more triggers eviction of oldest half
        _add_blocked_id(blocked, _MAX_BLOCKED_IDS)
        assert len(blocked) <= _MAX_BLOCKED_IDS
        # Oldest IDs (0, 1, 2, ...) should be evicted
        assert 0 not in blocked
        # Most recent should survive
        assert _MAX_BLOCKED_IDS in blocked

    def test_string_id(self) -> None:
        blocked: dict[int | float | str, None] = {}
        _add_blocked_id(blocked, "req-123")
        assert "req-123" in blocked

    def test_float_id(self) -> None:
        blocked: dict[int | float | str, None] = {}
        _add_blocked_id(blocked, 1.5)
        assert 1.5 in blocked


class TestShouldDropResponse:
    """Tests for _should_drop_response including batch filtering."""

    def test_single_blocked_dropped(self) -> None:
        blocked: dict[int | float | str, None] = {42: None}
        msg = {"jsonrpc": "2.0", "id": 42, "result": {}}
        should_drop, rebuilt = _should_drop_response(msg, blocked)
        assert should_drop is True
        assert rebuilt is None
        assert 42 not in blocked  # Consumed

    def test_single_unblocked_forwarded(self) -> None:
        blocked: dict[int | float | str, None] = {99: None}
        msg = {"jsonrpc": "2.0", "id": 1, "result": {}}
        should_drop, rebuilt = _should_drop_response(msg, blocked)
        assert should_drop is False
        assert rebuilt is None

    def test_batch_mixed(self) -> None:
        """Batch with one spoofed element: spoofed removed, rest rebuilt."""
        blocked: dict[int | float | str, None] = {2: None}
        batch = [
            {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
            {"jsonrpc": "2.0", "id": 2, "result": {"spoofed": True}},
            {"jsonrpc": "2.0", "id": 3, "result": {"ok": True}},
        ]
        should_drop, rebuilt = _should_drop_response(batch, blocked)
        assert should_drop is False
        assert rebuilt is not None
        parsed = json.loads(rebuilt)
        assert len(parsed) == 2
        assert parsed[0]["id"] == 1
        assert parsed[1]["id"] == 3

    def test_batch_all_spoofed(self) -> None:
        """All batch elements are spoofed → drop entire batch."""
        blocked: dict[int | float | str, None] = {1: None, 2: None}
        batch = [
            {"jsonrpc": "2.0", "id": 1, "result": {}},
            {"jsonrpc": "2.0", "id": 2, "result": {}},
        ]
        should_drop, _rebuilt = _should_drop_response(batch, blocked)
        assert should_drop is True

    def test_batch_no_spoofed(self) -> None:
        """No spoofed elements → no modification needed."""
        blocked: dict[int | float | str, None] = {99: None}
        batch = [
            {"jsonrpc": "2.0", "id": 1, "result": {}},
        ]
        should_drop, rebuilt = _should_drop_response(batch, blocked)
        assert should_drop is False
        assert rebuilt is None

    def test_non_response_not_dropped(self) -> None:
        """Notification (no id+result) is not treated as spoofed."""
        blocked: dict[int | float | str, None] = {1: None}
        msg = {"jsonrpc": "2.0", "method": "notification/data"}
        should_drop, _rebuilt = _should_drop_response(msg, blocked)
        assert should_drop is False
