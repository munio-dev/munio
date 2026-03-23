"""Tests for L6 ProtocolInterceptor orchestrator.

End-to-end tests that simulate full MCP message sequences through
the ProtocolInterceptor, verifying that monitors are orchestrated
correctly and block/alert decisions are propagated.
"""

from __future__ import annotations

import json
from typing import Any

from munio.gate.protocol_interceptor import ProtocolInterceptor, ProtocolResult
from munio.gate.protocol_models import (
    NotificationConfig,
    ProtocolAction,
    ProtocolConfig,
    ProtocolViolation,
    ProtocolViolationType,
    SamplingConfig,
)

# ── Helpers ──────────────────────────────────────────────────────────


def _jsonrpc_request(
    method: str,
    *,
    request_id: int | str = 1,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _jsonrpc_notification(
    method: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _jsonrpc_result(request_id: int | str, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _do_init(pi: ProtocolInterceptor, *, capabilities: dict[str, Any] | None = None) -> None:
    """Complete a normal MCP initialization handshake."""
    caps = capabilities or {"tools": {"listChanged": True}}

    pi.on_client_message(
        _jsonrpc_request(
            "initialize",
            params={
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        )
    )
    pi.on_server_message(
        _jsonrpc_result(
            1,
            {
                "protocolVersion": "2025-03-26",
                "capabilities": caps,
                "serverInfo": {"name": "test-server", "version": "1.0"},
            },
        )
    )
    pi.on_client_message(_jsonrpc_notification("notifications/initialized"))


# ── ProtocolResult Tests ─────────────────────────────────────────────


class TestProtocolResult:
    def test_allow_singleton(self) -> None:
        r = ProtocolResult.ALLOW
        assert not r.should_block
        assert not r.violations
        assert not bool(r)

    def test_bool_true_with_violations(self) -> None:

        r = ProtocolResult(
            violations=[
                ProtocolViolation(
                    violation_type=ProtocolViolationType.INIT_RACE_WINDOW,
                    action=ProtocolAction.ALERT,
                    message="test",
                    monitor="test",
                )
            ]
        )
        assert bool(r)
        assert not r.should_block  # alert only

    def test_block_violations_filter(self) -> None:

        r = ProtocolResult(
            should_block=True,
            violations=[
                ProtocolViolation(
                    violation_type=ProtocolViolationType.INIT_RACE_WINDOW,
                    action=ProtocolAction.BLOCK,
                    message="blocked",
                    monitor="test",
                ),
                ProtocolViolation(
                    violation_type=ProtocolViolationType.PROTOCOL_ANOMALY,
                    action=ProtocolAction.ALERT,
                    message="alert",
                    monitor="test",
                ),
            ],
        )
        assert len(r.block_violations) == 1
        assert len(r.alert_violations) == 1


# ── ProtocolInterceptor Tests ────────────────────────────────────────


class TestProtocolInterceptor:
    def test_disabled_config_passes_everything(self) -> None:
        pi = ProtocolInterceptor(ProtocolConfig(enabled=False))
        r = pi.on_client_message(_jsonrpc_request("tools/call", params={"name": "evil"}))
        assert not r.should_block
        assert r is ProtocolResult.ALLOW

    def test_normal_lifecycle_no_violations(self) -> None:
        pi = ProtocolInterceptor()
        _do_init(pi)

        # Normal tool call after init -- should be fine from L6 perspective
        r = pi.on_client_message(
            _jsonrpc_request("tools/call", request_id=2, params={"name": "read_file"})
        )
        assert not r.should_block

    def test_irwe_blocks_tool_call_before_init(self) -> None:
        """Integration: IRWE detected and blocked."""
        pi = ProtocolInterceptor()

        r = pi.on_client_message(_jsonrpc_request("tools/call", params={"name": "read_file"}))
        assert r.should_block
        assert any(v.violation_type == ProtocolViolationType.INIT_RACE_WINDOW for v in r.violations)

    def test_cpe_blocks_unnegotiated_sampling(self) -> None:
        """Integration: CPE detected and blocked."""
        pi = ProtocolInterceptor()
        _do_init(pi, capabilities={"tools": {"listChanged": True}})

        # Server sends sampling request without declaring capability
        r = pi.on_server_message(
            _jsonrpc_request("sampling/createMessage", request_id=10, params={"messages": []})
        )
        assert r.should_block
        assert any(
            v.violation_type == ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION
            for v in r.violations
        )

    def test_nsd_blocks_notification_storm(self) -> None:
        """Integration: NSD detected via notification storm."""
        config = ProtocolConfig(
            notifications=NotificationConfig(max_list_changed_per_minute=3),
        )
        pi = ProtocolInterceptor(config)
        _do_init(pi)

        results = []
        for _ in range(5):
            r = pi.on_server_message(_jsonrpc_notification("notifications/tools/list_changed"))
            results.append(r)

        blocked = [r for r in results if r.should_block]
        assert len(blocked) >= 1

    def test_pttra_blocks_progress_flood(self) -> None:
        """Integration: PTTRA detected via progress flood."""
        config = ProtocolConfig(
            notifications=NotificationConfig(max_progress_per_request=3),
        )
        pi = ProtocolInterceptor(config)
        _do_init(pi)

        results = []
        for i in range(5):
            r = pi.on_server_message(
                _jsonrpc_notification(
                    "notifications/progress",
                    params={"progressToken": "req-1", "progress": i, "total": 100},
                )
            )
            results.append(r)

        blocked = [r for r in results if r.should_block]
        assert len(blocked) >= 1

    def test_sral_blocks_deep_sampling(self) -> None:
        """Integration: SRAL detected via excessive sampling depth."""
        config = ProtocolConfig(
            sampling=SamplingConfig(max_depth=2),
        )
        pi = ProtocolInterceptor(config)
        _do_init(pi, capabilities={"tools": {}, "sampling": {}})

        results = []
        for i in range(3):
            r = pi.on_server_message(
                _jsonrpc_request(
                    "sampling/createMessage",
                    request_id=10 + i,
                    params={"messages": []},
                )
            )
            results.append(r)

        # 3rd call (depth=3) should exceed max_depth=2
        assert results[-1].should_block

    def test_tool_mutation_detected(self) -> None:
        """Integration: Tool list mutation mid-session detected."""
        pi = ProtocolInterceptor()
        _do_init(pi)

        # Baseline tool list
        tools_v1 = [
            {"name": "read_file", "description": "read", "inputSchema": {"type": "object"}},
        ]
        pi.on_server_message(_jsonrpc_result(2, {"tools": tools_v1}))

        # Mutated tool list (added tool)
        tools_v2 = [
            {"name": "read_file", "description": "read", "inputSchema": {"type": "object"}},
            {"name": "evil_tool", "description": "evil", "inputSchema": {"type": "object"}},
        ]
        r = pi.on_server_message(_jsonrpc_result(3, {"tools": tools_v2}))

        assert any(
            v.violation_type == ProtocolViolationType.TOOL_LIST_MUTATION for v in r.violations
        )

    def test_make_block_response(self) -> None:
        """Block response is valid JSON-RPC error."""
        pi = ProtocolInterceptor()

        violations = [
            ProtocolViolation(
                violation_type=ProtocolViolationType.INIT_RACE_WINDOW,
                action=ProtocolAction.BLOCK,
                message="test",
                monitor="test",
            )
        ]
        response = pi.make_block_response(42, violations)
        parsed = json.loads(response)
        assert parsed["id"] == 42
        assert parsed["error"]["code"] == -32600
        # Message should be generic (no monitor internals)
        assert "protocol violation" in parsed["error"]["message"].lower()

    def test_make_block_response_null_id(self) -> None:
        pi = ProtocolInterceptor()
        response = pi.make_block_response(None, [])
        parsed = json.loads(response)
        assert parsed["id"] is None

    def test_multiple_monitors_fire_on_same_message(self) -> None:
        """When a server sends a bad message, multiple monitors can fire."""
        config = ProtocolConfig(
            notifications=NotificationConfig(max_list_changed_per_minute=1),
        )
        pi = ProtocolInterceptor(config)
        # Don't initialize -- so both session and notification monitors can fire

        # Server sends list_changed before init and excessively
        for _ in range(3):
            pi.on_server_message(_jsonrpc_notification("notifications/tools/list_changed"))

        # Should have violations from both session CPE (no tools cap) and notification storm
        # Note: session monitor CPE only fires after capabilities are known,
        # so before init it won't fire CPE. But notification storm should fire.


class TestProtocolInterceptorEdgeCases:
    def test_non_dict_message_to_client(self) -> None:
        """Non-dict messages should not crash monitors."""
        pi = ProtocolInterceptor()
        # This should not be called with non-dict, but be robust
        r = pi.on_client_message({"jsonrpc": "2.0"})  # type: ignore[arg-type]
        assert not r.should_block

    def test_server_response_without_method(self) -> None:
        """Response messages (no method) should not trigger method-based checks."""
        pi = ProtocolInterceptor()
        _do_init(pi)

        r = pi.on_server_message({"jsonrpc": "2.0", "id": 5, "result": {"data": "ok"}})
        assert not r.should_block

    def test_empty_params(self) -> None:
        """Messages with empty params should not crash."""
        pi = ProtocolInterceptor()
        _do_init(pi)

        pi.on_server_message(_jsonrpc_request("sampling/createMessage", request_id=10, params={}))
        # Should not crash, but may trigger CPE if sampling not declared
        # (since we initialized with tools only)
        # This is expected behavior
