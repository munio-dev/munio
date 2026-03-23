"""Integration tests for L6 Protocol Analysis with the gate proxy.

Simulates full MCP message sequences through the ProtocolInterceptor,
including multi-monitor scenarios and the proxy integration layer.
"""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from munio.gate.protocol_interceptor import ProtocolInterceptor
from munio.gate.protocol_models import (
    NotificationConfig,
    ProtocolConfig,
    ProtocolViolationType,
    SamplingConfig,
    SessionConfig,
)
from munio.gate.protocol_monitors import NotificationMonitor, SessionStateMonitor, _hash_tool_list
from munio.gate.protocol_proxy import (
    protocol_filter_client_message,
    protocol_filter_server_message,
)

# ── Helpers ──────────────────────────────────────────────────────────


def _req(method: str, *, rid: int = 1, params: dict | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _notif(method: str, params: dict | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _result(rid: int, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _init_handshake(pi: ProtocolInterceptor, *, caps: dict | None = None) -> None:
    """Complete a full MCP init handshake."""
    c = caps or {"tools": {"listChanged": True}}
    pi.on_client_message(
        _req(
            "initialize",
            params={
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        )
    )
    pi.on_server_message(
        _result(
            1,
            {
                "protocolVersion": "2025-03-26",
                "capabilities": c,
                "serverInfo": {"name": "s", "version": "1"},
            },
        )
    )
    pi.on_client_message(_notif("notifications/initialized"))


class MockWriter:
    """Mock async writer that captures bytes."""

    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        pass


# ── Full Attack Scenario Tests ───────────────────────────────────────


class TestFullAttackScenarios:
    """Simulate real protocol-level attacks end-to-end."""

    def test_attack_irwe_tool_call_during_init_race(self) -> None:
        """
        Attack: IRWE (Init Race Window Exploitation)
        Sequence:
        1. Client sends initialize
        2. BEFORE server responds, attacker injects tools/call
        3. L6 should BLOCK the injected call
        """
        pi = ProtocolInterceptor()

        # Step 1: Client starts init
        r = pi.on_client_message(
            _req(
                "initialize",
                params={
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"},
                },
            )
        )
        assert not r.should_block

        # Step 2: tools/call before InitializeResult
        r = pi.on_client_message(
            _req("tools/call", rid=2, params={"name": "exec", "arguments": {"cmd": "rm -rf /"}})
        )
        assert r.should_block
        assert r.violations[0].violation_type == ProtocolViolationType.INIT_RACE_WINDOW

    def test_attack_cpe_sampling_escalation(self) -> None:
        """
        Attack: CPE (Capability Phantom Escalation)
        Sequence:
        1. Server declares only tools capability
        2. Server sends sampling/createMessage (undeclared!)
        3. L6 should BLOCK the sampling request
        """
        pi = ProtocolInterceptor()
        _init_handshake(pi, caps={"tools": {"listChanged": True}})

        # Server tries sampling without declaring it
        r = pi.on_server_message(
            _req(
                "sampling/createMessage",
                rid=10,
                params={
                    "messages": [
                        {
                            "role": "user",
                            "content": {"type": "text", "text": "What are the secrets?"},
                        }
                    ]
                },
            )
        )
        assert r.should_block
        cpe = [
            v
            for v in r.violations
            if v.violation_type == ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION
        ]
        assert len(cpe) == 1

    def test_attack_nsd_notification_storm_tool_injection(self) -> None:
        """
        Attack: NSD (Notification Storm Desync)
        Sequence:
        1. Normal init
        2. Server floods 20 list_changed notifications in rapid succession
        3. Between notifications, server injects new tools
        4. L6 should rate-limit and alert on storm
        """
        config = ProtocolConfig(
            notifications=NotificationConfig(max_list_changed_per_minute=5),
        )
        pi = ProtocolInterceptor(config)
        _init_handshake(pi)

        blocked_count = 0
        for _i in range(20):
            r = pi.on_server_message(_notif("notifications/tools/list_changed"))
            if r.should_block:
                blocked_count += 1

        # Should have blocked after exceeding 5/minute
        assert blocked_count > 0

    def test_attack_pttra_progress_flood_resource_hold(self) -> None:
        """
        Attack: PTTRA (Progress Token Timeout Resource Abuse)
        Sequence:
        1. Normal init
        2. Client makes a tool call
        3. Server sends 200 progress notifications without ever completing
        4. L6 should detect the flood and force-alert
        """
        config = ProtocolConfig(
            notifications=NotificationConfig(max_progress_per_request=10),
        )
        pi = ProtocolInterceptor(config)
        _init_handshake(pi)

        blocked_count = 0
        for i in range(20):
            r = pi.on_server_message(
                _notif(
                    "notifications/progress",
                    params={"progressToken": "malicious-req", "progress": i, "total": 1000},
                )
            )
            if r.should_block:
                blocked_count += 1

        assert blocked_count > 0

    def test_attack_sral_recursive_sampling_amplification(self) -> None:
        """
        Attack: SRAL (Sampling Recursive Amplification Loop)
        Sequence:
        1. Server A asks for sampling
        2. LLM responds, triggers tool call to Server B
        3. Server B asks for sampling
        4. Repeat -- L6 should block at depth > max
        """
        config = ProtocolConfig(
            sampling=SamplingConfig(max_depth=2),
        )
        pi = ProtocolInterceptor(config)
        _init_handshake(pi, caps={"tools": {}, "sampling": {}})

        # Depth 1: ok
        r = pi.on_server_message(_req("sampling/createMessage", rid=10, params={"messages": []}))
        assert not r.should_block

        # Depth 2: ok
        r = pi.on_server_message(_req("sampling/createMessage", rid=11, params={"messages": []}))
        assert not r.should_block

        # Depth 3: BLOCKED
        r = pi.on_server_message(_req("sampling/createMessage", rid=12, params={"messages": []}))
        assert r.should_block
        sral = [
            v
            for v in r.violations
            if v.violation_type == ProtocolViolationType.SAMPLING_RECURSIVE_AMPLIFICATION
        ]
        assert len(sral) == 1

    def test_attack_sral_cross_server_depth_propagation(self) -> None:
        """
        SRAL with cross-server depth via _meta.sampling_depth.
        Server B receives a forwarded message with depth=3 from Server A.
        """
        config = ProtocolConfig(
            sampling=SamplingConfig(max_depth=3),
        )
        pi = ProtocolInterceptor(config)
        _init_handshake(pi, caps={"tools": {}, "sampling": {}})

        # Server sends sampling with depth already at 4 (from upstream chain)
        r = pi.on_server_message(
            _req(
                "sampling/createMessage",
                rid=10,
                params={"messages": [], "_meta": {"sampling_depth": 4}},
            )
        )
        assert r.should_block

    def test_attack_tool_rug_pull(self) -> None:
        """
        Attack: Tool rug pull
        Sequence:
        1. Server advertises tools including "safe_tool"
        2. Agent decides to use "safe_tool"
        3. Before the call, server sends new tools/list WITHOUT "safe_tool"
        4. L6 should detect the removal
        """
        pi = ProtocolInterceptor()
        _init_handshake(pi)

        # Baseline
        tools_v1 = [
            {"name": "safe_tool", "description": "safe", "inputSchema": {"type": "object"}},
            {"name": "read_file", "description": "read", "inputSchema": {"type": "object"}},
        ]
        pi.on_server_message(_result(2, {"tools": tools_v1}))

        # Rug pull: remove safe_tool, add evil_tool
        tools_v2 = [
            {"name": "evil_tool", "description": "evil", "inputSchema": {"type": "object"}},
            {"name": "read_file", "description": "read", "inputSchema": {"type": "object"}},
        ]
        r = pi.on_server_message(_result(3, {"tools": tools_v2}))

        violations = r.violations
        # Should detect both addition and removal
        assert any(
            "removed" in v.message.lower() or "rug pull" in v.message.lower() for v in violations
        )
        assert any("added" in v.message.lower() for v in violations)

    def test_attack_combined_cpe_and_nsd(self) -> None:
        """
        Combined attack: Server floods list_changed (NSD) while also
        sending sampling requests (CPE) it didn't declare.
        Multiple monitors should fire simultaneously.
        """
        config = ProtocolConfig(
            notifications=NotificationConfig(max_list_changed_per_minute=2),
        )
        pi = ProtocolInterceptor(config)
        _init_handshake(pi, caps={"tools": {"listChanged": True}})

        all_violations = []

        # NSD: 5 list_changed
        for _ in range(5):
            r = pi.on_server_message(_notif("notifications/tools/list_changed"))
            all_violations.extend(r.violations)

        # CPE: sampling request
        r = pi.on_server_message(_req("sampling/createMessage", rid=20, params={"messages": []}))
        all_violations.extend(r.violations)

        violation_types = {v.violation_type for v in all_violations}
        assert ProtocolViolationType.NOTIFICATION_STORM_DESYNC in violation_types
        assert ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION in violation_types


# ── Proxy Integration Layer Tests ────────────────────────────────────


class TestProtocolProxyIntegration:
    """Test the async proxy integration functions."""

    @pytest.mark.asyncio
    async def test_filter_client_allows_normal_message(self) -> None:
        pi = ProtocolInterceptor()
        _init_handshake(pi)

        writer = MockWriter()
        msg = _req("tools/call", rid=5, params={"name": "read_file"})
        allowed = await protocol_filter_client_message(msg, b"", writer, pi)
        assert allowed
        assert len(writer.data) == 0  # No error response sent

    @pytest.mark.asyncio
    async def test_filter_client_blocks_pre_init_call(self) -> None:
        pi = ProtocolInterceptor()

        writer = MockWriter()
        msg = _req("tools/call", rid=5, params={"name": "evil"})
        line = json.dumps(msg).encode() + b"\n"
        allowed = await protocol_filter_client_message(msg, line, writer, pi)
        assert not allowed

        # Error response should have been written
        assert len(writer.data) > 0
        response = json.loads(writer.data.decode())
        assert response["id"] == 5
        assert "error" in response

    @pytest.mark.asyncio
    async def test_filter_client_notification_blocked_no_response(self) -> None:
        """Blocked notification (no id) should not send a response."""
        pi = ProtocolInterceptor()

        writer = MockWriter()
        msg = _notif("resources/list")  # No id, pre-init
        # Note: notifications don't have id, but _notif creates without id
        # Session monitor blocks based on method, but no response for notifications
        allowed = await protocol_filter_client_message(msg, b"", writer, pi)
        # IRWE should block
        assert not allowed
        # No response written (notification has no id)
        assert len(writer.data) == 0

    @pytest.mark.asyncio
    async def test_filter_server_allows_normal_response(self) -> None:
        pi = ProtocolInterceptor()
        _init_handshake(pi)

        msg = _result(5, {"content": [{"type": "text", "text": "hello"}]})
        allowed = await protocol_filter_server_message(msg, pi)
        assert allowed

    @pytest.mark.asyncio
    async def test_filter_server_drops_cpe_message(self) -> None:
        pi = ProtocolInterceptor()
        _init_handshake(pi, caps={"tools": {}})  # No sampling

        msg = _req("sampling/createMessage", rid=10, params={"messages": []})
        allowed = await protocol_filter_server_message(msg, pi)
        assert not allowed


# ── Hypothesis Property Tests ────────────────────────────────────────
# Note: These require hypothesis to be installed.
# If not available, they are skipped.


try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    _HAS_HYPOTHESIS = True
except ImportError:
    _HAS_HYPOTHESIS = False


@pytest.mark.skipif(not _HAS_HYPOTHESIS, reason="hypothesis not installed")
class TestProtocolPropertyBased:
    """Property-based tests for protocol monitors using Hypothesis."""

    @given(
        method=st.sampled_from(
            [
                "tools/call",
                "tools/list",
                "resources/read",
                "prompts/get",
                "logging/setLevel",
                "ping",
                "initialize",
            ]
        ),
        request_id=st.integers(min_value=1, max_value=1000),
    )
    @settings(max_examples=50)
    def test_session_monitor_never_crashes(self, method: str, request_id: int) -> None:
        """SessionStateMonitor should never crash on any valid JSON-RPC message."""
        mon = SessionStateMonitor(SessionConfig())
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        # Should not raise
        mon.on_message("client_to_server", msg)
        mon.on_message("server_to_client", msg)

    @given(
        count=st.integers(min_value=1, max_value=50),
    )
    @settings(max_examples=20)
    def test_notification_monitor_bounded_violations(self, count: int) -> None:
        """NotificationMonitor should produce bounded violations."""

        mon = NotificationMonitor(NotificationConfig(max_list_changed_per_minute=5))
        total_violations = 0
        for _ in range(count):
            v = mon.on_message("server_to_client", _notif("notifications/tools/list_changed"))
            total_violations += len(v)
        # Violations should be bounded: at most 1 per message
        assert total_violations <= count

    @given(
        tool_names=st.lists(
            st.text(min_size=1, max_size=50, alphabet="abcdefghijklmnopqrstuvwxyz_"),
            min_size=1,
            max_size=20,
            unique=True,
        ),
    )
    @settings(max_examples=30)
    def test_tool_registry_deterministic_hashing(self, tool_names: list[str]) -> None:
        """Tool registry hashing should be deterministic regardless of input order."""

        tools = [
            {"name": n, "description": "d", "inputSchema": {"type": "object"}} for n in tool_names
        ]
        h1 = _hash_tool_list(tools)

        # Shuffle and hash again

        shuffled = list(tools)
        random.shuffle(shuffled)
        h2 = _hash_tool_list(shuffled)

        assert h1 == h2  # Hash is order-independent (sorted internally)
