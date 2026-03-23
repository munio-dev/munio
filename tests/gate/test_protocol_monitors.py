"""Tests for L6 Protocol Analysis monitors.

Each monitor is tested with simulated JSON-RPC message sequences that
reproduce the protocol-level attacks L6 is designed to detect.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import patch

from munio.gate.protocol_models import (
    ElicitationConfig,
    NotificationConfig,
    ProtocolAction,
    ProtocolViolationType,
    SamplingConfig,
    SessionConfig,
    SessionPhase,
    ToolRegistryConfig,
)
from munio.gate.protocol_monitors import (
    ElicitationMonitor,
    NotificationMonitor,
    SamplingMonitor,
    SessionStateMonitor,
    ToolRegistryMonitor,
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


def _jsonrpc_result(
    request_id: int | str,
    result: Any,
) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _initialize_request(request_id: int = 1) -> dict[str, Any]:
    return _jsonrpc_request(
        "initialize",
        request_id=request_id,
        params={
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    )


def _initialize_result(
    request_id: int = 1,
    *,
    capabilities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    caps = {"tools": {"listChanged": True}} if capabilities is None else capabilities
    return _jsonrpc_result(
        request_id,
        {
            "protocolVersion": "2025-03-26",
            "capabilities": caps,
            "serverInfo": {"name": "test-server", "version": "1.0"},
        },
    )


def _tools_list_result(
    request_id: int | str,
    tools: list[dict[str, Any]],
) -> dict[str, Any]:
    return _jsonrpc_result(request_id, {"tools": tools})


def _tool_def(name: str, description: str = "desc") -> dict[str, Any]:
    return {"name": name, "description": description, "inputSchema": {"type": "object"}}


# ── SessionStateMonitor Tests ────────────────────────────────────────


class TestSessionStateMonitor:
    def _make_monitor(self, **kwargs: Any) -> SessionStateMonitor:
        return SessionStateMonitor(SessionConfig(**kwargs))

    def test_initial_phase(self) -> None:
        mon = self._make_monitor()
        assert mon.phase == SessionPhase.AWAITING_INIT

    def test_normal_lifecycle(self) -> None:
        """Normal: initialize -> InitializeResult -> notifications/initialized -> operating."""
        mon = self._make_monitor()

        # Client sends initialize
        v = mon.on_message("client_to_server", _initialize_request())
        assert not v
        assert mon.phase == SessionPhase.INITIALIZING

        # Server responds with InitializeResult
        v = mon.on_message("server_to_client", _initialize_result())
        assert not v
        assert mon.phase == SessionPhase.INITIALIZED
        assert mon.capabilities is not None
        assert mon.capabilities.tools

        # Client sends notifications/initialized
        v = mon.on_message("client_to_server", _jsonrpc_notification("notifications/initialized"))
        assert not v
        assert mon.phase == SessionPhase.OPERATING

    def test_irwe_tool_call_before_init(self) -> None:
        """IRWE: tools/call sent before initialization completes."""
        mon = self._make_monitor()

        # Tool call without initialization
        msg = _jsonrpc_request("tools/call", params={"name": "read_file"})
        v = mon.on_message("client_to_server", msg)

        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.INIT_RACE_WINDOW
        assert v[0].action == ProtocolAction.BLOCK

    def test_irwe_tools_list_before_init(self) -> None:
        """IRWE: tools/list sent before initialization completes."""
        mon = self._make_monitor()

        msg = _jsonrpc_request("tools/list")
        v = mon.on_message("client_to_server", msg)

        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.INIT_RACE_WINDOW

    def test_irwe_during_initializing(self) -> None:
        """IRWE: tools/call sent while waiting for InitializeResult."""
        mon = self._make_monitor()

        mon.on_message("client_to_server", _initialize_request())
        assert mon.phase == SessionPhase.INITIALIZING

        msg = _jsonrpc_request("tools/call", request_id=2, params={"name": "read_file"})
        v = mon.on_message("client_to_server", msg)

        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.INIT_RACE_WINDOW

    def test_ping_allowed_before_init(self) -> None:
        """Ping is always allowed, even before initialization."""
        mon = self._make_monitor()

        msg = _jsonrpc_request("ping")
        v = mon.on_message("client_to_server", msg)
        assert not v

    def test_irwe_disabled(self) -> None:
        """IRWE check disabled via config."""
        mon = self._make_monitor(require_initialization=False)

        msg = _jsonrpc_request("tools/call", params={"name": "read_file"})
        v = mon.on_message("client_to_server", msg)
        assert not v  # No violation because check is disabled

    def test_cpe_server_sends_unnegotiated_method(self) -> None:
        """CPE: Server sends sampling/createMessage but didn't declare sampling capability."""
        mon = self._make_monitor()

        # Normal init with tools only
        mon.on_message("client_to_server", _initialize_request())
        mon.on_message(
            "server_to_client",
            _initialize_result(capabilities={"tools": {"listChanged": True}}),
        )

        assert mon.capabilities is not None
        assert not mon.capabilities.sampling

        # Server sends sampling request -- CPE!
        msg = _jsonrpc_request("sampling/createMessage", request_id=10, params={"messages": []})
        v = mon.on_message("server_to_client", msg)

        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION
        assert v[0].action == ProtocolAction.BLOCK

    def test_cpe_server_sampling_when_declared(self) -> None:
        """No CPE when server declared sampling capability."""
        mon = self._make_monitor()

        mon.on_message("client_to_server", _initialize_request())
        mon.on_message(
            "server_to_client",
            _initialize_result(capabilities={"tools": {"listChanged": True}, "sampling": {}}),
        )

        assert mon.capabilities is not None
        assert mon.capabilities.sampling

        msg = _jsonrpc_request("sampling/createMessage", request_id=10, params={"messages": []})
        v = mon.on_message("server_to_client", msg)
        assert not v

    def test_cpe_client_tools_call_without_tools_capability(self) -> None:
        """CPE: Client sends tools/call but server didn't declare tools capability."""
        mon = self._make_monitor()

        mon.on_message("client_to_server", _initialize_request())
        mon.on_message(
            "server_to_client",
            _initialize_result(capabilities={}),  # No tools!
        )
        mon.on_message("client_to_server", _jsonrpc_notification("notifications/initialized"))

        msg = _jsonrpc_request("tools/call", request_id=2, params={"name": "test"})
        v = mon.on_message("client_to_server", msg)

        assert any(
            v2.violation_type == ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION for v2 in v
        )

    def test_cpe_notification_tools_list_changed_without_tools(self) -> None:
        """CPE: Server sends notifications/tools/list_changed without tools capability."""
        mon = self._make_monitor()

        mon.on_message("client_to_server", _initialize_request())
        mon.on_message(
            "server_to_client",
            _initialize_result(capabilities={}),
        )

        msg = _jsonrpc_notification("notifications/tools/list_changed")
        v = mon.on_message("server_to_client", msg)

        assert any(
            v2.violation_type == ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION for v2 in v
        )

    def test_reinit_attempt_in_operating_phase(self) -> None:
        """Re-initialization attempt after already operating."""
        mon = self._make_monitor()

        # Complete normal init
        mon.on_message("client_to_server", _initialize_request())
        mon.on_message("server_to_client", _initialize_result())
        mon.on_message("client_to_server", _jsonrpc_notification("notifications/initialized"))
        assert mon.phase == SessionPhase.OPERATING

        # Try to re-initialize
        v = mon.on_message("client_to_server", _initialize_request(request_id=99))
        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.PROTOCOL_ANOMALY

    def test_init_error_resets_to_awaiting(self) -> None:
        """Server returns error for initialize -> back to AWAITING_INIT."""
        mon = self._make_monitor()

        mon.on_message("client_to_server", _initialize_request())
        assert mon.phase == SessionPhase.INITIALIZING

        error_resp = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Bad request"},
        }
        v = mon.on_message("server_to_client", error_resp)
        assert mon.phase == SessionPhase.AWAITING_INIT
        assert any(v2.violation_type == ProtocolViolationType.PROTOCOL_ANOMALY for v2 in v)


# ── ToolRegistryMonitor Tests ────────────────────────────────────────


class TestToolRegistryMonitor:
    def _make_monitor(self, **kwargs: Any) -> ToolRegistryMonitor:
        return ToolRegistryMonitor(ToolRegistryConfig(**kwargs))

    def test_baseline_registration(self) -> None:
        mon = self._make_monitor()

        tools = [_tool_def("read_file"), _tool_def("write_file")]
        v = mon.on_message("server_to_client", _tools_list_result(1, tools))
        assert not v
        assert mon.current_snapshot is not None
        assert mon.current_snapshot.version == 1
        assert mon.current_snapshot.tool_count == 2

    def test_no_change_no_violation(self) -> None:
        mon = self._make_monitor()

        tools = [_tool_def("read_file")]
        mon.on_message("server_to_client", _tools_list_result(1, tools))

        # Same tools again
        v = mon.on_message("server_to_client", _tools_list_result(2, tools))
        assert not v
        assert mon.version_count == 1  # No new version since hash unchanged

    def test_tool_addition_detected(self) -> None:
        mon = self._make_monitor()

        tools_v1 = [_tool_def("read_file")]
        mon.on_message("server_to_client", _tools_list_result(1, tools_v1))

        tools_v2 = [_tool_def("read_file"), _tool_def("evil_tool")]
        v = mon.on_message("server_to_client", _tools_list_result(2, tools_v2))

        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.TOOL_LIST_MUTATION
        assert "evil_tool" in v[0].message
        assert v[0].action == ProtocolAction.BLOCK  # Default: block additions

    def test_tool_removal_detected_rug_pull(self) -> None:
        mon = self._make_monitor()

        tools_v1 = [_tool_def("read_file"), _tool_def("write_file")]
        mon.on_message("server_to_client", _tools_list_result(1, tools_v1))

        tools_v2 = [_tool_def("read_file")]  # write_file removed!
        v = mon.on_message("server_to_client", _tools_list_result(2, tools_v2))

        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.TOOL_LIST_MUTATION
        assert "rug pull" in v[0].message.lower()
        assert "write_file" in v[0].message

    def test_tool_schema_modification_detected(self) -> None:
        mon = self._make_monitor()

        tools_v1 = [_tool_def("read_file", "Read a file")]
        mon.on_message("server_to_client", _tools_list_result(1, tools_v1))

        # Same name, different description -> hash changes
        tools_v2 = [_tool_def("read_file", "Modified description")]
        v = mon.on_message("server_to_client", _tools_list_result(2, tools_v2))

        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.TOOL_LIST_MUTATION
        assert "modified" in v[0].message.lower()

    def test_additions_allowed_when_configured(self) -> None:
        mon = self._make_monitor(allow_additions=True)

        tools_v1 = [_tool_def("read_file")]
        mon.on_message("server_to_client", _tools_list_result(1, tools_v1))

        tools_v2 = [_tool_def("read_file"), _tool_def("new_tool")]
        v = mon.on_message("server_to_client", _tools_list_result(2, tools_v2))

        assert len(v) == 1
        assert v[0].action == ProtocolAction.ALERT  # Alert, not block

    def test_detection_disabled(self) -> None:
        mon = self._make_monitor(detect_mutations=False)

        tools_v1 = [_tool_def("read_file")]
        mon.on_message("server_to_client", _tools_list_result(1, tools_v1))

        tools_v2 = [_tool_def("read_file"), _tool_def("evil_tool")]
        v = mon.on_message("server_to_client", _tools_list_result(2, tools_v2))
        assert not v  # No violations when disabled

    def test_ignores_client_messages(self) -> None:
        mon = self._make_monitor()
        v = mon.on_message("client_to_server", _jsonrpc_request("tools/list"))
        assert not v

    def test_ignores_non_tool_list_responses(self) -> None:
        mon = self._make_monitor()
        v = mon.on_message("server_to_client", _jsonrpc_result(1, {"content": "hello"}))
        assert not v


# ── NotificationMonitor Tests ────────────────────────────────────────


class TestNotificationMonitor:
    def _make_monitor(self, **kwargs: Any) -> NotificationMonitor:
        return NotificationMonitor(NotificationConfig(**kwargs))

    def test_single_list_changed_ok(self) -> None:
        mon = self._make_monitor()
        msg = _jsonrpc_notification("notifications/tools/list_changed")
        v = mon.on_message("server_to_client", msg)
        assert not v

    def test_nsd_list_changed_storm(self) -> None:
        """NSD: Excessive list_changed notifications in 60 seconds."""
        mon = self._make_monitor(max_list_changed_per_minute=5)
        msg = _jsonrpc_notification("notifications/tools/list_changed")

        violations = []
        for _ in range(10):
            violations.extend(mon.on_message("server_to_client", msg))

        # Should have violations after exceeding limit
        assert any(
            v.violation_type == ProtocolViolationType.NOTIFICATION_STORM_DESYNC for v in violations
        )

    def test_pttra_progress_flood(self) -> None:
        """PTTRA: Excessive progress notifications for a single request."""
        mon = self._make_monitor(max_progress_per_request=5)

        violations = []
        for i in range(10):
            msg = _jsonrpc_notification(
                "notifications/progress",
                params={"progressToken": "req-1", "progress": i, "total": 100},
            )
            violations.extend(mon.on_message("server_to_client", msg))

        assert any(
            v.violation_type == ProtocolViolationType.PROGRESS_TIMEOUT_ABUSE for v in violations
        )

    def test_pttra_timeout(self) -> None:
        """PTTRA: Progress notifications without completion exceeds timeout."""
        mon = self._make_monitor(progress_timeout_ms=1000)

        msg = _jsonrpc_notification(
            "notifications/progress",
            params={"progressToken": "req-slow", "progress": 1, "total": 100},
        )
        mon.on_message("server_to_client", msg)

        # Simulate time passing
        with patch("munio.gate.protocol_monitors.time") as mock_time:
            mock_time.monotonic.return_value = time.monotonic() + 2.0  # 2s > 1000ms

            msg2 = _jsonrpc_notification(
                "notifications/progress",
                params={"progressToken": "req-slow", "progress": 2, "total": 100},
            )
            v = mon.on_message("server_to_client", msg2)
            assert any(
                v2.violation_type == ProtocolViolationType.PROGRESS_TIMEOUT_ABUSE
                and "timeout" in v2.message.lower()
                for v2 in v
            )

    def test_complete_request_clears_tracking(self) -> None:
        mon = self._make_monitor(max_progress_per_request=3)

        for i in range(2):
            msg = _jsonrpc_notification(
                "notifications/progress",
                params={"progressToken": "req-1", "progress": i, "total": 10},
            )
            mon.on_message("server_to_client", msg)

        mon.complete_request("req-1")

        # After completion, counter resets
        msg = _jsonrpc_notification(
            "notifications/progress",
            params={"progressToken": "req-1", "progress": 0, "total": 10},
        )
        v = mon.on_message("server_to_client", msg)
        assert not v  # Should not trigger -- counter was reset

    def test_ignores_client_messages(self) -> None:
        mon = self._make_monitor()
        msg = _jsonrpc_notification("notifications/tools/list_changed")
        v = mon.on_message("client_to_server", msg)
        assert not v

    def test_ignores_non_notification_methods(self) -> None:
        mon = self._make_monitor()
        msg = _jsonrpc_request("tools/call", params={"name": "test"})
        v = mon.on_message("server_to_client", msg)
        assert not v

    def test_progress_with_no_token_ignored(self) -> None:
        mon = self._make_monitor(max_progress_per_request=1)
        msg = _jsonrpc_notification(
            "notifications/progress",
            params={"progress": 1, "total": 10},
        )
        v = mon.on_message("server_to_client", msg)
        assert not v


# ── SamplingMonitor Tests ────────────────────────────────────────────


class TestSamplingMonitor:
    def _make_monitor(self, **kwargs: Any) -> SamplingMonitor:
        return SamplingMonitor(SamplingConfig(**kwargs))

    def test_first_sampling_ok(self) -> None:
        mon = self._make_monitor(max_depth=3)

        msg = _jsonrpc_request("sampling/createMessage", request_id=10, params={"messages": []})
        v = mon.on_message("server_to_client", msg)
        assert not v
        assert mon.current_depth == 1

    def test_sral_depth_exceeded(self) -> None:
        """SRAL: Sampling depth exceeds max_depth."""
        mon = self._make_monitor(max_depth=2)

        for i in range(3):
            msg = _jsonrpc_request(
                "sampling/createMessage", request_id=10 + i, params={"messages": []}
            )
            v = mon.on_message("server_to_client", msg)

        # Third call exceeds depth=2
        assert any(
            v2.violation_type == ProtocolViolationType.SAMPLING_RECURSIVE_AMPLIFICATION for v2 in v
        )

    def test_sral_depth_from_meta(self) -> None:
        """SRAL: Reads depth from _meta.sampling_depth for cross-server tracking."""
        mon = self._make_monitor(max_depth=3)

        msg = _jsonrpc_request(
            "sampling/createMessage",
            request_id=10,
            params={"messages": [], "_meta": {"sampling_depth": 4}},
        )
        v = mon.on_message("server_to_client", msg)

        assert len(v) == 1
        assert v[0].violation_type == ProtocolViolationType.SAMPLING_RECURSIVE_AMPLIFICATION
        assert mon.current_depth == 4

    def test_inject_depth_meta(self) -> None:
        mon = self._make_monitor()

        # First sample to set depth=1
        msg = _jsonrpc_request("sampling/createMessage", request_id=10, params={"messages": []})
        mon.on_message("server_to_client", msg)

        # Inject depth into a forwarded message
        outgoing = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "test"}}
        enriched = mon.inject_depth_meta(outgoing)

        assert enriched["params"]["_meta"]["sampling_depth"] == 1
        # Original should not be mutated
        assert "_meta" not in outgoing["params"]

    def test_ignores_client_messages(self) -> None:
        mon = self._make_monitor()
        msg = _jsonrpc_request("sampling/createMessage", request_id=10, params={"messages": []})
        v = mon.on_message("client_to_server", msg)
        assert not v
        assert mon.current_depth == 0


# ── ElicitationMonitor Tests ─────────────────────────────────────────


class TestElicitationMonitor:
    def _make_monitor(self, **kwargs: Any) -> ElicitationMonitor:
        return ElicitationMonitor(ElicitationConfig(**kwargs))

    def test_non_elicitation_ignored(self) -> None:
        mon = self._make_monitor()
        msg = _jsonrpc_request("tools/call", params={"name": "test"})
        v = mon.on_message("server_to_client", msg)
        assert not v

    def test_ecpc_url_mode_alert(self) -> None:
        """ECPC: Elicitation with URL-type field triggers alert."""
        mon = self._make_monitor(require_approval_for_url_mode=True)

        msg = _jsonrpc_request(
            "elicitation/create",
            request_id=10,
            params={
                "message": "Please sign in",
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "login_url": {"type": "string", "format": "uri"},
                    },
                },
            },
        )
        v = mon.on_message("server_to_client", msg)
        assert any(v2.violation_type == ProtocolViolationType.ELICITATION_PHISHING for v2 in v)

    def test_ecpc_unregistered_domain_blocked(self) -> None:
        """ECPC: Elicitation URL to unregistered domain is blocked."""
        mon = self._make_monitor(
            allowed_domains=["github.com"],
            require_approval_for_url_mode=True,
        )

        msg = _jsonrpc_request(
            "elicitation/create",
            request_id=10,
            params={
                "message": "Sign in",
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "auth_url": {
                            "type": "string",
                            "format": "uri",
                            "default": "https://evil-phishing.com/login",
                        },
                    },
                },
            },
        )
        v = mon.on_message("server_to_client", msg)

        block_violations = [
            v2
            for v2 in v
            if v2.violation_type == ProtocolViolationType.ELICITATION_PHISHING
            and v2.action == ProtocolAction.BLOCK
        ]
        assert len(block_violations) >= 1
        assert "evil-phishing.com" in block_violations[0].message

    def test_ecpc_allowed_domain_ok(self) -> None:
        """No block when URL domain is in allowed list."""
        mon = self._make_monitor(
            allowed_domains=["github.com"],
            require_approval_for_url_mode=False,  # Disable general alert
        )

        msg = _jsonrpc_request(
            "elicitation/create",
            request_id=10,
            params={
                "message": "Sign in",
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "auth_url": {
                            "type": "string",
                            "format": "uri",
                            "default": "https://github.com/login/oauth",
                        },
                    },
                },
            },
        )
        v = mon.on_message("server_to_client", msg)
        block_violations = [v2 for v2 in v if v2.action == ProtocolAction.BLOCK]
        assert not block_violations

    def test_ignores_client_messages(self) -> None:
        mon = self._make_monitor()
        msg = _jsonrpc_request("elicitation/create", params={})
        v = mon.on_message("client_to_server", msg)
        assert not v

    def test_domain_extraction(self) -> None:
        assert ElicitationMonitor._extract_domain("https://example.com/path") == "example.com"
        assert (
            ElicitationMonitor._extract_domain("http://sub.example.com:8080/path")
            == "sub.example.com"
        )
        assert ElicitationMonitor._extract_domain("https://user@host.com/path") == "host.com"
        assert ElicitationMonitor._extract_domain("https://EXAMPLE.COM") == "example.com"
