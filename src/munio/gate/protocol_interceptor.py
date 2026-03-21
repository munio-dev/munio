"""L6 Protocol Interceptor: orchestrates protocol monitors within the gate proxy.

The ProtocolInterceptor sits alongside the existing Interceptor (L1-L5 constraint
checks) and inspects ALL JSON-RPC messages bidirectionally, not just tools/call.

Architecture:
                 agent (stdin)
                      |
                      v
           +--------------------+
           | ProtocolInterceptor |  <-- L6: inspects ALL messages both directions
           |  SessionStateMon   |
           |  ToolRegistryMon   |
           |  NotificationMon   |
           |  SamplingMon       |
           |  ElicitationMon    |
           +--------------------+
                      |
                      v
              +---------------+
              |  Interceptor  |  <-- L1-L5: inspects tools/call only
              +---------------+
                      |
                      v
               MCP Server (subprocess)

Message flow:
1. Client->Server: ProtocolInterceptor.on_client_message() -> violations?
   - If BLOCK violation: message is dropped, error returned to client
   - Otherwise: forwarded to Interceptor for tools/call check, then to server
2. Server->Client: ProtocolInterceptor.on_server_message() -> violations?
   - If BLOCK violation: message is dropped (not forwarded to client)
   - Otherwise: forwarded to client

Performance budget:
- L6 adds <1ms per message (pure Python dict inspection + threading.Lock)
- No I/O, no subprocess, no Z3
- Monitor state is bounded (capped collections, sliding windows)
"""

from __future__ import annotations

import json
import logging
from typing import Any

from munio.gate.protocol_models import (
    ProtocolAction,
    ProtocolConfig,
    ProtocolViolation,
)
from munio.gate.protocol_monitors import (
    Direction,
    ElicitationMonitor,
    NotificationMonitor,
    SamplingMonitor,
    SessionStateMonitor,
    ToolRegistryMonitor,
)

__all__ = ["ProtocolInterceptor"]

logger = logging.getLogger(__name__)

# Cap violation list per message to prevent memory bomb from a
# pathological message that triggers every monitor simultaneously.
_MAX_VIOLATIONS_PER_MESSAGE = 20


class ProtocolInterceptor:
    """Orchestrates L6 protocol monitors for bidirectional message inspection.

    Usage in proxy.py:

        protocol = ProtocolInterceptor(config)

        # For every client->server message:
        result = protocol.on_client_message(msg)
        if result.should_block:
            # send error back, don't forward
        else:
            # forward to server (and then to L1-L5 Interceptor for tools/call)

        # For every server->client message:
        result = protocol.on_server_message(msg)
        if result.should_block:
            # drop message, don't forward to client
    """

    __slots__ = (
        "_config",
        "_elicitation_monitor",
        "_notification_monitor",
        "_sampling_monitor",
        "_session_monitor",
        "_tool_monitor",
    )

    def __init__(self, config: ProtocolConfig | None = None) -> None:
        self._config = config or ProtocolConfig()
        self._session_monitor = SessionStateMonitor(self._config.session)
        self._tool_monitor = ToolRegistryMonitor(self._config.tool_registry)
        self._notification_monitor = NotificationMonitor(self._config.notifications)
        self._sampling_monitor = SamplingMonitor(self._config.sampling)
        self._elicitation_monitor = ElicitationMonitor(self._config.elicitation)

    @property
    def session_monitor(self) -> SessionStateMonitor:
        return self._session_monitor

    @property
    def tool_monitor(self) -> ToolRegistryMonitor:
        return self._tool_monitor

    @property
    def notification_monitor(self) -> NotificationMonitor:
        return self._notification_monitor

    @property
    def sampling_monitor(self) -> SamplingMonitor:
        return self._sampling_monitor

    def on_client_message(self, msg: dict[str, Any]) -> ProtocolResult:
        """Inspect a client->server message through all monitors.

        Returns a ProtocolResult indicating whether to block or forward.
        """
        if not self._config.enabled:
            return ProtocolResult.ALLOW

        direction: Direction = "client_to_server"
        violations: list[ProtocolViolation] = []

        # Run all monitors (order matters: session first for phase tracking)
        violations.extend(self._session_monitor.on_message(direction, msg))
        violations.extend(self._tool_monitor.on_message(direction, msg))
        violations.extend(self._notification_monitor.on_message(direction, msg))
        violations.extend(self._sampling_monitor.on_message(direction, msg))
        violations.extend(self._elicitation_monitor.on_message(direction, msg))

        # Cap violations
        if len(violations) > _MAX_VIOLATIONS_PER_MESSAGE:
            violations = violations[:_MAX_VIOLATIONS_PER_MESSAGE]

        return self._build_result(violations, direction, msg)

    def on_server_message(self, msg: dict[str, Any]) -> ProtocolResult:
        """Inspect a server->client message through all monitors.

        Returns a ProtocolResult indicating whether to block or forward.
        """
        if not self._config.enabled:
            return ProtocolResult.ALLOW

        direction: Direction = "server_to_client"
        violations: list[ProtocolViolation] = []

        # Run all monitors
        violations.extend(self._session_monitor.on_message(direction, msg))
        violations.extend(self._tool_monitor.on_message(direction, msg))
        violations.extend(self._notification_monitor.on_message(direction, msg))
        violations.extend(self._sampling_monitor.on_message(direction, msg))
        violations.extend(self._elicitation_monitor.on_message(direction, msg))

        if len(violations) > _MAX_VIOLATIONS_PER_MESSAGE:
            violations = violations[:_MAX_VIOLATIONS_PER_MESSAGE]

        return self._build_result(violations, direction, msg)

    def _build_result(
        self,
        violations: list[ProtocolViolation],
        direction: Direction,
        msg: dict[str, Any],
    ) -> ProtocolResult:
        """Build a ProtocolResult from collected violations."""
        if not violations:
            return ProtocolResult.ALLOW

        should_block = any(v.action == ProtocolAction.BLOCK for v in violations)

        # Log all violations
        for v in violations:
            level = logging.WARNING if v.action == ProtocolAction.BLOCK else logging.INFO
            logger.log(
                level,
                "L6 %s [%s] %s: %s",
                v.action.value.upper(),
                v.violation_type.value,
                v.monitor,
                v.message,
            )

        return ProtocolResult(
            should_block=should_block,
            violations=violations,
        )

    def make_block_response(
        self,
        request_id: int | float | str | None,
        violations: list[ProtocolViolation],
    ) -> bytes:
        """Build a JSON-RPC error response for a blocked protocol violation.

        Uses generic error message to avoid leaking monitor internals.
        """
        # Use generic message -- internal details go to stderr logs only
        safe_message = "Blocked by munio: protocol violation"
        error_code = -32600  # Invalid Request (closest JSON-RPC error code)

        resp: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": error_code,
                "message": safe_message,
            },
        }
        return json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"


class ProtocolResult:
    """Result of protocol-level message inspection."""

    __slots__ = ("should_block", "violations")

    # Singleton for the common "no violation" case to avoid allocation
    ALLOW: ProtocolResult  # Set below class definition

    def __init__(
        self,
        *,
        should_block: bool = False,
        violations: list[ProtocolViolation] | None = None,
    ) -> None:
        self.should_block = should_block
        self.violations = violations or []

    def __bool__(self) -> bool:
        """True if there are any violations (even non-blocking)."""
        return bool(self.violations)

    @property
    def block_violations(self) -> list[ProtocolViolation]:
        """Return only violations with BLOCK action."""
        return [v for v in self.violations if v.action == ProtocolAction.BLOCK]

    @property
    def alert_violations(self) -> list[ProtocolViolation]:
        """Return only violations with ALERT action."""
        return [v for v in self.violations if v.action == ProtocolAction.ALERT]


# Singleton for the no-violation case
ProtocolResult.ALLOW = ProtocolResult(should_block=False, violations=[])
