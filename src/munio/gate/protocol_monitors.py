"""L6 Protocol Analysis monitors.

Four independent monitors that inspect JSON-RPC message flow and maintain
session state to detect protocol-level attacks on MCP:

- SessionStateMonitor: lifecycle tracking, capability escalation detection
- ToolRegistryMonitor: tool list versioning, mutation detection
- NotificationMonitor: rate limiting for notifications and progress
- SamplingMonitor: recursive sampling depth tracking

Each monitor is a Protocol implementor with:
- ``on_message(direction, msg) -> list[ProtocolViolation]``
- Thread-safe state via threading.Lock where needed

Monitors are stateful but do NOT block messages themselves. They return
violations; the ProtocolInterceptor decides block vs alert vs log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from typing import TYPE_CHECKING, Any, Literal

from munio.gate.protocol_models import (
    McpCapabilities,
    ProtocolAction,
    ProtocolViolation,
    ProtocolViolationType,
    SessionPhase,
    ToolSnapshot,
)

if TYPE_CHECKING:
    from munio.gate.protocol_models import (
        ElicitationConfig,
        NotificationConfig,
        SamplingConfig,
        SessionConfig,
        ToolRegistryConfig,
    )

__all__ = [
    "NotificationMonitor",
    "SamplingMonitor",
    "SessionStateMonitor",
    "ToolRegistryMonitor",
]

logger = logging.getLogger(__name__)

Direction = Literal["client_to_server", "server_to_client"]

# ── Helpers ──────────────────────────────────────────────────────────

# MCP methods that require specific capabilities.
# If the server sends a request/notification for a method but did NOT
# declare the capability, it is a CPE violation.
_CAPABILITY_METHOD_MAP: dict[str, str] = {
    # Server -> Client requests that require server to have declared capability
    "sampling/createMessage": "sampling",
    "roots/list": "roots",
    "elicitation/create": "elicitation",
    # Tool-related (server must have declared tools capability)
    "notifications/tools/list_changed": "tools",
    # Resource-related
    "notifications/resources/list_changed": "resources",
    "notifications/resources/updated": "resources",
    # Prompt-related
    "notifications/prompts/list_changed": "prompts",
    # Logging
    "notifications/message": "logging",
}

# Methods the client sends that require the server to have declared support
_CLIENT_METHODS_REQUIRING_CAPABILITY: dict[str, str] = {
    "tools/call": "tools",
    "tools/list": "tools",
    "resources/read": "resources",
    "resources/list": "resources",
    "resources/subscribe": "resources",
    "resources/unsubscribe": "resources",
    "prompts/get": "prompts",
    "prompts/list": "prompts",
    "logging/setLevel": "logging",
}


def _hash_tool_list(tools: list[dict[str, Any]]) -> str:
    """Compute SHA-256 of a canonical tool list representation."""
    # Sort by name for deterministic hashing
    canonical = sorted(tools, key=lambda t: t.get("name", ""))
    raw = json.dumps(canonical, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _extract_tool_names(tools: list[dict[str, Any]]) -> tuple[str, ...]:
    """Extract sorted tool names from a tools/list response."""
    return tuple(sorted(t.get("name", "") for t in tools if isinstance(t, dict)))


# ── SessionStateMonitor ──────────────────────────────────────────────


class SessionStateMonitor:
    """Tracks MCP lifecycle phases and negotiated capabilities.

    Detects:
    - IRWE: Tool calls before initialization completes
    - CPE: Server sends method referencing unnegotiated capability

    State machine:
    AWAITING_INIT -> INITIALIZING (on client sends initialize)
    INITIALIZING -> INITIALIZED (on server responds with InitializeResult)
    INITIALIZED -> OPERATING (on client sends notifications/initialized)
    OPERATING -> SHUTTING_DOWN (on either sends shutdown-related method)

    Thread safety: All state mutations under self._lock.
    """

    __slots__ = (
        "_capabilities",
        "_config",
        "_init_request_id",
        "_init_timestamp_ns",
        "_lock",
        "_phase",
        "_protocol_version",
        "_server_info",
    )

    def __init__(self, config: SessionConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._phase = SessionPhase.AWAITING_INIT
        self._capabilities: McpCapabilities | None = None
        self._init_request_id: int | float | str | None = None
        self._init_timestamp_ns: int = 0
        self._protocol_version: str = ""
        self._server_info: dict[str, Any] = {}

    @property
    def phase(self) -> SessionPhase:
        with self._lock:
            return self._phase

    @property
    def capabilities(self) -> McpCapabilities | None:
        with self._lock:
            return self._capabilities

    def on_message(
        self,
        direction: Direction,
        msg: dict[str, Any],
    ) -> list[ProtocolViolation]:
        """Process a JSON-RPC message and return any protocol violations."""
        violations: list[ProtocolViolation] = []

        method = msg.get("method")
        is_response = "result" in msg or "error" in msg

        with self._lock:
            if direction == "client_to_server":
                violations.extend(self._on_client_message(msg, method, is_response))
            else:
                violations.extend(self._on_server_message(msg, method, is_response))

        return violations

    def _on_client_message(
        self,
        msg: dict[str, Any],
        method: str | None,
        is_response: bool,
    ) -> list[ProtocolViolation]:
        violations: list[ProtocolViolation] = []

        if method == "initialize":
            # Client is starting initialization
            if self._phase == SessionPhase.AWAITING_INIT:
                self._phase = SessionPhase.INITIALIZING
                self._init_request_id = msg.get("id")
                self._init_timestamp_ns = time.monotonic_ns()
            # Re-initialization attempt
            elif self._phase in (SessionPhase.OPERATING, SessionPhase.INITIALIZED):
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.PROTOCOL_ANOMALY,
                        action=ProtocolAction.ALERT,
                        message="Re-initialization attempt in operating phase",
                        monitor="SessionStateMonitor",
                    )
                )

        elif method == "notifications/initialized":
            # Client confirms initialization complete
            if self._phase == SessionPhase.INITIALIZED:
                self._phase = SessionPhase.OPERATING
            elif self._phase != SessionPhase.OPERATING:
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.INIT_RACE_WINDOW,
                        action=ProtocolAction.ALERT,
                        message="notifications/initialized sent before InitializeResult received",
                        monitor="SessionStateMonitor",
                    )
                )

        elif method is not None and not is_response:
            # Any other client request/notification
            if (
                self._config.require_initialization
                and self._phase in (SessionPhase.AWAITING_INIT, SessionPhase.INITIALIZING)
                and method not in ("initialize", "notifications/initialized", "ping")
            ):
                # IRWE: Tool call before initialization complete
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.INIT_RACE_WINDOW,
                        action=ProtocolAction.BLOCK,
                        message=f"Method '{method}' sent before initialization complete",
                        details={"method": method, "phase": self._phase.value},
                        monitor="SessionStateMonitor",
                    )
                )

            # Check if method requires a capability the server didn't declare
            if self._capabilities is not None and method in _CLIENT_METHODS_REQUIRING_CAPABILITY:
                required_cap = _CLIENT_METHODS_REQUIRING_CAPABILITY[method]
                if not getattr(self._capabilities, required_cap, False):
                    violations.append(
                        ProtocolViolation(
                            violation_type=ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION,
                            action=ProtocolAction.BLOCK,
                            message=(
                                f"Client sent '{method}' but server did not declare "
                                f"'{required_cap}' capability"
                            ),
                            details={
                                "method": method,
                                "required_capability": required_cap,
                            },
                            monitor="SessionStateMonitor",
                        )
                    )

        return violations

    def _on_server_message(
        self,
        msg: dict[str, Any],
        method: str | None,
        is_response: bool,
    ) -> list[ProtocolViolation]:
        violations: list[ProtocolViolation] = []

        # Check if this is the InitializeResult response
        if is_response and self._phase == SessionPhase.INITIALIZING:
            msg_id = msg.get("id")
            if msg_id is not None and msg_id == self._init_request_id:
                if "error" in msg:
                    # Initialization failed -- must check BEFORE result
                    self._phase = SessionPhase.AWAITING_INIT
                    violations.append(
                        ProtocolViolation(
                            violation_type=ProtocolViolationType.PROTOCOL_ANOMALY,
                            action=ProtocolAction.ALERT,
                            message="Server returned error for initialize request",
                            monitor="SessionStateMonitor",
                        )
                    )
                else:
                    result = msg.get("result", {})
                    if isinstance(result, dict):
                        self._capabilities = McpCapabilities.from_initialize_result(result)
                        self._protocol_version = result.get("protocolVersion", "")
                        self._server_info = result.get("serverInfo", {})
                        self._phase = SessionPhase.INITIALIZED
                        logger.info(
                            "MCP initialized: protocol=%s, server=%s",
                            self._protocol_version,
                            self._server_info.get("name", "unknown"),
                        )

        # Check init timeout
        if self._phase == SessionPhase.INITIALIZING and self._init_timestamp_ns > 0:
            elapsed_ms = (time.monotonic_ns() - self._init_timestamp_ns) / 1_000_000
            if elapsed_ms > self._config.max_init_timeout_ms:
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.INIT_RACE_WINDOW,
                        action=ProtocolAction.ALERT,
                        message=(
                            f"Initialization timeout: {elapsed_ms:.0f}ms > "
                            f"{self._config.max_init_timeout_ms}ms"
                        ),
                        monitor="SessionStateMonitor",
                    )
                )

        # CPE: Server sends method requiring capability it didn't declare
        if (
            method is not None
            and not is_response
            and self._config.block_capability_escalation
            and self._capabilities is not None
            and method in _CAPABILITY_METHOD_MAP
        ):
            required_cap = _CAPABILITY_METHOD_MAP[method]
            if not getattr(self._capabilities, required_cap, False):
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.CAPABILITY_PHANTOM_ESCALATION,
                        action=ProtocolAction.BLOCK,
                        message=(
                            f"Server sent '{method}' but did not declare "
                            f"'{required_cap}' capability"
                        ),
                        details={
                            "method": method,
                            "required_capability": required_cap,
                        },
                        monitor="SessionStateMonitor",
                    )
                )

        return violations


# ── ToolRegistryMonitor ──────────────────────────────────────────────


class ToolRegistryMonitor:
    """Tracks tool list versions and detects mutations mid-session.

    On each tools/list response, hashes the tool list and compares to
    the previous version. Detects:
    - TLM: Tool additions, removals, or modifications
    - Rug pulls (tools disappearing after agent committed to using them)

    Maintains a monotonic version counter for auditing.
    """

    __slots__ = ("_config", "_lock", "_snapshots")

    def __init__(self, config: ToolRegistryConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._snapshots: list[ToolSnapshot] = []

    @property
    def current_snapshot(self) -> ToolSnapshot | None:
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    @property
    def version_count(self) -> int:
        with self._lock:
            return len(self._snapshots)

    def on_message(
        self,
        direction: Direction,
        msg: dict[str, Any],
    ) -> list[ProtocolViolation]:
        """Process message; only inspects server->client tools/list responses."""
        if direction != "server_to_client":
            return []

        # Only process responses that contain a tools list result
        result = msg.get("result")
        if not isinstance(result, dict):
            return []

        tools = result.get("tools")
        if not isinstance(tools, list):
            return []

        return self._process_tool_list(tools)

    def _process_tool_list(self, tools: list[dict[str, Any]]) -> list[ProtocolViolation]:
        """Compare new tool list against previous snapshot."""
        violations: list[ProtocolViolation] = []

        tool_names = _extract_tool_names(tools)
        tool_hash = _hash_tool_list(tools)

        with self._lock:
            version = len(self._snapshots) + 1
            new_snapshot = ToolSnapshot(
                version=version,
                tool_names=tool_names,
                tool_hash=tool_hash,
                tool_count=len(tools),
            )

            if not self._snapshots:
                # First tool list -- baseline
                self._snapshots.append(new_snapshot)
                logger.info(
                    "Tool registry baseline: v%d, %d tools, hash=%s",
                    version,
                    len(tools),
                    tool_hash[:12],
                )
                return violations

            prev = self._snapshots[-1]

            if tool_hash == prev.tool_hash:
                # No change
                return violations

            if not self._config.detect_mutations:
                self._snapshots.append(new_snapshot)
                return violations

            # Detect what changed
            prev_set = set(prev.tool_names)
            new_set = set(tool_names)
            added = new_set - prev_set
            removed = prev_set - new_set
            # Modified = same name but hash changed (detected via overall hash diff
            # with no add/remove)
            modified = not added and not removed and tool_hash != prev.tool_hash

            if added:
                action = (
                    ProtocolAction.ALERT if self._config.allow_additions else ProtocolAction.BLOCK
                )
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.TOOL_LIST_MUTATION,
                        action=action,
                        message=f"Tools added mid-session: {', '.join(sorted(added))}",
                        details={
                            "added": sorted(added),
                            "prev_version": prev.version,
                            "new_version": version,
                        },
                        monitor="ToolRegistryMonitor",
                    )
                )

            if removed:
                action = (
                    ProtocolAction.ALERT if self._config.allow_removals else ProtocolAction.BLOCK
                )
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.TOOL_LIST_MUTATION,
                        action=action,
                        message=f"Tools removed mid-session (rug pull): {', '.join(sorted(removed))}",
                        details={
                            "removed": sorted(removed),
                            "prev_version": prev.version,
                            "new_version": version,
                        },
                        monitor="ToolRegistryMonitor",
                    )
                )

            if modified:
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.TOOL_LIST_MUTATION,
                        action=ProtocolAction.ALERT,
                        message=("Tool schemas modified mid-session (same names, different hash)"),
                        details={
                            "prev_hash": prev.tool_hash[:16],
                            "new_hash": tool_hash[:16],
                            "prev_version": prev.version,
                            "new_version": version,
                        },
                        monitor="ToolRegistryMonitor",
                    )
                )

            self._snapshots.append(new_snapshot)

            # Cap snapshot history to prevent unbounded growth
            if len(self._snapshots) > 100:
                self._snapshots = self._snapshots[-50:]

        return violations


# ── NotificationMonitor ──────────────────────────────────────────────


class NotificationMonitor:
    """Rate-limits notifications and tracks per-request progress.

    Detects:
    - NSD: Excessive tools/list_changed notifications (desync attack)
    - PTTRA: Too many progress notifications for a single request
    - NF: Generic notification flooding

    Uses sliding window for rate limiting and per-token counters for progress.
    """

    __slots__ = (
        "_config",
        "_list_changed_timestamps",
        "_lock",
        "_progress_counters",
        "_progress_start_times",
    )

    # Max tracked in-flight requests to prevent memory growth
    _MAX_TRACKED_REQUESTS = 1000

    def __init__(self, config: NotificationConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        # Sliding window: timestamps of list_changed notifications
        self._list_changed_timestamps: list[float] = []
        # Per-request progress counter: progress_token -> count
        self._progress_counters: dict[str | int, int] = {}
        # Per-request start time: progress_token -> monotonic timestamp
        self._progress_start_times: dict[str | int, float] = {}

    def on_message(
        self,
        direction: Direction,
        msg: dict[str, Any],
    ) -> list[ProtocolViolation]:
        """Process message; inspects server->client notifications."""
        if direction != "server_to_client":
            return []

        method = msg.get("method")
        if method is None:
            return []

        violations: list[ProtocolViolation] = []

        if method == "notifications/tools/list_changed":
            violations.extend(self._check_list_changed_rate())

        elif method == "notifications/progress":
            violations.extend(self._check_progress(msg))

        return violations

    def _check_list_changed_rate(self) -> list[ProtocolViolation]:
        """Check if list_changed notifications exceed rate limit."""
        violations: list[ProtocolViolation] = []
        now = time.monotonic()

        with self._lock:
            self._list_changed_timestamps.append(now)

            # Prune timestamps older than 60 seconds
            cutoff = now - 60.0
            self._list_changed_timestamps = [
                ts for ts in self._list_changed_timestamps if ts > cutoff
            ]

            count = len(self._list_changed_timestamps)
            if count > self._config.max_list_changed_per_minute:
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.NOTIFICATION_STORM_DESYNC,
                        action=ProtocolAction.BLOCK,
                        message=(
                            f"Notification storm: {count} list_changed in 60s "
                            f"(limit: {self._config.max_list_changed_per_minute})"
                        ),
                        details={
                            "count": count,
                            "limit": self._config.max_list_changed_per_minute,
                            "window_seconds": 60,
                        },
                        monitor="NotificationMonitor",
                    )
                )

        return violations

    def _check_progress(self, msg: dict[str, Any]) -> list[ProtocolViolation]:
        """Check if progress notifications exceed per-request limit or timeout."""
        violations: list[ProtocolViolation] = []
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return violations

        progress_token = params.get("progressToken")
        if progress_token is None:
            return violations

        # Normalize token to str or int for dict key
        if not isinstance(progress_token, (str, int)):
            return violations

        now = time.monotonic()

        with self._lock:
            # Evict oldest entries if too many tracked requests
            if (
                progress_token not in self._progress_counters
                and len(self._progress_counters) >= self._MAX_TRACKED_REQUESTS
            ):
                # Evict oldest half by start time
                sorted_tokens = sorted(self._progress_start_times.items(), key=lambda x: x[1])
                evict_count = len(sorted_tokens) // 2
                for tok, _ in sorted_tokens[:evict_count]:
                    self._progress_counters.pop(tok, None)
                    self._progress_start_times.pop(tok, None)

            # Increment counter
            self._progress_counters[progress_token] = (
                self._progress_counters.get(progress_token, 0) + 1
            )
            if progress_token not in self._progress_start_times:
                self._progress_start_times[progress_token] = now

            count = self._progress_counters[progress_token]
            start = self._progress_start_times[progress_token]
            elapsed_ms = (now - start) * 1000

            # Check count limit
            if count > self._config.max_progress_per_request:
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.PROGRESS_TIMEOUT_ABUSE,
                        action=ProtocolAction.BLOCK,
                        message=(
                            f"Progress flood: {count} notifications for token "
                            f"'{progress_token}' (limit: {self._config.max_progress_per_request})"
                        ),
                        details={
                            "progress_token": str(progress_token),
                            "count": count,
                            "limit": self._config.max_progress_per_request,
                        },
                        monitor="NotificationMonitor",
                    )
                )

            # Check timeout
            if elapsed_ms > self._config.progress_timeout_ms:
                violations.append(
                    ProtocolViolation(
                        violation_type=ProtocolViolationType.PROGRESS_TIMEOUT_ABUSE,
                        action=ProtocolAction.ALERT,
                        message=(
                            f"Progress timeout: token '{progress_token}' active for "
                            f"{elapsed_ms:.0f}ms (limit: {self._config.progress_timeout_ms}ms)"
                        ),
                        details={
                            "progress_token": str(progress_token),
                            "elapsed_ms": elapsed_ms,
                            "timeout_ms": self._config.progress_timeout_ms,
                        },
                        monitor="NotificationMonitor",
                    )
                )

        return violations

    def complete_request(self, progress_token: str | int) -> None:
        """Mark a request as completed, removing its progress tracking."""
        with self._lock:
            self._progress_counters.pop(progress_token, None)
            self._progress_start_times.pop(progress_token, None)


# ── SamplingMonitor ──────────────────────────────────────────────────


class SamplingMonitor:
    """Tracks recursive sampling depth to detect SRAL attacks.

    When a server sends ``sampling/createMessage``, this is a server->client
    request asking the client to invoke an LLM. If the LLM response triggers
    another tool call that leads to another sampling request, this creates
    a recursive amplification chain.

    Depth tracking uses the ``_meta.sampling_depth`` field that munio injects
    into ``_meta`` of forwarded messages.

    Detects:
    - SRAL: Sampling depth exceeds max_depth
    """

    __slots__ = ("_config", "_current_depth", "_lock")

    def __init__(self, config: SamplingConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._current_depth: int = 0

    @property
    def current_depth(self) -> int:
        with self._lock:
            return self._current_depth

    def on_message(
        self,
        direction: Direction,
        msg: dict[str, Any],
    ) -> list[ProtocolViolation]:
        """Track sampling depth on server->client sampling/createMessage."""
        violations: list[ProtocolViolation] = []
        method = msg.get("method")

        if direction == "server_to_client" and method == "sampling/createMessage":
            with self._lock:
                # Read depth from _meta if present, otherwise increment
                params = msg.get("params", {})
                meta = params.get("_meta", {}) if isinstance(params, dict) else {}
                if isinstance(meta, dict) and "sampling_depth" in meta:
                    depth = meta.get("sampling_depth", 0)
                    if isinstance(depth, int):
                        self._current_depth = depth
                else:
                    self._current_depth += 1

                if self._current_depth > self._config.max_depth:
                    violations.append(
                        ProtocolViolation(
                            violation_type=ProtocolViolationType.SAMPLING_RECURSIVE_AMPLIFICATION,
                            action=ProtocolAction.BLOCK,
                            message=(
                                f"Sampling depth {self._current_depth} exceeds "
                                f"max_depth={self._config.max_depth}"
                            ),
                            details={
                                "current_depth": self._current_depth,
                                "max_depth": self._config.max_depth,
                            },
                            monitor="SamplingMonitor",
                        )
                    )

        return violations

    def inject_depth_meta(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Inject current sampling depth into a message's _meta for propagation.

        This allows downstream servers to know the current depth.
        Returns a shallow copy with _meta.sampling_depth set.
        """
        with self._lock:
            depth = self._current_depth

        params = msg.get("params")
        if not isinstance(params, dict):
            return msg

        # Shallow copy to avoid mutating the original
        new_msg = dict(msg)
        new_params = dict(params)
        meta = (
            dict(new_params.get("_meta", {})) if isinstance(new_params.get("_meta"), dict) else {}
        )
        meta["sampling_depth"] = depth
        new_params["_meta"] = meta
        new_msg["params"] = new_params
        return new_msg


# ── ElicitationMonitor (lightweight, part of SessionStateMonitor) ─────


class ElicitationMonitor:
    """Detects ECPC (Elicitation Phishing via Credential Pages).

    When server sends ``elicitation/create`` with ``requestedSchema`` containing
    a URL-type field or ``uri`` format, checks the URL against allowed domains.

    Also flags any URL-mode elicitation when require_approval_for_url_mode is set.
    """

    __slots__ = ("_config",)

    def __init__(self, config: ElicitationConfig) -> None:
        self._config = config

    def on_message(
        self,
        direction: Direction,
        msg: dict[str, Any],
    ) -> list[ProtocolViolation]:
        """Inspect server->client elicitation/create for phishing URLs."""
        if direction != "server_to_client":
            return []

        method = msg.get("method")
        if method != "elicitation/create":
            return []

        violations: list[ProtocolViolation] = []
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return violations

        requested_schema = params.get("requestedSchema", {})
        if not isinstance(requested_schema, dict):
            return violations

        # Check for URL-type fields in the schema
        urls_found = self._extract_url_fields(requested_schema)

        if urls_found and self._config.require_approval_for_url_mode:
            violations.append(
                ProtocolViolation(
                    violation_type=ProtocolViolationType.ELICITATION_PHISHING,
                    action=ProtocolAction.ALERT,
                    message="Elicitation request contains URL fields requiring user approval",
                    details={"url_fields": urls_found},
                    monitor="ElicitationMonitor",
                )
            )

        # Check URLs against domain allowlist
        if self._config.allowed_domains:
            for field_name, url_value in urls_found:
                if isinstance(url_value, str) and url_value.startswith(("http://", "https://")):
                    domain = self._extract_domain(url_value)
                    if domain and domain.lower() not in self._config.allowed_domains:
                        violations.append(
                            ProtocolViolation(
                                violation_type=ProtocolViolationType.ELICITATION_PHISHING,
                                action=ProtocolAction.BLOCK,
                                message=(f"Elicitation URL domain '{domain}' not in allowed list"),
                                details={
                                    "field": field_name,
                                    "domain": domain,
                                    "allowed": self._config.allowed_domains,
                                },
                                monitor="ElicitationMonitor",
                            )
                        )

        return violations

    @staticmethod
    def _extract_url_fields(
        schema: dict[str, Any],
        _depth: int = 0,
    ) -> list[tuple[str, Any]]:
        """Find fields with format:uri or type containing URL-like values."""
        if _depth > 5:
            return []

        results: list[tuple[str, Any]] = []
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return results

        for name, prop in properties.items():
            if not isinstance(prop, dict):
                continue
            fmt = prop.get("format", "")
            if fmt in ("uri", "url", "iri"):
                results.append((name, prop.get("default", "")))
            # Check nested objects
            if prop.get("type") == "object":
                results.extend(ElicitationMonitor._extract_url_fields(prop, _depth + 1))

        return results

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL without importing urllib (lightweight)."""
        # Strip protocol
        rest = url
        for prefix in ("https://", "http://"):
            if rest.startswith(prefix):
                rest = rest[len(prefix) :]
                break
        # Strip path, query, fragment
        for sep in ("/", "?", "#"):
            idx = rest.find(sep)
            if idx != -1:
                rest = rest[:idx]
        # Strip port
        idx = rest.rfind(":")
        if idx != -1:
            rest = rest[:idx]
        # Strip userinfo
        idx = rest.find("@")
        if idx != -1:
            rest = rest[idx + 1 :]
        return rest.lower()
