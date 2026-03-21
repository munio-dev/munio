"""Data models for L6 Protocol Analysis layer.

Defines protocol-level violation types, session state, MCP capability
tracking, and the ProtocolConfig model parsed from YAML.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ── Protocol violation severity (reuses ViolationSeverity concept) ────


class ProtocolViolationType(str, enum.Enum):
    """Classification of protocol-level attacks detected by L6 monitors."""

    # Session lifecycle
    INIT_RACE_WINDOW = "IRWE"  # Tool call before initialization complete
    CAPABILITY_PHANTOM_ESCALATION = "CPE"  # Server uses unnegotiated capability

    # Tool list integrity
    NOTIFICATION_STORM_DESYNC = "NSD"  # Excessive list_changed notifications
    TOOL_LIST_MUTATION = "TLM"  # Tool added/removed/modified mid-session

    # Progress / notification abuse
    PROGRESS_TIMEOUT_ABUSE = "PTTRA"  # Excessive progress without completion
    NOTIFICATION_FLOOD = "NF"  # Generic notification rate exceeded

    # Sampling recursion
    SAMPLING_RECURSIVE_AMPLIFICATION = "SRAL"  # Depth exceeded

    # Elicitation
    ELICITATION_PHISHING = "ECPC"  # URL-mode to unregistered domain

    # Transport
    TRANSPORT_DOWNGRADE = "TDBCP"  # Fallback to deprecated SSE transport

    # Catch-all
    PROTOCOL_ANOMALY = "ANOMALY"  # Unclassified protocol violation


class ProtocolAction(str, enum.Enum):
    """What L6 should do when a violation is detected."""

    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"


class ProtocolViolation(BaseModel):
    """A single protocol-level violation detected by an L6 monitor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    violation_type: ProtocolViolationType
    action: ProtocolAction
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    monitor: str = Field(description="Name of the monitor that detected this")


# ── MCP Session State ────────────────────────────────────────────────


class SessionPhase(str, enum.Enum):
    """MCP protocol lifecycle phases."""

    AWAITING_INIT = "awaiting_init"
    INITIALIZING = "initializing"  # initialize request sent, not yet responded
    INITIALIZED = "initialized"  # InitializeResult received, notifications/initialized sent
    OPERATING = "operating"  # Normal operation
    SHUTTING_DOWN = "shutting_down"  # Shutdown requested


class McpCapabilities(BaseModel):
    """Negotiated MCP server capabilities from InitializeResult.

    Tracks which features the server declared support for during handshake.
    Any server message referencing an undeclared capability is a CPE violation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tools: bool = False
    resources: bool = False
    prompts: bool = False
    logging: bool = False
    sampling: bool = False  # Server requests sampling from client
    roots: bool = False  # Server requests root list from client
    elicitation: bool = False  # Server requests elicitation from client
    experimental: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_initialize_result(cls, result: dict[str, Any]) -> McpCapabilities:
        """Parse capabilities from InitializeResult.result.capabilities."""
        caps = result.get("capabilities", {})
        if not isinstance(caps, dict):
            return cls()
        return cls(
            tools=isinstance(caps.get("tools"), dict),
            resources=isinstance(caps.get("resources"), dict),
            prompts=isinstance(caps.get("prompts"), dict),
            logging=isinstance(caps.get("logging"), dict),
            # Sampling/roots/elicitation are capability flags the server
            # declares it wants the client to support
            sampling="sampling" in caps,
            roots="roots" in caps,
            elicitation="elicitation" in caps,
            experimental=caps.get("experimental", {}),
        )


class ToolSnapshot(BaseModel):
    """A point-in-time snapshot of the tool list for version tracking."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = Field(description="Monotonic version counter")
    tool_names: tuple[str, ...] = Field(description="Sorted tool names")
    tool_hash: str = Field(description="SHA-256 of canonical tool list JSON")
    tool_count: int = Field(description="Number of tools")


# ── Protocol Configuration ───────────────────────────────────────────


class SessionConfig(BaseModel):
    """Configuration for session lifecycle monitoring."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    require_initialization: bool = Field(
        default=True,
        description="Block tool calls before initialization handshake completes",
    )
    max_init_timeout_ms: int = Field(
        default=5000,
        description="Maximum ms to wait for InitializeResult after initialize request",
        ge=100,
        le=60_000,
    )
    block_capability_escalation: bool = Field(
        default=True,
        description="Block server methods that reference unnegotiated capabilities",
    )


class NotificationConfig(BaseModel):
    """Configuration for notification rate limiting."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_list_changed_per_minute: int = Field(
        default=10,
        description="Max tools/list_changed notifications per minute",
        ge=1,
        le=1000,
    )
    max_progress_per_request: int = Field(
        default=100,
        description="Max progress notifications per single request token",
        ge=1,
        le=10_000,
    )
    progress_timeout_ms: int = Field(
        default=120_000,
        description="Force-timeout a request if only progress notifications, no result",
        ge=1000,
        le=600_000,
    )


class SamplingConfig(BaseModel):
    """Configuration for sampling recursion depth tracking."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_depth: int = Field(
        default=3,
        description="Maximum recursive sampling depth across servers",
        ge=1,
        le=20,
    )
    max_cost_budget_usd: float = Field(
        default=1.0,
        description="Maximum estimated cost budget for sampling chain (USD)",
        ge=0.0,
        le=100.0,
    )


class ElicitationConfig(BaseModel):
    """Configuration for elicitation phishing detection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_domains: list[str] = Field(
        default_factory=list,
        description="Domains allowed for URL-mode elicitation",
    )
    require_approval_for_url_mode: bool = Field(
        default=True,
        description="Always alert on URL-mode elicitation requests",
    )

    @field_validator("allowed_domains")
    @classmethod
    def _lowercase_domains(cls, v: list[str]) -> list[str]:
        return [d.lower().strip() for d in v if d.strip()]


class ToolRegistryConfig(BaseModel):
    """Configuration for tool list integrity monitoring."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    detect_mutations: bool = Field(
        default=True,
        description="Alert on tool additions/removals/modifications mid-session",
    )
    allow_additions: bool = Field(
        default=False,
        description="If True, new tools added mid-session only trigger alert (not block)",
    )
    allow_removals: bool = Field(
        default=False,
        description="If True, tool removals mid-session only trigger alert (not block)",
    )


class ProtocolConfig(BaseModel):
    """Root configuration for L6 Protocol Analysis layer.

    Parsed from YAML ``protocol:`` section in gate config or
    standalone ``protocol.yaml`` file.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=True, description="Enable L6 protocol monitoring")
    session: SessionConfig = Field(default_factory=SessionConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    sampling: SamplingConfig = Field(default_factory=SamplingConfig)
    elicitation: ElicitationConfig = Field(default_factory=ElicitationConfig)
    tool_registry: ToolRegistryConfig = Field(default_factory=ToolRegistryConfig)
