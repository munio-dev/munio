"""munio scan data models: findings, tool definitions, server configs, scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum, IntEnum, unique
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ── Exceptions ───────────────────────────────────────────────────────────


class MunioScanError(Exception):
    """Base exception for all munio scan errors."""


# Backward compatibility alias
ProofScanError = MunioScanError


class ScanConnectionError(MunioScanError):
    """MCP server connection or communication failure."""


class DiscoveryError(MunioScanError):
    """Config file discovery or parsing failure."""


class SchemaLoadError(MunioScanError):
    """Tool definition file loading failure."""


# ── Enums ────────────────────────────────────────────────────────────────


@unique
class Layer(IntEnum):
    """Analysis layer identifier (decade-spaced for future insertions)."""

    L0_CONFIG = 5
    L1_SCHEMA = 10
    L2_HEURISTIC = 20
    L2_CLASSIFIER = 25
    L2_MULTILINGUAL = 26
    L3_STATIC = 30
    L4_Z3 = 40
    L5_COMPOSITIONAL = 50
    L6_FUZZING = 60
    L7_SOURCE = 70


@unique
class FindingSeverity(IntEnum):
    """Finding severity level (ordered: CRITICAL=0 highest)."""

    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


@unique
class AttackType(IntEnum):
    """MCP attack type category."""

    PROMPT_INJECTION = 1
    DATA_EXFILTRATION = 2
    COMMAND_INJECTION = 3
    PATH_TRAVERSAL = 4
    SSRF = 5
    CREDENTIAL_EXPOSURE = 6
    SYSTEM_PROMPT_EXTRACTION = 7
    CROSS_SERVER_SHADOWING = 8
    TOKEN_STUFFING = 9
    SCHEMA_PERMISSIVENESS = 10
    RUG_PULL = 11
    AUTHORIZATION_BYPASS = 12
    SUPPLY_CHAIN = 13
    CONFIG_INJECTION = 14


@unique
class OutputFormat(str, Enum):
    """CLI output format."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"


# ── Core models ──────────────────────────────────────────────────────────


class ToolDefinition(BaseModel):
    """MCP tool definition with its JSON Schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    title: str = ""
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None
    server_name: str = ""


class ServerConfig(BaseModel):
    """Discovered MCP server configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    source: str
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] | None = None
    url: str | None = None
    enabled: bool = True


class Finding(BaseModel):
    """Single security finding from a scan layer."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    layer: Layer
    severity: FindingSeverity
    tool_name: str
    message: str
    description: str = ""
    attack_type: AttackType | None = None
    cwe: str | None = None
    location: str = ""
    counterexample: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class SkippedLayer(BaseModel):
    """A scan layer that was requested but could not run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    layer: Layer
    reason: str
    install_hint: str


class ServerScanResult(BaseModel):
    """Scan result for a single MCP server."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server_name: str
    source: str
    tool_count: int = 0
    tools: list[ToolDefinition] = Field(default_factory=list)
    connected: bool = True
    error: str | None = None
    schema_completeness_avg: float = Field(default=0.0, ge=0.0, le=100.0)


class ScanResult(BaseModel):
    """Aggregate scan result across all servers/files."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    servers: list[ServerScanResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    elapsed_ms: float = 0.0
    enabled_layers: frozenset[Layer] = Field(default_factory=frozenset)
    skipped_layers: tuple[SkippedLayer, ...] = ()

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def by_severity(self) -> dict[str, int]:
        """Findings count grouped by severity name."""
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.severity.name
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def by_layer(self) -> dict[str, int]:
        """Findings count grouped by layer name."""
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.layer.name
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_json_dict(self) -> dict[str, object]:
        """Serialize to dict including computed properties (safe for JSON output).

        Enum fields are serialized as names (not integer values) for readability.
        """
        d: dict[str, object] = self.model_dump(mode="json")
        d["total_findings"] = self.total_findings
        d["by_severity"] = self.by_severity
        d["by_layer"] = self.by_layer

        # Convert IntEnum values to names for JSON consumers
        _severity_names = {s.value: s.name for s in FindingSeverity}
        _layer_names = {lyr.value: lyr.name for lyr in Layer}
        _attack_names = {a.value: a.name for a in AttackType}

        for f in d.get("findings", []):  # type: ignore[union-attr,attr-defined]
            if isinstance(f, dict):
                if "severity" in f and isinstance(f["severity"], int):
                    f["severity"] = _severity_names.get(f["severity"], f["severity"])
                if "layer" in f and isinstance(f["layer"], int):
                    f["layer"] = _layer_names.get(f["layer"], f["layer"])
                if "attack_type" in f and isinstance(f["attack_type"], int):
                    f["attack_type"] = _attack_names.get(f["attack_type"], f["attack_type"])

        return d


class ConfigPermissions(BaseModel):
    """Unix file permission check result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: int
    world_readable: bool = False
    world_writable: bool = False


class ConfigFileResult(BaseModel):
    """Scan result for a single config file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    ide: str = "unknown"
    servers_count: int = 0
    findings: list[Finding] = Field(default_factory=list)
    permissions: ConfigPermissions | None = None


class ConfigScanResult(BaseModel):
    """Aggregate config scan result across all discovered config files."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    files: list[ConfigFileResult] = Field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def total_findings(self) -> int:
        return sum(len(f.findings) for f in self.files)

    @property
    def all_findings(self) -> list[Finding]:
        result: list[Finding] = []
        for f in self.files:
            result.extend(f.findings)
        return result

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.all_findings:
            key = f.severity.name
            counts[key] = counts.get(key, 0) + 1
        return counts
