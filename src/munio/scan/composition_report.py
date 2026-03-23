"""Models for multi-server composition analysis reports."""

from __future__ import annotations

from enum import Enum, unique

from pydantic import BaseModel, ConfigDict, Field


@unique
class DangerGrade(str, Enum):
    """Danger grade classification."""

    A = "A"  # <20
    B = "B"  # >=20
    C = "C"  # >=40
    D = "D"  # >=60
    F = "F"  # >=80


class ChainNode(BaseModel):
    """A single node in an attack chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str
    server_name: str = ""
    capabilities: list[str] = Field(default_factory=list)
    role: str = ""  # "P", "U", "S", "P|U", etc.


class AttackChain(BaseModel):
    """A detected multi-hop attack chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: list[ChainNode]
    risk: str  # "CRITICAL", "HIGH", "MEDIUM"
    description: str
    cwe: str = ""
    cross_server: bool = False
    score: float = 0.0
    signal: str = "low"  # "high", "medium", "low" — chain quality signal


class DangerScore(BaseModel):
    """Computed danger score for a configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    score: float = Field(ge=0.0, le=100.0)
    grade: DangerGrade
    chain_count: int = 0
    server_count: int = 0
    amplification: float = 1.0


class CVEDraft(BaseModel):
    """Auto-generated CVE filing draft."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str
    affected_servers: list[str] = Field(default_factory=list)
    description: str
    chain: AttackChain
    cvss_vector: str = ""
    cvss_score: float = 0.0
    cvss_estimated: bool = True
    poc_narrative: str = ""


class CompositionReport(BaseModel):
    """Full composition analysis report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str
    server_count: int = 0
    tool_count: int = 0
    chains: list[AttackChain] = Field(default_factory=list)
    danger: DangerScore
    cve_drafts: list[CVEDraft] = Field(default_factory=list)
    elapsed_ms: float = 0.0
