"""Models for Reverse Engineer Anything (morluto/rea) dissection and defensive metabolism."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CapturedArtifact(BaseModel):
    """Forensic artifact harvested from an ensnared attacking agent or red-hat host."""

    artifact_id: str = Field(default_factory=lambda: f"art-{uuid4().hex[:10]}")
    captured_at: datetime = Field(default_factory=utc_now)
    snare_session_id: str
    attacker_family: str
    artifact_kind: str  # javascript_bundle | elf_native_binary | sqlite_memory | mcp_protocol_trace | systemd_dropper
    filename: str
    file_path: str | None = None
    sha256: str
    size_bytes: int
    raw_excerpt: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReaEvidenceItem(BaseModel):
    """Single provenance-backed finding returned by REA (or REA-contract static engine)."""

    evidence_id: str = Field(default_factory=lambda: f"evd-{uuid4().hex[:8]}")
    category: str  # obfuscation | tool_schema | c2_protocol | evasion_loop | persistence | syscall_pattern | prompt_template
    symbol_or_offset: str
    summary: str
    extracted_pattern: str
    confidence: float = Field(ge=0.0, le=1.0)
    source_tool: str  # e.g. rea_analyze_javascript_application, rea_decompile, rea_inspect_sqlite_database


class ResidualUnknown(BaseModel):
    """Explicit unknown surfaced by REA that triggers an adaptive snare follow-up probe."""

    unknown_id: str = Field(default_factory=lambda: f"unk-{uuid4().hex[:8]}")
    description: str
    hypothesis: str
    probe_bait: str
    resolved: bool = False
    resolution_evidence: str | None = None


class ReaEvidenceDossier(BaseModel):
    """Complete structured dissection report from Reverse Engineer Anything."""

    dossier_id: str = Field(default_factory=lambda: f"rea-{uuid4().hex[:10]}")
    created_at: datetime = Field(default_factory=utc_now)
    artifact_id: str
    attacker_family: str
    engine_mode: str  # live_rea_cli | live_rea_mcp | deterministic_rea_contract
    rea_commands_executed: list[str] = Field(default_factory=list)
    evidence_items: list[ReaEvidenceItem] = Field(default_factory=list)
    residual_unknowns: list[ResidualUnknown] = Field(default_factory=list)
    behavioral_summary: str = ""
    dissection_completeness: float = Field(default=0.0, ge=0.0, le=1.0)
    probe_rounds: int = 0


class MetabolizedDefenseModule(BaseModel):
    """Sanitized defensive primitive compiled from a dissected attacker's inner workings."""

    module_id: str = Field(default_factory=lambda: f"metab-{uuid4().hex[:10]}")
    created_at: datetime = Field(default_factory=utc_now)
    source_dossier_id: str
    source_attacker_family: str
    name: str
    capability_kind: str  # decoder_preprocessor | behavioral_loop_detector | mcp_counter_snare | persistence_guard | rhel_hardening
    description: str
    # Executable matching / counter-defense specification consumed live by GigaMesh detectors & snares
    match_patterns: list[str] = Field(default_factory=list)
    target_attack_classes: list[str] = Field(default_factory=list)
    detection_boost: float = Field(default=0.22, ge=0.05, le=0.50)
    containment_boost: float = Field(default=0.18, ge=0.05, le=0.45)
    snare_bait_templates: list[str] = Field(default_factory=list)
    rhel_hardening_snippet: str | None = None
    safety_verified: bool = True
    safety_notes: str = "Verified strictly in-perimeter defensive capability; zero outbound exploit logic."
    cross_attacker_hits: dict[str, int] = Field(default_factory=dict)
    quorum_approved: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
