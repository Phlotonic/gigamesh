"""Canonical Agentic Security Event Format (ASEF) and incident models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ActorType(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    SUB_AGENT = "sub_agent"
    RED_HAT_SUSPECT = "red_hat_suspect"
    HOST = "host"
    EXTERNAL_SOURCE = "external_source"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"
    POISONED = "poisoned"


class EventType(str, Enum):
    CONTENT_INGEST = "content_ingest"
    PROMPT_EXECUTION = "prompt_execution"
    TOOL_MCP_CALL = "tool_mcp_call"
    SUBAGENT_SPAWN = "subagent_spawn"
    AGENT_MESSAGE = "agent_message"
    MEMORY_MUTATION = "memory_mutation"
    SKILL_MUTATION = "skill_mutation"
    HOST_AUDITD_SYSCALL = "host_auditd_syscall"
    SELINUX_AVC_DENIAL = "selinux_avc_denial"
    SYSTEMD_PERSISTENCE = "systemd_persistence"
    OPENSHIFT_POD_EXEC = "openshift_pod_exec"
    NETWORK_EGRESS = "network_egress"
    HUMAN_MFA_ANOMALY = "human_mfa_anomaly"
    HUMAN_PHISHING_REPORT = "human_phishing_report"
    OAUTH_DELEGATION_GRANT = "oauth_delegation_grant"
    CANARY_TRIP = "canary_trip"
    SNARE_INTERACTION = "snare_interaction"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AsefEvent(BaseModel):
    """Unified telemetry envelope spanning agentic, human, and Red Hat host layers."""

    event_id: str = Field(default_factory=lambda: f"evt-{uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=utc_now)
    trace_id: str = Field(default_factory=lambda: f"trc-{uuid4().hex[:10]}")
    parent_span_id: str | None = None
    span_id: str = Field(default_factory=lambda: f"spn-{uuid4().hex[:8]}")

    use_case: str = "enterprise-balanced"
    event_type: EventType
    actor_type: ActorType = ActorType.AGENT
    actor_id: str
    human_principal_id: str | None = None
    delegation_chain: list[str] = Field(default_factory=list)
    parent_agent_id: str | None = None

    privilege_level: int = Field(default=1, ge=0, le=10)
    tool_name: str | None = None
    mcp_server: str | None = None
    target_resource: str | None = None
    host_id: str | None = None

    source_trust_level: TrustLevel = TrustLevel.TRUSTED
    taint_labels: list[str] = Field(default_factory=list)
    payload_preview: str = ""
    original_goal: str = ""
    content_hash: str | None = None

    # Red-Hat offensive agent & RHEL/OpenShift host metadata
    loop_cadence_ms: float | None = None
    selinux_context: str | None = None
    auditd_syscall: str | None = None
    systemd_unit: str | None = None
    egress_destination: str | None = None

    # Human-layer risk enrichment (populated by HumanSecurityHub)
    human_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionHit(BaseModel):
    """Structured finding raised by a defensive detector or metabolized REA module."""

    hit_id: str = Field(default_factory=lambda: f"hit-{uuid4().hex[:10]}")
    detector_id: str
    attack_class: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    rationale: str
    event_id: str
    trace_id: str
    fork_id: str
    metabolized_module_id: str | None = None
    recommended_action: str = "monitor"
    indicators: list[str] = Field(default_factory=list)


class IncidentCase(BaseModel):
    """Correlated security incident with causal trace and active fork context."""

    case_id: str = Field(default_factory=lambda: f"inc-{uuid4().hex[:10]}")
    created_at: datetime = Field(default_factory=utc_now)
    trace_id: str
    use_case: str
    active_fork_id: str
    attacker_family: str = "unknown"
    severity: Severity
    title: str
    summary: str
    patient_zero: str | None = None
    human_principal_id: str | None = None
    blast_radius_nodes: list[str] = Field(default_factory=list)
    taint_chain: list[str] = Field(default_factory=list)
    hits: list[DetectionHit] = Field(default_factory=list)
    status: str = "open"  # open | ensnared | dissecting | quorum_pending | contained | resolved
    containment_action: str | None = None
    snare_session_id: str | None = None
    rea_dossier_id: str | None = None
    human_votes: int = 0
    human_consensus_label: str | None = None
