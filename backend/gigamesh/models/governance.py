"""Models for Human Security Aggregation, HITL Quorum, Federated STIX, and Red-Hat Controls."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HumanIdentityRisk(BaseModel):
    """Aggregated human-layer security risk state that propagates to delegated agents."""

    human_principal_id: str
    display_name: str
    department: str = "engineering"
    risk_score: float = Field(default=0.05, ge=0.0, le=1.0)
    mfa_anomalies: int = 0
    phishing_reports: int = 0
    suspicious_oauth_grants: int = 0
    active_delegated_agents: list[str] = Field(default_factory=list)
    last_signal_at: datetime = Field(default_factory=utc_now)
    notes: list[str] = Field(default_factory=list)


class AnalystVote(BaseModel):
    """Collective analyst review & reward vote that updates Neural Repo weights."""

    vote_id: str = Field(default_factory=lambda: f"vot-{uuid4().hex[:10]}")
    timestamp: datetime = Field(default_factory=utc_now)
    analyst_id: str
    analyst_reputation: float = Field(default=1.0, ge=0.1, le=3.0)
    target_kind: str  # incident | fork | metabolized_module | candidate_rule
    target_id: str
    verdict: str  # confirm_threat | false_positive | approve_promotion | reject
    annotation: str = ""
    proposed_pattern: str | None = None


class HumanSynthesizedRule(BaseModel):
    """Detection rule compiled from weighted collective analyst consensus."""

    rule_id: str = Field(default_factory=lambda: f"hrule-{uuid4().hex[:8]}")
    created_at: datetime = Field(default_factory=utc_now)
    title: str
    attack_class: str
    pattern: str
    author_analysts: list[str] = Field(default_factory=list)
    consensus_weight: float = 0.0
    active: bool = True


class QuorumSignature(BaseModel):
    analyst_id: str
    decision: str  # approve | reject
    signed_at: datetime = Field(default_factory=utc_now)
    signature_digest: str
    comment: str = ""


class QuorumRequest(BaseModel):
    """Cryptographic M-of-N Human-in-the-Loop gate for high-impact containment or fork promotion."""

    quorum_id: str = Field(default_factory=lambda: f"qrm-{uuid4().hex[:10]}")
    created_at: datetime = Field(default_factory=utc_now)
    action_kind: str  # promote_metabolized_fork | revoke_org_oauth | rhel_host_isolate | deploy_counter_snare
    target_id: str
    use_case: str
    risk_tier: str = "tier2_high_impact"
    required_approvals: int = 2
    status: str = "pending"  # pending | approved | rejected | fail_closed_quarantined
    summary: str
    evidence_refs: list[str] = Field(default_factory=list)
    signatures: list[QuorumSignature] = Field(default_factory=list)
    executed_result: dict[str, Any] | None = None


class FederatedStixBundle(BaseModel):
    """Anonymized, PII-scrubbed STIX 2.1 threat intelligence & graph-motif bundle."""

    bundle_id: str = Field(default_factory=lambda: f"bundle--{uuid4()}")
    spec_version: str = "2.1"
    created_at: datetime = Field(default_factory=utc_now)
    origin_org_hash: str
    signature: str
    trust_score: float = Field(default=0.85, ge=0.0, le=1.0)
    motifs: list[dict[str, Any]] = Field(default_factory=list)
    imported: bool = False


class RedHatControlOrder(BaseModel):
    """Auditable containment artifact for Red Hat Enterprise Linux / OpenShift or offensive red-hat systems."""

    order_id: str = Field(default_factory=lambda: f"rhc-{uuid4().hex[:10]}")
    created_at: datetime = Field(default_factory=utc_now)
    target_kind: str  # offensive_agent | rhel_host | openshift_namespace | mcp_server
    target_id: str
    mode: str = "dry_run_validated"  # dry_run_validated | enforced_simulated
    quorum_id: str | None = None
    selinux_policy: str = ""
    nftables_rules: str = ""
    auditd_rules: str = ""
    systemd_commands: list[str] = Field(default_factory=list)
    openshift_network_policy: str = ""
    mcp_block_rules: list[str] = Field(default_factory=list)
    status: str = "generated"
