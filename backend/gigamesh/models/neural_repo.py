"""Models for GigaMesh's Repo-as-Immutable-Neural-Network and Darwinian A/B evolution."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TradeOffVector(BaseModel):
    """Normalized 6-axis defensive trade-off coordinates in [0, 1]^6."""

    containment_aggressiveness: float = Field(default=0.55, ge=0.0, le=1.0)
    deception_dwell_budget: float = Field(default=0.45, ge=0.0, le=1.0)
    rea_dissection_depth: float = Field(default=0.60, ge=0.0, le=1.0)
    human_quorum_strictness: float = Field(default=0.50, ge=0.0, le=1.0)
    false_positive_tolerance: float = Field(default=0.25, ge=0.0, le=1.0)
    host_isolation_scope: float = Field(default=0.50, ge=0.0, le=1.0)

    def as_dict(self) -> dict[str, float]:
        return self.model_dump()


class ForkBenchmarkStats(BaseModel):
    """Empirical metrics automatically uncovered by exhaustive multi-attacker benchmarking."""

    detection_recall: float = Field(ge=0.0, le=1.0)
    containment_success: float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)
    precision_score: float = Field(ge=0.0, le=1.0)
    snare_capture_rate: float = Field(ge=0.0, le=1.0)
    cross_attacker_transfer: float = Field(ge=0.0, le=1.0)
    latency_efficiency: float = Field(ge=0.0, le=1.0)
    composite_success_rate: float = Field(ge=0.0, le=1.0)
    scenarios_tested: int = 0
    benign_tested: int = 0
    per_attacker_scores: dict[str, float] = Field(default_factory=dict)


class ForkGenome(BaseModel):
    """Immutable defensive fork node stored in GigaMesh's Git neural DAG."""

    fork_id: str
    parent_fork_id: str | None = None
    git_commit_sha: str | None = None
    git_ref: str | None = None
    use_case: str
    generation: int = 0
    status: str = "active"  # active | champion | shadow | culled | quorum_pending
    created_at: datetime = Field(default_factory=utc_now)
    rationale: str = ""
    trade_offs: TradeOffVector = Field(default_factory=TradeOffVector)
    # Detector sensitivity thresholds & active metabolized defensive modules
    detector_threshold: float = Field(default=0.55, ge=0.15, le=0.95)
    taint_strictness: float = Field(default=0.60, ge=0.1, le=1.0)
    metabolized_module_ids: list[str] = Field(default_factory=list)
    human_rule_ids: list[str] = Field(default_factory=list)
    # Synaptic weight priors (Beta distribution alpha/beta for Thompson Sampling)
    alpha_weight: float = 2.0
    beta_weight: float = 2.0
    human_reward_bonus: float = 0.0
    benchmark_stats: ForkBenchmarkStats | None = None
    cull_reason: str | None = None


class StatLedgerEntry(BaseModel):
    """Hash-chained append-only neural weight ledger record."""

    entry_id: str = Field(default_factory=lambda: f"ldg-{uuid4().hex[:10]}")
    timestamp: datetime = Field(default_factory=utc_now)
    prev_hash: str
    entry_hash: str = ""
    use_case: str
    fork_id: str
    git_commit_sha: str | None = None
    event_kind: str  # benchmark | live_outcome | human_vote | promotion | cull
    success_rate: float
    delta_vs_champion: float = 0.0
    metrics: dict[str, Any] = Field(default_factory=dict)
    signer: str = "gigamesh-autopoiesis"


class EvolutionCandidateOutcome(BaseModel):
    """Audit trail for a single tested option in an evolution generation."""

    fork_id: str
    parent_fork_id: str
    use_case: str
    mutation_kind: str
    success_rate: float
    incumbent_success_rate: float
    delta: float
    false_positive_rate: float
    survived: bool
    verdict_reason: str
    git_commit_sha: str | None = None
    metabolized_modules_added: list[str] = Field(default_factory=list)


class EvolutionGenerationReport(BaseModel):
    """Summary of one autonomous perpetual self-building generation."""

    generation_id: int
    timestamp: datetime = Field(default_factory=utc_now)
    use_case: str
    trigger: str = "autopoiesis"
    artifacts_dissected: list[str] = Field(default_factory=list)
    modules_metabolized: list[str] = Field(default_factory=list)
    candidates_tested: list[EvolutionCandidateOutcome] = Field(default_factory=list)
    survivors: list[str] = Field(default_factory=list)
    culled: list[str] = Field(default_factory=list)
    champion_before: str | None = None
    champion_after: str | None = None
    champion_success_before: float = 0.0
    champion_success_after: float = 0.0
    net_improvement: float = 0.0
