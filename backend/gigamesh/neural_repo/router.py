"""Contextual Mixture-of-Experts (MoE) Use-Case Router with Thompson Sampling."""

from __future__ import annotations

import random
from typing import Any

from gigamesh.models.neural_repo import ForkGenome
from gigamesh.neural_repo.git_store import GitNeuralStore


class ContextualMoERouter:
    """Routes incoming telemetry to surviving immutable forks via contextual Thompson Sampling.

    - Exploits the use-case champion while exploring active surviving sibling forks.
    - Dynamically biases toward higher-aggression forks when human-identity risk spikes.
    - Never routes live traffic to `culled` tombstones.
    """

    def __init__(self, store: GitNeuralStore, seed: int | None = None) -> None:
        self.store = store
        self._rng = random.Random(seed)

    def route(
        self,
        use_case: str,
        human_risk_score: float = 0.0,
        explore: bool = True,
    ) -> dict[str, Any]:
        """Select primary active fork + optional shadow A/B fork for recursive evaluation."""
        surviving = [
            f
            for f in self.store.list_forks(use_case=use_case, include_culled=False)
            if f.status in ("champion", "active")
        ]
        if not surviving:
            fallback = self.store.get_champion(use_case)
            return {"primary": fallback, "shadow": None, "routing_reason": "fallback_champion"}

        champion = next((f for f in surviving if f.status == "champion"), surviving[0])

        # Contextual gating: elevated human identity compromise shifts weight toward strict containment
        scored: list[tuple[float, ForkGenome]] = []
        for fork in surviving:
            if explore:
                sample = self._rng.betavariate(max(0.5, fork.alpha_weight), max(0.5, fork.beta_weight))
            else:
                sample = fork.alpha_weight / (fork.alpha_weight + fork.beta_weight)

            # Apply human-aggregated reward bonus + empirical benchmark anchor
            bench_anchor = (
                fork.benchmark_stats.composite_success_rate if fork.benchmark_stats else 0.55
            )
            context_bias = 0.0
            if human_risk_score >= 0.55:
                context_bias += 0.14 * fork.trade_offs.containment_aggressiveness
            if fork.status == "champion":
                context_bias += 0.04

            total_score = 0.45 * sample + 0.45 * bench_anchor + context_bias + fork.human_reward_bonus
            scored.append((total_score, fork))

        scored.sort(key=lambda item: item[0], reverse=True)
        primary = scored[0][1]
        shadow = scored[1][1] if len(scored) > 1 else None

        reason = (
            f"context_human_risk={human_risk_score:.2f}"
            if human_risk_score >= 0.55
            else f"thompson_moe(champion={champion.fork_id})"
        )
        return {
            "primary": primary,
            "shadow": shadow,
            "routing_reason": reason,
            "weights": {f.fork_id: round(score, 4) for score, f in scored},
        }

    def record_outcome(self, fork_id: str, success: bool, weight: float = 1.0) -> ForkGenome | None:
        """Update Beta synaptic priors for a fork based on live or human-verified outcomes."""
        fork = self.store.get_fork(fork_id)
        if not fork or fork.status == "culled":
            return None
        if success:
            fork.alpha_weight = round(fork.alpha_weight + weight, 4)
        else:
            fork.beta_weight = round(fork.beta_weight + weight, 4)
        self.store.commit_fork(fork, message=f"weight-update({fork.use_case}): {fork_id} success={success}")
        return fork
