"""Perpetual Autonomous Self-Building Engine (AutopoiesisEngine).

Continuously runs in perpetuity (and on demand):
1. Harvests ensnared attacker artifacts -> dissects via Reverse Engineer Anything (REA)
2. Closes REA residual unknowns via targeted snare bait probes
3. Metabolizes attacker inner workings into verified defensive modules
4. Spawns recursive A/B candidate forks across trade-off axes & metabolized modules
5. Exhaustively tests EVERY option via OptionEvaluator
6. Strict Darwinian Survival: only options achieving strictly higher success rates (within
   false-positive guardrails) survive as immutable Git neural nodes; inferior options are
   culled as immutable Git tombstones.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any, Callable
from uuid import uuid4

from gigamesh.config import USE_CASE_OBJECTIVES
from gigamesh.control.snare import AdaptiveDeceptionSnare
from gigamesh.evolution.evaluator import OptionEvaluator
from gigamesh.human_sec.hub import HumanSecurityHub
from gigamesh.models.neural_repo import (
    EvolutionCandidateOutcome,
    EvolutionGenerationReport,
    ForkGenome,
    TradeOffVector,
)
from gigamesh.models.rea import ReaEvidenceDossier
from gigamesh.neural_repo.git_store import GitNeuralStore
from gigamesh.rea.bridge import ReaBridge
from gigamesh.rea.metabolism import MetabolismCompiler
from gigamesh.simulator.corpus import build_attack_scenarios


class AutopoiesisEngine:
    """Self-evolving Darwinian engine that builds and hardens GigaMesh in perpetuity."""

    def __init__(
        self,
        *,
        store: GitNeuralStore,
        evaluator: OptionEvaluator,
        snare: AdaptiveDeceptionSnare,
        rea_bridge: ReaBridge,
        metabolism: MetabolismCompiler,
        human_hub: HumanSecurityHub,
        interval_sec: float = 18.0,
        on_generation: Callable[[EvolutionGenerationReport], Any] | None = None,
    ) -> None:
        self.store = store
        self.evaluator = evaluator
        self.snare = snare
        self.rea_bridge = rea_bridge
        self.metabolism = metabolism
        self.human_hub = human_hub
        self.interval_sec = interval_sec
        self.on_generation = on_generation

        self.generation_counter: int = 0
        self.reports: list[EvolutionGenerationReport] = []
        self.dossiers: dict[str, ReaEvidenceDossier] = {}
        self.autopilot_running: bool = False
        self._task: asyncio.Task[Any] | None = None
        self._use_case_cycle = list(USE_CASE_OBJECTIVES.keys())
        self._scenarios = build_attack_scenarios()
        self._dissected_families: set[str] = set()
        self._rng = random.Random(42)

        # Ensure all genesis champions have baseline empirical benchmarks recorded
        self._benchmark_initial_forks()

    def _benchmark_initial_forks(self) -> None:
        modules_map = {m.module_id: m for m in self.store.list_modules()}
        rules = list(self.human_hub.rules.values())
        for fork in self.store.list_forks(include_culled=False):
            if fork.benchmark_stats is None:
                stats = self.evaluator.evaluate_fork(fork, modules_map, rules)
                fork.benchmark_stats = stats
                fork.alpha_weight = round(2.0 + stats.composite_success_rate * 6.0, 3)
                fork.beta_weight = round(2.0 + (1.0 - stats.composite_success_rate) * 6.0, 3)
                self.store.commit_fork(fork, message=f"baseline-benchmark({fork.use_case}): {fork.fork_id}")
                self.store.append_ledger(
                    use_case=fork.use_case,
                    fork_id=fork.fork_id,
                    event_kind="benchmark",
                    success_rate=stats.composite_success_rate,
                    metrics=stats.model_dump(),
                )

    # ------------------------------------------------------------------
    # Perpetual Background Loop
    # ------------------------------------------------------------------
    def start_autopilot(self) -> None:
        if self._task is not None and not self._task.done():
            self.autopilot_running = True
            return
        self.autopilot_running = True
        self._task = asyncio.create_task(self._perpetual_loop())

    def stop_autopilot(self) -> None:
        self.autopilot_running = False
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None

    async def _perpetual_loop(self) -> None:
        try:
            while self.autopilot_running:
                await asyncio.sleep(self.interval_sec)
                if not self.autopilot_running:
                    break
                report = await asyncio.to_thread(self.run_generation, None, "perpetual_autopoiesis")
                if self.on_generation:
                    maybe_coro = self.on_generation(report)
                    if asyncio.iscoroutine(maybe_coro):
                        await maybe_coro
        except asyncio.CancelledError:
            self.autopilot_running = False

    # ------------------------------------------------------------------
    # Single Autonomous Generation: Ensnare -> REA -> Metabolize -> Fork -> Test -> Survive/Cull
    # ------------------------------------------------------------------
    def run_generation(
        self,
        use_case: str | None = None,
        trigger: str = "manual_step",
    ) -> EvolutionGenerationReport:
        self.generation_counter += 1
        gen_id = self.generation_counter
        target_uc = use_case or self._use_case_cycle[(gen_id - 1) % len(self._use_case_cycle)]
        objective = USE_CASE_OBJECTIVES.get(target_uc, USE_CASE_OBJECTIVES["enterprise-balanced"])

        champion = self.store.get_champion(target_uc)
        modules_map = {m.module_id: m for m in self.store.list_modules()}
        rules = list(self.human_hub.rules.values())

        if champion.benchmark_stats is None:
            champion.benchmark_stats = self.evaluator.evaluate_fork(champion, modules_map, rules)
        incumbent_sr = champion.benchmark_stats.composite_success_rate

        artifacts_dissected: list[str] = []
        newly_metabolized_ids: list[str] = []

        # 1. Harvest & REA-Dissect an undissected attacker family (or latest live snare artifact)
        dissected_dossier = self._harvest_and_dissect_next(champion)
        if dissected_dossier is not None:
            self.dossiers[dissected_dossier.dossier_id] = dissected_dossier
            artifacts_dissected.append(dissected_dossier.artifact_id)
            compiled = self.metabolism.compile(dissected_dossier)
            for mod in compiled:
                if mod.safety_verified:
                    # Measure cross-attacker hits across corpus before committing
                    mod.cross_attacker_hits = self._measure_cross_hits(mod)
                    self.store.commit_metabolized_module(mod)
                    modules_map[mod.module_id] = mod
                    newly_metabolized_ids.append(mod.module_id)

        # 2. Generate recursive A/B candidate forks covering distinct trade-offs & metabolized modules
        candidates = self._spawn_candidates(
            champion=champion,
            generation=gen_id,
            available_module_ids=list(modules_map.keys()),
            newly_metabolized_ids=newly_metabolized_ids,
        )

        # 3. Exhaustively test EVERY candidate option & apply strict Darwinian survival
        outcomes: list[EvolutionCandidateOutcome] = []
        survivors: list[tuple[ForkGenome, float]] = []
        culled_ids: list[str] = []

        for mutation_kind, cand in candidates:
            stats = self.evaluator.evaluate_fork(cand, modules_map, rules)
            cand.benchmark_stats = stats
            delta = round(stats.composite_success_rate - incumbent_sr, 4)

            fp_ok = stats.false_positive_rate <= objective.max_false_positive_rate
            strictly_better = delta >= objective.min_improvement_delta

            if fp_ok and strictly_better:
                cand.status = "active"
                cand.alpha_weight = round(2.5 + stats.composite_success_rate * 8.0, 3)
                cand.beta_weight = round(2.0 + (1.0 - stats.composite_success_rate) * 5.0, 3)
                self.store.commit_fork(
                    cand,
                    message=f"survive(gen={gen_id},{target_uc}): {cand.fork_id} +{delta:.4f}",
                )
                self.store.append_ledger(
                    use_case=target_uc,
                    fork_id=cand.fork_id,
                    event_kind="benchmark",
                    success_rate=stats.composite_success_rate,
                    delta_vs_champion=delta,
                    metrics=stats.model_dump(),
                )
                survivors.append((cand, stats.composite_success_rate))
                verdict = f"SURVIVED (+{delta:.4f} success rate, FP={stats.false_positive_rate:.3f})"
            else:
                reason = (
                    f"FP ceiling exceeded ({stats.false_positive_rate:.3f} > {objective.max_false_positive_rate:.3f})"
                    if not fp_ok
                    else f"No strict improvement (delta={delta:+.4f} < +{objective.min_improvement_delta:.3f})"
                )
                self.store.cull_fork(cand, reason=reason)
                self.store.append_ledger(
                    use_case=target_uc,
                    fork_id=cand.fork_id,
                    event_kind="cull",
                    success_rate=stats.composite_success_rate,
                    delta_vs_champion=delta,
                    metrics={"reason": reason, **stats.model_dump()},
                )
                culled_ids.append(cand.fork_id)
                verdict = f"CULLED: {reason}"

            outcomes.append(
                EvolutionCandidateOutcome(
                    fork_id=cand.fork_id,
                    parent_fork_id=champion.fork_id,
                    use_case=target_uc,
                    mutation_kind=mutation_kind,
                    success_rate=stats.composite_success_rate,
                    incumbent_success_rate=incumbent_sr,
                    delta=delta,
                    false_positive_rate=stats.false_positive_rate,
                    survived=fp_ok and strictly_better,
                    verdict_reason=verdict,
                    git_commit_sha=cand.git_commit_sha,
                    metabolized_modules_added=[
                        m for m in cand.metabolized_module_ids if m not in champion.metabolized_module_ids
                    ],
                )
            )

        # 4. Promote the highest-scoring survivor to champion for this use case
        champion_after = champion.fork_id
        champion_sr_after = incumbent_sr
        if survivors:
            survivors.sort(key=lambda pair: pair[1], reverse=True)
            best_fork, best_sr = survivors[0]
            self.store.promote_champion(
                best_fork.fork_id,
                reason=f"gen={gen_id} +{best_sr - incumbent_sr:.4f}",
            )
            self.store.append_ledger(
                use_case=target_uc,
                fork_id=best_fork.fork_id,
                event_kind="promotion",
                success_rate=best_sr,
                delta_vs_champion=round(best_sr - incumbent_sr, 4),
                metrics={"promoted_over": champion.fork_id},
            )
            champion_after = best_fork.fork_id
            champion_sr_after = best_sr

            # If fork introduces newly metabolized modules under high quorum strictness, log human review request
            if best_fork.metabolized_module_ids and best_fork.trade_offs.human_quorum_strictness >= 0.55:
                self.human_hub.open_quorum(
                    action_kind="promote_metabolized_fork",
                    target_id=best_fork.fork_id,
                    use_case=target_uc,
                    summary=(
                        f"Verify production rollout of surviving fork {best_fork.fork_id} "
                        f"(success_rate={best_sr:.4f}, +{best_sr - incumbent_sr:.4f}) carrying "
                        f"{len(best_fork.metabolized_module_ids)} REA-metabolized defensive module(s)."
                    ),
                    evidence_refs=list(artifacts_dissected),
                )

        report = EvolutionGenerationReport(
            generation_id=gen_id,
            use_case=target_uc,
            trigger=trigger,
            artifacts_dissected=artifacts_dissected,
            modules_metabolized=newly_metabolized_ids,
            candidates_tested=outcomes,
            survivors=[f.fork_id for f, _ in survivors],
            culled=culled_ids,
            champion_before=champion.fork_id,
            champion_after=champion_after,
            champion_success_before=incumbent_sr,
            champion_success_after=champion_sr_after,
            net_improvement=round(champion_sr_after - incumbent_sr, 4),
        )
        self.reports.append(report)
        return report

    def _harvest_and_dissect_next(self, champion: ForkGenome) -> ReaEvidenceDossier | None:
        """Pick an undissected ensnared artifact (or harvest from the next undissected attacker family)."""
        # First check if live snare captured any undissected artifact
        dissected_art_ids = {d.artifact_id for d in self.dossiers.values()}
        for art in self.snare.artifacts.values():
            if art.artifact_id not in dissected_art_ids:
                dossier = self.rea_bridge.dissect(art, depth=champion.trade_offs.rea_dissection_depth)
                session = self.snare.sessions.get(art.snare_session_id)
                if session and dossier.residual_unknowns:
                    unk = dossier.residual_unknowns[0]
                    resp = self.snare.simulate_bait_probe_response(session, dossier, unk.probe_bait)
                    self.rea_bridge.resolve_unknown_from_snare_probe(dossier, unk.unknown_id, resp)
                return dossier

        # Otherwise proactively ensnare & dissect the next attacker family in the adversarial corpus
        next_scn = next(
            (s for s in self._scenarios if s.attacker_family not in self._dissected_families),
            None,
        )
        if next_scn is None:
            return None

        self._dissected_families.add(next_scn.attacker_family)
        session = self.snare.ensnare(
            attacker_id=next_scn.events[0].actor_id,
            attacker_family=next_scn.attacker_family,
            trace_id=next_scn.events[0].trace_id,
            fork_id=champion.fork_id,
        )
        artifact = self.snare.harvest_artifact(
            session=session,
            artifact_kind=next_scn.artifact_kind,
            filename=next_scn.artifact_filename,
            content_bytes=next_scn.artifact_bytes,
            sqlite_rows=next_scn.artifact_sqlite_rows,
            metadata={"scenario_id": next_scn.scenario_id},
        )
        dossier = self.rea_bridge.dissect(artifact, depth=max(0.6, champion.trade_offs.rea_dissection_depth))
        if dossier.residual_unknowns:
            unk = dossier.residual_unknowns[0]
            resp = self.snare.simulate_bait_probe_response(session, dossier, unk.probe_bait)
            self.rea_bridge.resolve_unknown_from_snare_probe(dossier, unk.unknown_id, resp)
        session.status = "dissected"
        return dossier

    def _spawn_candidates(
        self,
        *,
        champion: ForkGenome,
        generation: int,
        available_module_ids: list[str],
        newly_metabolized_ids: list[str],
    ) -> list[tuple[str, ForkGenome]]:
        """Spawn 4 competing recursive A/B child forks exploring distinct trade-off hypotheses."""
        candidates: list[tuple[str, ForkGenome]] = []
        base_tv = champion.trade_offs
        uc = champion.use_case

        def clamp(v: float, lo: float = 0.05, hi: float = 0.95) -> float:
            return round(max(lo, min(hi, v)), 3)

        # Candidate 1: Metabolic Fusion Fork (integrates newly metabolized REA modules + balanced tuning)
        unattached = [m for m in (newly_metabolized_ids + available_module_ids) if m not in champion.metabolized_module_ids]
        if unattached:
            added = unattached[:2]
            c1 = ForkGenome(
                fork_id=f"fork-g{generation}-metab-{uuid4().hex[:5]}",
                parent_fork_id=champion.fork_id,
                use_case=uc,
                generation=generation,
                status="shadow",
                rationale=f"Integrate REA-metabolized module(s) {', '.join(added)} into {champion.fork_id}.",
                trade_offs=TradeOffVector(
                    containment_aggressiveness=clamp(base_tv.containment_aggressiveness + (0.08 if uc != "stealth-intel-snare" else 0.02)),
                    deception_dwell_budget=clamp(base_tv.deception_dwell_budget + (0.08 if uc == "stealth-intel-snare" else 0.04)),
                    rea_dissection_depth=clamp(base_tv.rea_dissection_depth + 0.04),
                    human_quorum_strictness=base_tv.human_quorum_strictness,
                    false_positive_tolerance=clamp(base_tv.false_positive_tolerance - 0.02),
                    host_isolation_scope=clamp(base_tv.host_isolation_scope + 0.06),
                ),
                detector_threshold=clamp(champion.detector_threshold - 0.04, 0.42, 0.85),
                taint_strictness=clamp(champion.taint_strictness + 0.06, 0.25, 0.95),
                metabolized_module_ids=list(dict.fromkeys([*champion.metabolized_module_ids, *added])),
                human_rule_ids=list(champion.human_rule_ids),
            )
            candidates.append(("rea_metabolic_fusion", c1))

        # Candidate 2: Use-Case Trade-Off Specialist Fork
        is_snare = uc == "stealth-intel-snare"
        is_zt = uc == "zero-trust-critical"
        c2 = ForkGenome(
            fork_id=f"fork-g{generation}-tradeoff-{uuid4().hex[:5]}",
            parent_fork_id=champion.fork_id,
            use_case=uc,
            generation=generation,
            status="shadow",
            rationale=f"Recursive trade-off optimization specialized for {uc}.",
            trade_offs=TradeOffVector(
                containment_aggressiveness=clamp(base_tv.containment_aggressiveness + (0.14 if is_zt else (-0.06 if is_snare else 0.09))),
                deception_dwell_budget=clamp(base_tv.deception_dwell_budget + (0.12 if is_snare else (-0.05 if is_zt else 0.06))),
                rea_dissection_depth=clamp(base_tv.rea_dissection_depth + (0.10 if is_snare else -0.04)),
                human_quorum_strictness=clamp(base_tv.human_quorum_strictness - 0.05),
                false_positive_tolerance=clamp(base_tv.false_positive_tolerance - 0.03),
                host_isolation_scope=clamp(base_tv.host_isolation_scope + 0.10),
            ),
            detector_threshold=clamp(champion.detector_threshold - 0.03, 0.44, 0.85),
            taint_strictness=clamp(champion.taint_strictness + 0.08, 0.25, 0.95),
            metabolized_module_ids=list(champion.metabolized_module_ids),
            human_rule_ids=list(champion.human_rule_ids),
        )
        candidates.append(("use_case_tradeoff_split", c2))

        # Candidate 3: Ultra-Paranoid Low-Threshold Probe (tests FP guardrail culling!)
        c3 = ForkGenome(
            fork_id=f"fork-g{generation}-paranoid-{uuid4().hex[:5]}",
            parent_fork_id=champion.fork_id,
            use_case=uc,
            generation=generation,
            status="shadow",
            rationale="Aggressive low-threshold hypothesis testing false-positive ceiling boundary.",
            trade_offs=TradeOffVector(
                containment_aggressiveness=0.94,
                deception_dwell_budget=0.10,
                rea_dissection_depth=0.92,
                human_quorum_strictness=0.88,
                false_positive_tolerance=0.78,
                host_isolation_scope=0.95,
            ),
            detector_threshold=0.22,
            taint_strictness=0.95,
            metabolized_module_ids=list(champion.metabolized_module_ids),
            human_rule_ids=list(champion.human_rule_ids),
        )
        candidates.append(("aggressive_fp_boundary_test", c3))

        # Candidate 4: Ultra-Relaxed Low-Latency Hypothesis (tests recall regression culling!)
        c4 = ForkGenome(
            fork_id=f"fork-g{generation}-relaxed-{uuid4().hex[:5]}",
            parent_fork_id=champion.fork_id,
            use_case=uc,
            generation=generation,
            status="shadow",
            rationale="Minimal-overhead high-threshold hypothesis testing recall vs latency trade-off.",
            trade_offs=TradeOffVector(
                containment_aggressiveness=0.25,
                deception_dwell_budget=0.15,
                rea_dissection_depth=0.15,
                human_quorum_strictness=0.20,
                false_positive_tolerance=0.08,
                host_isolation_scope=0.20,
            ),
            detector_threshold=0.88,
            taint_strictness=0.25,
            metabolized_module_ids=list(champion.metabolized_module_ids),
            human_rule_ids=list(champion.human_rule_ids),
        )
        candidates.append(("low_overhead_recall_test", c4))

        return candidates

    def _measure_cross_hits(self, mod) -> dict[str, int]:
        """Count how many attacker scenarios (including DIFFERENT families) match this module's patterns."""
        import re

        hits: dict[str, int] = {}
        for scn in self._scenarios:
            blob = " ".join(
                f"{e.payload_preview} {e.target_resource or ''} {e.mcp_server or ''} {e.egress_destination or ''} {e.auditd_syscall or ''}"
                for e in scn.events
            ).lower()
            count = sum(1 for p in mod.match_patterns if p and re.search(p, blob, re.IGNORECASE))
            if count > 0:
                hits[scn.attacker_family] = count
        return hits
