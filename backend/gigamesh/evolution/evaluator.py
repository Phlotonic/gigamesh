"""Exhaustive Option Benchmark Harness for GigaMesh's Darwinian selection gate.

Every candidate fork option MUST be empirically evaluated against all attacker families
AND benign enterprise workloads. Only options achieving a strictly higher use-case success
rate (without violating false-positive ceilings) survive.
"""

from __future__ import annotations

from gigamesh.config import USE_CASE_OBJECTIVES
from gigamesh.detectors.base import DetectorContext
from gigamesh.detectors.registry import DetectorRegistry
from gigamesh.human_sec.hub import HumanSecurityHub
from gigamesh.models.governance import HumanSynthesizedRule
from gigamesh.models.neural_repo import ForkBenchmarkStats, ForkGenome
from gigamesh.models.rea import MetabolizedDefenseModule
from gigamesh.provenance.graph import CausalProvenanceGraph
from gigamesh.simulator.corpus import AttackScenario, build_attack_scenarios, build_benign_baseline_events


class OptionEvaluator:
    """Runs deterministic multi-attacker + benign A/B benchmarks on any candidate ForkGenome."""

    def __init__(self, detector_registry: DetectorRegistry | None = None) -> None:
        self.detectors = detector_registry or DetectorRegistry()
        self.attack_scenarios: list[AttackScenario] = build_attack_scenarios()
        self.benign_events = build_benign_baseline_events()

    def evaluate_fork(
        self,
        fork: ForkGenome,
        modules_by_id: dict[str, MetabolizedDefenseModule],
        human_rules: list[HumanSynthesizedRule] | None = None,
    ) -> ForkBenchmarkStats:
        """Exhaustively test a candidate fork across all attacker families & benign traces."""
        objective = USE_CASE_OBJECTIVES.get(fork.use_case, USE_CASE_OBJECTIVES["enterprise-balanced"])
        active_modules = [
            modules_by_id[mid]
            for mid in fork.metabolized_module_ids
            if mid in modules_by_id and modules_by_id[mid].safety_verified
        ]
        rules = list(human_rules or [])

        # 1. Evaluate across all 6 attacker scenarios in isolated provenance graphs
        detected_scenarios = 0
        contained_score_sum = 0.0
        snare_score_sum = 0.0
        cross_transfer_hits = 0
        cross_transfer_possible = 0
        per_attacker_scores: dict[str, float] = {}

        for scn in self.attack_scenarios:
            graph = CausalProvenanceGraph()
            temp_human = HumanSecurityHub()
            scenario_hits = []
            for raw_evt in scn.events:
                evt = raw_evt.model_copy(deep=True)
                temp_human.ingest_human_signal(evt)
                evt.human_risk_score = max(evt.human_risk_score, temp_human.get_human_risk(evt.human_principal_id))
                g_ctx = graph.ingest_event(evt)
                d_ctx = DetectorContext(
                    fork=fork,
                    graph_context=g_ctx,
                    metabolized_modules=active_modules,
                    human_rules=rules,
                )
                scenario_hits.extend(self.detectors.evaluate_event(evt, d_ctx))

            detected = len(scenario_hits) > 0
            if detected:
                detected_scenarios += 1
                max_conf = max(h.confidence for h in scenario_hits)

                # Compute containment effectiveness for this scenario
                metab_contain_boost = sum(
                    m.containment_boost
                    for m in active_modules
                    if any(h.metabolized_module_id == m.module_id for h in scenario_hits)
                )
                c_score = min(
                    1.0,
                    0.42
                    + 0.36 * fork.trade_offs.containment_aggressiveness
                    + 0.14 * fork.trade_offs.host_isolation_scope
                    + 0.10 * max_conf
                    + min(0.20, metab_contain_boost),
                )
                contained_score_sum += c_score

                # Compute snare capture & REA dissection intelligence yield
                has_counter_snare = any(m.capability_kind == "mcp_counter_snare" for m in active_modules)
                s_score = min(
                    1.0,
                    0.22
                    + 0.48 * fork.trade_offs.deception_dwell_budget
                    + 0.24 * fork.trade_offs.rea_dissection_depth
                    + (0.12 if has_counter_snare else 0.0)
                    - 0.14 * max(0.0, fork.trade_offs.containment_aggressiveness - 0.72),
                )
                snare_score_sum += max(0.0, s_score)

                # Cross-attacker immunity: did a metabolized module trained on a DIFFERENT attacker fire here?
                cross_hits = [
                    h
                    for h in scenario_hits
                    if h.metabolized_module_id
                    and h.metabolized_module_id in modules_by_id
                    and modules_by_id[h.metabolized_module_id].source_attacker_family != scn.attacker_family
                ]
                if active_modules:
                    cross_transfer_possible += 1
                    if cross_hits:
                        cross_transfer_hits += 1

                per_attacker_scores[scn.attacker_family] = round(0.5 * max_conf + 0.5 * c_score, 4)
            else:
                per_attacker_scores[scn.attacker_family] = 0.0

        total_attacks = max(1, len(self.attack_scenarios))
        detection_recall = round(detected_scenarios / total_attacks, 4)
        containment_success = round(contained_score_sum / total_attacks, 4)
        snare_capture_rate = round(snare_score_sum / total_attacks, 4)
        cross_attacker_transfer = (
            round(cross_transfer_hits / cross_transfer_possible, 4)
            if cross_transfer_possible > 0
            else 0.0
        )

        # 2. Evaluate against benign enterprise baseline to measure false positives
        fp_count = 0
        benign_graph = CausalProvenanceGraph()
        for raw_evt in self.benign_events:
            evt = raw_evt.model_copy(deep=True)
            g_ctx = benign_graph.ingest_event(evt)
            d_ctx = DetectorContext(
                fork=fork,
                graph_context=g_ctx,
                metabolized_modules=active_modules,
                human_rules=rules,
            )
            hits = self.detectors.evaluate_event(evt, d_ctx)
            if hits:
                fp_count += 1

        # Threshold & tolerance calibration penalty (prevents trivial threshold=0.15 gaming)
        threshold_fp_risk = max(0.0, (0.40 - fork.detector_threshold) * 0.65)
        tolerance_fp_risk = max(0.0, (fork.trade_offs.false_positive_tolerance - 0.45) * 0.25)
        false_positive_rate = round(
            min(1.0, (fp_count / max(1, len(self.benign_events))) + threshold_fp_risk + tolerance_fp_risk),
            4,
        )
        precision_score = round(max(0.0, 1.0 - false_positive_rate), 4)

        # Latency efficiency reflects compute cost of deep dissection & strict quorum overhead
        overhead = (
            0.22 * fork.trade_offs.rea_dissection_depth
            + 0.14 * fork.trade_offs.human_quorum_strictness
            + 0.015 * len(active_modules)
        )
        latency_efficiency = round(max(0.25, 1.0 - overhead), 4)

        # Weighted composite success rate for this use case
        w = objective.weights
        composite = (
            w["detection_recall"] * detection_recall
            + w["containment_success"] * containment_success
            + w["precision_score"] * precision_score
            + w["snare_capture_rate"] * snare_capture_rate
            + w["cross_attacker_transfer"] * cross_attacker_transfer
            + w["latency_efficiency"] * latency_efficiency
            + max(-0.05, min(0.05, fork.human_reward_bonus))
        )
        composite_success_rate = round(min(1.0, max(0.0, composite)), 4)

        return ForkBenchmarkStats(
            detection_recall=detection_recall,
            containment_success=containment_success,
            false_positive_rate=false_positive_rate,
            precision_score=precision_score,
            snare_capture_rate=snare_capture_rate,
            cross_attacker_transfer=cross_attacker_transfer,
            latency_efficiency=latency_efficiency,
            composite_success_rate=composite_success_rate,
            scenarios_tested=len(self.attack_scenarios),
            benign_tested=len(self.benign_events),
            per_attacker_scores=per_attacker_scores,
        )
