"""Tests for Causal Provenance Graph multi-hop tainting and all 5 detection modules."""

from __future__ import annotations

from gigamesh.detectors.base import DetectorContext
from gigamesh.detectors.registry import DetectorRegistry
from gigamesh.human_sec.hub import HumanSecurityHub
from gigamesh.models.neural_repo import ForkGenome, TradeOffVector
from gigamesh.provenance.graph import CausalProvenanceGraph
from gigamesh.simulator.corpus import build_attack_scenarios, build_benign_baseline_events


def test_multi_hop_taint_and_all_attack_detectors() -> None:
    registry = DetectorRegistry()
    fork = ForkGenome(
        fork_id="fork-test",
        use_case="enterprise-balanced",
        detector_threshold=0.55,
        taint_strictness=0.72,
        trade_offs=TradeOffVector(containment_aggressiveness=0.65, deception_dwell_budget=0.55),
    )

    scenarios = build_attack_scenarios()
    for scn in scenarios[:5]:
        graph = CausalProvenanceGraph()
        human = HumanSecurityHub()
        all_hits = []
        last_gctx = None
        for raw in scn.events:
            evt = raw.model_copy(deep=True)
            human.ingest_human_signal(evt)
            evt.human_risk_score = human.get_human_risk(evt.human_principal_id)
            last_gctx = graph.ingest_event(evt)
            ctx = DetectorContext(fork=fork, graph_context=last_gctx)
            all_hits.extend(registry.evaluate_event(evt, ctx))

        assert len(all_hits) > 0, f"Expected detection hits for {scn.scenario_id}"
        assert any(h.attack_class == scn.expected_attack_class for h in all_hits)
        assert last_gctx is not None and last_gctx["patient_zero"] is not None

        # Verify graph snapshot exports nodes & edges cleanly
        snap = graph.snapshot(trace_id=scn.events[0].trace_id)
        assert len(snap["nodes"]) >= 2


def test_benign_baseline_produces_zero_false_positives() -> None:
    registry = DetectorRegistry()
    fork = ForkGenome(
        fork_id="fork-benign-check",
        use_case="enterprise-balanced",
        detector_threshold=0.55,
        taint_strictness=0.60,
    )
    graph = CausalProvenanceGraph()
    for evt in build_benign_baseline_events():
        gctx = graph.ingest_event(evt)
        hits = registry.evaluate_event(evt, DetectorContext(fork=fork, graph_context=gctx))
        assert hits == [], f"Unexpected false positive on benign trace {evt.trace_id}: {hits}"
