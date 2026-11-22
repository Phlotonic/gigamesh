"""Tests for Reverse Engineer Anything (morluto/rea) dissection, unknown-resolution loop,
and cross-attacker defensive metabolism.
"""

from __future__ import annotations

from pathlib import Path

from gigamesh.control.snare import AdaptiveDeceptionSnare
from gigamesh.detectors.base import DetectorContext
from gigamesh.detectors.registry import DetectorRegistry
from gigamesh.models.neural_repo import ForkGenome
from gigamesh.provenance.graph import CausalProvenanceGraph
from gigamesh.rea.bridge import ReaBridge
from gigamesh.rea.metabolism import MetabolismCompiler
from gigamesh.simulator.corpus import build_attack_scenarios


def test_ensnare_rea_dissect_resolve_unknowns_and_cross_attacker_immunity(tmp_path: Path) -> None:
    snare = AdaptiveDeceptionSnare(tmp_path / "artifacts")
    rea = ReaBridge()
    compiler = MetabolismCompiler()
    scenarios = {s.scenario_id: s for s in build_attack_scenarios()}

    # 1. Ensnare & dissect Attacker A (obfuscated-doc-injector JS stager)
    scn_a = scenarios["scn-prompt-injection"]
    session = snare.ensnare(
        attacker_id="agent-doc-summarizer",
        attacker_family=scn_a.attacker_family,
        trace_id=scn_a.events[0].trace_id,
        fork_id="fork-genesis-stealth-snare",
    )
    artifact = snare.harvest_artifact(
        session=session,
        artifact_kind=scn_a.artifact_kind,
        filename=scn_a.artifact_filename,
        content_bytes=scn_a.artifact_bytes,
    )
    assert Path(artifact.file_path).exists()

    dossier = rea.dissect(artifact, depth=0.8)
    assert len(dossier.evidence_items) >= 2
    assert len(dossier.residual_unknowns) >= 1
    initial_completeness = dossier.dissection_completeness

    # 2. Resolve residual unknown via targeted snare bait probe
    unk = dossier.residual_unknowns[0]
    elicited = snare.simulate_bait_probe_response(session, dossier, unk.probe_bait)
    rea.resolve_unknown_from_snare_probe(dossier, unk.unknown_id, elicited)
    assert dossier.residual_unknowns[0].resolved is True
    assert dossier.dissection_completeness >= initial_completeness

    # 3. Metabolize into strictly safe defensive modules
    modules = compiler.compile(dossier)
    assert len(modules) >= 2
    assert all(m.safety_verified for m in modules)

    # 4. Prove CROSS-ATTACKER IMMUNITY: metabolized modules from Attacker A catch DIFFERENT Attacker B (stealth-polyglot-hybrid)!
    scn_b = scenarios["scn-cross-hybrid"]
    assert scn_b.attacker_family != scn_a.attacker_family
    fork_with_metab = ForkGenome(
        fork_id="fork-metab-test",
        use_case="enterprise-balanced",
        detector_threshold=0.60,
        metabolized_module_ids=[m.module_id for m in modules],
    )
    graph = CausalProvenanceGraph()
    registry = DetectorRegistry()
    evt_b = scn_b.events[0].model_copy(deep=True)
    gctx = graph.ingest_event(evt_b)
    hits = registry.evaluate_event(
        evt_b,
        DetectorContext(fork=fork_with_metab, graph_context=gctx, metabolized_modules=modules),
    )
    assert any(h.metabolized_module_id is not None for h in hits), (
        "Expected REA-metabolized module from Attacker A to fire against DIFFERENT Attacker B"
    )


def test_rea_dissects_real_sqlite_poisoned_memory(tmp_path: Path) -> None:
    snare = AdaptiveDeceptionSnare(tmp_path / "artifacts")
    rea = ReaBridge()
    scn = next(s for s in build_attack_scenarios() if s.scenario_id == "scn-persistence")
    session = snare.ensnare(
        attacker_id="agent-invoice-bot",
        attacker_family=scn.attacker_family,
        trace_id=scn.events[0].trace_id,
        fork_id="fork-genesis-rhel-fortress",
    )
    artifact = snare.harvest_artifact(
        session=session,
        artifact_kind="sqlite_memory",
        filename=scn.artifact_filename,
        sqlite_rows=scn.artifact_sqlite_rows,
    )
    dossier = rea.dissect(artifact)
    assert any(e.source_tool == "rea_inspect_sqlite_database" for e in dossier.evidence_items)
    assert any("silent_beacon" in e.extracted_pattern or "always" in e.extracted_pattern for e in dossier.evidence_items)
