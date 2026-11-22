"""Tests for Exhaustive Option Benchmarking, Strict Darwinian Survival/Culling, and Perpetual Autopoiesis."""

from __future__ import annotations

from pathlib import Path

from gigamesh.config import GigaMeshConfig
from gigamesh.engine import GigaMeshEngine


def test_every_option_tested_only_higher_success_survives(tmp_path: Path) -> None:
    cfg = GigaMeshConfig(base_dir=tmp_path, autopoiesis_enabled_on_boot=False)
    engine = GigaMeshEngine(cfg)

    champ_before = engine.store.get_champion("enterprise-balanced")
    sr_before = champ_before.benchmark_stats.composite_success_rate

    # Run 4 autonomous generations across use cases (starting with enterprise-balanced)
    r1 = engine.autopoiesis.run_generation(use_case="enterprise-balanced", trigger="test_gen_1")
    assert len(r1.candidates_tested) >= 3
    assert len(r1.culled) >= 1, "Inferior / boundary-violating options must be culled"
    assert len(r1.survivors) >= 1, "REA-metabolized & trade-off-improved option should survive"
    assert r1.champion_success_after > sr_before

    # Verify strict survival invariant on EVERY tested candidate
    for outcome in r1.candidates_tested:
        fork = engine.store.get_fork(outcome.fork_id)
        assert fork is not None
        assert fork.git_commit_sha is not None
        if outcome.survived:
            assert outcome.delta > 0
            assert fork.status in ("active", "champion")
        else:
            assert fork.status == "culled"
            assert fork.cull_reason is not None

    # Run another generation across stealth-intel-snare & verify monotonic neural repo integrity
    r2 = engine.autopoiesis.run_generation(use_case="stealth-intel-snare", trigger="test_gen_2")
    assert r2.champion_success_after >= r2.champion_success_before

    integrity = engine.store.verify_integrity()
    assert integrity["valid"] is True
    assert integrity["culled_tombstones"] >= 2
    assert integrity["metabolized_modules"] >= 1
