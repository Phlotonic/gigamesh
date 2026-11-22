"""Tests for GigaMesh's Real Git-backed Immutable Neural / Neutral Repo."""

from __future__ import annotations

from pathlib import Path

from gigamesh.models.neural_repo import ForkGenome, TradeOffVector
from gigamesh.neural_repo.git_store import GitNeuralStore
from gigamesh.neural_repo.router import ContextualMoERouter


def test_git_neural_repo_genesis_and_merkle_integrity(tmp_path: Path) -> None:
    store = GitNeuralStore(tmp_path / "genome_repo")
    integrity = store.verify_integrity()

    assert integrity["valid"] is True
    assert integrity["total_forks"] == 4
    assert integrity["surviving_forks"] == 4
    assert integrity["culled_tombstones"] == 0
    assert integrity["total_git_commits"] >= 5

    # Append hash-chained ledger entries
    e1 = store.append_ledger(
        use_case="enterprise-balanced",
        fork_id="fork-genesis-balanced",
        event_kind="benchmark",
        success_rate=0.72,
    )
    e2 = store.append_ledger(
        use_case="enterprise-balanced",
        fork_id="fork-genesis-balanced",
        event_kind="promotion",
        success_rate=0.81,
        delta_vs_champion=0.09,
    )
    assert e2.prev_hash == e1.entry_hash
    assert store.verify_integrity()["valid"] is True

    # Tamper detection: mutating an in-memory/on-disk ledger line must break verification
    store._ledger[0].success_rate = 0.9999
    tampered = store.verify_integrity()
    assert tampered["valid"] is False
    assert any("digest_tampered" in b for b in tampered["broken_entries"])


def test_cull_tombstones_never_routed_by_moe(tmp_path: Path) -> None:
    store = GitNeuralStore(tmp_path / "genome_repo")
    bad_fork = ForkGenome(
        fork_id="fork-bad-option",
        parent_fork_id="fork-genesis-balanced",
        use_case="enterprise-balanced",
        generation=1,
        status="shadow",
        trade_offs=TradeOffVector(containment_aggressiveness=0.99),
    )
    store.cull_fork(bad_fork, reason="FP ceiling exceeded")
    assert store.get_fork("fork-bad-option").status == "culled"

    router = ContextualMoERouter(store, seed=7)
    for _ in range(15):
        decision = router.route("enterprise-balanced", human_risk_score=0.8)
        assert decision["primary"].fork_id != "fork-bad-option"
        if decision["shadow"]:
            assert decision["shadow"].fork_id != "fork-bad-option"
