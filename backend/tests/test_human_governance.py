"""Tests for Human Security Aggregation: Collective Voting, Identity Risk, HITL Quorum, STIX 2.1, and RHEL Controls."""

from __future__ import annotations

from pathlib import Path

import pytest

from gigamesh.config import GigaMeshConfig
from gigamesh.engine import GigaMeshEngine
from gigamesh.models.governance import AnalystVote


def test_collective_voting_compiles_rule_and_updates_neural_weights(tmp_path: Path) -> None:
    engine = GigaMeshEngine(GigaMeshConfig(base_dir=tmp_path, autopoiesis_enabled_on_boot=False))
    champ = engine.store.get_champion("enterprise-balanced")

    v1 = engine.submit_analyst_vote(
        AnalystVote(
            analyst_id="sec-lead-1",
            analyst_reputation=1.0,
            target_kind="fork",
            target_id=champ.fork_id,
            verdict="confirm_threat",
            annotation="Block rogue covert MCP header",
            proposed_pattern="x-covert-exfil-v9",
        )
    )
    assert v1["compiled_rule"] is None  # Needs weighted consensus >= 1.5

    v2 = engine.submit_analyst_vote(
        AnalystVote(
            analyst_id="sec-lead-2",
            analyst_reputation=1.2,
            target_kind="fork",
            target_id=champ.fork_id,
            verdict="confirm_threat",
            annotation="Confirmed across 2 clusters",
            proposed_pattern="x-covert-exfil-v9",
        )
    )
    assert v2["compiled_rule"] is not None
    assert v2["compiled_rule"]["pattern"] == "x-covert-exfil-v9"
    assert engine.store.get_fork(champ.fork_id).human_reward_bonus > 0


def test_hitl_quorum_gate_and_rhel_enforcement(tmp_path: Path) -> None:
    engine = GigaMeshEngine(GigaMeshConfig(base_dir=tmp_path, autopoiesis_enabled_on_boot=False))
    req = engine.human_hub.open_quorum(
        action_kind="rhel_host_isolate",
        target_id="ocp-worker-rhel9-04",
        use_case="rhel-openshift-fortress",
        summary="Isolate compromised OpenShift RHEL worker",
        required_approvals=2,
    )

    # First signature keeps it pending
    s1 = engine.sign_quorum(quorum_id=req.quorum_id, analyst_id="analyst-a", decision="approve")
    assert s1["status"] == "pending"

    # Duplicate signature by same analyst must be rejected
    with pytest.raises(ValueError):
        engine.sign_quorum(quorum_id=req.quorum_id, analyst_id="analyst-a", decision="approve")

    # Second distinct analyst reaches 2-of-2 quorum and enforces Red-Hat order
    s2 = engine.sign_quorum(quorum_id=req.quorum_id, analyst_id="analyst-b", decision="approve")
    assert s2["status"] == "approved"
    assert s2["executed_result"]["status"] == "enforced"
    orders = engine.redhat_ctrl.list_orders()
    assert any(
        o.quorum_id == req.quorum_id
        and "neverallow" in o.selinux_policy
        and "/etc/selinux/config" in o.auditd_rules
        for o in orders
    )


def test_federated_stix_signature_verification(tmp_path: Path) -> None:
    engine = GigaMeshEngine(GigaMeshConfig(base_dir=tmp_path, autopoiesis_enabled_on_boot=False))
    engine.autopoiesis.run_generation(use_case="enterprise-balanced")

    bundle = engine.export_stix_bundle("org-alpha")
    assert len(bundle.motifs) >= 1

    # Import into a fresh peer org GigaMesh instance
    peer = GigaMeshEngine(GigaMeshConfig(base_dir=tmp_path / "peer", autopoiesis_enabled_on_boot=False))
    imported = peer.human_hub.import_stix_bundle(bundle.model_copy(deep=True))
    assert len(imported) >= 1

    # Tampered bundle must be rejected
    bad = bundle.model_copy(deep=True)
    bad.motifs.append({"type": "indicator", "patterns": ["evil"]})
    with pytest.raises(ValueError):
        peer.human_hub.import_stix_bundle(bad)
