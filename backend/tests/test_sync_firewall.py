"""Tests for GigaMesh's Mutual Genome Sync Firewall (zero-trust Local <-> GitHub sync)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import yaml

from gigamesh.config import GigaMeshConfig
from gigamesh.engine import GigaMeshEngine
from gigamesh.models.neural_repo import ForkBenchmarkStats, ForkGenome, TradeOffVector
from gigamesh.models.rea import MetabolizedDefenseModule


def _init_bare_remote(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--bare", str(path)], check=True, capture_output=True)
    return str(path)


def test_clean_bidirectional_sync_between_two_nodes(tmp_path: Path) -> None:
    remote = _init_bare_remote(tmp_path / "remote_github.git")

    # Node A evolves 1 generation with REA metabolism and pushes through Outbound Firewall
    node_a = GigaMeshEngine(
        GigaMeshConfig(base_dir=tmp_path / "node_a", genome_remote_url=remote, autopoiesis_enabled_on_boot=False)
    )
    node_a.autopoiesis.run_generation(use_case="enterprise-balanced", trigger="node_a_evolve")
    push_rep = node_a.sync_firewall.push_to_remote()
    assert push_rep.verdict == "passed_synced"
    assert len(push_rep.accepted_forks) >= 4
    assert len(push_rep.accepted_modules) >= 1
    assert push_rep.manifest_sha256 is not None

    # Node B pulls through Inbound Firewall -> independently re-benchmarks & promotes verified winner!
    node_b = GigaMeshEngine(
        GigaMeshConfig(base_dir=tmp_path / "node_b", genome_remote_url=remote, autopoiesis_enabled_on_boot=False)
    )
    champ_b_before = node_b.store.get_champion("enterprise-balanced").benchmark_stats.composite_success_rate
    pull_rep = node_b.sync_firewall.pull_from_remote()
    assert pull_rep.verdict == "passed_synced"
    assert len(pull_rep.accepted_modules) >= 1
    assert len(pull_rep.accepted_forks) >= 1
    champ_b_after = node_b.store.get_champion("enterprise-balanced").benchmark_stats.composite_success_rate
    assert champ_b_after > champ_b_before
    assert node_b.store.verify_integrity()["valid"] is True


def test_outbound_firewall_blocks_compromised_local_node(tmp_path: Path) -> None:
    remote = _init_bare_remote(tmp_path / "remote_github.git")
    node = GigaMeshEngine(
        GigaMeshConfig(base_dir=tmp_path / "local_compromised", genome_remote_url=remote, autopoiesis_enabled_on_boot=False)
    )

    # Case 1: Leaked GitHub token inside a local module -> Outbound DLP Firewall MUST block!
    leaked_mod = MetabolizedDefenseModule(
        source_dossier_id="rea-evil",
        source_attacker_family="compromised-local",
        name="Secret Leak Module",
        capability_kind="decoder_preprocessor",
        description="Accidentally embeds ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWX",
        match_patterns=["safe_pattern"],
        safety_verified=True,
    )
    node.store.commit_metabolized_module(leaked_mod)
    rep1 = node.sync_firewall.push_to_remote()
    assert rep1.verdict == "blocked_contamination"
    assert any(f.gate == "dlp_secret_scan" for f in rep1.findings)

    # Case 2: Tampered local Merkle ledger -> Outbound Integrity Firewall MUST block!
    node.store._ledger[0].success_rate = 0.9999
    rep2 = node.sync_firewall.push_to_remote()
    assert rep2.verdict == "blocked_contamination"
    assert any(f.gate == "local_merkle_integrity" for f in rep2.findings)


def test_inbound_firewall_blocks_compromised_github_forged_score_and_malicious_files(tmp_path: Path) -> None:
    remote = _init_bare_remote(tmp_path / "remote_github.git")
    node_a = GigaMeshEngine(
        GigaMeshConfig(base_dir=tmp_path / "node_a", genome_remote_url=remote, autopoiesis_enabled_on_boot=False)
    )
    assert node_a.sync_firewall.push_to_remote().verdict == "passed_synced"

    # Simulate an attacker compromising the GitHub `genome-sync` branch and pushing:
    # (1) A forged fork claiming 99.9% success rate while actually blind/weak
    # (2) An unauthorized executable script outside the allowlist
    attacker_clone = tmp_path / "attacker_clone"
    subprocess.run(["git", "clone", "-b", "genome-sync", remote, str(attacker_clone)], check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Attacker"], cwd=str(attacker_clone), check=True)
    subprocess.run(["git", "config", "user.email", "evil@bad.invalid"], cwd=str(attacker_clone), check=True)

    forged_fork = ForkGenome(
        fork_id="fork-forged-backdoor",
        parent_fork_id="fork-genesis-balanced",
        use_case="enterprise-balanced",
        generation=9,
        status="champion",
        rationale="Trojanized fork claiming 99.9% success rate with blind 0.89 threshold",
        detector_threshold=0.89,
        taint_strictness=0.15,
        trade_offs=TradeOffVector(containment_aggressiveness=0.1, deception_dwell_budget=0.1),
        benchmark_stats=ForkBenchmarkStats(
            detection_recall=1.0,
            containment_success=1.0,
            false_positive_rate=0.0,
            precision_score=1.0,
            snare_capture_rate=1.0,
            cross_attacker_transfer=1.0,
            latency_efficiency=1.0,
            composite_success_rate=0.999,
            scenarios_tested=6,
            benign_tested=8,
        ),
    )
    forged_path = attacker_clone / "forks" / f"{forged_fork.fork_id}.yaml"
    forged_path.write_text(yaml.safe_dump(forged_fork.model_dump(mode="json"), sort_keys=True), encoding="utf-8")

    # Even if attacker re-signs sync_manifest.json with valid file hashes, local re-benchmarking MUST catch the lie!
    manifest_p = attacker_clone / "sync_manifest.json"
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
    manifest["files"][f"forks/{forged_fork.fork_id}.yaml"] = hashlib.sha256(forged_path.read_bytes()).hexdigest()
    body_for_hash = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    manifest_p.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    subprocess.run(["git", "add", "-A"], cwd=str(attacker_clone), check=True)
    subprocess.run(["git", "commit", "-m", "trojan: inject forged high-score fork"], cwd=str(attacker_clone), check=True)
    subprocess.run(["git", "push", "origin", "genome-sync"], cwd=str(attacker_clone), check=True, capture_output=True)

    # Local defender pulls through Inbound Firewall -> forged fork MUST be quarantined!
    defender = GigaMeshEngine(
        GigaMeshConfig(base_dir=tmp_path / "defender", genome_remote_url=remote, autopoiesis_enabled_on_boot=False)
    )
    pull_rep = defender.sync_firewall.pull_from_remote()
    assert pull_rep.verdict == "blocked_contamination"
    assert "fork-forged-backdoor" in pull_rep.quarantined_items
    assert any(f.gate == "inbound_forged_score_detection" for f in pull_rep.findings)
    assert defender.store.get_fork("fork-forged-backdoor") is None

    # Now attacker also plants an unauthorized executable shell script in remote
    evil_sh = attacker_clone / "backdoor.sh"
    evil_sh.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    evil_sh.chmod(0o755)
    subprocess.run(["git", "add", "backdoor.sh"], cwd=str(attacker_clone), check=True)
    subprocess.run(["git", "commit", "-m", "trojan: drop executable"], cwd=str(attacker_clone), check=True)
    subprocess.run(["git", "push", "origin", "genome-sync"], cwd=str(attacker_clone), check=True, capture_output=True)

    pull_rep2 = defender.sync_firewall.pull_from_remote()
    assert pull_rep2.verdict == "blocked_contamination"
    assert any(f.gate in ("inbound_no_executables", "inbound_file_allowlist") for f in pull_rep2.findings)
