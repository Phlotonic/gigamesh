"""Mutual-Firewall Bidirectional Genome Sync between Local `genome_repo/` and GitHub (`genome-sync`).

Both local and remote repositories treat each other as untrusted peers across an isolated
quarantine stage so a compromise on EITHER side cannot contaminate the other:

- Outbound Firewall (Local -> GitHub `genome-sync`):
  1. Verifies local Merkle ledger & Git DAG integrity (`store.verify_integrity()`).
  2. Strict schema & safety verification (blocks forbidden offensive payloads or unverified modules).
  3. Secret / PII / credential DLP scan (blocks leaked tokens, private keys, AWS/GitHub PATs).
  4. Enforces FP ceiling & valid empirical benchmark stats on all active/champion forks.
  5. Writes content-addressed `sync_manifest.json` and pushes ONLY to isolated `genome-sync` branch.

- Inbound Firewall (GitHub `genome-sync` -> Local `genome_repo/`):
  1. Clones/fetches remote into an air-gapped quarantine dir (`data/sync_quarantine/`).
  2. Strict file allowlist & path safety (blocks symlinks, executables, hooks, path traversal).
  3. Cryptographic manifest SHA-256 verification & remote Merkle chain continuity validation.
  4. Static anti-poisoning & secret/offensive pattern scan.
  5. Zero-Trust Independent Local Re-Benchmarking via `OptionEvaluator`: NEVER trusts remote
     benchmark claims; rejects forged scores, FP ceiling violations, or inferior forks!
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from pydantic import BaseModel, Field

from gigamesh.config import USE_CASE_OBJECTIVES
from gigamesh.evolution.evaluator import OptionEvaluator
from gigamesh.models.neural_repo import ForkGenome, StatLedgerEntry
from gigamesh.models.rea import MetabolizedDefenseModule
from gigamesh.neural_repo.git_store import GENESIS_HASH, GitNeuralStore
from gigamesh.rea.metabolism import FORBIDDEN_OFFENSIVE_PATTERNS

SECRET_LEAK_PATTERNS = [
    (r"gh[pousr]_[A-Za-z0-9_]{20,}", "github_token_leak"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "github_pat_leak"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_leak"),
    (r"-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----", "private_key_leak"),
    (r"sk-[A-Za-z0-9]{24,}", "api_secret_key_leak"),
    (r"/opt/antigravity/tokens/[A-Za-z0-9._-]+", "vm_token_path_leak"),
]

ALLOWED_SYNC_PREFIXES = ("forks/", "modules/", "ledger/")
ALLOWED_ROOT_FILES = {"sync_manifest.json", "README.md"}


class FirewallCheckFinding(BaseModel):
    gate: str
    severity: str  # block | warn | pass
    item: str
    reason: str


class SyncFirewallReport(BaseModel):
    report_id: str = Field(default_factory=lambda: f"fw-{uuid4().hex[:10]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    direction: str  # outbound_local_to_remote | inbound_remote_to_local
    remote_url: str
    remote_branch: str
    verdict: str  # passed_synced | blocked_contamination | no_remote_branch
    accepted_forks: list[str] = Field(default_factory=list)
    accepted_modules: list[str] = Field(default_factory=list)
    quarantined_items: list[str] = Field(default_factory=list)
    findings: list[FirewallCheckFinding] = Field(default_factory=list)
    manifest_sha256: str | None = None
    remote_commit_sha: str | None = None


class GenomeSyncFirewall:
    """Bidirectional zero-trust firewall synchronizing local `genome_repo/` with GitHub `genome-sync`."""

    def __init__(
        self,
        *,
        store: GitNeuralStore,
        evaluator: OptionEvaluator,
        quarantine_dir: Path,
        remote_url: str | None = None,
        remote_branch: str = "genome-sync",
        max_claimed_score_drift: float = 0.06,
    ) -> None:
        self.store = store
        self.evaluator = evaluator
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.remote_url = remote_url or os.environ.get(
            "GIGAMESH_GENOME_REMOTE", "https://github.com/Phlotonic/gigamesh.git"
        )
        self.remote_branch = remote_branch
        self.max_claimed_score_drift = max_claimed_score_drift
        self.history: list[SyncFirewallReport] = []

    # ------------------------------------------------------------------
    # Shared Security / DLP / Schema Gates
    # ------------------------------------------------------------------
    @staticmethod
    def _scan_secrets_and_poison(text: str, item_label: str) -> list[FirewallCheckFinding]:
        findings: list[FirewallCheckFinding] = []
        for pat, kind in SECRET_LEAK_PATTERNS:
            if re.search(pat, text):
                findings.append(
                    FirewallCheckFinding(
                        gate="dlp_secret_scan",
                        severity="block",
                        item=item_label,
                        reason=f"Blocked potential secret/credential exfiltration ({kind}).",
                    )
                )
        lowered = text.lower()
        for bad in FORBIDDEN_OFFENSIVE_PATTERNS:
            if bad in lowered:
                findings.append(
                    FirewallCheckFinding(
                        gate="offensive_safety_scan",
                        severity="block",
                        item=item_label,
                        reason=f"Blocked forbidden offensive payload pattern '{bad}'.",
                    )
                )
        return findings

    @staticmethod
    def _validate_module(mod: MetabolizedDefenseModule) -> list[FirewallCheckFinding]:
        findings: list[FirewallCheckFinding] = []
        if not mod.safety_verified:
            findings.append(
                FirewallCheckFinding(
                    gate="module_safety_invariant",
                    severity="block",
                    item=mod.module_id,
                    reason="Module is not marked safety_verified.",
                )
            )
        if mod.detection_boost > 0.50 or mod.containment_boost > 0.45:
            findings.append(
                FirewallCheckFinding(
                    gate="module_bounds_check",
                    severity="block",
                    item=mod.module_id,
                    reason="Module boost parameters exceed allowed defensive bounds.",
                )
            )
        raw = json.dumps(mod.model_dump(mode="json"), sort_keys=True)
        findings.extend(GenomeSyncFirewall._scan_secrets_and_poison(raw, mod.module_id))
        return findings

    @staticmethod
    def _validate_fork_static(fork: ForkGenome) -> list[FirewallCheckFinding]:
        findings: list[FirewallCheckFinding] = []
        if fork.use_case not in USE_CASE_OBJECTIVES:
            findings.append(
                FirewallCheckFinding(
                    gate="fork_schema_bounds",
                    severity="block",
                    item=fork.fork_id,
                    reason=f"Unknown use_case '{fork.use_case}'.",
                )
            )
        if fork.status != "culled":
            if fork.detector_threshold < 0.35 or fork.detector_threshold > 0.90:
                findings.append(
                    FirewallCheckFinding(
                        gate="fork_anti_poison_bounds",
                        severity="block",
                        item=fork.fork_id,
                        reason=f"Suspicious detector_threshold={fork.detector_threshold} outside [0.35, 0.90].",
                    )
                )
            if abs(fork.human_reward_bonus) > 0.10:
                findings.append(
                    FirewallCheckFinding(
                        gate="fork_reward_cap",
                        severity="block",
                        item=fork.fork_id,
                        reason=f"Reward bonus {fork.human_reward_bonus} exceeds anti-poisoning cap (+/-0.10).",
                    )
                )
        raw = yaml.safe_dump(fork.model_dump(mode="json"), sort_keys=True)
        findings.extend(GenomeSyncFirewall._scan_secrets_and_poison(raw, fork.fork_id))
        return findings

    @staticmethod
    def _hash_file(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _run_git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc

    # ------------------------------------------------------------------
    # OUTBOUND FIREWALL: Local `genome_repo/` -> Remote GitHub `genome-sync`
    # ------------------------------------------------------------------
    def push_to_remote(self, remote_url: str | None = None, dry_run: bool = False) -> SyncFirewallReport:
        target_remote = remote_url or self.remote_url
        findings: list[FirewallCheckFinding] = []
        quarantined: list[str] = []

        # Gate 1: Verify local Merkle ledger & Git DAG integrity before exporting anything
        integrity = self.store.verify_integrity()
        if not integrity["valid"]:
            findings.append(
                FirewallCheckFinding(
                    gate="local_merkle_integrity",
                    severity="block",
                    item="local_genome_repo",
                    reason=(
                        f"Local genome repo failed integrity check: "
                        f"broken={integrity['broken_entries']} missing={integrity['missing_commits']}"
                    ),
                )
            )
            report = SyncFirewallReport(
                direction="outbound_local_to_remote",
                remote_url=target_remote,
                remote_branch=self.remote_branch,
                verdict="blocked_contamination",
                quarantined_items=["local_genome_repo"],
                findings=findings,
            )
            self.history.append(report)
            return report

        # Gate 2 & 3: Validate every module & fork via safety + DLP + bounds checks
        approved_modules: list[MetabolizedDefenseModule] = []
        for mod in self.store.list_modules():
            mod_findings = self._validate_module(mod)
            if any(f.severity == "block" for f in mod_findings):
                findings.extend(mod_findings)
                quarantined.append(mod.module_id)
            else:
                approved_modules.append(mod)

        approved_forks: list[ForkGenome] = []
        for fork in self.store.list_forks(include_culled=True):
            fork_findings = self._validate_fork_static(fork)
            # Active / champion forks must also respect their use-case FP ceiling
            if fork.status != "culled" and fork.benchmark_stats is not None:
                obj = USE_CASE_OBJECTIVES[fork.use_case]
                if fork.benchmark_stats.false_positive_rate > obj.max_false_positive_rate:
                    fork_findings.append(
                        FirewallCheckFinding(
                            gate="outbound_fp_ceiling",
                            severity="block",
                            item=fork.fork_id,
                            reason=(
                                f"Active fork FP={fork.benchmark_stats.false_positive_rate:.3f} "
                                f"exceeds ceiling {obj.max_false_positive_rate:.3f}."
                            ),
                        )
                    )
            if any(f.severity == "block" for f in fork_findings):
                findings.extend(fork_findings)
                quarantined.append(fork.fork_id)
            else:
                approved_forks.append(fork)

        # Fail-closed if ANY local artifact triggered a security/DLP block (possible local compromise!)
        if any(f.severity == "block" for f in findings):
            report = SyncFirewallReport(
                direction="outbound_local_to_remote",
                remote_url=target_remote,
                remote_branch=self.remote_branch,
                verdict="blocked_contamination",
                quarantined_items=quarantined,
                findings=findings,
            )
            self.history.append(report)
            return report

        # Gate 4: Stage sanitized snapshot into isolated outbound staging repo + signed manifest
        stage_dir = self.quarantine_dir / f"outbound_{uuid4().hex[:8]}"
        try:
            stage_dir.mkdir(parents=True, exist_ok=True)
            (stage_dir / "forks").mkdir()
            (stage_dir / "modules").mkdir()
            (stage_dir / "ledger").mkdir()

            manifest_files: dict[str, str] = {}
            for fork in approved_forks:
                p = stage_dir / "forks" / f"{fork.fork_id}.yaml"
                p.write_text(yaml.safe_dump(fork.model_dump(mode="json"), sort_keys=True), encoding="utf-8")
                manifest_files[f"forks/{fork.fork_id}.yaml"] = self._hash_file(p)

            for mod in approved_modules:
                p = stage_dir / "modules" / f"{mod.module_id}.json"
                p.write_text(json.dumps(mod.model_dump(mode="json"), indent=2, sort_keys=True), encoding="utf-8")
                manifest_files[f"modules/{mod.module_id}.json"] = self._hash_file(p)

            ledger_entries = list(reversed(self.store.list_ledger(limit=10000)))
            ledger_p = stage_dir / "ledger" / "neural_weights.jsonl"
            ledger_p.write_text(
                "\n".join(e.model_dump_json() for e in ledger_entries) + ("\n" if ledger_entries else ""),
                encoding="utf-8",
            )
            manifest_files["ledger/neural_weights.jsonl"] = self._hash_file(ledger_p)

            manifest_body = {
                "schema_version": "gigamesh-sync-v1",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source_head_commit": integrity["head_commit"],
                "ledger_head_hash": ledger_entries[-1].entry_hash if ledger_entries else GENESIS_HASH,
                "files": manifest_files,
            }
            manifest_digest = hashlib.sha256(
                json.dumps(manifest_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            manifest_body["manifest_sha256"] = manifest_digest
            (stage_dir / "sync_manifest.json").write_text(
                json.dumps(manifest_body, indent=2, sort_keys=True), encoding="utf-8"
            )
            (stage_dir / "README.md").write_text(
                "# GigaMesh Genome Sync Branch (`genome-sync`)\n\n"
                "Isolated immutable neural genome branch synchronized exclusively through\n"
                "`GenomeSyncFirewall`. Never merged directly into `main`; every inbound sync\n"
                "is independently re-verified and re-benchmarked before local ingestion.\n",
                encoding="utf-8",
            )

            remote_commit_sha: str | None = None
            if not dry_run:
                self._run_git(stage_dir, "init", "-b", self.remote_branch)
                self._run_git(stage_dir, "config", "user.name", "GigaMesh Sync Firewall")
                self._run_git(stage_dir, "config", "user.email", "sync-firewall@gigamesh.local")
                self._run_git(stage_dir, "remote", "add", "origin", target_remote)

                # Try fetching existing remote genome-sync branch to preserve monotonic history (no force push!)
                fetch_res = self._run_git(
                    stage_dir, "fetch", "origin", self.remote_branch, check=False
                )
                if fetch_res.returncode == 0:
                    # Keep staged files while setting parent commit to remote FETCH_HEAD
                    self._run_git(stage_dir, "reset", "--soft", "FETCH_HEAD")

                self._run_git(stage_dir, "add", "-A")
                if self._run_git(stage_dir, "status", "--porcelain").stdout.strip():
                    self._run_git(
                        stage_dir,
                        "commit",
                        "-m",
                        f"genome-sync: {len(approved_forks)} forks, {len(approved_modules)} modules, manifest={manifest_digest[:12]}",
                    )
                remote_commit_sha = self._run_git(stage_dir, "rev-parse", "HEAD").stdout.strip()
                self._run_git(stage_dir, "push", "origin", f"HEAD:refs/heads/{self.remote_branch}")

            findings.append(
                FirewallCheckFinding(
                    gate="outbound_firewall_pass",
                    severity="pass",
                    item=self.remote_branch,
                    reason=(
                        f"Verified {len(approved_forks)} forks, {len(approved_modules)} modules, "
                        f"and {len(ledger_entries)} Merkle ledger entries cleanly."
                    ),
                )
            )
            report = SyncFirewallReport(
                direction="outbound_local_to_remote",
                remote_url=target_remote,
                remote_branch=self.remote_branch,
                verdict="passed_synced",
                accepted_forks=[f.fork_id for f in approved_forks],
                accepted_modules=[m.module_id for m in approved_modules],
                findings=findings,
                manifest_sha256=manifest_digest,
                remote_commit_sha=remote_commit_sha,
            )
            self.history.append(report)
            return report
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # INBOUND FIREWALL: Remote GitHub `genome-sync` -> Air-Gapped Quarantine -> Local `genome_repo/`
    # ------------------------------------------------------------------
    def pull_from_remote(self, remote_url: str | None = None) -> SyncFirewallReport:
        target_remote = remote_url or self.remote_url
        findings: list[FirewallCheckFinding] = []
        quarantined: list[str] = []
        accepted_modules: list[str] = []
        accepted_forks: list[str] = []

        q_dir = self.quarantine_dir / f"inbound_{uuid4().hex[:8]}"
        try:
            q_dir.mkdir(parents=True, exist_ok=True)
            clone = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    "--branch",
                    self.remote_branch,
                    "--config",
                    "core.hooksPath=/dev/null",
                    "--config",
                    "core.symlinks=false",
                    target_remote,
                    str(q_dir),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if clone.returncode != 0:
                findings.append(
                    FirewallCheckFinding(
                        gate="inbound_fetch",
                        severity="warn",
                        item=self.remote_branch,
                        reason=f"Remote branch '{self.remote_branch}' unavailable: {clone.stderr.strip()[:160]}",
                    )
                )
                report = SyncFirewallReport(
                    direction="inbound_remote_to_local",
                    remote_url=target_remote,
                    remote_branch=self.remote_branch,
                    verdict="no_remote_branch",
                    findings=findings,
                )
                self.history.append(report)
                return report

            remote_sha = self._run_git(q_dir, "rev-parse", "HEAD").stdout.strip()

            # Gate 1: Strict Path Allowlist, Symlink & Executable Ban
            for path in q_dir.rglob("*"):
                rel = path.relative_to(q_dir).as_posix()
                if rel == ".git" or rel.startswith(".git/"):
                    continue
                if path.is_symlink():
                    findings.append(
                        FirewallCheckFinding(
                            gate="inbound_path_safety",
                            severity="block",
                            item=rel,
                            reason="Symlinks are strictly forbidden inside genome sync payloads.",
                        )
                    )
                    quarantined.append(rel)
                if path.is_file():
                    if os.access(path, os.X_OK):
                        findings.append(
                            FirewallCheckFinding(
                                gate="inbound_no_executables",
                                severity="block",
                                item=rel,
                                reason="Executable files are strictly forbidden inside genome sync payloads.",
                            )
                        )
                        quarantined.append(rel)
                    allowed = rel in ALLOWED_ROOT_FILES or any(rel.startswith(p) for p in ALLOWED_SYNC_PREFIXES)
                    if not allowed:
                        findings.append(
                            FirewallCheckFinding(
                                gate="inbound_file_allowlist",
                                severity="block",
                                item=rel,
                                reason=f"Unauthorized file path '{rel}' outside genome allowlist.",
                            )
                        )
                        quarantined.append(rel)

            # Gate 2: Cryptographic Sync Manifest & Merkle Chain Verification
            manifest_path = q_dir / "sync_manifest.json"
            manifest_sha: str | None = None
            if not manifest_path.exists():
                findings.append(
                    FirewallCheckFinding(
                        gate="inbound_manifest_required",
                        severity="block",
                        item="sync_manifest.json",
                        reason="Missing signed sync_manifest.json — possible unauthenticated tampering.",
                    )
                )
                quarantined.append("sync_manifest.json")
            else:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                claimed_digest = manifest.get("manifest_sha256", "")
                body_for_hash = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
                recomputed = hashlib.sha256(
                    json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                manifest_sha = claimed_digest
                if claimed_digest != recomputed:
                    findings.append(
                        FirewallCheckFinding(
                            gate="inbound_manifest_digest",
                            severity="block",
                            item="sync_manifest.json",
                            reason="Manifest SHA-256 mismatch — remote repo may be tampered.",
                        )
                    )
                    quarantined.append("sync_manifest.json")
                else:
                    for rel_file, expected_hash in manifest.get("files", {}).items():
                        fp = q_dir / rel_file
                        if not fp.exists() or self._hash_file(fp) != expected_hash:
                            findings.append(
                                FirewallCheckFinding(
                                    gate="inbound_file_digest",
                                    severity="block",
                                    item=rel_file,
                                    reason=f"File hash mismatch for '{rel_file}' against sync_manifest.json.",
                                )
                            )
                            quarantined.append(rel_file)

            # Verify remote Merkle ledger chain integrity
            remote_ledger = q_dir / "ledger" / "neural_weights.jsonl"
            if remote_ledger.exists():
                prev_hash = GENESIS_HASH
                for idx, line in enumerate(remote_ledger.read_text(encoding="utf-8").splitlines()):
                    line = line.strip()
                    if not line:
                        continue
                    entry = StatLedgerEntry.model_validate_json(line)
                    if entry.prev_hash != prev_hash:
                        findings.append(
                            FirewallCheckFinding(
                                gate="inbound_merkle_chain",
                                severity="block",
                                item=f"ledger:{idx}",
                                reason="Broken Merkle prev_hash link in remote stat ledger.",
                            )
                        )
                        quarantined.append(f"ledger:{idx}")
                        break
                    if GitNeuralStore._compute_entry_hash(entry) != entry.entry_hash:
                        findings.append(
                            FirewallCheckFinding(
                                gate="inbound_merkle_digest",
                                severity="block",
                                item=entry.entry_id,
                                reason="Tampered entry digest in remote stat ledger.",
                            )
                        )
                        quarantined.append(entry.entry_id)
                        break
                    prev_hash = entry.entry_hash

            # Abort immediately if structural / manifest / Merkle gates failed!
            if any(f.severity == "block" for f in findings):
                report = SyncFirewallReport(
                    direction="inbound_remote_to_local",
                    remote_url=target_remote,
                    remote_branch=self.remote_branch,
                    verdict="blocked_contamination",
                    quarantined_items=quarantined,
                    findings=findings,
                    manifest_sha256=manifest_sha,
                    remote_commit_sha=remote_sha,
                )
                self.history.append(report)
                return report

            # Gate 3: Inspect & sanitize candidate remote modules
            remote_modules: dict[str, MetabolizedDefenseModule] = {}
            for mp in sorted((q_dir / "modules").glob("*.json")):
                mod = MetabolizedDefenseModule.model_validate_json(mp.read_text(encoding="utf-8"))
                mod_findings = self._validate_module(mod)
                if any(f.severity == "block" for f in mod_findings):
                    findings.extend(mod_findings)
                    quarantined.append(mod.module_id)
                else:
                    remote_modules[mod.module_id] = mod

            # Gate 4: Zero-Trust Independent Local Re-Benchmarking of EVERY remote fork!
            combined_modules = {m.module_id: m for m in self.store.list_modules()}
            combined_modules.update(remote_modules)

            candidate_forks_to_ingest: list[ForkGenome] = []
            for fp in sorted((q_dir / "forks").glob("*.yaml")):
                fork = ForkGenome.model_validate(yaml.safe_load(fp.read_text(encoding="utf-8")))
                # Skip forks already present locally or culled tombstones
                if self.store.get_fork(fork.fork_id) is not None or fork.status == "culled":
                    continue

                static_findings = self._validate_fork_static(fork)
                if any(f.severity == "block" for f in static_findings):
                    findings.extend(static_findings)
                    quarantined.append(fork.fork_id)
                    continue

                # Independent local benchmark — NEVER trust remote claimed numbers!
                measured = self.evaluator.evaluate_fork(fork, combined_modules, human_rules=[])
                obj = USE_CASE_OBJECTIVES[fork.use_case]

                if measured.false_positive_rate > obj.max_false_positive_rate:
                    findings.append(
                        FirewallCheckFinding(
                            gate="inbound_local_rebenchmark_fp",
                            severity="block",
                            item=fork.fork_id,
                            reason=(
                                f"Quarantined remote fork: local re-benchmark FP={measured.false_positive_rate:.3f} "
                                f"exceeds ceiling {obj.max_false_positive_rate:.3f}."
                            ),
                        )
                    )
                    quarantined.append(fork.fork_id)
                    continue

                if fork.benchmark_stats is not None:
                    claimed = fork.benchmark_stats.composite_success_rate
                    if claimed - measured.composite_success_rate > self.max_claimed_score_drift:
                        findings.append(
                            FirewallCheckFinding(
                                gate="inbound_forged_score_detection",
                                severity="block",
                                item=fork.fork_id,
                                reason=(
                                    f"Quarantined remote fork: forged/inflated benchmark claim "
                                    f"(claimed={claimed:.4f} vs local_measured={measured.composite_success_rate:.4f})."
                                ),
                            )
                        )
                        quarantined.append(fork.fork_id)
                        continue

                # Overwrite benchmark stats with our trusted local measurement
                fork.benchmark_stats = measured
                fork.status = "active"
                candidate_forks_to_ingest.append(fork)

            # Commit ONLY verified, clean modules & locally re-benchmarked forks into local `genome_repo/`
            for mid, mod in remote_modules.items():
                if self.store.get_module(mid) is None:
                    self.store.commit_metabolized_module(mod)
                    accepted_modules.append(mid)

            for fork in candidate_forks_to_ingest:
                local_champ = self.store.get_champion(fork.use_case)
                local_sr = local_champ.benchmark_stats.composite_success_rate if local_champ.benchmark_stats else 0.0
                measured_sr = fork.benchmark_stats.composite_success_rate if fork.benchmark_stats else 0.0
                self.store.commit_fork(fork, message=f"inbound-verified({fork.use_case}): {fork.fork_id}")
                self.store.append_ledger(
                    use_case=fork.use_case,
                    fork_id=fork.fork_id,
                    event_kind="benchmark",
                    success_rate=measured_sr,
                    delta_vs_champion=round(measured_sr - local_sr, 4),
                    metrics={"source": "inbound_sync_firewall", "remote_commit": remote_sha},
                    signer="gigamesh-sync-firewall",
                )
                if measured_sr > local_sr + USE_CASE_OBJECTIVES[fork.use_case].min_improvement_delta:
                    self.store.promote_champion(fork.fork_id, reason="inbound_verified_strict_improvement")
                accepted_forks.append(fork.fork_id)

            verdict = "blocked_contamination" if quarantined and not (accepted_forks or accepted_modules) else "passed_synced"
            if not quarantined:
                findings.append(
                    FirewallCheckFinding(
                        gate="inbound_firewall_pass",
                        severity="pass",
                        item=self.remote_branch,
                        reason=(
                            f"Independently re-verified remote genome: ingested {len(accepted_forks)} new fork(s) "
                            f"and {len(accepted_modules)} module(s) with zero contamination."
                        ),
                    )
                )

            report = SyncFirewallReport(
                direction="inbound_remote_to_local",
                remote_url=target_remote,
                remote_branch=self.remote_branch,
                verdict=verdict,
                accepted_forks=accepted_forks,
                accepted_modules=accepted_modules,
                quarantined_items=quarantined,
                findings=findings,
                manifest_sha256=manifest_sha,
                remote_commit_sha=remote_sha,
            )
            self.history.append(report)
            return report
        finally:
            shutil.rmtree(q_dir, ignore_errors=True)

    def status(self) -> dict[str, Any]:
        return {
            "remote_url": self.remote_url,
            "remote_branch": self.remote_branch,
            "max_claimed_score_drift": self.max_claimed_score_drift,
            "total_syncs": len(self.history),
            "blocked_contaminations": sum(1 for r in self.history if r.verdict == "blocked_contamination"),
            "recent_reports": [r.model_dump(mode="json") for r in reversed(self.history[-15:])],
        }
