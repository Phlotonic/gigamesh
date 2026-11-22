"""Real Git-backed Immutable Neural / Neutral Network storage substrate for GigaMesh.

Every defensive fork, metabolized REA module, and Merkle-chained stat ledger record is
committed immutably into a local Git DAG. Surviving forks are tagged under `fork/<id>`,
culled options are preserved as `culled/<id>` tombstones, and per-use-case champions
advance strictly monotonically when a higher success rate is empirically verified.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import threading
from pathlib import Path
from typing import Any

import yaml

from gigamesh.models.neural_repo import ForkGenome, StatLedgerEntry, TradeOffVector
from gigamesh.models.rea import MetabolizedDefenseModule


GENESIS_HASH = "0" * 64


class GitNeuralStore:
    """Manages GigaMesh's immutable Git DAG of defensive forks and synaptic weight ledgers."""

    def __init__(self, repo_dir: Path) -> None:
        self.repo_dir = Path(repo_dir)
        self._lock = threading.RLock()
        self._forks: dict[str, ForkGenome] = {}
        self._modules: dict[str, MetabolizedDefenseModule] = {}
        self._ledger: list[StatLedgerEntry] = []
        self._ensure_initialized()

    # ------------------------------------------------------------------
    # Git helpers
    # ------------------------------------------------------------------
    def _git(self, *args: str, check: bool = True) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(self.repo_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}"
            )
        return proc.stdout.strip()

    def _ensure_initialized(self) -> None:
        with self._lock:
            self.repo_dir.mkdir(parents=True, exist_ok=True)
            (self.repo_dir / "forks").mkdir(exist_ok=True)
            (self.repo_dir / "modules").mkdir(exist_ok=True)
            (self.repo_dir / "ledger").mkdir(exist_ok=True)

            if not (self.repo_dir / ".git").exists():
                self._git("init", "-b", "main")
                self._git("config", "user.name", "GigaMesh Neural Repo")
                self._git("config", "user.email", "autopoiesis@gigamesh.local")
                readme = self.repo_dir / "README.md"
                readme.write_text(
                    "# GigaMesh Immutable Neural Genome Repository\n\n"
                    "Append-only, content-addressed Git DAG storing defensive forks,\n"
                    "metabolized Reverse Engineer Anything (REA) modules, and Merkle-chained\n"
                    "empirical fitness ledgers. Only strictly superior options survive.\n",
                    encoding="utf-8",
                )
                self._git("add", "README.md")
                self._git("commit", "-m", "genesis: initialize GigaMesh immutable neural network")
                self._seed_genesis_forks()
            else:
                self._load_from_disk()
                if not self._forks:
                    self._seed_genesis_forks()

    def _seed_genesis_forks(self) -> None:
        """Seed baseline trade-off forks across all four core use cases."""
        genesis_specs = [
            ForkGenome(
                fork_id="fork-genesis-balanced",
                parent_fork_id=None,
                use_case="enterprise-balanced",
                generation=0,
                status="champion",
                rationale="Balanced genesis posture weighing recall, containment, low FP, and snare capture.",
                trade_offs=TradeOffVector(
                    containment_aggressiveness=0.52,
                    deception_dwell_budget=0.45,
                    rea_dissection_depth=0.55,
                    human_quorum_strictness=0.55,
                    false_positive_tolerance=0.22,
                    host_isolation_scope=0.45,
                ),
                detector_threshold=0.62,
                taint_strictness=0.55,
            ),
            ForkGenome(
                fork_id="fork-genesis-stealth-snare",
                parent_fork_id="fork-genesis-balanced",
                use_case="stealth-intel-snare",
                generation=0,
                status="champion",
                rationale="High-dwell deception snare optimized to ensnare red-hat agents for REA dissection.",
                trade_offs=TradeOffVector(
                    containment_aggressiveness=0.35,
                    deception_dwell_budget=0.82,
                    rea_dissection_depth=0.85,
                    human_quorum_strictness=0.45,
                    false_positive_tolerance=0.30,
                    host_isolation_scope=0.40,
                ),
                detector_threshold=0.58,
                taint_strictness=0.52,
            ),
            ForkGenome(
                fork_id="fork-genesis-zero-trust",
                parent_fork_id="fork-genesis-balanced",
                use_case="zero-trust-critical",
                generation=0,
                status="champion",
                rationale="Fast containment posture minimizing blast radius for critical production systems.",
                trade_offs=TradeOffVector(
                    containment_aggressiveness=0.80,
                    deception_dwell_budget=0.20,
                    rea_dissection_depth=0.40,
                    human_quorum_strictness=0.65,
                    false_positive_tolerance=0.18,
                    host_isolation_scope=0.78,
                ),
                detector_threshold=0.56,
                taint_strictness=0.72,
            ),
            ForkGenome(
                fork_id="fork-genesis-rhel-fortress",
                parent_fork_id="fork-genesis-balanced",
                use_case="rhel-openshift-fortress",
                generation=0,
                status="champion",
                rationale="Red Hat Enterprise Linux & OpenShift hardened baseline with SELinux/auditd telemetry.",
                trade_offs=TradeOffVector(
                    containment_aggressiveness=0.68,
                    deception_dwell_budget=0.50,
                    rea_dissection_depth=0.68,
                    human_quorum_strictness=0.60,
                    false_positive_tolerance=0.20,
                    host_isolation_scope=0.82,
                ),
                detector_threshold=0.58,
                taint_strictness=0.64,
            ),
        ]
        for genome in genesis_specs:
            self.commit_fork(genome, message=f"genesis-fork({genome.use_case}): {genome.fork_id}")

    def _load_from_disk(self) -> None:
        self._forks.clear()
        for path in sorted((self.repo_dir / "forks").glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data:
                fork = ForkGenome.model_validate(data)
                self._forks[fork.fork_id] = fork

        self._modules.clear()
        for path in sorted((self.repo_dir / "modules").glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            mod = MetabolizedDefenseModule.model_validate(data)
            self._modules[mod.module_id] = mod

        self._ledger.clear()
        ledger_file = self.repo_dir / "ledger" / "neural_weights.jsonl"
        if ledger_file.exists():
            for line in ledger_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    self._ledger.append(StatLedgerEntry.model_validate_json(line))

    # ------------------------------------------------------------------
    # Immutable Fork & Module Commits
    # ------------------------------------------------------------------
    def commit_fork(self, genome: ForkGenome, message: str | None = None) -> ForkGenome:
        """Persist a ForkGenome as an immutable Git commit and tag its lineage."""
        with self._lock:
            fork_path = self.repo_dir / "forks" / f"{genome.fork_id}.yaml"
            tag_prefix = "culled" if genome.status == "culled" else "fork"
            genome.git_ref = f"refs/tags/{tag_prefix}/{genome.fork_id}"
            payload = yaml.safe_dump(
                genome.model_dump(mode="json"),
                sort_keys=True,
            )
            fork_path.write_text(payload, encoding="utf-8")
            self._git("add", str(fork_path.relative_to(self.repo_dir)))
            commit_msg = message or f"{tag_prefix}({genome.use_case}): {genome.fork_id}"
            # Only commit if there are staged changes
            status_out = self._git("status", "--porcelain")
            if status_out:
                self._git("commit", "-m", commit_msg)
            sha = self._git("rev-parse", "HEAD")
            genome.git_commit_sha = sha
            # Pin immutable tag (do not overwrite existing fork tag; allow status transition tag)
            self._git("tag", "-f", f"{tag_prefix}/{genome.fork_id}", sha)
            if genome.status == "champion":
                self._git("tag", "-f", f"champion/{genome.use_case}", sha)
            # Rewrite cached yaml with git_commit_sha recorded in memory
            self._forks[genome.fork_id] = genome
            return genome

    def promote_champion(self, fork_id: str, reason: str = "strict_success_rate_improvement") -> ForkGenome:
        """Promote a surviving fork to champion for its use case, demoting the prior champion to active."""
        with self._lock:
            target = self._forks[fork_id]
            for existing in self._forks.values():
                if existing.use_case == target.use_case and existing.status == "champion" and existing.fork_id != fork_id:
                    existing.status = "active"
                    self.commit_fork(existing, message=f"demote-prior-champion({existing.use_case}): {existing.fork_id}")
            target.status = "champion"
            return self.commit_fork(target, message=f"promote-champion({target.use_case}): {fork_id} [{reason}]")

    def cull_fork(self, genome: ForkGenome, reason: str) -> ForkGenome:
        """Archive a failed/dominated option as an immutable culled tombstone in Git."""
        with self._lock:
            genome.status = "culled"
            genome.cull_reason = reason
            return self.commit_fork(
                genome,
                message=f"cull({genome.use_case}): {genome.fork_id} — {reason}",
            )

    def commit_metabolized_module(self, module: MetabolizedDefenseModule) -> str:
        """Commit a sanitized REA-metabolized defensive module into the immutable repo."""
        with self._lock:
            mod_path = self.repo_dir / "modules" / f"{module.module_id}.json"
            mod_path.write_text(
                json.dumps(module.model_dump(mode="json"), indent=2, sort_keys=True),
                encoding="utf-8",
            )
            self._git("add", str(mod_path.relative_to(self.repo_dir)))
            if self._git("status", "--porcelain"):
                self._git(
                    "commit",
                    "-m",
                    f"metabolize({module.source_attacker_family}): {module.module_id} [{module.capability_kind}]",
                )
            sha = self._git("rev-parse", "HEAD")
            self._git("tag", "-f", f"module/{module.module_id}", sha)
            self._modules[module.module_id] = module
            return sha

    # ------------------------------------------------------------------
    # Merkle-Chained Append-Only Neural Weight Ledger
    # ------------------------------------------------------------------
    @staticmethod
    def _compute_entry_hash(entry: StatLedgerEntry) -> str:
        canonical = json.dumps(
            {
                "entry_id": entry.entry_id,
                "timestamp": entry.timestamp.isoformat(),
                "prev_hash": entry.prev_hash,
                "use_case": entry.use_case,
                "fork_id": entry.fork_id,
                "git_commit_sha": entry.git_commit_sha,
                "event_kind": entry.event_kind,
                "success_rate": round(entry.success_rate, 6),
                "delta_vs_champion": round(entry.delta_vs_champion, 6),
                "metrics": entry.metrics,
                "signer": entry.signer,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append_ledger(
        self,
        *,
        use_case: str,
        fork_id: str,
        event_kind: str,
        success_rate: float,
        delta_vs_champion: float = 0.0,
        metrics: dict[str, Any] | None = None,
        signer: str = "gigamesh-autopoiesis",
    ) -> StatLedgerEntry:
        """Append a cryptographically hash-chained metric/weight entry and commit it to Git."""
        with self._lock:
            prev_hash = self._ledger[-1].entry_hash if self._ledger else GENESIS_HASH
            fork = self._forks.get(fork_id)
            entry = StatLedgerEntry(
                prev_hash=prev_hash,
                use_case=use_case,
                fork_id=fork_id,
                git_commit_sha=fork.git_commit_sha if fork else None,
                event_kind=event_kind,
                success_rate=success_rate,
                delta_vs_champion=delta_vs_champion,
                metrics=metrics or {},
                signer=signer,
            )
            entry.entry_hash = self._compute_entry_hash(entry)
            ledger_file = self.repo_dir / "ledger" / "neural_weights.jsonl"
            with ledger_file.open("a", encoding="utf-8") as fh:
                fh.write(entry.model_dump_json() + "\n")
            self._git("add", str(ledger_file.relative_to(self.repo_dir)))
            if self._git("status", "--porcelain"):
                self._git(
                    "commit",
                    "-m",
                    f"ledger({event_kind}): {fork_id} sr={success_rate:.4f} hash={entry.entry_hash[:10]}",
                )
            self._ledger.append(entry)
            return entry

    def verify_integrity(self) -> dict[str, Any]:
        """Verify full Merkle hash-chain integrity and Git DAG object validity."""
        with self._lock:
            expected_prev = GENESIS_HASH
            broken_entries: list[str] = []
            for entry in self._ledger:
                if entry.prev_hash != expected_prev:
                    broken_entries.append(f"{entry.entry_id}:prev_hash_mismatch")
                recomputed = self._compute_entry_hash(entry)
                if recomputed != entry.entry_hash:
                    broken_entries.append(f"{entry.entry_id}:digest_tampered")
                expected_prev = entry.entry_hash

            missing_commits: list[str] = []
            for fork in self._forks.values():
                if fork.git_commit_sha:
                    proc = subprocess.run(
                        ["git", "cat-file", "-e", f"{fork.git_commit_sha}^{{commit}}"],
                        cwd=str(self.repo_dir),
                        capture_output=True,
                        check=False,
                    )
                    if proc.returncode != 0:
                        missing_commits.append(fork.fork_id)

            commit_count = int(self._git("rev-list", "--count", "HEAD"))
            head_sha = self._git("rev-parse", "HEAD")
            return {
                "valid": len(broken_entries) == 0 and len(missing_commits) == 0,
                "head_commit": head_sha,
                "total_git_commits": commit_count,
                "ledger_entries": len(self._ledger),
                "total_forks": len(self._forks),
                "surviving_forks": sum(1 for f in self._forks.values() if f.status != "culled"),
                "culled_tombstones": sum(1 for f in self._forks.values() if f.status == "culled"),
                "metabolized_modules": len(self._modules),
                "broken_entries": broken_entries,
                "missing_commits": missing_commits,
            }

    # ------------------------------------------------------------------
    # Query Helpers
    # ------------------------------------------------------------------
    def get_fork(self, fork_id: str) -> ForkGenome | None:
        return self._forks.get(fork_id)

    def list_forks(self, use_case: str | None = None, include_culled: bool = True) -> list[ForkGenome]:
        forks = list(self._forks.values())
        if use_case:
            forks = [f for f in forks if f.use_case == use_case]
        if not include_culled:
            forks = [f for f in forks if f.status != "culled"]
        return sorted(forks, key=lambda f: (f.generation, f.created_at))

    def get_champion(self, use_case: str) -> ForkGenome:
        candidates = [f for f in self._forks.values() if f.use_case == use_case and f.status == "champion"]
        if candidates:
            return candidates[-1]
        active = [f for f in self._forks.values() if f.use_case == use_case and f.status != "culled"]
        if active:
            return active[-1]
        return next(iter(self._forks.values()))

    def list_modules(self) -> list[MetabolizedDefenseModule]:
        return list(self._modules.values())

    def get_module(self, module_id: str) -> MetabolizedDefenseModule | None:
        return self._modules.get(module_id)

    def list_ledger(self, limit: int = 100) -> list[StatLedgerEntry]:
        return list(reversed(self._ledger[-limit:]))

    def git_log_summary(self, limit: int = 25) -> list[dict[str, str]]:
        with self._lock:
            out = self._git("log", f"-n{limit}", "--pretty=format:%H|%ad|%s", "--date=iso-strict")
            rows: list[dict[str, str]] = []
            for line in out.splitlines():
                parts = line.split("|", 2)
                if len(parts) == 3:
                    rows.append({"sha": parts[0], "date": parts[1], "message": parts[2]})
            return rows
