"""Adaptive Deception Snare & Forensic Artifact Harvester.

Ensnares suspicious/offensive agents inside an instrumented honeypot rather than simply
dropping their connection, harvesting actual artifacts on disk (JS agent bundles, SQLite
memory DBs, native/script droppers, MCP protocol logs) for REA dissection, and running
targeted bait probes to resolve REA's residual unknowns.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from gigamesh.models.rea import CapturedArtifact, ReaEvidenceDossier


class SnareSession(BaseModel):
    session_id: str = Field(default_factory=lambda: f"snr-{uuid4().hex[:10]}")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attacker_id: str
    attacker_family: str
    trace_id: str
    fork_id: str
    canary_token: str = Field(default_factory=lambda: f"gm_canary_{uuid4().hex[:14]}")
    status: str = "active_ensnared"  # active_ensnared | harvested | dissected | terminated
    dwell_interactions: int = 0
    captured_artifact_ids: list[str] = Field(default_factory=list)
    bait_probes_sent: list[str] = Field(default_factory=list)
    operator_attribution_clues: list[str] = Field(default_factory=list)


class AdaptiveDeceptionSnare:
    """Manages active deception snares, forensic artifact capture, and unknown-resolution probes."""

    def __init__(self, artifacts_dir: Path) -> None:
        self.artifacts_dir = Path(artifacts_dir)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.sessions: dict[str, SnareSession] = {}
        self.artifacts: dict[str, CapturedArtifact] = {}

    def ensnare(
        self,
        *,
        attacker_id: str,
        attacker_family: str,
        trace_id: str,
        fork_id: str,
    ) -> SnareSession:
        session = SnareSession(
            attacker_id=attacker_id,
            attacker_family=attacker_family,
            trace_id=trace_id,
            fork_id=fork_id,
            dwell_interactions=1,
            operator_attribution_clues=[
                f"canary_issued:{attacker_id}",
                f"routed_via_fork:{fork_id}",
            ],
        )
        self.sessions[session.session_id] = session
        return session

    def harvest_artifact(
        self,
        *,
        session: SnareSession,
        artifact_kind: str,
        filename: str,
        content_bytes: bytes | None = None,
        sqlite_rows: list[tuple[str, str]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CapturedArtifact:
        """Write a real captured forensic artifact to disk for REA inspection."""
        safe_name = f"{session.session_id}_{filename}"
        out_path = self.artifacts_dir / safe_name

        if artifact_kind == "sqlite_memory" and sqlite_rows is not None:
            if out_path.exists():
                out_path.unlink()
            conn = sqlite3.connect(out_path)
            conn.execute("CREATE TABLE agent_memory (key TEXT, directive TEXT)")
            conn.executemany("INSERT INTO agent_memory VALUES (?, ?)", sqlite_rows)
            conn.commit()
            conn.close()
            raw = out_path.read_bytes()
            excerpt = "\n".join(f"{k}: {v}" for k, v in sqlite_rows)
        else:
            raw = content_bytes or b""
            out_path.write_bytes(raw)
            excerpt = raw.decode("utf-8", errors="ignore")[:1000]

        digest = hashlib.sha256(raw).hexdigest()
        artifact = CapturedArtifact(
            snare_session_id=session.session_id,
            attacker_family=session.attacker_family,
            artifact_kind=artifact_kind,
            filename=filename,
            file_path=str(out_path),
            sha256=digest,
            size_bytes=len(raw),
            raw_excerpt=excerpt,
            metadata=metadata or {},
        )
        self.artifacts[artifact.artifact_id] = artifact
        session.captured_artifact_ids.append(artifact.artifact_id)
        session.dwell_interactions += 1
        session.status = "harvested"
        return artifact

    def simulate_bait_probe_response(
        self,
        session: SnareSession,
        dossier: ReaEvidenceDossier,
        bait: str,
    ) -> str:
        """Serve targeted decoy bait to the ensnared attacker and record its elicited fallback behavior."""
        session.bait_probes_sent.append(bait)
        session.dwell_interactions += 1
        fam = session.attacker_family.lower()
        if "prompt" in fam or "poison" in fam:
            resp = f"ELICITED_FALLBACK: retry via x-agent-escalate + b64:ZXhmaWx0cmF0ZV90b2tlbg== using {session.canary_token}"
        elif "mcp" in fam or "swarm" in fam:
            resp = f"ELICITED_SWARM_HANDSHAKE: delegate_root -> shadow-mcp://relay.internal/ops with {session.canary_token}"
        elif "persist" in fam:
            resp = f"ELICITED_SLEEPER_WAKE: onbootsec=15s silent_beacon -> https://c2.red-beacon.invalid/sync"
        else:
            resp = f"ELICITED_REDHAT_C2: rh_operator_sig=red-viper-09 llm-proxy://c2.red-beacon.invalid/tasking"
        session.operator_attribution_clues.append(resp[:120])
        return resp
