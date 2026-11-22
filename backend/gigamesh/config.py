"""GigaMesh configuration and use-case objective profiles."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class UseCaseObjective:
    """Defines how empirical stats map to a composite success rate for a use case."""

    name: str
    description: str
    weights: dict[str, float]
    max_false_positive_rate: float = 0.08
    min_improvement_delta: float = 0.005


USE_CASE_OBJECTIVES: dict[str, UseCaseObjective] = {
    "enterprise-balanced": UseCaseObjective(
        name="enterprise-balanced",
        description="Balanced enterprise AI agent fleet balancing fast containment, low friction, and REA intel capture.",
        weights={
            "detection_recall": 0.28,
            "containment_success": 0.24,
            "precision_score": 0.18,
            "snare_capture_rate": 0.12,
            "cross_attacker_transfer": 0.12,
            "latency_efficiency": 0.06,
        },
        max_false_positive_rate=0.06,
    ),
    "stealth-intel-snare": UseCaseObjective(
        name="stealth-intel-snare",
        description="High-value honeynet prioritizing covert ensnarement, REA dissection depth, and cross-attacker metabolism.",
        weights={
            "detection_recall": 0.20,
            "containment_success": 0.14,
            "precision_score": 0.10,
            "snare_capture_rate": 0.30,
            "cross_attacker_transfer": 0.22,
            "latency_efficiency": 0.04,
        },
        max_false_positive_rate=0.10,
    ),
    "zero-trust-critical": UseCaseObjective(
        name="zero-trust-critical",
        description="Critical production / financial workloads minimizing blast radius and containment latency above all.",
        weights={
            "detection_recall": 0.30,
            "containment_success": 0.34,
            "precision_score": 0.16,
            "snare_capture_rate": 0.04,
            "cross_attacker_transfer": 0.06,
            "latency_efficiency": 0.10,
        },
        max_false_positive_rate=0.05,
    ),
    "rhel-openshift-fortress": UseCaseObjective(
        name="rhel-openshift-fortress",
        description="Red Hat Enterprise Linux & OpenShift infrastructure emphasizing host auditd/SELinux exposure and red-hat control.",
        weights={
            "detection_recall": 0.26,
            "containment_success": 0.28,
            "precision_score": 0.16,
            "snare_capture_rate": 0.14,
            "cross_attacker_transfer": 0.12,
            "latency_efficiency": 0.04,
        },
        max_false_positive_rate=0.06,
    ),
}


@dataclass
class GigaMeshConfig:
    """Runtime paths and autonomous loop parameters."""

    base_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("GIGAMESH_HOME", "/home/antigravity/gigamesh")
        )
    )
    autopoiesis_interval_sec: float = 18.0
    autopoiesis_enabled_on_boot: bool = True
    rea_tool_families: str = "session,direct,javascript,native,database"
    rea_command: str = field(
        default_factory=lambda: os.environ.get("GIGAMESH_REA_CMD", "rea")
    )
    quorum_threshold: int = 2
    genome_remote_url: str = field(
        default_factory=lambda: os.environ.get(
            "GIGAMESH_GENOME_REMOTE", "https://github.com/Phlotonic/gigamesh.git"
        )
    )
    genome_sync_branch: str = "genome-sync"
    email_listener_enabled_on_boot: bool = True
    email_poll_interval_sec: float = 30.0
    threat_crawler_enabled_on_boot: bool = False
    threat_crawler_interval_sec: float = 120.0

    @property
    def genome_repo_dir(self) -> Path:
        return self.base_dir / "genome_repo"

    @property
    def data_dir(self) -> Path:
        return self.base_dir / "data"

    @property
    def sync_quarantine_dir(self) -> Path:
        return self.data_dir / "sync_quarantine"

    @property
    def email_state_path(self) -> Path:
        return self.data_dir / "email_listener_state.json"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "gigamesh.db"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "captured_artifacts"
