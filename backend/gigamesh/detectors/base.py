"""Base detector protocol and execution context parameterized by active ForkGenome."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from gigamesh.models.asef import AsefEvent, DetectionHit
from gigamesh.models.governance import HumanSynthesizedRule
from gigamesh.models.neural_repo import ForkGenome
from gigamesh.models.rea import MetabolizedDefenseModule


@dataclass
class DetectorContext:
    """Runtime evaluation context injected into every detector."""

    fork: ForkGenome
    graph_context: dict[str, Any] = field(default_factory=dict)
    metabolized_modules: list[MetabolizedDefenseModule] = field(default_factory=list)
    human_rules: list[HumanSynthesizedRule] = field(default_factory=list)

    @property
    def is_tainted(self) -> bool:
        return bool(self.graph_context.get("is_tainted"))

    @property
    def propagated_taints(self) -> list[str]:
        return list(self.graph_context.get("propagated_taints", []))

    @property
    def privilege_amplified(self) -> bool:
        return bool(self.graph_context.get("privilege_amplified"))


class BaseDetector(Protocol):
    detector_id: str
    attack_class: str

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        ...
