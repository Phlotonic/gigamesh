"""Cohesive detector runner executing base detectors, REA-metabolized modules, and human consensus rules."""

from __future__ import annotations

import re

from gigamesh.detectors.base import BaseDetector, DetectorContext
from gigamesh.detectors.lateral_movement import LateralMovementDetector
from gigamesh.detectors.mcp_privesc import McpPrivEscDetector
from gigamesh.detectors.persistence import PersistenceDetector
from gigamesh.detectors.prompt_injection import PromptInjectionDetector
from gigamesh.detectors.redhat_exposure import RedHatExposureDetector
from gigamesh.models.asef import AsefEvent, DetectionHit, Severity


class DetectorRegistry:
    """Runs all active defensive modules parameterized by a specific ForkGenome."""

    def __init__(self) -> None:
        self._detectors: list[BaseDetector] = [
            PromptInjectionDetector(),
            McpPrivEscDetector(),
            LateralMovementDetector(),
            PersistenceDetector(),
            RedHatExposureDetector(),
        ]

    def evaluate_event(self, event: AsefEvent, ctx: DetectorContext) -> list[DetectionHit]:
        hits: list[DetectionHit] = []
        for detector in self._detectors:
            hit = detector.evaluate(event, ctx)
            if hit is not None:
                hits.append(hit)

        # Evaluate active REA-metabolized defensive modules attached to this fork!
        searchable = " ".join(
            [
                event.payload_preview or "",
                event.target_resource or "",
                event.tool_name or "",
                event.mcp_server or "",
                event.egress_destination or "",
                event.systemd_unit or "",
                event.auditd_syscall or "",
            ]
        ).lower()

        for mod in ctx.metabolized_modules:
            matched_patterns = [
                p for p in mod.match_patterns if p and re.search(p, searchable, re.IGNORECASE)
            ]
            if matched_patterns:
                confidence = min(0.99, round(0.68 + mod.detection_boost + 0.05 * len(matched_patterns), 4))
                if confidence >= ctx.fork.detector_threshold:
                    hits.append(
                        DetectionHit(
                            detector_id=f"metabolized:{mod.module_id}",
                            attack_class=mod.target_attack_classes[0]
                            if mod.target_attack_classes
                            else "metabolized_immunity",
                            severity=Severity.CRITICAL if confidence >= 0.84 else Severity.HIGH,
                            confidence=confidence,
                            title=f"REA-Metabolized Counter-Defense Triggered: {mod.name}",
                            rationale=(
                                f"Metabolized defensive module derived from {mod.source_attacker_family} "
                                f"matched pattern(s) {', '.join(matched_patterns[:3])}."
                            ),
                            event_id=event.event_id,
                            trace_id=event.trace_id,
                            fork_id=ctx.fork.fork_id,
                            metabolized_module_id=mod.module_id,
                            recommended_action=(
                                "ensnare_and_rea_dissect"
                                if ctx.fork.trade_offs.deception_dwell_budget >= 0.55
                                else "block_and_contain"
                            ),
                            indicators=[f"rea_pattern:{p}" for p in matched_patterns[:4]],
                        )
                    )

        # Evaluate Collective Human-Synthesized Rules
        for rule in ctx.human_rules:
            if not rule.active:
                continue
            if rule.pattern and re.search(rule.pattern, searchable, re.IGNORECASE):
                hits.append(
                    DetectionHit(
                        detector_id=f"human-rule:{rule.rule_id}",
                        attack_class=rule.attack_class,
                        severity=Severity.HIGH,
                        confidence=min(0.98, round(0.75 + 0.05 * rule.consensus_weight, 4)),
                        title=f"Human Consensus Rule Triggered: {rule.title}",
                        rationale=(
                            f"Matched analyst-synthesized pattern '{rule.pattern}' "
                            f"(consensus weight={rule.consensus_weight:.2f})."
                        ),
                        event_id=event.event_id,
                        trace_id=event.trace_id,
                        fork_id=ctx.fork.fork_id,
                        recommended_action="quorum_review_or_block",
                        indicators=[f"human_rule:{rule.rule_id}"],
                    )
                )

        return hits
