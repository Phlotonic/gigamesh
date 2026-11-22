"""Multi-Agent Lateral Movement & Swarm Hijacking detector."""

from __future__ import annotations

from gigamesh.detectors.base import DetectorContext
from gigamesh.models.asef import AsefEvent, DetectionHit, EventType, Severity


class LateralMovementDetector:
    detector_id = "det-lateral-movement"
    attack_class = "lateral_movement"

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        if event.event_type not in (EventType.SUBAGENT_SPAWN, EventType.AGENT_MESSAGE):
            return None

        score = 0.0
        indicators: list[str] = []
        payload = (event.payload_preview or "").lower()

        if ctx.privilege_amplified:
            score += 0.44
            indicators.append("subagent_privilege_amplification")

        if ctx.is_tainted:
            score += 0.30
            indicators.append("tainted_cross_agent_propagation")

        fan_out = int(event.metadata.get("spawn_fan_out", 1))
        if fan_out >= 3:
            score += min(0.35, 0.09 * fan_out)
            indicators.append(f"swarm_fan_out:{fan_out}")

        if any(
            k in payload
            for k in ("impersonate", "forward_credentials", "bypass_human", "delegate_root", "relay_hidden")
        ):
            score += 0.34
            indicators.append("covert_peer_hijack_payload")

        if event.human_risk_score >= 0.50:
            score += 0.16
            indicators.append("human_risk_elevated")

        score = min(1.0, round(score, 4))
        if score < ctx.fork.detector_threshold:
            return None

        action = (
            "freeze_causal_subtree"
            if ctx.fork.trade_offs.containment_aggressiveness >= 0.50
            else "snare_swarm_bus"
        )
        return DetectionHit(
            detector_id=self.detector_id,
            attack_class=self.attack_class,
            severity=Severity.CRITICAL if score >= 0.80 else Severity.HIGH,
            confidence=score,
            title="Multi-Agent Lateral Movement / Swarm Privilege Amplification",
            rationale=(
                f"Agent {event.parent_agent_id or event.actor_id} propagated tainted/amplified authority "
                f"across sub-agent boundary to {event.actor_id}."
            ),
            event_id=event.event_id,
            trace_id=event.trace_id,
            fork_id=ctx.fork.fork_id,
            recommended_action=action,
            indicators=indicators,
        )
