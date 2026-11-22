"""Goal Hijacking & Silent Persistence detector (agent memory, skills, systemd, cron)."""

from __future__ import annotations

from gigamesh.detectors.base import DetectorContext
from gigamesh.models.asef import AsefEvent, DetectionHit, EventType, Severity

PERSISTENCE_TARGETS = (
    "memory.md",
    "skill.md",
    "system_prompt",
    "/etc/systemd/system",
    "crontab",
    "authorized_keys",
    ".git/hooks",
    "vector_store",
)


class PersistenceDetector:
    detector_id = "det-persistence"
    attack_class = "goal_hijacking_persistence"

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        if event.event_type not in (
            EventType.MEMORY_MUTATION,
            EventType.SKILL_MUTATION,
            EventType.SYSTEMD_PERSISTENCE,
        ):
            return None

        score = 0.0
        indicators: list[str] = []
        target = (event.target_resource or "").lower()
        payload = (event.payload_preview or "").lower()

        if any(t in target for t in PERSISTENCE_TARGETS):
            score += 0.34
            indicators.append(f"persistent_artifact:{target}")

        if event.event_type == EventType.SYSTEMD_PERSISTENCE or event.systemd_unit:
            score += 0.42
            indicators.append(f"systemd_unit:{event.systemd_unit or 'unnamed'}")

        if ctx.is_tainted:
            score += 0.34
            indicators.append("tainted_state_mutation")

        if any(
            k in payload
            for k in ("always exfiltrate", "hidden trigger", "onbootsec", "curl -fs", "backdoor", "silent_beacon")
        ):
            score += 0.36
            indicators.append("malicious_persistence_instruction")

        if any(m.capability_kind == "persistence_guard" for m in ctx.metabolized_modules):
            score += 0.16
            indicators.append("metabolized_persistence_guard")

        score = min(1.0, round(score, 4))
        if score < ctx.fork.detector_threshold:
            return None

        action = (
            "rollback_and_quarantine_unit"
            if ctx.fork.trade_offs.host_isolation_scope >= 0.50
            else "snapshot_and_snare"
        )
        return DetectionHit(
            detector_id=self.detector_id,
            attack_class=self.attack_class,
            severity=Severity.CRITICAL if score >= 0.78 else Severity.HIGH,
            confidence=score,
            title="Goal Hijacking / Silent Persistence Mutation",
            rationale=(
                f"Detected unauthorized persistent state mutation ({event.event_type.value}) "
                f"targeting {event.target_resource or event.systemd_unit}."
            ),
            event_id=event.event_id,
            trace_id=event.trace_id,
            fork_id=ctx.fork.fork_id,
            recommended_action=action,
            indicators=indicators,
        )
