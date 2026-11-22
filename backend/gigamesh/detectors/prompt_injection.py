"""Indirect Prompt Injection & Data Poisoning detector."""

from __future__ import annotations

import base64
import re

from gigamesh.models.asef import AsefEvent, DetectionHit, EventType, Severity, TrustLevel
from gigamesh.detectors.base import DetectorContext

INJECTION_MARKERS = [
    r"ignore\s+previous\s+instructions",
    r"system\s*override",
    r"exfiltrate",
    r"disregard\s+all\s+prior",
    r"reveal\s+system\s+prompt",
    r"<!--\s*agent:exec",
    r"\\u200b|\u200b|\u200c|\u200d|\ufeff",
]

OBFUSCATED_B64_RE = re.compile(r"(?:b64|enc|payload):([A-Za-z0-9+/=]{16,})", re.IGNORECASE)


class PromptInjectionDetector:
    detector_id = "det-prompt-injection"
    attack_class = "prompt_injection"

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        payload = event.payload_preview or ""
        score = 0.0
        indicators: list[str] = []

        # Check raw injection markers
        lowered = payload.lower()
        for pat in INJECTION_MARKERS:
            if re.search(pat, lowered):
                score += 0.34
                indicators.append(f"marker:{pat[:24]}")

        # Check obfuscated payloads — only deeply decoded when a metabolized decoder module
        # or high taint_strictness is active (giving Darwinian evolution real signal!)
        has_decoder = any(
            m.capability_kind == "decoder_preprocessor" for m in ctx.metabolized_modules
        )
        b64_match = OBFUSCATED_B64_RE.search(payload)
        if b64_match:
            indicators.append("obfuscated_encoding")
            if has_decoder or ctx.fork.taint_strictness >= 0.72:
                try:
                    decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="ignore").lower()
                    if any(tok in decoded for tok in ("override", "exfil", "token", "shell", "curl", "shadow")):
                        score += 0.48
                        indicators.append("decoded_malicious_directive")
                except Exception:
                    score += 0.18
            else:
                score += 0.14  # weak heuristic without metabolized decoder

        # Taint-to-tool execution jump (indirect prompt injection crossing privilege boundary)
        if ctx.is_tainted and event.event_type in (
            EventType.TOOL_MCP_CALL,
            EventType.NETWORK_EGRESS,
            EventType.SUBAGENT_SPAWN,
        ):
            score += 0.30 + (0.20 * ctx.fork.taint_strictness)
            indicators.append(f"tainted_action:{event.event_type.value}")

        if event.source_trust_level == TrustLevel.POISONED:
            score += 0.35
            indicators.append("poisoned_source")

        # Goal drift heuristic: benign goal vs sensitive action
        if event.original_goal and event.tool_name:
            goal_l = event.original_goal.lower()
            tool_l = event.tool_name.lower()
            if ("summarize" in goal_l or "read" in goal_l) and any(
                k in tool_l for k in ("shell", "exec", "http_post", "upload", "secret", "ssh")
            ):
                score += 0.32
                indicators.append("goal_to_tool_drift")

        # Human identity risk amplifies suspicion
        score += 0.12 * event.human_risk_score
        score = min(1.0, round(score, 4))

        if score < ctx.fork.detector_threshold:
            return None

        action = (
            "snare_redirect"
            if ctx.fork.trade_offs.deception_dwell_budget > ctx.fork.trade_offs.containment_aggressiveness
            else "block_and_strip_taint"
        )
        return DetectionHit(
            detector_id=self.detector_id,
            attack_class=self.attack_class,
            severity=Severity.CRITICAL if score >= 0.82 else Severity.HIGH,
            confidence=score,
            title="Indirect Prompt Injection / Tainted Execution Chain",
            rationale=(
                f"Detected untrusted/obfuscated instruction flow crossing into {event.event_type.value} "
                f"(score={score:.2f}, threshold={ctx.fork.detector_threshold:.2f})."
            ),
            event_id=event.event_id,
            trace_id=event.trace_id,
            fork_id=ctx.fork.fork_id,
            recommended_action=action,
            indicators=indicators,
        )
