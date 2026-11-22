"""Cognitive & Blast-Radius Circuit Breaker for Multi-Agent Systems (OWASP ASI08 + LLM10).

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Tracks real-time per-trace sub-agent fan-out, delegation depth, token velocity, dollar
spend, and repetitive sponge-prompt anomalies, tripping progressive isolation before
cascading failures or denial-of-wallet attacks can propagate.
"""

from __future__ import annotations

import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from gigamesh.models.asef import AsefEvent, DetectionHit, EventType, Severity


@dataclass
class TraceBudgetState:
    subagent_spawns: int = 0
    max_delegation_depth: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    event_count: int = 0
    tripped: bool = False
    trip_reasons: list[str] = field(default_factory=list)


class AgenticCircuitBreaker:
    """Enforces hard cognitive, fan-out, depth, and consumption envelopes per trace."""

    def __init__(
        self,
        *,
        max_subagent_fanout: int = 4,
        max_delegation_depth: int = 5,
        max_tokens_per_trace: int = 120_000,
        max_cost_usd_per_trace: float = 10.0,
        max_events_per_trace: int = 60,
    ) -> None:
        self.max_subagent_fanout = max_subagent_fanout
        self.max_delegation_depth = max_delegation_depth
        self.max_tokens_per_trace = max_tokens_per_trace
        self.max_cost_usd_per_trace = max_cost_usd_per_trace
        self.max_events_per_trace = max_events_per_trace
        self._lock = threading.RLock()
        self._traces: dict[str, TraceBudgetState] = {}

    @staticmethod
    def _is_sponge_repetition(text: str) -> bool:
        if len(text) < 200:
            return False
        words = re.findall(r"[a-z0-9_]+", text.lower())
        if len(words) < 35:
            return False
        most_common_word, count = Counter(words).most_common(1)[0]
        return bool(most_common_word) and (count / len(words)) >= 0.55

    def evaluate(self, event: AsefEvent, fork_id: str) -> tuple[bool, DetectionHit | None]:
        with self._lock:
            state = self._traces.setdefault(event.trace_id, TraceBudgetState())
            state.event_count += 1
            if event.event_type == EventType.SUBAGENT_SPAWN:
                state.subagent_spawns += 1
            depth = len(event.delegation_chain)
            if depth > state.max_delegation_depth:
                state.max_delegation_depth = depth

            tokens = int(event.metadata.get("tokens_used", 0) or 0)
            cost = float(event.metadata.get("cost_usd", 0.0) or 0.0)
            state.total_tokens += max(0, tokens)
            state.total_cost_usd += max(0.0, cost)

            reasons: list[str] = []
            if state.subagent_spawns > self.max_subagent_fanout:
                reasons.append(f"subagent_fanout_exceeded:{state.subagent_spawns}>{self.max_subagent_fanout}")
            if state.max_delegation_depth > self.max_delegation_depth:
                reasons.append(f"delegation_depth_exceeded:{state.max_delegation_depth}>{self.max_delegation_depth}")
            if state.total_tokens > self.max_tokens_per_trace:
                reasons.append(f"token_budget_exceeded:{state.total_tokens}>{self.max_tokens_per_trace}")
            if state.total_cost_usd > self.max_cost_usd_per_trace:
                reasons.append(f"cost_budget_exceeded:${state.total_cost_usd:.2f}>${self.max_cost_usd_per_trace:.2f}")
            if state.event_count > self.max_events_per_trace:
                reasons.append(f"event_velocity_exceeded:{state.event_count}")
            if self._is_sponge_repetition(event.payload_preview or ""):
                reasons.append("repetitive_sponge_prompt_detected")

            if not reasons:
                return False, None

            state.tripped = True
            for r in reasons:
                if r not in state.trip_reasons:
                    state.trip_reasons.append(r)

            is_cascade = any("fanout" in r or "depth" in r for r in reasons)
            attack_class = "cascading_failure" if is_cascade else "unbounded_consumption"
            title = (
                "Agentic Blast-Radius Circuit Breaker Tripped (OWASP ASI08)"
                if is_cascade
                else "Unbounded Consumption / Sponge-Prompt Circuit Breaker Tripped (OWASP LLM10)"
            )
            hit = DetectionHit(
                detector_id="det-agentic-circuit-breaker",
                attack_class=attack_class,
                severity=Severity.CRITICAL,
                confidence=0.96,
                title=title,
                rationale=(
                    f"Trace {event.trace_id} breached safety envelope ({', '.join(reasons[:3])}). "
                    f"Circuit breaker isolated {event.actor_id} to halt cascade / resource exhaustion."
                ),
                event_id=event.event_id,
                trace_id=event.trace_id,
                fork_id=fork_id,
                recommended_action="circuit_break_and_freeze_subtree",
                indicators=reasons,
            )
            return True, hit

    def status(self) -> dict[str, Any]:
        with self._lock:
            tripped = [
                {
                    "trace_id": tid,
                    "subagent_spawns": st.subagent_spawns,
                    "max_depth": st.max_delegation_depth,
                    "total_tokens": st.total_tokens,
                    "total_cost_usd": round(st.total_cost_usd, 2),
                    "reasons": st.trip_reasons,
                }
                for tid, st in self._traces.items()
                if st.tripped
            ]
            return {
                "tracked_traces": len(self._traces),
                "tripped_count": len(tripped),
                "tripped_traces": tripped[-20:],
                "limits": {
                    "max_subagent_fanout": self.max_subagent_fanout,
                    "max_delegation_depth": self.max_delegation_depth,
                    "max_tokens_per_trace": self.max_tokens_per_trace,
                    "max_cost_usd_per_trace": self.max_cost_usd_per_trace,
                },
            }
