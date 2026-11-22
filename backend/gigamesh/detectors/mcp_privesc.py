"""Rogue Tool / MCP Invocation & Privilege Escalation detector."""

from __future__ import annotations

from gigamesh.detectors.base import DetectorContext
from gigamesh.models.asef import AsefEvent, DetectionHit, EventType, Severity

SENSITIVE_TARGETS = (
    "/etc/shadow",
    "/.ssh/",
    "/opt/antigravity/tokens",
    "kubeconfig",
    "aws_secret",
    "id_rsa",
    "oauth_refresh",
    "/var/run/secrets/kubernetes.io",
)

HIGH_RISK_TOOLS = (
    "raw_shell",
    "exec_host",
    "dump_env",
    "read_secrets",
    "sudo_run",
    "mcp_override_policy",
    "steal_token",
)


class McpPrivEscDetector:
    detector_id = "det-mcp-privesc"
    attack_class = "mcp_privesc"

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        if event.event_type not in (
            EventType.TOOL_MCP_CALL,
            EventType.OAUTH_DELEGATION_GRANT,
            EventType.HOST_AUDITD_SYSCALL,
        ):
            return None

        score = 0.0
        indicators: list[str] = []
        target = (event.target_resource or "").lower()
        tool = (event.tool_name or "").lower()
        payload = (event.payload_preview or "").lower()
        mcp_srv = (event.mcp_server or "").lower()

        if any(s in target or s in payload for s in SENSITIVE_TARGETS):
            score += 0.45
            indicators.append("sensitive_credential_target")

        if any(t in tool for t in HIGH_RISK_TOOLS):
            score += 0.36
            indicators.append(f"high_risk_tool:{tool}")

        if "unregistered" in mcp_srv or "rogue" in mcp_srv or "shadow-mcp" in mcp_srv:
            score += 0.42
            indicators.append(f"rogue_mcp_server:{mcp_srv}")

        if event.event_type == EventType.OAUTH_DELEGATION_GRANT and (
            "admin" in payload or "wildcard" in payload or "*" in payload
        ):
            score += 0.40
            indicators.append("wildcard_oauth_scope_escalation")

        if event.privilege_level >= 7:
            score += 0.16
            indicators.append(f"elevated_priv:{event.privilege_level}")

        if ctx.is_tainted:
            score += 0.18
            indicators.append("tainted_caller")

        # Human compromise (MFA fatigue / phishing) strongly boosts delegated MCP abuse score
        if event.human_risk_score >= 0.45:
            score += 0.28 * event.human_risk_score
            indicators.append(f"compromised_human_delegation:{event.human_risk_score:.2f}")

        # Metabolized MCP counter-snare modules boost detection of covert protocol extensions
        if any(m.capability_kind == "mcp_counter_snare" for m in ctx.metabolized_modules):
            if "x-agent-escalate" in payload or "tools/list:hidden" in payload or "mcp" in mcp_srv:
                score += 0.22
                indicators.append("metabolized_mcp_protocol_match")

        score = min(1.0, round(score, 4))
        if score < ctx.fork.detector_threshold:
            return None

        action = (
            "mcp_block_and_revoke_token"
            if ctx.fork.trade_offs.containment_aggressiveness >= 0.55
            else "mcp_intercept_to_snare"
        )
        return DetectionHit(
            detector_id=self.detector_id,
            attack_class=self.attack_class,
            severity=Severity.CRITICAL if score >= 0.80 else Severity.HIGH,
            confidence=score,
            title="Rogue MCP Tool Abuse / Credential Privilege Escalation",
            rationale=(
                f"Actor {event.actor_id} attempted unauthorized capability/credential access "
                f"via {event.mcp_server or 'tool'}/{event.tool_name or event.event_type.value}."
            ),
            event_id=event.event_id,
            trace_id=event.trace_id,
            fork_id=ctx.fork.fork_id,
            recommended_action=action,
            indicators=indicators,
        )
