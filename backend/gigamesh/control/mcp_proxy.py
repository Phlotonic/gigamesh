"""Dynamic MCP Policy Proxy & Agent Session/Token Kill-Switch."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class McpPolicyProxy:
    """Enforces dynamic MCP capability blocks, frozen agent sessions, and revoked tokens."""

    def __init__(self) -> None:
        self.frozen_agents: dict[str, dict[str, Any]] = {}
        self.revoked_tokens: set[str] = set()
        self.blocked_mcp_tools: dict[str, str] = {}
        self.intercepted_calls: list[dict[str, Any]] = []

    def freeze_agent(self, agent_id: str, reason: str, fork_id: str) -> dict[str, Any]:
        record = {
            "agent_id": agent_id,
            "reason": reason,
            "fork_id": fork_id,
            "frozen_at": datetime.now(timezone.utc).isoformat(),
        }
        self.frozen_agents[agent_id] = record
        return record

    def revoke_delegation(self, token_or_principal: str) -> None:
        self.revoked_tokens.add(token_or_principal)

    def block_tool(self, tool_pattern: str, reason: str) -> None:
        self.blocked_mcp_tools[tool_pattern.lower()] = reason

    def check_call(self, agent_id: str, tool_name: str | None, mcp_server: str | None) -> dict[str, Any]:
        if agent_id in self.frozen_agents:
            verdict = {"allowed": False, "action": "kill_switch_frozen", "reason": self.frozen_agents[agent_id]["reason"]}
            self.intercepted_calls.append({"agent_id": agent_id, "tool": tool_name, **verdict})
            return verdict

        key = f"{mcp_server or ''}/{tool_name or ''}".lower()
        for pat, reason in self.blocked_mcp_tools.items():
            if pat in key:
                verdict = {"allowed": False, "action": "mcp_policy_blocked", "reason": reason}
                self.intercepted_calls.append({"agent_id": agent_id, "tool": tool_name, **verdict})
                return verdict

        return {"allowed": True, "action": "allow", "reason": "policy_clean"}

    def status(self) -> dict[str, Any]:
        return {
            "frozen_agents": list(self.frozen_agents.values()),
            "revoked_tokens": sorted(self.revoked_tokens),
            "blocked_mcp_tools": dict(self.blocked_mcp_tools),
            "intercepted_count": len(self.intercepted_calls),
            "recent_interceptions": self.intercepted_calls[-20:],
        }
