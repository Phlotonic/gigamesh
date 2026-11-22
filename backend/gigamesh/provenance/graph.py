"""Causal Provenance & Multi-Hop Taint Propagation Graph powered by NetworkX."""

from __future__ import annotations

from collections import deque
from typing import Any

import networkx as nx

from gigamesh.models.asef import AsefEvent, EventType, TrustLevel


class CausalProvenanceGraph:
    """Tracks full causal chains: Human -> Delegation -> Agent -> SubAgent -> Tool/MCP -> Host.

    Propagates untrusted/poisoned taint across hops so indirect prompt injection and
    multi-agent lateral movement remain traceable back to patient zero.
    """

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._agent_taint: dict[str, set[str]] = {}
        self._agent_privilege: dict[str, int] = {}
        self._trace_roots: dict[str, str] = {}

    def ingest_event(self, event: AsefEvent) -> dict[str, Any]:
        """Insert an ASEF event into the causal graph and compute propagated taint & privilege deltas."""
        actor_node = f"{event.actor_type.value}:{event.actor_id}"
        self._ensure_node(
            actor_node,
            kind=event.actor_type.value,
            label=event.actor_id,
            privilege=event.privilege_level,
            trace_id=event.trace_id,
        )

        # Track maximum observed privilege per actor
        prev_priv = self._agent_privilege.get(event.actor_id, event.privilege_level)
        self._agent_privilege[event.actor_id] = max(prev_priv, event.privilege_level)

        # Link human principal & delegation chain
        if event.human_principal_id:
            human_node = f"human:{event.human_principal_id}"
            self._ensure_node(
                human_node,
                kind="human",
                label=event.human_principal_id,
                risk_score=event.human_risk_score,
                trace_id=event.trace_id,
            )
            self.graph.add_edge(
                human_node,
                actor_node,
                relation="delegates_to",
                trace_id=event.trace_id,
                event_id=event.event_id,
                delegation_chain=list(event.delegation_chain),
            )
            self._trace_roots.setdefault(event.trace_id, human_node)

        # Link parent agent -> child sub-agent spawn & propagate taint
        privilege_amplified = False
        if event.parent_agent_id:
            parent_node = f"agent:{event.parent_agent_id}"
            self._ensure_node(parent_node, kind="agent", label=event.parent_agent_id, trace_id=event.trace_id)
            parent_priv = self._agent_privilege.get(event.parent_agent_id, 1)
            if event.privilege_level > parent_priv:
                privilege_amplified = True
            self.graph.add_edge(
                parent_node,
                actor_node,
                relation="spawns_or_delegates",
                trace_id=event.trace_id,
                event_id=event.event_id,
                privilege_amplified=privilege_amplified,
            )
            # Propagate parent's taint to spawned child
            parent_taints = self._agent_taint.get(event.parent_agent_id, set())
            if parent_taints:
                self._agent_taint.setdefault(event.actor_id, set()).update(parent_taints)

        # Handle untrusted / poisoned content ingestion -> taint actor
        inherited_taints = set(self._agent_taint.get(event.actor_id, set()))
        incoming_taints = set(event.taint_labels)
        if event.source_trust_level in (TrustLevel.UNTRUSTED, TrustLevel.POISONED):
            source_label = event.target_resource or f"untrusted:{event.event_id}"
            src_node = f"source:{source_label}"
            self._ensure_node(
                src_node,
                kind="external_source",
                label=source_label,
                trust_level=event.source_trust_level.value,
                tainted=True,
                trace_id=event.trace_id,
            )
            taint_tag = f"taint:{source_label}"
            incoming_taints.add(taint_tag)
            self.graph.add_edge(
                src_node,
                actor_node,
                relation="taints",
                trace_id=event.trace_id,
                event_id=event.event_id,
                taint_tag=taint_tag,
            )
            self._trace_roots[event.trace_id] = src_node

        if incoming_taints:
            inherited_taints.update(incoming_taints)
            self._agent_taint[event.actor_id] = inherited_taints
            self.graph.nodes[actor_node]["tainted"] = True
            self.graph.nodes[actor_node]["taint_labels"] = sorted(inherited_taints)

        # Link actor -> tool/MCP/host/egress target
        target_node: str | None = None
        if event.tool_name or event.mcp_server:
            t_label = f"{event.mcp_server or 'tool'}/{event.tool_name or 'call'}"
            target_node = f"mcp:{t_label}"
            self._ensure_node(
                target_node,
                kind="mcp_tool",
                label=t_label,
                tainted=bool(inherited_taints),
                trace_id=event.trace_id,
            )
            self.graph.add_edge(
                actor_node,
                target_node,
                relation="invokes_tool",
                trace_id=event.trace_id,
                event_id=event.event_id,
                tainted=bool(inherited_taints),
            )

        if event.host_id:
            host_node = f"host:{event.host_id}"
            self._ensure_node(
                host_node,
                kind="rhel_host",
                label=event.host_id,
                selinux_context=event.selinux_context,
                trace_id=event.trace_id,
            )
            src = target_node or actor_node
            self.graph.add_edge(
                src,
                host_node,
                relation=event.event_type.value,
                trace_id=event.trace_id,
                event_id=event.event_id,
                syscall=event.auditd_syscall,
                systemd_unit=event.systemd_unit,
            )

        if event.egress_destination:
            egress_node = f"egress:{event.egress_destination}"
            self._ensure_node(
                egress_node,
                kind="egress",
                label=event.egress_destination,
                tainted=bool(inherited_taints),
                trace_id=event.trace_id,
            )
            self.graph.add_edge(
                target_node or actor_node,
                egress_node,
                relation="exfiltrates_or_beacons",
                trace_id=event.trace_id,
                event_id=event.event_id,
            )

        return {
            "actor_node": actor_node,
            "propagated_taints": sorted(inherited_taints),
            "privilege_amplified": privilege_amplified,
            "is_tainted": bool(inherited_taints),
            "patient_zero": self.find_patient_zero(actor_node, event.trace_id),
        }

    def _ensure_node(self, node_id: str, **attrs: Any) -> None:
        if node_id not in self.graph:
            self.graph.add_node(node_id, **attrs)
        else:
            for k, v in attrs.items():
                if v is not None:
                    self.graph.nodes[node_id][k] = v

    def get_taints(self, actor_id: str) -> list[str]:
        return sorted(self._agent_taint.get(actor_id, set()))

    def find_patient_zero(self, start_node: str, trace_id: str | None = None) -> str | None:
        """Walk upstream edges to expose the originating untrusted source or compromised human."""
        if start_node not in self.graph:
            return self._trace_roots.get(trace_id or "")
        visited: set[str] = set()
        queue = deque([start_node])
        roots: list[str] = []
        while queue:
            curr = queue.popleft()
            if curr in visited:
                continue
            visited.add(curr)
            preds = list(self.graph.predecessors(curr))
            if not preds:
                roots.append(curr)
            else:
                for p in preds:
                    if p not in visited:
                        queue.append(p)
        # Prefer external poisoned source if present, otherwise human principal
        for r in roots:
            if r.startswith("source:"):
                return r
        for r in roots:
            if r.startswith("human:"):
                return r
        return roots[0] if roots else start_node

    def blast_radius(self, start_node: str) -> list[str]:
        """Compute all downstream impacted agents, tools, hosts, and egress endpoints."""
        if start_node not in self.graph:
            return []
        return sorted(nx.descendants(self.graph, start_node))

    def snapshot(self, trace_id: str | None = None, max_nodes: int = 80) -> dict[str, Any]:
        """Export graph nodes and edges for API/UI visualization."""
        if trace_id:
            matching_nodes = [
                n for n, d in self.graph.nodes(data=True) if d.get("trace_id") == trace_id
            ]
            sub = self.graph.subgraph(matching_nodes)
        else:
            nodes_all = list(self.graph.nodes())[-max_nodes:]
            sub = self.graph.subgraph(nodes_all)

        return {
            "nodes": [
                {"id": n, **dict(d)}
                for n, d in sub.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **dict(d)}
                for u, v, d in sub.edges(data=True)
            ],
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
        }
