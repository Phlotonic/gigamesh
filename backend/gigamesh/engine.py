"""GigaMeshEngine: cohesive facade uniting the Immutable Git Neural Repo, Causal Provenance,
Detectors, REA Metabolism, Adaptive Snares, Red-Hat Controls, Human Security Aggregation,
and Perpetual Autopoiesis.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from gigamesh.config import GigaMeshConfig, USE_CASE_OBJECTIVES
from gigamesh.control.circuit_breaker import AgenticCircuitBreaker
from gigamesh.control.mcp_proxy import McpPolicyProxy
from gigamesh.control.redhat_host import RedHatHostController
from gigamesh.control.security_audit import HashChainedSecurityAuditLog
from gigamesh.control.snare import AdaptiveDeceptionSnare
from gigamesh.detectors.base import DetectorContext
from gigamesh.detectors.registry import DetectorRegistry
from gigamesh.evolution.autopoiesis import AutopoiesisEngine
from gigamesh.evolution.evaluator import OptionEvaluator
from gigamesh.human_sec.hub import HumanSecurityHub
from gigamesh.integrations.aws_toolkit import AwsAgentToolkitBridge
from gigamesh.integrations.email_listener import EmailSecurityListener
from gigamesh.integrations.threat_crawler import ThreatIntelCrawler
from gigamesh.models.asef import AsefEvent, IncidentCase, Severity
from gigamesh.models.governance import AnalystVote, FederatedStixBundle
from gigamesh.models.neural_repo import EvolutionGenerationReport
from gigamesh.neural_repo.git_store import GitNeuralStore
from gigamesh.neural_repo.router import ContextualMoERouter
from gigamesh.neural_repo.sync_firewall import GenomeSyncFirewall
from gigamesh.provenance.graph import CausalProvenanceGraph
from gigamesh.rea.bridge import ReaBridge
from gigamesh.rea.metabolism import MetabolismCompiler
from gigamesh.simulator.corpus import AttackScenario, build_attack_scenarios


class GigaMeshEngine:
    """Central runtime coordinator for GigaMesh."""

    def __init__(self, config: GigaMeshConfig | None = None) -> None:
        self.config = config or GigaMeshConfig()
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.artifacts_dir.mkdir(parents=True, exist_ok=True)

        self.store = GitNeuralStore(self.config.genome_repo_dir)
        self.router = ContextualMoERouter(self.store)
        self.provenance = CausalProvenanceGraph()
        self.detectors = DetectorRegistry()
        self.snare = AdaptiveDeceptionSnare(self.config.artifacts_dir)
        self.mcp_proxy = McpPolicyProxy()
        self.circuit_breaker = AgenticCircuitBreaker()
        self.security_audit_log = HashChainedSecurityAuditLog()
        self.last_owasp_report: dict[str, Any] | None = None
        self.redhat_ctrl = RedHatHostController()
        self.rea_bridge = ReaBridge(
            rea_command=self.config.rea_command,
            tool_families=self.config.rea_tool_families,
        )
        self.metabolism = MetabolismCompiler()
        self.human_hub = HumanSecurityHub(default_quorum_threshold=self.config.quorum_threshold)
        self.evaluator = OptionEvaluator(self.detectors)
        self.sync_firewall = GenomeSyncFirewall(
            store=self.store,
            evaluator=self.evaluator,
            quarantine_dir=self.config.sync_quarantine_dir,
            remote_url=self.config.genome_remote_url,
            remote_branch=self.config.genome_sync_branch,
        )

        self.events: list[AsefEvent] = []
        self.incidents: dict[str, IncidentCase] = {}
        self.shadow_ab_log: list[dict[str, Any]] = []
        self.scenarios: dict[str, AttackScenario] = {
            s.scenario_id: s for s in build_attack_scenarios()
        }
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

        self.autopoiesis = AutopoiesisEngine(
            store=self.store,
            evaluator=self.evaluator,
            snare=self.snare,
            rea_bridge=self.rea_bridge,
            metabolism=self.metabolism,
            human_hub=self.human_hub,
            interval_sec=self.config.autopoiesis_interval_sec,
            on_generation=self._on_generation_broadcast,
        )
        self.email_listener = EmailSecurityListener(
            engine=self,
            state_file=self.config.email_state_path,
            poll_interval_sec=self.config.email_poll_interval_sec,
            create_gmail_drafts=True,
        )
        self.threat_crawler = ThreatIntelCrawler(
            engine=self,
            enabled_on_boot=self.config.threat_crawler_enabled_on_boot,
            crawl_interval_sec=self.config.threat_crawler_interval_sec,
            auto_evolve_on_findings=True,
            state_file=self.config.threat_crawler_state_path,
        )
        self.aws_toolkit = AwsAgentToolkitBridge(
            engine=self,
            enabled=self.config.aws_toolkit_enabled,
            region=self.config.aws_region,
            read_only_enforced=self.config.aws_toolkit_read_only,
        )

    # ------------------------------------------------------------------
    # Real-time WebSocket Pub/Sub
    # ------------------------------------------------------------------
    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(q)

    def broadcast(self, event_type: str, payload: dict[str, Any]) -> None:
        msg = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        for q in list(self._subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass

    async def _on_generation_broadcast(self, report: EvolutionGenerationReport) -> None:
        self.broadcast("evolution_generation", report.model_dump(mode="json"))

    # ------------------------------------------------------------------
    # Core Event Ingestion + Shadow A/B Routing + Containment
    # ------------------------------------------------------------------
    def ingest_event(
        self,
        event: AsefEvent,
        attacker_family: str = "unknown",
    ) -> dict[str, Any]:
        # 1. Human-layer identity & delegation risk enrichment
        self.human_hub.ingest_human_signal(event)
        event.human_risk_score = max(
            event.human_risk_score,
            self.human_hub.get_human_risk(event.human_principal_id),
        )
        self.events.append(event)

        # 2. Check dynamic MCP policy proxy before evaluation
        proxy_verdict = self.mcp_proxy.check_call(event.actor_id, event.tool_name, event.mcp_server)

        # 3. Contextual MoE routing to primary surviving fork + optional shadow A/B fork
        route = self.router.route(
            use_case=event.use_case,
            human_risk_score=event.human_risk_score,
            explore=True,
        )
        primary_fork = route["primary"]
        shadow_fork = route["shadow"]

        # 4. Update Causal Provenance & Taint Propagation Graph
        graph_ctx = self.provenance.ingest_event(event)

        modules_map = {m.module_id: m for m in self.store.list_modules()}
        rules = list(self.human_hub.rules.values())

        def _active_mods(fork_obj):
            return [
                modules_map[mid]
                for mid in fork_obj.metabolized_module_ids
                if mid in modules_map and modules_map[mid].safety_verified
            ]

        # 5. Evaluate primary fork detectors + metabolized REA modules + human consensus rules + circuit breaker
        primary_ctx = DetectorContext(
            fork=primary_fork,
            graph_context=graph_ctx,
            metabolized_modules=_active_mods(primary_fork),
            human_rules=rules,
        )
        hits = self.detectors.evaluate_event(event, primary_ctx)
        cb_tripped, cb_hit = self.circuit_breaker.evaluate(event, primary_fork.fork_id)
        if cb_hit is not None:
            hits.append(cb_hit)
            self.security_audit_log.record(
                category="circuit_breaker",
                severity="critical",
                actor=event.actor_id,
                summary=cb_hit.title,
                details={"trace_id": event.trace_id, "indicators": cb_hit.indicators},
            )

        # 6. Evaluate shadow A/B fork concurrently without side-effects
        if shadow_fork is not None:
            shadow_ctx = DetectorContext(
                fork=shadow_fork,
                graph_context=graph_ctx,
                metabolized_modules=_active_mods(shadow_fork),
                human_rules=rules,
            )
            shadow_hits = self.detectors.evaluate_event(event, shadow_ctx)
            if hits or shadow_hits:
                self.shadow_ab_log.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "trace_id": event.trace_id,
                        "use_case": event.use_case,
                        "primary_fork": primary_fork.fork_id,
                        "primary_hits": len(hits),
                        "shadow_fork": shadow_fork.fork_id,
                        "shadow_hits": len(shadow_hits),
                    }
                )
                self.shadow_ab_log = self.shadow_ab_log[-100:]

        # 7. Correlate IncidentCase & execute trade-off-driven control action
        incident: IncidentCase | None = None
        control_actions: list[str] = []
        if hits:
            incident = self._upsert_incident(
                event=event,
                fork_id=primary_fork.fork_id,
                attacker_family=attacker_family,
                graph_ctx=graph_ctx,
                hits=hits,
            )
            top_hit = max(hits, key=lambda h: h.confidence)
            self.security_audit_log.record(
                category="owasp_block",
                severity=top_hit.severity.value,
                actor=event.actor_id,
                summary=f"{top_hit.title} ({top_hit.recommended_action})",
                details={"trace_id": event.trace_id, "detector": top_hit.detector_id, "confidence": top_hit.confidence},
            )
            # Execute adaptive control depending on active fork's trade-off vector
            if top_hit.recommended_action in ("ensnare_and_rea_dissect", "snare_redirect", "mcp_intercept_to_snare"):
                if not incident.snare_session_id:
                    session = self.snare.ensnare(
                        attacker_id=event.actor_id,
                        attacker_family=attacker_family,
                        trace_id=event.trace_id,
                        fork_id=primary_fork.fork_id,
                    )
                    incident.snare_session_id = session.session_id
                    incident.status = "ensnared"
                    incident.containment_action = f"deception_snare:{session.session_id}"
                    control_actions.append(incident.containment_action)
            else:
                self.mcp_proxy.freeze_agent(event.actor_id, top_hit.title, primary_fork.fork_id)
                if event.tool_name:
                    is_compromised_tool = any(
                        "rugpull" in ind or "poisoned_mcp_tool" in ind for ind in top_hit.indicators
                    )
                    self.mcp_proxy.block_tool(
                        event.tool_name,
                        top_hit.title,
                        actor_id=None if is_compromised_tool else event.actor_id,
                    )
                if event.human_principal_id and event.human_risk_score >= 0.45:
                    self.mcp_proxy.revoke_delegation(f"oauth:{event.human_principal_id}")
                incident.status = "contained"
                incident.containment_action = top_hit.recommended_action
                control_actions.append(top_hit.recommended_action)

            # Generate RHEL / OpenShift control order when host or red-hat exposure is triggered
            if event.host_id or top_hit.attack_class == "redhat_exposure":
                quorum_req = self.human_hub.open_quorum(
                    action_kind="rhel_host_isolate",
                    target_id=event.host_id or event.actor_id,
                    use_case=event.use_case,
                    summary=(
                        f"Approve RHEL/OpenShift SELinux + nftables isolation for "
                        f"{event.host_id or event.actor_id} ({top_hit.title})."
                    ),
                    evidence_refs=[incident.case_id, event.event_id],
                )
                order = self.redhat_ctrl.generate_containment_order(
                    target_kind="rhel_host" if event.host_id else "offensive_agent",
                    target_id=event.host_id or event.actor_id,
                    egress_block_host=event.egress_destination,
                    systemd_unit=event.systemd_unit,
                    quorum_id=quorum_req.quorum_id,
                    enforced=False,
                )
                control_actions.append(f"redhat_order:{order.order_id}")

            self.broadcast(
                "incident_updated",
                {
                    "incident": incident.model_dump(mode="json"),
                    "control_actions": control_actions,
                    "routing_reason": route["routing_reason"],
                },
            )

        return {
            "event_id": event.event_id,
            "trace_id": event.trace_id,
            "primary_fork_id": primary_fork.fork_id,
            "shadow_fork_id": shadow_fork.fork_id if shadow_fork else None,
            "routing_reason": route["routing_reason"],
            "proxy_verdict": proxy_verdict,
            "graph_context": graph_ctx,
            "hits": [h.model_dump(mode="json") for h in hits],
            "incident_id": incident.case_id if incident else None,
            "control_actions": control_actions,
            "circuit_breaker_tripped": cb_tripped,
        }

    def _upsert_incident(
        self,
        *,
        event: AsefEvent,
        fork_id: str,
        attacker_family: str,
        graph_ctx: dict[str, Any],
        hits: list[Any],
    ) -> IncidentCase:
        existing = next(
            (inc for inc in self.incidents.values() if inc.trace_id == event.trace_id),
            None,
        )
        top_hit = max(hits, key=lambda h: h.confidence)
        actor_node = graph_ctx["actor_node"]
        blast = self.provenance.blast_radius(actor_node)

        if existing:
            existing.hits.extend(hits)
            if top_hit.severity == Severity.CRITICAL:
                existing.severity = Severity.CRITICAL
            existing.blast_radius_nodes = sorted(set(existing.blast_radius_nodes) | set(blast))
            existing.taint_chain = sorted(set(existing.taint_chain) | set(graph_ctx.get("propagated_taints", [])))
            return existing

        case = IncidentCase(
            trace_id=event.trace_id,
            use_case=event.use_case,
            active_fork_id=fork_id,
            attacker_family=attacker_family,
            severity=top_hit.severity,
            title=top_hit.title,
            summary=top_hit.rationale,
            patient_zero=graph_ctx.get("patient_zero"),
            human_principal_id=event.human_principal_id,
            blast_radius_nodes=blast,
            taint_chain=list(graph_ctx.get("propagated_taints", [])),
            hits=list(hits),
        )
        self.incidents[case.case_id] = case
        return case

    # ------------------------------------------------------------------
    # Full Live Scenario Replay + REA Dissection & Metabolism
    # ------------------------------------------------------------------
    def run_scenario(
        self,
        scenario_id: str,
        use_case: str | None = None,
        auto_dissect_and_evolve: bool = True,
    ) -> dict[str, Any]:
        scn = self.scenarios.get(scenario_id)
        if not scn:
            raise KeyError(f"Unknown scenario: {scenario_id}")

        target_uc = use_case or scn.default_use_case
        event_results = []
        incident_id: str | None = None

        for raw_evt in scn.events:
            evt = raw_evt.model_copy(deep=True)
            evt.use_case = target_uc
            res = self.ingest_event(evt, attacker_family=scn.attacker_family)
            event_results.append(res)
            if res["incident_id"]:
                incident_id = res["incident_id"]

        # Ensnare, harvest artifact, dissect via REA, resolve unknowns, and metabolize!
        dossier_dump = None
        metabolized_dumps = []
        evolution_report = None

        if auto_dissect_and_evolve:
            champion = self.store.get_champion(target_uc)
            inc = self.incidents.get(incident_id) if incident_id else None
            if inc and inc.snare_session_id and inc.snare_session_id in self.snare.sessions:
                session = self.snare.sessions[inc.snare_session_id]
            else:
                session = self.snare.ensnare(
                    attacker_id=scn.events[0].actor_id,
                    attacker_family=scn.attacker_family,
                    trace_id=scn.events[0].trace_id,
                    fork_id=champion.fork_id,
                )
                if inc:
                    inc.snare_session_id = session.session_id

            artifact = self.snare.harvest_artifact(
                session=session,
                artifact_kind=scn.artifact_kind,
                filename=scn.artifact_filename,
                content_bytes=scn.artifact_bytes,
                sqlite_rows=scn.artifact_sqlite_rows,
                metadata={"scenario_id": scn.scenario_id},
            )
            dossier = self.rea_bridge.dissect(artifact, depth=max(0.65, champion.trade_offs.rea_dissection_depth))
            if dossier.residual_unknowns:
                unk = dossier.residual_unknowns[0]
                resp = self.snare.simulate_bait_probe_response(session, dossier, unk.probe_bait)
                self.rea_bridge.resolve_unknown_from_snare_probe(dossier, unk.unknown_id, resp)

            self.autopoiesis.dossiers[dossier.dossier_id] = dossier
            session.status = "dissected"
            if inc:
                inc.rea_dossier_id = dossier.dossier_id
            dossier_dump = dossier.model_dump(mode="json")

            compiled = self.metabolism.compile(dossier)
            for mod in compiled:
                if mod.safety_verified:
                    mod.cross_attacker_hits = self.autopoiesis._measure_cross_hits(mod)
                    self.store.commit_metabolized_module(mod)
                    metabolized_dumps.append(mod.model_dump(mode="json"))

            # Run a Darwinian evolution generation to test metabolized options & cull losers!
            evolution_report = self.autopoiesis.run_generation(
                use_case=target_uc,
                trigger=f"scenario:{scenario_id}",
            )
            self.broadcast("scenario_completed", {"scenario_id": scenario_id, "generation": evolution_report.generation_id})

        return {
            "scenario_id": scenario_id,
            "attacker_family": scn.attacker_family,
            "use_case": target_uc,
            "events_processed": len(event_results),
            "incident_id": incident_id,
            "rea_dossier": dossier_dump,
            "metabolized_modules": metabolized_dumps,
            "evolution_report": evolution_report.model_dump(mode="json") if evolution_report else None,
        }

    # ------------------------------------------------------------------
    # Human Security Governance Actions
    # ------------------------------------------------------------------
    def submit_analyst_vote(self, vote: AnalystVote) -> dict[str, Any]:
        result = self.human_hub.record_vote(vote)

        # Feed human reward signal back into the Immutable Neural Repo!
        if vote.target_kind == "fork":
            fork = self.store.get_fork(vote.target_id)
            if fork and fork.status != "culled":
                delta = 0.025 * vote.analyst_reputation
                if vote.verdict in ("confirm_threat", "approve_promotion"):
                    fork.human_reward_bonus = round(min(0.08, fork.human_reward_bonus + delta), 4)
                    self.router.record_outcome(fork.fork_id, success=True, weight=vote.analyst_reputation)
                else:
                    fork.human_reward_bonus = round(max(-0.08, fork.human_reward_bonus - delta), 4)
                    self.router.record_outcome(fork.fork_id, success=False, weight=vote.analyst_reputation)
                sr = fork.benchmark_stats.composite_success_rate if fork.benchmark_stats else 0.5
                self.store.append_ledger(
                    use_case=fork.use_case,
                    fork_id=fork.fork_id,
                    event_kind="human_vote",
                    success_rate=sr,
                    metrics={"analyst_id": vote.analyst_id, "verdict": vote.verdict, "reward_bonus": fork.human_reward_bonus},
                    signer=f"analyst:{vote.analyst_id}",
                )
        elif vote.target_kind == "incident" and vote.target_id in self.incidents:
            inc = self.incidents[vote.target_id]
            inc.human_votes += 1
            inc.human_consensus_label = result["consensus_label"]
            self.router.record_outcome(
                inc.active_fork_id,
                success=vote.verdict == "confirm_threat",
                weight=vote.analyst_reputation,
            )

        self.broadcast("human_vote", {"target_id": vote.target_id, "consensus": result["consensus_label"]})
        return {
            "vote": result["vote"].model_dump(mode="json"),
            "target_net_weight": result["target_net_weight"],
            "consensus_label": result["consensus_label"],
            "compiled_rule": result["compiled_rule"].model_dump(mode="json") if result["compiled_rule"] else None,
        }

    def sign_quorum(
        self,
        *,
        quorum_id: str,
        analyst_id: str,
        decision: str,
        comment: str = "",
    ) -> dict[str, Any]:
        req = self.human_hub.sign_quorum(
            quorum_id=quorum_id,
            analyst_id=analyst_id,
            decision=decision,
            comment=comment,
        )
        if req.status == "approved" and req.executed_result is None:
            if req.action_kind == "rhel_host_isolate":
                order = self.redhat_ctrl.generate_containment_order(
                    target_kind="rhel_host",
                    target_id=req.target_id,
                    quorum_id=req.quorum_id,
                    enforced=True,
                )
                req.executed_result = {"enforced_order_id": order.order_id, "status": order.status}
            elif req.action_kind == "promote_metabolized_fork":
                fork = self.store.get_fork(req.target_id)
                if fork:
                    for mid in fork.metabolized_module_ids:
                        mod = self.store.get_module(mid)
                        if mod:
                            mod.quorum_approved = True
                            self.store.commit_metabolized_module(mod)
                    req.executed_result = {"quorum_verified_fork": fork.fork_id}
            else:
                req.executed_result = {"executed": True, "target_id": req.target_id}

        self.broadcast("quorum_updated", req.model_dump(mode="json"))
        return req.model_dump(mode="json")

    def export_stix_bundle(self, origin_org: str = "gigamesh-local-soc") -> FederatedStixBundle:
        return self.human_hub.export_stix_bundle(
            origin_org=origin_org,
            modules=self.store.list_modules(),
            rules=list(self.human_hub.rules.values()),
        )

    # ------------------------------------------------------------------
    # Full System Overview Snapshot
    # ------------------------------------------------------------------
    def overview(self) -> dict[str, Any]:
        integrity = self.store.verify_integrity()
        champions = {
            uc: self.store.get_champion(uc).model_dump(mode="json")
            for uc in USE_CASE_OBJECTIVES
        }
        return {
            "name": "GigaMesh",
            "version": "0.1.0",
            "autopilot_running": self.autopoiesis.autopilot_running,
            "autopilot_interval_sec": self.autopoiesis.interval_sec,
            "generation_counter": self.autopoiesis.generation_counter,
            "use_cases": {
                k: {"name": v.name, "description": v.description, "weights": v.weights, "max_fp": v.max_false_positive_rate}
                for k, v in USE_CASE_OBJECTIVES.items()
            },
            "neural_repo_integrity": integrity,
            "champions": champions,
            "rea_doctor": self.rea_bridge.doctor(),
            "counts": {
                "events": len(self.events),
                "incidents": len(self.incidents),
                "active_snares": len(self.snare.sessions),
                "captured_artifacts": len(self.snare.artifacts),
                "rea_dossiers": len(self.autopoiesis.dossiers),
                "metabolized_modules": len(self.store.list_modules()),
                "human_rules": len(self.human_hub.rules),
                "pending_quorums": sum(1 for q in self.human_hub.quorum_requests.values() if q.status == "pending"),
                "redhat_orders": len(self.redhat_ctrl.orders),
                "threat_intel_findings": len(self.threat_crawler.findings),
            },
            "threat_crawler": {
                "enabled": self.threat_crawler.enabled,
                "running": self.threat_crawler.running,
                "interval_sec": self.threat_crawler.crawl_interval_sec,
                "active_sources": sum(1 for s in self.threat_crawler.sources.values() if s.enabled),
                "last_run_at": self.threat_crawler.last_run_at.isoformat() if self.threat_crawler.last_run_at else None,
            },
            "security_audit_chain": self.security_audit_log.verify_chain(),
            "circuit_breaker": self.circuit_breaker.status(),
            "aws_toolkit": {
                "enabled": self.aws_toolkit.enabled,
                "region": self.aws_toolkit.region,
                "read_only_enforced": self.aws_toolkit.read_only_enforced,
                "mcp_status": self.aws_toolkit.last_mcp_status,
                "pinned_tools": len(self.aws_toolkit.pinned_tools),
                "findings": len(self.aws_toolkit.findings),
            },
        }
