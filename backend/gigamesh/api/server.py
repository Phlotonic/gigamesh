"""FastAPI REST + WebSocket Server for GigaMesh SOC Command Center."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from gigamesh.config import GigaMeshConfig
from gigamesh.engine import GigaMeshEngine
from gigamesh.models.asef import AsefEvent
from gigamesh.models.governance import AnalystVote, FederatedStixBundle


class EvolutionStepRequest(BaseModel):
    use_case: str | None = None


class AutopilotToggleRequest(BaseModel):
    enabled: bool
    interval_sec: float | None = None


class ScenarioRunRequest(BaseModel):
    scenario_id: str
    use_case: str | None = None
    auto_dissect_and_evolve: bool = True


class QuorumSignRequest(BaseModel):
    analyst_id: str
    decision: str  # approve | reject
    comment: str = ""


class RedHatOrderRequest(BaseModel):
    target_kind: str = "rhel_host"
    target_id: str
    egress_block_host: str | None = None
    systemd_unit: str | None = None


class EmailListenerToggleRequest(BaseModel):
    enabled: bool
    poll_interval_sec: float | None = None
    search_query: str | None = None
    create_gmail_drafts: bool | None = None


class ThreatCrawlerToggleRequest(BaseModel):
    enabled: bool
    crawl_interval_sec: float | None = None
    auto_evolve_on_findings: bool | None = None
    enforce_allowlist: bool | None = None


class ThreatCrawlerScanRequest(BaseModel):
    source_ids: list[str] | None = None


class ThreatCrawlerDirectDocRequest(BaseModel):
    url: str
    title: str
    raw_body: str
    content_type: str = "text/html"


class ThreatSourceUpsertRequest(BaseModel):
    source_id: str
    name: str
    url: str
    kind: str = "json_feed"
    enabled: bool = True
    trust_tier: float = 0.85
    region: str = "Custom"
    publisher: str = ""
    max_items: int = 10


class ThreatSourceToggleRequest(BaseModel):
    enabled: bool


class AwsToolkitToggleRequest(BaseModel):
    enabled: bool
    region: str | None = None
    read_only_enforced: bool | None = None


class AwsDocSearchRequest(BaseModel):
    search_phrase: str
    limit: int = 4


class AwsRetrieveSkillRequest(BaseModel):
    skill_name: str
    file: str | None = None


def create_app(config: GigaMeshConfig | None = None, enable_autopilot: bool | None = None) -> FastAPI:
    cfg = config or GigaMeshConfig()
    if enable_autopilot is not None:
        cfg.autopoiesis_enabled_on_boot = enable_autopilot
        cfg.email_listener_enabled_on_boot = enable_autopilot
        if not enable_autopilot:
            cfg.threat_crawler_enabled_on_boot = False

    engine = GigaMeshEngine(cfg)
    if enable_autopilot is False:
        # Explicit test/offline mode: never auto-start network crawling (persisted toggle untouched)
        engine.threat_crawler.enabled = False

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if cfg.autopoiesis_enabled_on_boot:
            engine.autopoiesis.start_autopilot()
        if cfg.email_listener_enabled_on_boot:
            engine.email_listener.start()
        # Resume the crawler if the operator left it ON (persisted) or config forces it on boot
        if cfg.threat_crawler_enabled_on_boot or engine.threat_crawler.enabled:
            engine.threat_crawler.start()
        yield
        engine.threat_crawler.shutdown()
        engine.email_listener.stop()
        engine.autopoiesis.stop_autopilot()

    from gigamesh.api.security_middleware import (
        SecurityHardeningMiddleware,
        install_fail_closed_exception_handlers,
    )

    app = FastAPI(
        title="GigaMesh — Non-Linear Self-Evolving Agentic SIEM",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.engine = engine

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.allowed_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-GigaMesh-API-Key"],
    )
    app.add_middleware(
        SecurityHardeningMiddleware,
        engine=engine,
        max_body_bytes=cfg.max_request_body_bytes,
        rate_limit_per_min=cfg.api_rate_limit_per_min,
    )
    install_fail_closed_exception_handlers(app, engine)

    # ------------------------------------------------------------------
    # Overview & Neural Repo Endpoints
    # ------------------------------------------------------------------
    @app.get("/api/overview")
    def get_overview() -> dict[str, Any]:
        return engine.overview()

    @app.get("/api/neural-repo/forks")
    def list_forks(use_case: str | None = None, include_culled: bool = True) -> dict[str, Any]:
        forks = engine.store.list_forks(use_case=use_case, include_culled=include_culled)
        return {
            "forks": [f.model_dump(mode="json") for f in forks],
            "integrity": engine.store.verify_integrity(),
            "git_log": engine.store.git_log_summary(20),
        }

    @app.get("/api/neural-repo/ledger")
    def list_ledger(limit: int = 80) -> dict[str, Any]:
        return {
            "entries": [e.model_dump(mode="json") for e in engine.store.list_ledger(limit=limit)],
            "integrity": engine.store.verify_integrity(),
            "shadow_ab_log": engine.shadow_ab_log[-40:],
        }

    @app.get("/api/neural-repo/sync/status")
    def sync_status() -> dict[str, Any]:
        return engine.sync_firewall.status()

    @app.post("/api/neural-repo/sync/push")
    def sync_push(dry_run: bool = False) -> dict[str, Any]:
        report = engine.sync_firewall.push_to_remote(dry_run=dry_run)
        engine.broadcast("genome_sync", report.model_dump(mode="json"))
        return report.model_dump(mode="json")

    @app.post("/api/neural-repo/sync/pull")
    def sync_pull() -> dict[str, Any]:
        report = engine.sync_firewall.pull_from_remote()
        engine.broadcast("genome_sync", report.model_dump(mode="json"))
        return report.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Perpetual Autopoiesis & Darwinian Evolution Endpoints
    # ------------------------------------------------------------------
    @app.post("/api/evolution/step")
    def step_evolution(req: EvolutionStepRequest | None = None) -> dict[str, Any]:
        uc = req.use_case if req else None
        report = engine.autopoiesis.run_generation(use_case=uc, trigger="manual_step")
        engine.broadcast("evolution_generation", report.model_dump(mode="json"))
        return report.model_dump(mode="json")

    @app.get("/api/evolution/reports")
    def get_evolution_reports(limit: int = 30) -> dict[str, Any]:
        return {
            "autopilot_running": engine.autopoiesis.autopilot_running,
            "interval_sec": engine.autopoiesis.interval_sec,
            "generation_counter": engine.autopoiesis.generation_counter,
            "reports": [r.model_dump(mode="json") for r in reversed(engine.autopoiesis.reports[-limit:])],
        }

    @app.post("/api/evolution/autopilot")
    async def toggle_autopilot(req: AutopilotToggleRequest) -> dict[str, Any]:
        if req.interval_sec is not None and req.interval_sec >= 2.0:
            engine.autopoiesis.interval_sec = req.interval_sec
        if req.enabled:
            engine.autopoiesis.start_autopilot()
        else:
            engine.autopoiesis.stop_autopilot()
        return {
            "autopilot_running": engine.autopoiesis.autopilot_running,
            "interval_sec": engine.autopoiesis.interval_sec,
        }

    # ------------------------------------------------------------------
    # Telemetry Ingestion, Provenance Graph & Incidents
    # ------------------------------------------------------------------
    @app.post("/api/ingest")
    def ingest_event(event: AsefEvent) -> dict[str, Any]:
        return engine.ingest_event(event)

    @app.get("/api/provenance/graph")
    def get_provenance_graph(trace_id: str | None = None) -> dict[str, Any]:
        return engine.provenance.snapshot(trace_id=trace_id)

    @app.get("/api/incidents")
    def list_incidents() -> dict[str, Any]:
        items = sorted(engine.incidents.values(), key=lambda i: i.created_at, reverse=True)
        return {"incidents": [i.model_dump(mode="json") for i in items]}

    # ------------------------------------------------------------------
    # REA (Reverse Engineer Anything) Dissection & Metabolism Lab
    # ------------------------------------------------------------------
    @app.get("/api/rea/lab")
    def get_rea_lab() -> dict[str, Any]:
        return {
            "doctor": engine.rea_bridge.doctor(),
            "snare_sessions": [s.model_dump(mode="json") for s in reversed(list(engine.snare.sessions.values()))],
            "artifacts": [a.model_dump(mode="json") for a in reversed(list(engine.snare.artifacts.values()))],
            "dossiers": [d.model_dump(mode="json") for d in reversed(list(engine.autopoiesis.dossiers.values()))],
            "metabolized_modules": [m.model_dump(mode="json") for m in reversed(engine.store.list_modules())],
        }

    # ------------------------------------------------------------------
    # Human Security Aggregation Hub (Votes, Identity, Quorum, STIX)
    # ------------------------------------------------------------------
    @app.get("/api/human-hub")
    def get_human_hub() -> dict[str, Any]:
        return {
            "identities": [i.model_dump(mode="json") for i in engine.human_hub.identities.values()],
            "votes": [v.model_dump(mode="json") for v in reversed(engine.human_hub.votes[-40:])],
            "rules": [r.model_dump(mode="json") for r in reversed(list(engine.human_hub.rules.values()))],
            "quorums": [q.model_dump(mode="json") for q in reversed(list(engine.human_hub.quorum_requests.values()))],
            "stix_bundles": [b.model_dump(mode="json") for b in reversed(list(engine.human_hub.stix_bundles.values()))],
        }

    @app.post("/api/human-hub/vote")
    def submit_vote(vote: AnalystVote) -> dict[str, Any]:
        return engine.submit_analyst_vote(vote)

    @app.post("/api/human-hub/quorum/{quorum_id}/sign")
    def sign_quorum(quorum_id: str, req: QuorumSignRequest) -> dict[str, Any]:
        try:
            return engine.sign_quorum(
                quorum_id=quorum_id,
                analyst_id=req.analyst_id,
                decision=req.decision,
                comment=req.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/human-hub/stix/export")
    def export_stix(origin_org: str = "gigamesh-local-soc") -> dict[str, Any]:
        return engine.export_stix_bundle(origin_org=origin_org).model_dump(mode="json")

    @app.post("/api/human-hub/stix/import")
    def import_stix(bundle: FederatedStixBundle) -> dict[str, Any]:
        try:
            rules = engine.human_hub.import_stix_bundle(bundle)
            return {"imported_rules": [r.model_dump(mode="json") for r in rules]}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # ------------------------------------------------------------------
    # Red-Hat Exposure & Active Containment Control Plane
    # ------------------------------------------------------------------
    @app.get("/api/control/redhat")
    def get_redhat_control() -> dict[str, Any]:
        return {
            "mcp_proxy": engine.mcp_proxy.status(),
            "redhat_orders": [o.model_dump(mode="json") for o in engine.redhat_ctrl.list_orders()],
            "snare_sessions": [s.model_dump(mode="json") for s in reversed(list(engine.snare.sessions.values()))],
        }

    @app.post("/api/control/redhat/order")
    def create_redhat_order(req: RedHatOrderRequest) -> dict[str, Any]:
        quorum = engine.human_hub.open_quorum(
            action_kind="rhel_host_isolate",
            target_id=req.target_id,
            use_case="rhel-openshift-fortress",
            summary=f"Approve manual RHEL/OpenShift isolation for {req.target_id}",
        )
        order = engine.redhat_ctrl.generate_containment_order(
            target_kind=req.target_kind,
            target_id=req.target_id,
            egress_block_host=req.egress_block_host,
            systemd_unit=req.systemd_unit,
            quorum_id=quorum.quorum_id,
            enforced=False,
        )
        return {"order": order.model_dump(mode="json"), "quorum": quorum.model_dump(mode="json")}

    # ------------------------------------------------------------------
    # Multi-Attacker Simulator Endpoints
    # ------------------------------------------------------------------
    @app.get("/api/simulator/scenarios")
    def list_scenarios() -> dict[str, Any]:
        return {
            "scenarios": [
                {
                    "scenario_id": s.scenario_id,
                    "attacker_family": s.attacker_family,
                    "title": s.title,
                    "description": s.description,
                    "expected_attack_class": s.expected_attack_class,
                    "default_use_case": s.default_use_case,
                    "artifact_kind": s.artifact_kind,
                    "artifact_filename": s.artifact_filename,
                }
                for s in engine.scenarios.values()
            ]
        }

    @app.post("/api/simulator/run")
    def run_scenario(req: ScenarioRunRequest) -> dict[str, Any]:
        try:
            return engine.run_scenario(
                scenario_id=req.scenario_id,
                use_case=req.use_case,
                auto_dissect_and_evolve=req.auto_dissect_and_evolve,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    # ------------------------------------------------------------------
    # Event-Driven Email Security Vulnerability Listener Endpoints
    # ------------------------------------------------------------------
    @app.get("/api/email-listener/status")
    def email_listener_status() -> dict[str, Any]:
        return {
            "status": engine.email_listener.status().model_dump(mode="json"),
            "decisions": [d.model_dump(mode="json") for d in reversed(engine.email_listener.decisions[-40:])],
        }

    @app.post("/api/email-listener/toggle")
    async def email_listener_toggle(req: EmailListenerToggleRequest) -> dict[str, Any]:
        if req.poll_interval_sec is not None and req.poll_interval_sec >= 5.0:
            engine.email_listener.poll_interval_sec = req.poll_interval_sec
        if req.search_query is not None and req.search_query.strip():
            engine.email_listener.search_query = req.search_query.strip()
        if req.create_gmail_drafts is not None:
            engine.email_listener.create_gmail_drafts = req.create_gmail_drafts
        if req.enabled:
            engine.email_listener.start()
        else:
            engine.email_listener.stop()
        return engine.email_listener.status().model_dump(mode="json")

    @app.post("/api/email-listener/poll")
    def email_listener_poll(max_messages: int = 5) -> dict[str, Any]:
        decisions = engine.email_listener.poll_once(max_messages=max_messages)
        return {
            "new_decisions": [d.model_dump(mode="json") for d in decisions],
            "status": engine.email_listener.status().model_dump(mode="json"),
        }

    @app.post("/api/email-listener/webhook")
    def email_listener_webhook(payload: dict[str, Any]) -> dict[str, Any]:
        return engine.email_listener.handle_webhook(payload)

    # ------------------------------------------------------------------
    # Toggle-able Threat Intelligence Web Crawler Endpoints
    # ------------------------------------------------------------------
    @app.get("/api/threat-crawler/status")
    def threat_crawler_status() -> dict[str, Any]:
        return {
            "status": engine.threat_crawler.status().model_dump(mode="json"),
            "recent_findings": [f.model_dump(mode="json") for f in reversed(engine.threat_crawler.findings[-40:])],
            "recent_runs": [r.model_dump(mode="json") for r in reversed(engine.threat_crawler.runs[-15:])],
        }

    @app.post("/api/threat-crawler/toggle")
    async def threat_crawler_toggle(req: ThreatCrawlerToggleRequest) -> dict[str, Any]:
        if req.crawl_interval_sec is not None and req.crawl_interval_sec >= 10.0:
            engine.threat_crawler.crawl_interval_sec = req.crawl_interval_sec
        if req.auto_evolve_on_findings is not None:
            engine.threat_crawler.auto_evolve_on_findings = req.auto_evolve_on_findings
        if req.enforce_allowlist is not None:
            engine.threat_crawler.enforce_allowlist = req.enforce_allowlist
        if req.enabled:
            engine.threat_crawler.start()
        else:
            engine.threat_crawler.stop()
        return engine.threat_crawler.status().model_dump(mode="json")

    @app.post("/api/threat-crawler/scan")
    def threat_crawler_scan(req: ThreatCrawlerScanRequest | None = None) -> dict[str, Any]:
        ids = req.source_ids if req else None
        report = engine.threat_crawler.scan_once(source_ids=ids, trigger="manual_api_scan")
        return report.model_dump(mode="json")

    @app.post("/api/threat-crawler/scan-document")
    def threat_crawler_scan_document(req: ThreatCrawlerDirectDocRequest) -> dict[str, Any]:
        try:
            report = engine.threat_crawler.scan_raw_document(
                url=req.url,
                title=req.title,
                raw_body=req.raw_body,
                content_type=req.content_type,
            )
            return report.model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/threat-crawler/sources")
    def threat_crawler_upsert_source(req: ThreatSourceUpsertRequest) -> dict[str, Any]:
        from gigamesh.integrations.threat_crawler import ThreatSource

        try:
            src = engine.threat_crawler.add_or_update_source(ThreatSource(**req.model_dump()))
            return src.model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/threat-crawler/sources/{source_id}/toggle")
    def threat_crawler_toggle_source(source_id: str, req: ThreatSourceToggleRequest) -> dict[str, Any]:
        try:
            return engine.threat_crawler.set_source_enabled(source_id, req.enabled).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown source {source_id}") from exc

    @app.delete("/api/threat-crawler/sources/{source_id}")
    def threat_crawler_delete_source(source_id: str) -> dict[str, Any]:
        try:
            engine.threat_crawler.remove_source(source_id)
            return {"deleted": source_id}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown source {source_id}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # ------------------------------------------------------------------
    # OWASP Triple-Framework Benchmark & Tamper-Evident Security Audit
    # ------------------------------------------------------------------
    def _run_isolated_owasp_benchmark() -> dict[str, Any]:
        import tempfile
        from gigamesh.benchmarks.owasp_benchmark import run_owasp_benchmark

        with tempfile.TemporaryDirectory() as td:
            sandbox_cfg = GigaMeshConfig(
                base_dir=Path(td),
                autopoiesis_enabled_on_boot=False,
                email_listener_enabled_on_boot=False,
                threat_crawler_enabled_on_boot=False,
                api_auth_key=cfg.api_auth_key,
                allowed_cors_origins=list(cfg.allowed_cors_origins),
                max_request_body_bytes=cfg.max_request_body_bytes,
                api_rate_limit_per_min=cfg.api_rate_limit_per_min,
            )
            sandbox_engine = GigaMeshEngine(sandbox_cfg)
            report = run_owasp_benchmark(sandbox_engine, fastapi_app=app)
            data = report.model_dump(mode="json")
            engine.last_owasp_report = data
            engine.broadcast("owasp_benchmark_completed", {
                "overall_pass_rate": data["overall_pass_rate"],
                "passed_probes": data["passed_probes"],
                "total_probes": data["total_probes"],
                "benign_fp_rate": data["benign_fp_rate"],
            })
            return data

    @app.get("/api/benchmarks/owasp")
    def get_owasp_benchmark() -> dict[str, Any]:
        if engine.last_owasp_report is None:
            return _run_isolated_owasp_benchmark()
        return engine.last_owasp_report

    @app.post("/api/benchmarks/owasp/run")
    def trigger_owasp_benchmark() -> dict[str, Any]:
        return _run_isolated_owasp_benchmark()

    @app.get("/api/security/audit")
    def get_security_audit(limit: int = 50) -> dict[str, Any]:
        return {
            "chain_integrity": engine.security_audit_log.verify_chain(),
            "circuit_breaker": engine.circuit_breaker.status(),
            "recent_entries": engine.security_audit_log.recent(limit=min(limit, 200)),
        }

    # ------------------------------------------------------------------
    # AWS Agent Toolkit (aws/agent-toolkit-for-aws) Endpoints
    # ------------------------------------------------------------------
    @app.get("/api/aws-toolkit/status")
    def aws_toolkit_status() -> dict[str, Any]:
        return engine.aws_toolkit.status()

    @app.post("/api/aws-toolkit/toggle")
    def aws_toolkit_toggle(req: AwsToolkitToggleRequest) -> dict[str, Any]:
        engine.aws_toolkit.enabled = req.enabled
        if req.region and req.region.strip():
            engine.aws_toolkit.region = req.region.strip()
        if req.read_only_enforced is not None:
            engine.aws_toolkit.read_only_enforced = req.read_only_enforced
        return engine.aws_toolkit.status()

    @app.post("/api/aws-toolkit/discover-mcp")
    def aws_toolkit_discover_mcp() -> dict[str, Any]:
        try:
            return engine.aws_toolkit.discover_mcp_tools()
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"AWS MCP discovery failed: {exc}") from exc

    @app.post("/api/aws-toolkit/search-docs")
    def aws_toolkit_search_docs(req: AwsDocSearchRequest) -> dict[str, Any]:
        try:
            results = engine.aws_toolkit.search_aws_docs(req.search_phrase, limit=req.limit)
            return {"query": req.search_phrase, "results": [r.model_dump(mode="json") for r in results]}
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"AWS MCP docs search failed: {exc}") from exc

    @app.post("/api/aws-toolkit/retrieve-skill")
    def aws_toolkit_retrieve_skill(req: AwsRetrieveSkillRequest) -> dict[str, Any]:
        try:
            rec = engine.aws_toolkit.retrieve_skill(req.skill_name, file=req.file)
            return rec.model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"AWS MCP skill retrieval failed: {exc}") from exc

    @app.post("/api/aws-toolkit/ingest-finding")
    def aws_toolkit_ingest_finding(payload: dict[str, Any]) -> dict[str, Any]:
        from gigamesh.integrations.aws_toolkit import AwsSecurityFindingInput

        rec = engine.aws_toolkit.ingest_aws_finding(AwsSecurityFindingInput(**payload))
        return rec.model_dump(mode="json")

    @app.post("/api/aws-toolkit/simulate-attack-sequence")
    def aws_toolkit_simulate_attack() -> dict[str, Any]:
        records = engine.aws_toolkit.simulate_aws_attack_sequence()
        return {"ingested": [r.model_dump(mode="json") for r in records]}

    @app.get("/api/aws-toolkit/mcp-config")
    def aws_toolkit_mcp_config() -> dict[str, Any]:
        return engine.aws_toolkit.generate_mcp_config()

    # ------------------------------------------------------------------
    # Live WebSocket Stream
    # ------------------------------------------------------------------
    @app.websocket("/ws/live")
    async def ws_live(websocket: WebSocket) -> None:
        await websocket.accept()
        queue = engine.subscribe()
        try:
            await websocket.send_json({"type": "hello", "payload": engine.overview()})
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    await websocket.send_json(msg)
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "heartbeat", "payload": {"generation": engine.autopoiesis.generation_counter}})
        except WebSocketDisconnect:
            pass
        finally:
            engine.unsubscribe(queue)

    # Optional static serving of built frontend bundle
    dist_dir = cfg.base_dir / "frontend" / "dist"
    if dist_dir.exists() and (dist_dir / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=str(dist_dir / "assets")), name="assets")

        @app.get("/{full_path:path}")
        def serve_spa(full_path: str):
            if full_path.startswith("api/") or full_path.startswith("ws/"):
                raise HTTPException(status_code=404, detail="Not found")
            return FileResponse(str(dist_dir / "index.html"))

    return app


app = create_app()
