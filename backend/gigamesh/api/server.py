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


def create_app(config: GigaMeshConfig | None = None, enable_autopilot: bool | None = None) -> FastAPI:
    cfg = config or GigaMeshConfig()
    if enable_autopilot is not None:
        cfg.autopoiesis_enabled_on_boot = enable_autopilot

    engine = GigaMeshEngine(cfg)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if cfg.autopoiesis_enabled_on_boot:
            engine.autopoiesis.start_autopilot()
        yield
        engine.autopoiesis.stop_autopilot()

    app = FastAPI(
        title="GigaMesh — Non-Linear Self-Evolving Agentic SIEM",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.engine = engine

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
    def toggle_autopilot(req: AutopilotToggleRequest) -> dict[str, Any]:
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
