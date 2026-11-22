"""End-to-end FastAPI integration tests for GigaMesh."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from gigamesh.api.server import create_app
from gigamesh.config import GigaMeshConfig


def test_api_end_to_end_scenario_rea_evolution_and_governance(tmp_path: Path) -> None:
    app = create_app(GigaMeshConfig(base_dir=tmp_path), enable_autopilot=False)
    with TestClient(app) as client:
        ov = client.get("/api/overview")
        assert ov.status_code == 200
        body = ov.json()
        assert body["name"] == "GigaMesh"
        assert body["neural_repo_integrity"]["valid"] is True

        # Run the Red-Hat offensive scenario end-to-end (detect -> ensnare -> REA dissect -> metabolize -> evolve)
        run_res = client.post(
            "/api/simulator/run",
            json={"scenario_id": "scn-redhat-offensive", "auto_dissect_and_evolve": True},
        )
        assert run_res.status_code == 200
        run_data = run_res.json()
        assert run_data["incident_id"] is not None
        assert run_data["rea_dossier"] is not None
        assert len(run_data["metabolized_modules"]) >= 1
        assert run_data["evolution_report"] is not None

        # Check provenance graph, REA lab, neural repo forks, and Red-Hat controls
        assert len(client.get("/api/provenance/graph").json()["nodes"]) >= 2
        assert len(client.get("/api/rea/lab").json()["metabolized_modules"]) >= 1
        assert len(client.get("/api/control/redhat").json()["redhat_orders"]) >= 1
        forks_resp = client.get("/api/neural-repo/forks").json()
        assert forks_resp["integrity"]["valid"] is True
        assert forks_resp["integrity"]["culled_tombstones"] >= 1
