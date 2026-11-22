"""Tests for GigaMesh's OWASP Triple-Framework Benchmark (30/30) and Beyond-SOTA Defenses."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from gigamesh.api.server import create_app
from gigamesh.benchmarks.owasp_benchmark import run_owasp_benchmark
from gigamesh.config import GigaMeshConfig
from gigamesh.models.asef import ActorType, AsefEvent, EventType, TrustLevel


def test_owasp_triple_framework_30_of_30_with_zero_false_positives(tmp_path: Path) -> None:
    app = create_app(GigaMeshConfig(base_dir=tmp_path), enable_autopilot=False)
    report = run_owasp_benchmark(app.state.engine, fastapi_app=app)

    assert report.total_probes == 30
    assert report.passed_probes == 30, [r.model_dump() for r in report.results if not r.passed]
    assert report.overall_pass_rate == 1.0
    assert report.benign_false_positives == 0
    assert report.benign_fp_rate == 0.0
    for fw in report.framework_scores:
        assert fw.passed == 10 and fw.total == 10 and fw.pass_rate == 1.0


def test_owasp_api_auth_guard_rate_limit_and_audit_chain(tmp_path: Path) -> None:
    cfg = GigaMeshConfig(
        base_dir=tmp_path,
        api_auth_key="super-secret-operator-token",
        api_rate_limit_per_min=15,
    )
    app = create_app(cfg, enable_autopilot=False)
    with TestClient(app) as client:
        # GET works and includes hardened OWASP A02 security headers
        r_ov = client.get("/api/overview")
        assert r_ov.status_code == 200
        assert r_ov.headers["x-frame-options"] == "DENY"
        assert r_ov.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'self'" in r_ov.headers["content-security-policy"]
        assert "no-store" in r_ov.headers["cache-control"]

        # Unauthenticated mutating POST fails closed with 401 (A07)
        r_unauth = client.post("/api/threat-crawler/toggle", json={"enabled": False})
        assert r_unauth.status_code == 401

        # Wrong token fails closed with 401
        r_wrong = client.post(
            "/api/threat-crawler/toggle",
            json={"enabled": False},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert r_wrong.status_code == 401

        # Valid constant-time Bearer token succeeds
        r_ok = client.post(
            "/api/threat-crawler/toggle",
            json={"enabled": False},
            headers={"Authorization": "Bearer super-secret-operator-token"},
        )
        assert r_ok.status_code == 200

        # Audit chain verifies cleanly and recorded auth failures (A09)
        aud = client.get("/api/security/audit").json()
        assert aud["chain_integrity"]["valid"] is True
        assert any(e["category"] == "auth_failure" for e in aud["recent_entries"])

        # Sliding-window rate limiter trips cleanly at 429 (A06)
        statuses = [client.get("/api/overview").status_code for _ in range(18)]
        assert 429 in statuses


def test_inter_agent_hmac_mesh_allows_valid_and_blocks_replay(tmp_path: Path) -> None:
    app = create_app(GigaMeshConfig(base_dir=tmp_path), enable_autopilot=False)
    engine = app.state.engine
    guard = engine.detectors.tool_supply_guard
    nonce = "nonce-valid-001"
    sig = guard.sign_inter_agent_message("agent-planner", "agent-worker", "Sync status report", nonce)

    evt_ok = AsefEvent(
        trace_id="trc-mesh-1",
        event_type=EventType.AGENT_MESSAGE,
        actor_type=ActorType.AGENT,
        actor_id="agent-planner",
        target_resource="agent-worker",
        source_trust_level=TrustLevel.TRUSTED,
        payload_preview="Sync status report",
        metadata={"message_hmac": sig, "nonce": nonce},
    )
    res_ok = engine.ingest_event(evt_ok, attacker_family="benign-mesh")
    assert len(res_ok["hits"]) == 0

    # Replaying the exact same signed message with reused nonce is caught!
    evt_replay = evt_ok.model_copy(update={"event_id": "evt-replay-2"})
    res_replay = engine.ingest_event(evt_replay, attacker_family="replay-attacker")
    assert len(res_replay["hits"]) >= 1
    assert any("inter_agent_replay_nonce" in ind for h in res_replay["hits"] for ind in h["indicators"])


def test_owasp_benchmark_rest_endpoint(tmp_path: Path) -> None:
    app = create_app(GigaMeshConfig(base_dir=tmp_path), enable_autopilot=False)
    with TestClient(app) as client:
        res = client.post("/api/benchmarks/owasp/run")
        assert res.status_code == 200
        data = res.json()
        assert data["passed_probes"] == 30 and data["total_probes"] == 30
        assert data["benign_false_positives"] == 0
