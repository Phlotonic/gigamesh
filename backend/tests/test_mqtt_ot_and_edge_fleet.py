"""Tests for Industrial MQTT 5.0 / Sparkplug B / Ignition Security Middleware & Edge Device Fleet."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from gigamesh.api.server import create_app
from gigamesh.config import GigaMeshConfig
from gigamesh.integrations.edge_fleet import SignedOfflinePolicyBundle
from gigamesh.integrations.mqtt_ot_middleware import SparkplugMetric, SparkplugPacketInput


def test_sparkplug_b_birth_pinning_physics_envelope_taint_and_replay(tmp_path: Path) -> None:
    app = create_app(GigaMeshConfig(base_dir=tmp_path), enable_autopilot=False)
    ot = app.state.engine.mqtt_ot

    # 1. Legitimate DBIRTH pins BoilerPLC01 schema (fail-open passive telemetry)
    v_birth = ot.inspect_packet(
        SparkplugPacketInput(
            topic="spBv1.0/PlantA/DBIRTH/Node1/BoilerPLC01",
            sender_id="edge-node-1",
            metrics=[
                SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=95.0),
                SparkplugMetric(name="Boiler/EmergencyReliefInterlock", datatype="Boolean", value=True),
            ],
        )
    )
    assert v_birth.mode == "passive_fail_open" and v_birth.decision == "allow"

    # 2. Rogue spoofed DBIRTH adding shadow tag triggers Birth-Certificate tamper alert (fail-open visibility preserved!)
    v_tamper = ot.inspect_packet(
        SparkplugPacketInput(
            topic="spBv1.0/PlantA/DBIRTH/Node1/BoilerPLC01",
            sender_id="rogue-plc-spoofer",
            metrics=[
                SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=95.0),
                SparkplugMetric(name="Boiler/ShadowBackdoorWrite", datatype="String", value="evil"),
            ],
        )
    )
    assert v_tamper.decision == "allow_with_alert"
    assert ot.stats["birth_tamper_alerts"] == 1

    # 3. IT-to-OT AI crossover attempt is diverted to Ghost PLC snare (fail-closed)
    v_ai = ot.inspect_packet(
        SparkplugPacketInput(
            topic="spBv1.0/PlantA/DCMD/Node1/BoilerPLC01",
            sender_id="ai-copilot",
            sender_role="ai_agent",
            metrics=[SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=100.0)],
            metadata={"it_tainted": True},
        )
    )
    assert v_ai.decision == "diverted_to_ghost_plc"
    assert v_ai.ghost_plc_snare_id is not None

    # 4. Signed command exceeding hard max bound (220 > 145 PSI) is blocked by Digital Physics Envelope
    m_over = [SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=220.0)]
    sig_over = ot.sign_command(topic="spBv1.0/PlantA/DCMD/Node1/BoilerPLC01", sender_id="eng-1", nonce="n-over", metrics=m_over)
    v_over = ot.inspect_packet(
        SparkplugPacketInput(
            topic="spBv1.0/PlantA/DCMD/Node1/BoilerPLC01",
            sender_id="eng-1",
            sender_role="admin_android",
            nonce="n-over",
            signature=sig_over,
            metrics=m_over,
        )
    )
    assert v_over.decision == "block" and any("above_max_bound" in r for r in v_over.reasons)

    # 5. Valid signed setpoint change inside physical envelope is allowed; exact replay is blocked!
    m_ok = [SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=101.0)]
    sig_ok = ot.sign_command(topic="spBv1.0/PlantA/DCMD/Node1/BoilerPLC01", sender_id="eng-1", nonce="n-ok-1", metrics=m_ok)
    pkt_ok = SparkplugPacketInput(
        topic="spBv1.0/PlantA/DCMD/Node1/BoilerPLC01",
        sender_id="eng-1",
        sender_role="admin_android",
        nonce="n-ok-1",
        signature=sig_ok,
        metrics=m_ok,
    )
    assert ot.inspect_packet(pkt_ok).decision == "allow"
    v_replay = ot.inspect_packet(pkt_ok)
    assert v_replay.decision == "block" and any("replayed_command_nonce" in r for r in v_replay.reasons)


def test_edge_fleet_enrollment_signed_offline_bundle_and_rest_api(tmp_path: Path) -> None:
    app = create_app(GigaMeshConfig(base_dir=tmp_path), enable_autopilot=False)
    with TestClient(app) as client:
        # Simulate full Ignition factory scenario via API
        sim = client.post("/api/ot-mqtt/simulate-ignition")
        assert sim.status_code == 200
        verdicts = sim.json()["verdicts"]
        assert len(verdicts) == 4
        assert verdicts[0]["decision"] == "allow"  # DBIRTH pinned
        assert verdicts[1]["decision"] == "diverted_to_ghost_plc"  # AI crossover caught
        assert verdicts[2]["decision"] == "block"  # Interlock immutable
        assert verdicts[3]["decision"] == "allow"  # Signed safe admin setpoint

        # Enroll Android device + fetch signed offline policy bundle
        enr = client.post(
            "/api/edge/enroll",
            json={
                "device_name": "Safety Engineer Galaxy S25",
                "platform": "android",
                "site_or_plant": "Austin Factory",
                "edge_runtime": "capacitor-android",
                "capabilities": ["biometric_quorum", "vpn_dns_shield"],
            },
        )
        assert enr.status_code == 200
        dev_id = enr.json()["device"]["device_id"]
        assert enr.json()["device_token_once"].startswith("gm_edge_")

        bundle_data = client.get("/api/edge/policy-bundle").json()
        bundle = SignedOfflinePolicyBundle(**bundle_data)
        assert app.state.engine.edge_fleet.verify_policy_bundle(bundle) is True
        assert len(bundle.blocked_domains_for_vpn) >= 4
        assert len(bundle.safety_envelopes) >= 4

        # Heartbeat succeeds, then revocation blocks future heartbeats
        hb = client.post("/api/edge/heartbeat", json={"device_id": dev_id, "policy_version": bundle.bundle_version, "blocked_threats_delta": 3, "vpn_shield_active": True})
        assert hb.status_code == 200 and hb.json()["blocked_threats_local"] == 3

        rev = client.post(f"/api/edge/devices/{dev_id}/revoke")
        assert rev.status_code == 200 and rev.json()["status"] == "revoked"
        assert client.post("/api/edge/heartbeat", json={"device_id": dev_id}).status_code == 403
