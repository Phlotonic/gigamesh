"""Tests for GigaMesh Security-First Unified Namespace (S-UNS):
ISA-95 semantic hierarchy + Sparkplug B dual-mode projection + MQTT wildcard policy
inheritance (`+`/`#`) + 1-click Site Read-Only Lockdown + Security Digital Twin +
signed offline policy bundle verification + REST API.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from gigamesh.api.server import create_app
from gigamesh.config import GigaMeshConfig
from gigamesh.engine import GigaMeshEngine
from gigamesh.integrations.aws_toolkit import AwsSecurityFindingInput
from gigamesh.integrations.edge_fleet import EdgeEnrollRequest
from gigamesh.integrations.mqtt_ot_middleware import SparkplugMetric, SparkplugPacketInput
from gigamesh.integrations.uns import UnsMessageInput, UnsPolicyRule, mqtt_topic_matches


def _make_engine(tmp_path: Path) -> GigaMeshEngine:
    cfg = GigaMeshConfig(
        base_dir=tmp_path,
        autopoiesis_enabled_on_boot=False,
        email_listener_enabled_on_boot=False,
        threat_crawler_enabled_on_boot=False,
    )
    return GigaMeshEngine(cfg)


def test_mqtt_wildcard_matching() -> None:
    assert mqtt_topic_matches(
        "QuanumisCorp/+/+/+/+/+/Commands/#",
        "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM",
    )
    assert mqtt_topic_matches(
        "QuanumisCorp/AustinPlant/#",
        "QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Commands/PressureSetpointPSI",
    )
    assert not mqtt_topic_matches(
        "QuanumisCorp/AustinPlant/#",
        "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM",
    )
    assert not mqtt_topic_matches(
        "QuanumisCorp/+/Commands/Speed",
        "QuanumisCorp/AustinPlant/Area1/Commands/Speed",
    )
    assert mqtt_topic_matches("QuanumisCorp/#", "QuanumisCorp/Cloud/AWS/us-east-1/guardduty/Security/Alert")


def test_monotonic_strictest_wins_wildcard_policy_inheritance(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path)
    # Add a stricter line-level rule tightening max_value from 145 -> 125 PSI while trying to weaken require_e2e_signature=False
    engine.uns.upsert_policy(
        UnsPolicyRule(
            policy_id="unsp-line3-tight",
            name="Line 3 Tighter Thermal Limit",
            topic_pattern="QuanumisCorp/AustinPlant/ThermalArea/Line3/+/+/Commands/PressureSetpointPSI",
            scope_level="Line",
            require_e2e_signature=False,  # Cannot weaken Enterprise requirement!
            max_value=125.0,
            min_value=25.0,
        )
    )
    topic = "QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Commands/PressureSetpointPSI"
    matched, eff = engine.uns.resolve_effective_policies(topic)
    assert len(matched) >= 3
    # Enterprise invariants remain enforced monotonically
    assert eff["require_e2e_signature"] is True
    assert eff["block_ai_tainted"] is True
    # Tighter Line-3 bounds win over looser Area bounds (15..145 -> 25..125)
    assert eff["min_value"] == 25.0
    assert eff["max_value"] == 125.0

    # A signed write of 130 PSI is now blocked because Line-3 tightened max to 125 PSI
    nonce = "n-tight-130"
    sig = engine.uns.sign_uns_command(topic=topic, sender_id="eng-android", nonce=nonce, value=130.0)
    verdict = engine.uns.publish_uns_message(
        UnsMessageInput(
            topic=topic,
            value=130.0,
            sender_id="eng-android",
            sender_role="admin_android",
            nonce=nonce,
            signature=sig,
        )
    )
    assert verdict.decision == "block"
    assert any("above_inherited_max" in r for r in verdict.reasons)


def test_site_read_only_lockdown_isolates_plant_across_uns_and_sparkplug(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path)

    # Activate 1-click Read-Only Lockdown on AustinPlant
    engine.uns.set_site_read_only_lockdown("AustinPlant", True)
    assert "QuanumisCorp/AustinPlant/#" in engine.uns.status()["active_lockdowns"]

    # 1. Telemetry in AustinPlant MUST still flow (fail-open visibility)
    v_telem = engine.uns.publish_uns_message(
        UnsMessageInput(
            topic="QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Telemetry/PressureSetpointPSI",
            value=97.5,
            sender_id="ignition-edge-01",
            sender_role="edge_node",
        )
    )
    assert v_telem.decision == "allow"

    # 2. Signed ISA-95 UNS command in AustinPlant MUST be blocked
    t_austin = "QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Commands/PressureSetpointPSI"
    sig_a = engine.uns.sign_uns_command(topic=t_austin, sender_id="eng-android", nonce="n-a1", value=100.0)
    v_austin_cmd = engine.uns.publish_uns_message(
        UnsMessageInput(
            topic=t_austin,
            value=100.0,
            sender_id="eng-android",
            sender_role="admin_android",
            nonce="n-a1",
            signature=sig_a,
        )
    )
    assert v_austin_cmd.decision == "block"
    assert "site_or_branch_read_only_lockdown_active" in v_austin_cmd.reasons

    # 3. Signed Sparkplug B DCMD targeting PlantAustin/EdgeNode01/BoilerPLC01 MUST ALSO be blocked by AustinPlant lockdown!
    m = [SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=100.0)]
    sp_topic = "spBv1.0/PlantAustin/DCMD/EdgeNode01/BoilerPLC01"
    sp_sig = engine.mqtt_ot.sign_command(topic=sp_topic, sender_id="eng-android", nonce="sp-a1", metrics=m)
    v_sp = engine.mqtt_ot.inspect_packet(
        SparkplugPacketInput(
            topic=sp_topic,
            sender_id="eng-android",
            sender_role="admin_android",
            nonce="sp-a1",
            signature=sp_sig,
            metrics=m,
        )
    )
    assert v_sp.decision == "block"
    assert "uns_site_read_only_lockdown_active" in v_sp.reasons

    # 4. Signed ISA-95 command in MunichPlant MUST remain unaffected & allowed!
    t_munich = "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM"
    sig_m = engine.uns.sign_uns_command(topic=t_munich, sender_id="munich-eng", nonce="n-m1", value=120.0)
    v_munich = engine.uns.publish_uns_message(
        UnsMessageInput(
            topic=t_munich,
            value=120.0,
            sender_id="munich-eng",
            sender_role="admin_android",
            nonce="n-m1",
            signature=sig_m,
        )
    )
    assert v_munich.decision == "allow"

    # 5. Releasing lockdown restores AustinPlant command writes
    engine.uns.set_site_read_only_lockdown("AustinPlant", False)
    sig_a2 = engine.uns.sign_uns_command(topic=t_austin, sender_id="eng-android", nonce="n-a2", value=101.0)
    v_austin_ok = engine.uns.publish_uns_message(
        UnsMessageInput(
            topic=t_austin,
            value=101.0,
            sender_id="eng-android",
            sender_role="admin_android",
            nonce="n-a2",
            signature=sig_a2,
        )
    )
    assert v_austin_ok.decision == "allow"


def test_cross_domain_projections_and_signed_bundle_with_rust_edge(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path)

    # Sparkplug B -> UNS automatic projection
    engine.mqtt_ot.simulate_ignition_factory_scenario()
    assert any("BoilerPLC01/Security/GigaMesh/LastSparkplugVerdict" in t for t in engine.uns.nodes)

    # AWS Security Finding -> UNS Cloud branch projection
    engine.aws_toolkit.ingest_aws_finding(
        AwsSecurityFindingInput(
            service="guardduty",
            finding_type="AttackSequence:IAM/CompromisedCredentials",
            title="Compromised IAM role probing S3",
            severity="CRITICAL",
            region="us-east-1",
            account_id="123456789012",
            description="Credential exfiltration sequence",
            is_attack_sequence=True,
        )
    )
    assert any("/Cloud/AWS/us-east-1/guardduty/Security/" in t for t in engine.uns.nodes)

    # Edge Device enrollment -> UNS Operations/Edge branch projection
    engine.edge_fleet.enroll_device(
        EdgeEnrollRequest(
            device_name="Munich-HMI-Tablet",
            platform="android",
            site_or_plant="MunichPlant",
            edge_runtime="capacitor-android",
        )
    )
    assert any("MunichPlant/Operations/Edge/android/Munich-HMI-Tablet/Devices/Status" in t for t in engine.uns.nodes)

    # Signed Offline Policy Bundle includes UNS policies & verifies in BOTH Python and compiled Rust binary
    bundle = engine.edge_fleet.compile_signed_policy_bundle()
    assert bundle.uns_enterprise == "QuanumisCorp"
    assert len(bundle.uns_policies) >= 4
    assert "PlantAustin/EdgeNode01/BoilerPLC01" in bundle.sparkplug_to_uns_map
    assert engine.edge_fleet.verify_policy_bundle(bundle) is True

    rust_bin = Path("/home/antigravity/gigamesh/edge/rust/target/release/gigamesh-edge-rust")
    if rust_bin.exists():
        bundle_path = tmp_path / "uns_bundle.json"
        bundle_path.write_text(json.dumps(bundle.model_dump(mode="json")), encoding="utf-8")
        res = subprocess.run([str(rust_bin), "--verify-bundle", str(bundle_path)], capture_output=True, text=True, check=True)
        assert "VERIFIED offline bundle" in res.stdout
        assert "enterprise=QuanumisCorp" in res.stdout


def test_uns_rest_endpoints(tmp_path: Path) -> None:
    cfg = GigaMeshConfig(
        base_dir=tmp_path,
        autopoiesis_enabled_on_boot=False,
        email_listener_enabled_on_boot=False,
        threat_crawler_enabled_on_boot=False,
    )
    app = create_app(cfg)
    client = TestClient(app)

    st = client.get("/api/uns/status")
    assert st.status_code == 200
    body = st.json()
    assert body["enterprise"] == "QuanumisCorp"
    assert "AustinPlant" in body["sites"]
    assert "MunichPlant" in body["sites"]

    sim = client.post("/api/uns/simulate-enterprise")
    assert sim.status_code == 200
    decisions = [v["decision"] for v in sim.json()["verdicts"]]
    assert decisions == ["allow", "diverted_to_ghost_plc", "quorum_required", "allow"]

    lock = client.post("/api/uns/sites/AustinPlant/lockdown", json={"locked": True})
    assert lock.status_code == 200
    assert "QuanumisCorp/AustinPlant/#" in lock.json()["active_lockdowns"]

    tree = client.get("/api/uns/tree")
    assert tree.status_code == 200
    assert tree.json()["name"] == "QuanumisCorp"
