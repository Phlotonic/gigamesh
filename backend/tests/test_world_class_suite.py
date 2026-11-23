"""Comprehensive tests for GigaMesh World-Class Clean-Room Enterprise Security Suite:
1. UNS Versioned Data Contracts & Schema Drift Governance
2. Passive Multi-Protocol OT DPI (Modbus/S7comm/DNP3/OPC-UA/EtherNet-IP/BACnet/IEC-104),
   Purdue 0-5 Asset Inventory, Exploitability Risk Scoring & Dry-Run Zone Segmentation
3. Zero-Trust Just-in-Time (JIT) Vendor Secure Remote Access (SRA), Hash-Chained Transcripts & Kill-Switch
4. Inline AI Runtime Gateway, DSPM Secret/PII Redaction, AI-SPM Shadow AI Blocking & Automated Red-Team
5. 5-Framework Compliance (IEC 62443, NIST 800-82, NERC CIP, NIST CSF 2.0, EU NIS2/CRA),
   MITRE Triple-Matrix (Enterprise/ICS/ATLAS), OCSF v1.3 Export & Sigma Detection-as-Code
6. Air-Gapped 'Ask GigaMesh' SOC Copilot & Declarative SOAR Playbooks with Dry-Run & 1-Click Rollback

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from gigamesh.api.server import create_app
from gigamesh.config import GigaMeshConfig
from gigamesh.engine import GigaMeshEngine
from gigamesh.integrations.ai_gateway_spm import AiGatewayInspectRequest
from gigamesh.integrations.compliance_suite import SigmaRuleRecord
from gigamesh.integrations.secure_remote_access import SraSessionRequest
from gigamesh.integrations.uns import UnsMessageInput


def _make_engine(tmp_path: Path) -> GigaMeshEngine:
    return GigaMeshEngine(
        GigaMeshConfig(
            base_dir=tmp_path,
            autopoiesis_enabled_on_boot=False,
            email_listener_enabled_on_boot=False,
            threat_crawler_enabled_on_boot=False,
        )
    )


def test_uns_data_contracts_detect_schema_drift_and_strict_reject(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path)
    # 1. Telemetry contract (fail-open alert on out-of-range value 999 PSI > 300 PSI)
    v_drift = engine.uns.publish_uns_message(
        UnsMessageInput(
            topic="QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Telemetry/PressureSetpointPSI",
            value=999.0,
            datatype="Double",
            sender_id="broken-sensor",
        )
    )
    assert v_drift.decision == "allow_with_alert"
    assert any("contract_range_overflow" in r for r in v_drift.reasons)

    # 2. Strict Boolean contract on EmergencyReliefInterlock rejects poisoned non-Boolean payload
    v_strict = engine.uns.publish_uns_message(
        UnsMessageInput(
            topic="QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/State/EmergencyReliefInterlock",
            value="DISABLED_BY_ATTACKER",
            datatype="String",
            sender_id="spoofed-edge",
        )
    )
    assert v_strict.decision == "block"
    assert any("schema_drift" in r for r in v_strict.reasons)
    assert len(engine.uns.schema_violations) >= 2


def test_ot_dpi_purdue_inventory_virtual_patch_and_zone_policies(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path)
    st = engine.ot_dpi.status()
    assert st["total_assets"] >= 5
    assert st["avg_effective_risk"] < st["avg_base_risk"]
    assert st["virtual_patch_risk_reduction_pct"] > 25.0
    assert "ota-rtu-03" in st["visibility_gap_assets"]

    alerts = engine.ot_dpi.simulate_ot_protocol_attacks()
    assert len(alerts) == 3
    assert alerts[0].verdict == "allow_observed"  # Modbus read
    assert alerts[1].verdict == "block_dangerous_write"  # S7comm PLC_STOP
    assert alerts[1].mitre_ics_technique == "T0816"
    assert alerts[2].verdict == "block_dangerous_write"  # IT->L1 DNP3 Cold Restart

    pol = engine.ot_dpi.set_zone_policy_mode("zseg-l3-to-l1-s7", "enforced")
    assert pol.mode == "enforced"


def test_jit_vendor_sra_transcript_hash_chain_and_kill_switch(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path)
    sess = engine.sra.request_jit_session(
        SraSessionRequest(
            vendor_name="Siemens Field Services",
            contractor_email="tech@siemens-partner.invalid",
            site="AustinPlant",
            target_uns_asset="QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01",
            access_mode="read_only",
            duration_minutes=30,
            justification="Inspect pressure transmitter calibration",
        )
    )
    assert sess.status == "pending_approval"
    assert sess.quorum_id is not None

    # Command before approval is blocked
    e0 = engine.sra.record_session_command(sess.session_id, "read_diagnostics")
    assert e0.allowed is False

    # Activate after approval -> read succeeds, write & forbidden command blocked
    engine.sra.approve_and_activate(sess.session_id, approver="plant-director")
    e1 = engine.sra.record_session_command(sess.session_id, "read_diagnostics --tag PressureSetpointPSI")
    e2 = engine.sra.record_session_command(sess.session_id, "write_register 40001 250")
    e3 = engine.sra.record_session_command(sess.session_id, "plc_stop --force")
    assert e1.allowed is True
    assert e2.allowed is False
    assert e3.allowed is False

    # 1-Click Kill-Switch terminates immediately and transcript chain verifies cleanly
    killed = engine.sra.kill_session(sess.session_id, killed_by="soc-lead")
    assert killed.status == "killed"
    assert engine.sra.verify_transcript_chain(sess.session_id) is True


def test_ai_gateway_dspm_shadow_ai_and_automated_red_team(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path)
    v = engine.ai_gateway.inspect_ai_traffic(
        AiGatewayInspectRequest(
            provider="bedrock",
            model="claude-sonnet-4",
            agent_id="ops-bot",
            content="Please check account AKIAIOSFODNN7EXAMPLE for bob@plant.io",
        )
    )
    assert v.decision == "allow_redacted"
    assert "AKIAIOSFODNN7EXAMPLE" not in v.sanitized_content
    assert "bob@plant.io" not in v.sanitized_content

    report = engine.ai_gateway.run_automated_red_team()
    assert report.total_probes == 6
    assert report.blocked_probes == 6
    assert report.resilience_score_pct == 100.0


def test_compliance_mitre_ocsf_sigma_copilot_and_soar_rollback(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path)
    engine.ot_dpi.simulate_ot_protocol_attacks()
    engine.ai_gateway.run_automated_red_team()

    comp = engine.compliance.evaluate_compliance()
    assert len(comp["frameworks"]) == 5
    assert comp["overall_readiness_pct"] >= 80.0
    assert len(comp["mitre_triple_matrix"]["enterprise_attack"]) >= 4
    assert len(comp["mitre_triple_matrix"]["ics_attack"]) >= 4
    assert len(comp["mitre_triple_matrix"]["atlas_ai"]) >= 4

    # Custom Sigma rule compiles & matches live OT DPI plc_stop alert
    sig = engine.compliance.add_sigma_rule(
        SigmaRuleRecord(
            title="Custom S7 Stop Rule",
            level="critical",
            logsource="ot_dpi",
            mitre_tags=["attack.ics.t0816"],
            keywords=["plc_stop"],
        )
    )
    assert sig.matches_count >= 1

    ocsf = engine.compliance.export_ocsf_events()
    assert ocsf["schema"] == "OCSF v1.3.0"
    assert ocsf["count"] >= 1

    # Air-gapped Copilot answers grounded in live state
    ans = engine.soar_copilot.ask_copilot("How is our IEC 62443 compliance?")
    assert ans["mode"] == "local_deterministic_airgap_safe"
    assert "IEC 62443" in ans["answer"]

    # SOAR Playbook Dry-Run -> Execute -> 1-Click Safe Rollback
    sim = engine.soar_copilot.run_playbook("pb-plant-lockdown", target="AustinPlant", dry_run=True)
    assert sim.status == "simulated"
    assert "QuanumisCorp/AustinPlant/#" not in engine.uns.status()["active_lockdowns"]

    exe = engine.soar_copilot.run_playbook("pb-plant-lockdown", target="AustinPlant", dry_run=False)
    assert exe.status == "executed"
    assert "QuanumisCorp/AustinPlant/#" in engine.uns.status()["active_lockdowns"]

    rb = engine.soar_copilot.rollback_execution(exe.execution_id)
    assert rb.status == "rolled_back"
    assert "QuanumisCorp/AustinPlant/#" not in engine.uns.status()["active_lockdowns"]


def test_world_class_rest_endpoints(tmp_path: Path) -> None:
    app = create_app(
        GigaMeshConfig(
            base_dir=tmp_path,
            autopoiesis_enabled_on_boot=False,
            email_listener_enabled_on_boot=False,
            threat_crawler_enabled_on_boot=False,
        )
    )
    client = TestClient(app)
    assert client.get("/api/ot-dpi/status").status_code == 200
    assert client.post("/api/ot-dpi/simulate").status_code == 200
    assert client.get("/api/sra/status").status_code == 200
    assert client.post("/api/ai-gateway/red-team/run").json()["resilience_score_pct"] == 100.0
    assert client.get("/api/compliance/status").json()["overall_readiness_pct"] >= 80.0
    assert client.get("/api/compliance/ocsf").json()["schema"] == "OCSF v1.3.0"
    assert client.get("/api/soar/status").status_code == 200
    assert client.post("/api/copilot/ask", json={"question": "Is AustinPlant safe?"}).status_code == 200
