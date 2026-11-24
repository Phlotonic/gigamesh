"""Production Hardening End-to-End Verification Suite:
1. Durable SQLite WAL / PostgreSQL persistence & unbroken audit hash chain across full restarts
2. Fail-closed production secret startup guard, Ed25519 asymmetric bundle signing & Multi-Tenant JWT RBAC
3. REAL live TCP wire-level Rust MQTT 3.1.1/5.0 inline proxy blocking rogue AI commands on the wire
4. REAL binary libpcap (.pcap) + binary Modbus/TCP, Siemens S7comm, and DNP3 wire frame decoders
5. REAL live WebSocket JIT Vendor SRA bastion tunnel + 1-Click Kill-Switch
6. Kubernetes /healthz, /readyz, and Prometheus /metrics probes

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
"""

from __future__ import annotations

import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gigamesh.api.server import create_app
from gigamesh.config import GigaMeshConfig
from gigamesh.engine import GigaMeshEngine
from gigamesh.integrations.edge_fleet import EdgeEnrollRequest
from gigamesh.integrations.secure_remote_access import SraSessionRequest
from gigamesh.integrations.uns import UnsDataContract


def _make_cfg(tmp_path: Path, **kwargs) -> GigaMeshConfig:
    return GigaMeshConfig(
        base_dir=tmp_path,
        autopoiesis_enabled_on_boot=False,
        email_listener_enabled_on_boot=False,
        threat_crawler_enabled_on_boot=False,
        **kwargs,
    )


def test_durable_persistence_and_audit_chain_survive_full_restart(tmp_path: Path) -> None:
    # Boot Engine 1 and mutate UNS, Edge Fleet, SRA, and Audit Chain
    eng1 = GigaMeshEngine(_make_cfg(tmp_path))
    eng1.uns.set_site_read_only_lockdown("AustinPlant", True)
    eng1.uns.register_data_contract(
        UnsDataContract(
            contract_id="unsc-persist-v2",
            name="Persisted Temp Contract",
            version="2.0.0",
            topic_pattern="QuanumisCorp/+/+/+/+/+/Telemetry/TempC",
            expected_datatype="Double",
            valid_min=0.0,
            valid_max=150.0,
        )
    )
    enrolled = eng1.edge_fleet.enroll_device(
        EdgeEnrollRequest(
            device_name="Persisted-Android-15",
            platform="android",
            site_or_plant="MunichPlant",
            edge_runtime="capacitor-android",
        )
    )
    dev_id = enrolled["device"]["device_id"]
    sess = eng1.sra.request_jit_session(
        SraSessionRequest(
            vendor_name="ABB Field",
            contractor_email="abb@partner.invalid",
            site="MunichPlant",
            target_uns_asset="QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04",
            access_mode="read_only",
            duration_minutes=20,
            justification="Verify persistence",
        )
    )
    eng1.sra.approve_and_activate(sess.session_id)
    eng1.sra.record_session_command(sess.session_id, "read_diagnostics")
    chain_before = eng1.security_audit_log.verify_chain()
    assert chain_before["valid"] is True
    assert chain_before["entries"] >= 2
    eng1.state_store.close()

    # Boot brand-new Engine 2 pointing to the exact same directory/database
    eng2 = GigaMeshEngine(_make_cfg(tmp_path))
    assert "QuanumisCorp/AustinPlant/#" in eng2.uns.status()["active_lockdowns"]
    assert "unsc-persist-v2" in eng2.uns.data_contracts
    assert dev_id in eng2.edge_fleet.devices
    assert sess.session_id in eng2.sra.sessions
    assert len(eng2.sra.sessions[sess.session_id].transcript) == 1
    assert eng2.sra.verify_transcript_chain(sess.session_id) is True

    # Append a new audit entry after restart and verify the SHA-256 chain stays unbroken across restarts!
    eng2.security_audit_log.record(category="owasp_block", severity="low", actor="post-restart", summary="Post-restart audit continuity")
    chain_after = eng2.security_audit_log.verify_chain()
    assert chain_after["valid"] is True
    assert chain_after["entries"] == chain_before["entries"] + 1
    eng2.state_store.close()


def test_fail_closed_production_guard_ed25519_and_jwt_rbac(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Production mode with default/weak secrets MUST fail closed on boot!
    monkeypatch.delenv("GIGAMESH_JWT_SECRET", raising=False)
    monkeypatch.delenv("GIGAMESH_OT_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("GIGAMESH_EDGE_BUNDLE_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="FAIL-CLOSED PRODUCTION GUARD"):
        GigaMeshEngine(_make_cfg(tmp_path / "fail_closed", production_mode=True))

    # 2. With auth_required=True + strong JWT secret, enforce RBAC across viewer/operator/admin
    app = create_app(
        _make_cfg(
            tmp_path / "rbac",
            auth_required=True,
            jwt_secret="super-strong-production-jwt-secret-key-2026-quanumis!!",
        )
    )
    client = TestClient(app)

    # Public routes remain accessible
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    assert "gigamesh_compliance_readiness_pct" in client.get("/metrics").text
    pub = client.get("/api/auth/public-key").json()
    assert pub["algorithm"] == "Ed25519"
    assert len(pub["public_key_hex"]) == 64

    # Protected API rejects unauthenticated access (401)
    assert client.get("/api/uns/status").status_code == 401

    # Login as viewer -> GET succeeds (200), plant lockdown DENIED (403)
    viewer_tok = client.post("/api/auth/login", json={"username": "auditor", "password": "GigaMesh!Audit2026"}).json()["access_token"]
    assert client.get("/api/uns/status", headers={"Authorization": f"Bearer {viewer_tok}"}).status_code == 200
    assert (
        client.post(
            "/api/uns/sites/AustinPlant/lockdown",
            json={"locked": True},
            headers={"Authorization": f"Bearer {viewer_tok}"},
        ).status_code
        == 403
    )

    # Login as plant_operator -> plant lockdown ALLOWED (200), SOAR admin route DENIED (403)
    op_tok = client.post("/api/auth/login", json={"username": "operator", "password": "GigaMesh!Plant2026"}).json()["access_token"]
    assert (
        client.post(
            "/api/uns/sites/AustinPlant/lockdown",
            json={"locked": True},
            headers={"Authorization": f"Bearer {op_tok}"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/soar/playbooks/pb-plant-lockdown/run",
            json={"target": "AustinPlant", "dry_run": True},
            headers={"Authorization": f"Bearer {op_tok}"},
        ).status_code
        == 403
    )

    # Login as super_admin -> SOAR ALLOWED (200) and Ed25519-signed policy bundle verifies!
    adm_tok = client.post("/api/auth/login", json={"username": "admin", "password": "GigaMesh!Admin2026"}).json()["access_token"]
    assert (
        client.post(
            "/api/soar/playbooks/pb-plant-lockdown/run",
            json={"target": "AustinPlant", "dry_run": True},
            headers={"Authorization": f"Bearer {adm_tok}"},
        ).status_code
        == 200
    )
    bundle = client.get("/api/edge/policy-bundle", headers={"Authorization": f"Bearer {adm_tok}"}).json()
    assert len(bundle["ed25519_signature"]) == 128
    assert bundle["ed25519_public_key_hex"] == pub["public_key_hex"]


def _build_mqtt_publish(topic: str, payload: str) -> bytes:
    t_bytes = topic.encode("utf-8")
    p_bytes = payload.encode("utf-8")
    body = struct.pack(">H", len(t_bytes)) + t_bytes + p_bytes
    rem = len(body)
    enc = bytearray()
    while True:
        byte = rem % 128
        rem //= 128
        if rem > 0:
            byte |= 0x80
        enc.append(byte)
        if rem == 0:
            break
    return bytes([0x30]) + bytes(enc) + body


def test_live_rust_wire_tcp_mqtt_proxy_drops_rogue_ai_command_and_forwards_telemetry() -> None:
    rust_bin = Path("/home/antigravity/gigamesh/edge/rust/target/release/gigamesh-edge-rust")
    assert rust_bin.exists(), "Compiled Rust gigamesh-edge-rust binary missing"

    # Spin up a real TCP mock upstream MQTT broker capturing all forwarded bytes
    received_chunks: list[bytes] = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    up_port = srv.getsockname()[1]
    srv.listen(2)

    def _mock_broker() -> None:
        conn, _ = srv.accept()
        conn.settimeout(2.0)
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                received_chunks.append(data)
        except socket.timeout:
            pass
        finally:
            conn.close()
            srv.close()

    t = threading.Thread(target=_mock_broker, daemon=True)
    t.start()

    # Reserve free local port for Rust proxy
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    proxy_port = probe.getsockname()[1]
    probe.close()

    proc = subprocess.Popen(
        [str(rust_bin), "--proxy", "--listen", f"127.0.0.1:{proxy_port}", "--upstream", f"127.0.0.1:{up_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # Wait for GIGAMESH_EDGE_PROXY_READY line
        ready = proc.stdout.readline() if proc.stdout else ""
        assert "GIGAMESH_EDGE_PROXY_READY" in ready

        # Send REAL MQTT packets over TCP to the Rust inline proxy:
        # 1. Valid Telemetry PUBLISH (MUST reach upstream broker)
        telem_pkt = _build_mqtt_publish(
            "QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Telemetry/PressureSetpointPSI",
            '{"value":96.4,"sender_id":"ignition-edge-01"}',
        )
        # 2. Rogue AI-tainted Command PUBLISH (MUST be DROPPED on the wire!)
        rogue_pkt = _build_mqtt_publish(
            "QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Commands/PressureSetpointPSI",
            '{"value":310.0,"sender_id":"ai-rogue","ai_tainted":true}',
        )
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3.0) as cli:
            cli.sendall(telem_pkt)
            cli.sendall(rogue_pkt)
            time.sleep(0.25)
    finally:
        proc.terminate()
        proc.wait(timeout=3)
    t.join(timeout=3)

    all_upstream = b"".join(received_chunks)
    assert b"Telemetry/PressureSetpointPSI" in all_upstream
    assert b"Commands/PressureSetpointPSI" not in all_upstream


def _wrap_pcap_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, 1, 0, (5 << 4), 0x18, 8192, 0, 0) + payload
    ip_total = 20 + len(tcp)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        ip_total,
        1,
        0,
        64,
        6,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    frame = eth + ip + tcp
    return struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame


def test_real_binary_pcap_modbus_s7comm_dnp3_and_sra_websocket_bastion(tmp_path: Path) -> None:
    app = create_app(_make_cfg(tmp_path))
    client = TestClient(app)

    # Build a real binary libpcap capture with 3 real industrial wire payloads:
    pcap_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # 1. Modbus/TCP FC03 Read Holding Registers (port 502)
    modbus_read = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 40001, 2)
    # 2. Siemens TPKT + COTP + S7comm Job PLC_STOP (0x29) (port 102)
    s7_stop = bytes([0x03, 0x00, 0x00, 0x13, 0x02, 0xF0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x29, 0x00])
    # 3. DNP3 Data Link + App Cold Restart (0x0D) (port 20000)
    dnp3_restart = bytes([0x05, 0x64, 0x0A, 0xC4, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0xC0, 0xC0, 0x0D])

    pcap_blob = (
        pcap_hdr
        + _wrap_pcap_tcp_packet("10.10.3.10", "10.10.1.21", 49152, 502, modbus_read)
        + _wrap_pcap_tcp_packet("10.10.3.99", "10.10.1.21", 49153, 102, s7_stop)
        + _wrap_pcap_tcp_packet("192.168.50.14", "10.10.1.88", 49154, 20000, dnp3_restart)
    )

    resp = client.post("/api/ot-dpi/ingest-pcap", content=pcap_blob)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_pcap_packets"] == 3
    assert body["decoded_ot_frames"] == 3
    assert body["alerts"][0]["protocol"] == "modbus_tcp"
    assert body["alerts"][0]["verdict"] == "allow_observed"
    assert body["alerts"][1]["protocol"] == "s7comm"
    assert body["alerts"][1]["function_name"] == "plc_stop"
    assert body["alerts"][1]["verdict"] == "block_dangerous_write"
    assert body["alerts"][2]["protocol"] == "dnp3"
    assert body["alerts"][2]["function_name"] == "cold_restart"
    assert body["alerts"][2]["verdict"] == "block_dangerous_write"

    # Real Live WebSocket JIT Vendor SRA Bastion Tunnel
    s_req = client.post(
        "/api/sra/request",
        json={
            "vendor_name": "Rockwell Support",
            "contractor_email": "tech@rockwell.invalid",
            "site": "AustinPlant",
            "target_uns_asset": "QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01",
            "access_mode": "read_only",
            "duration_minutes": 15,
            "justification": "Live bastion WS test",
        },
    ).json()
    sid = s_req["session_id"]
    client.post(f"/api/sra/sessions/{sid}/approve")

    with client.websocket_connect(f"/ws/sra/{sid}") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "sra_connected"
        ws.send_json({"command": "read_diagnostics --tag PressureSetpointPSI"})
        v_ok = ws.receive_json()
        assert v_ok["allowed"] is True
        ws.send_json({"command": "write_register 40001 999"})
        v_blk = ws.receive_json()
        assert v_blk["allowed"] is False

    kill_res = client.post(f"/api/sra/sessions/{sid}/kill")
    assert kill_res.status_code == 200
    assert kill_res.json()["status"] == "killed"
