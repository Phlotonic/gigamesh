"""Real Wire-Level Binary OT Protocol Frame Decoders & Standard PCAP SPAN-Port Ingestor.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Decodes real binary network payloads captured from plant switch SPAN/mirror ports or `.pcap` files:
- Modbus/TCP (Port 502): MBAP 7-byte header + PDU Function Code (FC 1..16) + Register Address
- Siemens S7comm (Port 102): TPKT (0x03 0x00) + COTP + S7 Header (0x32) + Job Function
  (0x04 Read Var, 0x05 Write Var, 0x29 PLC_STOP, 0x1A/0x1B Program Download)
- DNP3 (Port 20000): Data Link Start Bytes (0x05 0x64) + Application Function Code
  (0x01 Read, 0x05 Direct Operate, 0x0D Cold Restart, 0x0E Warm Restart)
- Standard Libpcap (`.pcap`, magic 0xa1b2c3d4 / 0xd4c3b2a1): parses Ethernet -> IPv4 -> TCP
  packets directly into `OtDpiInventoryManager.inspect_dpi_frame(...)` with zero external C deps!
"""

from __future__ import annotations

import socket
import struct
from typing import TYPE_CHECKING, Any

from gigamesh.integrations.ot_dpi_inventory import OtDpiFrameInput

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


MODBUS_FC_MAP: dict[int, str] = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    8: "diagnostics_restart",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
}

S7_FN_MAP: dict[int, str] = {
    0x04: "read_var",
    0x05: "write_var",
    0x1A: "download_block",
    0x1B: "download_block",
    0x1D: "upload_program",
    0x28: "plc_start",
    0x29: "plc_stop",
}

DNP3_FN_MAP: dict[int, str] = {
    0x01: "read",
    0x02: "write",
    0x03: "select",
    0x04: "operate",
    0x05: "direct_operate",
    0x0D: "cold_restart",
    0x0E: "warm_restart",
    0x15: "disable_unsolicited",
}


def decode_modbus_tcp(payload: bytes) -> dict[str, Any] | None:
    """Decode binary Modbus/TCP MBAP + PDU frame (RFC / Modbus.org spec)."""
    if len(payload) < 8:
        return None
    tx_id, proto_id, length, unit_id, fc = struct.unpack(">HHHBB", payload[:8])
    if proto_id != 0x0000:
        return None
    fn = MODBUS_FC_MAP.get(fc, f"fc_{fc}")
    reg = str(struct.unpack(">H", payload[8:10])[0]) if len(payload) >= 10 else ""
    val = struct.unpack(">H", payload[10:12])[0] if len(payload) >= 12 else None
    return {
        "protocol": "modbus_tcp",
        "tx_id": tx_id,
        "unit_id": unit_id,
        "function_code": fc,
        "function_name": fn,
        "register_or_tag": reg,
        "value": val,
    }


def decode_s7comm(payload: bytes) -> dict[str, Any] | None:
    """Decode binary Siemens TPKT (RFC 1006) + COTP + S7comm PDU frame."""
    if len(payload) < 18 or payload[0] != 0x03 or payload[1] != 0x00:
        return None
    cotp_len = payload[4]
    s7_offset = 4 + 1 + cotp_len
    if s7_offset + 12 > len(payload) or payload[s7_offset] != 0x32:
        return None
    rosctr = payload[s7_offset + 1]
    # Header is 10 bytes for Job (rosctr=1) or Userdata (7), 12 bytes for Ack_Data (3)
    hdr_len = 12 if rosctr == 0x03 else 10
    param_offset = s7_offset + hdr_len
    fn_code = payload[param_offset] if param_offset < len(payload) else 0x00
    fn = S7_FN_MAP.get(fn_code, f"s7_fn_0x{fn_code:02x}")
    return {
        "protocol": "s7comm",
        "rosctr": rosctr,
        "function_code": fn_code,
        "function_name": fn,
        "register_or_tag": "S7_CPU",
        "value": None,
    }


def decode_dnp3(payload: bytes) -> dict[str, Any] | None:
    """Decode binary DNP3 Data Link + Transport + Application layer frame."""
    if len(payload) < 13 or payload[0] != 0x05 or payload[1] != 0x64:
        return None
    # Standard DNP3 header is 10 bytes (with 2-byte CRC), followed by transport(1) + app_ctrl(1) + app_fc(1)
    app_fc = payload[12]
    fn = DNP3_FN_MAP.get(app_fc, f"dnp3_fc_0x{app_fc:02x}")
    return {
        "protocol": "dnp3",
        "function_code": app_fc,
        "function_name": fn,
        "register_or_tag": "DNP3_OUTSTATION",
        "value": None,
    }


def decode_wire_ot_payload(dst_port: int, payload: bytes) -> dict[str, Any] | None:
    """Auto-dispatch raw TCP payload to the exact industrial L7 binary decoder."""
    if dst_port == 502:
        return decode_modbus_tcp(payload)
    if dst_port == 102:
        return decode_s7comm(payload)
    if dst_port == 20000:
        return decode_dnp3(payload)
    # Fallback signature sniffing for non-standard ports
    return decode_s7comm(payload) or decode_dnp3(payload) or decode_modbus_tcp(payload)


def _infer_purdue_level(ip: str) -> int:
    if ip.startswith("10.10.0.") or ip.startswith("10.20.0."):
        return 0
    if ip.startswith("10.10.1.") or ip.startswith("10.20.1."):
        return 1
    if ip.startswith("10.10.2."):
        return 2
    if ip.startswith("10.10.3."):
        return 3
    return 4


def ingest_pcap_bytes(engine: GigaMeshEngine, pcap_bytes: bytes) -> dict[str, Any]:
    """Parse a real binary `.pcap` capture (Ethernet + IPv4 + TCP) and feed decoded OT frames into GigaMesh DPI."""
    if len(pcap_bytes) < 24:
        raise ValueError("Invalid PCAP: shorter than 24-byte global header")
    magic = pcap_bytes[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("Unsupported PCAP magic bytes (expected standard libpcap)")

    offset = 24
    total_packets = 0
    decoded_ot = 0
    alerts: list[dict[str, Any]] = []

    while offset + 16 <= len(pcap_bytes):
        _ts_s, _ts_us, incl_len, _orig_len = struct.unpack(f"{endian}IIII", pcap_bytes[offset : offset + 16])
        offset += 16
        pkt = pcap_bytes[offset : offset + incl_len]
        offset += incl_len
        total_packets += 1

        # Ethernet (14 bytes) -> IPv4 (EtherType 0x0800)
        if len(pkt) < 34:
            continue
        ethertype = struct.unpack(">H", pkt[12:14])[0]
        if ethertype != 0x0800:
            continue
        ip_start = 14
        ihl = (pkt[ip_start] & 0x0F) * 4
        proto = pkt[ip_start + 9]
        if proto != 6 or len(pkt) < ip_start + ihl + 20:  # TCP only
            continue
        src_ip = socket.inet_ntoa(pkt[ip_start + 12 : ip_start + 16])
        dst_ip = socket.inet_ntoa(pkt[ip_start + 16 : ip_start + 20])
        tcp_start = ip_start + ihl
        src_port, dst_port = struct.unpack(">HH", pkt[tcp_start : tcp_start + 4])
        data_offset = ((pkt[tcp_start + 12] >> 4) & 0x0F) * 4
        app_payload = pkt[tcp_start + data_offset :]
        if not app_payload:
            continue

        decoded = decode_wire_ot_payload(dst_port, app_payload) or decode_wire_ot_payload(src_port, app_payload)
        if decoded is None:
            continue
        decoded_ot += 1
        alert = engine.ot_dpi.inspect_dpi_frame(
            OtDpiFrameInput(
                protocol=decoded["protocol"],
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_purdue_level=_infer_purdue_level(src_ip),
                dst_purdue_level=_infer_purdue_level(dst_ip),
                function_name=decoded["function_name"],
                register_or_tag=str(decoded.get("register_or_tag", "")),
                value=decoded.get("value"),
            )
        )
        alerts.append(alert.model_dump(mode="json"))

    return {
        "total_pcap_packets": total_packets,
        "decoded_ot_frames": decoded_ot,
        "alerts": alerts,
    }
