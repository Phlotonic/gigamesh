"""Clean-Room Passive Multi-Protocol OT DPI, Purdue 0-5 Asset Inventory, Exploitability Risk
Scoring, Visibility Gap Orchestration & Dry-Run Zone Micro-Segmentation.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Covers industrial protocols passively without disrupting legacy PLCs:
- Modbus/TCP (function codes 1-16, coils/registers, write-function alerts)
- OPC-UA (SecureChannel, Write/Call service inspection)
- Siemens S7comm (CPU Stop/Start, Program Download detection)
- DNP3 (Direct Operate / Cold Restart protection)
- EtherNet/IP CIP (Set_Attribute_Single / Reset detection)
- BACnet/IP & IEC 60870-5-104 (substation telecontrol)
- MQTT / Sparkplug B (bridged with UnifiedNamespaceHub)

Exploitability-Adjusted Risk Scoring:
  EffectiveRisk = CVSS * (0.4 + 0.6 * EPSS) * KEV_Multiplier * Purdue_Exposure * Compensating_Factor
  When GigaMesh Digital Physics Envelopes or UNS Site Lockdown guard an unpatchable PLC,
  the Compensating_Factor quantifies the real virtual-patching risk reduction!
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


SUPPORTED_OT_PROTOCOLS = (
    "modbus_tcp",
    "opc_ua",
    "s7comm",
    "dnp3",
    "ethernet_ip",
    "bacnet_ip",
    "iec_60870_5_104",
    "sparkplug_b",
)

DANGEROUS_OT_FUNCTIONS: dict[str, set[str]] = {
    "modbus_tcp": {"write_single_coil", "write_single_register", "write_multiple_registers", "diagnostics_restart"},
    "opc_ua": {"write_node", "call_method", "delete_nodes"},
    "s7comm": {"plc_stop", "download_block", "upload_program", "write_var"},
    "dnp3": {"cold_restart", "warm_restart", "direct_operate", "disable_unsolicited"},
    "ethernet_ip": {"cip_reset", "set_attribute_single", "firmware_update"},
    "bacnet_ip": {"reinitialize_device", "device_communication_control", "write_property"},
    "iec_60870_5_104": {"reset_process", "single_command_exec", "setpoint_scaled"},
}


class OtVulnerability(BaseModel):
    cve_id: str
    cvss: float
    epss: float  # 0.0 - 1.0 exploit prediction probability
    cisa_kev: bool = False
    summary: str
    virtual_patch_available: bool = True


class OtAssetRecord(BaseModel):
    asset_id: str = Field(default_factory=lambda: f"ota-{uuid4().hex[:8]}")
    name: str
    site: str
    purdue_level: int  # 0 (Field/SIS) .. 5 (Enterprise/Cloud)
    ip_address: str
    mac_address: str = ""
    vendor: str
    model: str
    firmware: str
    protocols: list[str] = Field(default_factory=list)
    uns_prefix: str = ""
    patchable_online: bool = False
    digital_physics_guarded: bool = True
    vulnerabilities: list[OtVulnerability] = Field(default_factory=list)
    base_risk_score: float = 0.0  # 0-100
    effective_risk_score: float = 0.0  # After virtual patching / compensating controls
    visibility_completeness: float = 1.0  # 0-1
    visibility_gaps: list[str] = Field(default_factory=list)
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OtDpiFrameInput(BaseModel):
    protocol: str  # modbus_tcp | opc_ua | s7comm | dnp3 | ethernet_ip | bacnet_ip | iec_60870_5_104
    src_ip: str
    dst_ip: str
    src_purdue_level: int = 3
    dst_purdue_level: int = 1
    function_name: str
    register_or_tag: str = ""
    value: Any = None
    asset_id: str | None = None
    authorized_maintenance: bool = False


class OtDpiAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"dpi-{uuid4().hex[:8]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    protocol: str
    src_ip: str
    dst_ip: str
    function_name: str
    severity: str  # low | medium | high | critical
    verdict: str  # allow_observed | alert_purdue_violation | block_dangerous_write
    mitre_ics_technique: str
    reasons: list[str] = Field(default_factory=list)


class ZoneSegmentationPolicy(BaseModel):
    policy_id: str = Field(default_factory=lambda: f"zseg-{uuid4().hex[:8]}")
    name: str
    src_purdue_level: int
    dst_purdue_level: int
    allowed_protocols: list[str]
    deny_write_functions: bool = True
    mode: str = "dry_run"  # dry_run | enforced
    dry_run_would_block_count: int = 0
    dry_run_would_allow_count: int = 0


class OtDpiInventoryManager:
    """Passive multi-protocol OT DPI, Purdue 0-5 asset inventory, and exploitability risk engine."""

    def __init__(self, *, engine: GigaMeshEngine) -> None:
        self.engine = engine
        self._lock = threading.RLock()
        self.assets: dict[str, OtAssetRecord] = {}
        self.dpi_alerts: list[OtDpiAlert] = []
        self.observed_frames: list[dict[str, Any]] = []
        self.zone_policies: dict[str, ZoneSegmentationPolicy] = {}
        self._seed_factory_inventory()

    def _compute_asset_scores(self, asset: OtAssetRecord) -> None:
        gaps: list[str] = []
        if not asset.mac_address:
            gaps.append("missing_l2_mac_fingerprint")
        if not asset.firmware or asset.firmware.lower() == "unknown":
            gaps.append("unverified_firmware_version")
        if not asset.uns_prefix:
            gaps.append("unmapped_to_uns_hierarchy")
        if not asset.digital_physics_guarded and asset.purdue_level <= 2:
            gaps.append("missing_digital_physics_envelope")
        asset.visibility_gaps = gaps
        asset.visibility_completeness = round(max(0.25, 1.0 - 0.2 * len(gaps)), 2)

        if not asset.vulnerabilities:
            asset.base_risk_score = 12.0 if asset.purdue_level <= 1 else 8.0
            asset.effective_risk_score = round(asset.base_risk_score * (0.55 if asset.digital_physics_guarded else 1.0), 1)
            return

        purdue_mult = 1.25 if asset.purdue_level <= 1 else 1.1 if asset.purdue_level == 2 else 0.95
        worst_base = 0.0
        for v in asset.vulnerabilities:
            kev_mult = 1.35 if v.cisa_kev else 1.0
            score = min(100.0, v.cvss * 8.2 * (0.4 + 0.6 * v.epss) * kev_mult * purdue_mult)
            worst_base = max(worst_base, score)
        asset.base_risk_score = round(worst_base, 1)

        # Quantify virtual-patching risk reduction from GigaMesh Digital Physics + UNS Lockdown
        comp = 1.0
        if asset.digital_physics_guarded:
            comp *= 0.48
        if hasattr(self.engine, "uns"):
            site_pat = f"{self.engine.uns.enterprise}/{asset.site}/#"
            if site_pat in self.engine.uns.status()["active_lockdowns"]:
                comp *= 0.65
        asset.effective_risk_score = round(max(5.0, asset.base_risk_score * comp), 1)

    def _seed_factory_inventory(self) -> None:
        ent = self.engine.uns.enterprise if hasattr(self.engine, "uns") else "QuanumisCorp"
        seeds = [
            OtAssetRecord(
                asset_id="ota-sis-00",
                name="Boiler Emergency SIS Interlock Controller",
                site="AustinPlant",
                purdue_level=0,
                ip_address="10.10.0.5",
                mac_address="00:1B:1B:00:05:10",
                vendor="Triconex / Schneider",
                model="Tricon CX v11",
                firmware="11.5.2",
                protocols=["modbus_tcp"],
                uns_prefix=f"{ent}/AustinPlant/ThermalArea/Line3/BoilerCell/SIS01",
                patchable_online=False,
                digital_physics_guarded=True,
                vulnerabilities=[],
            ),
            OtAssetRecord(
                asset_id="ota-plc-01",
                name="BoilerPLC01 (Siemens S7-1500)",
                site="AustinPlant",
                purdue_level=1,
                ip_address="10.10.1.21",
                mac_address="00:1B:1B:44:21:01",
                vendor="Siemens",
                model="SIMATIC S7-1500 CPU 1516-3",
                firmware="2.9.4",
                protocols=["s7comm", "opc_ua", "sparkplug_b"],
                uns_prefix=f"{ent}/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01",
                patchable_online=False,
                digital_physics_guarded=True,
                vulnerabilities=[
                    OtVulnerability(
                        cve_id="CVE-2022-38465",
                        cvss=9.3,
                        epss=0.78,
                        cisa_kev=True,
                        summary="Hardcoded cryptographic key in SIMATIC S7-1500 allows spoofed PLC commands if unguarded.",
                        virtual_patch_available=True,
                    )
                ],
            ),
            OtAssetRecord(
                asset_id="ota-plc-02",
                name="RobotCell04 (Rockwell ControlLogix)",
                site="MunichPlant",
                purdue_level=1,
                ip_address="10.20.1.44",
                mac_address="00:00:BC:12:44:04",
                vendor="Rockwell Automation",
                model="ControlLogix 5580",
                firmware="33.011",
                protocols=["ethernet_ip", "opc_ua", "sparkplug_b"],
                uns_prefix=f"{ent}/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04",
                patchable_online=False,
                digital_physics_guarded=True,
                vulnerabilities=[
                    OtVulnerability(
                        cve_id="CVE-2023-3595",
                        cvss=9.8,
                        epss=0.84,
                        cisa_kev=True,
                        summary="CIP/EtherNet/IP remote code execution on unsegmented ControlLogix modules.",
                        virtual_patch_available=True,
                    )
                ],
            ),
            OtAssetRecord(
                asset_id="ota-rtu-03",
                name="Substation Feeder RTU-03",
                site="AustinPlant",
                purdue_level=1,
                ip_address="10.10.1.88",
                mac_address="",  # Intentional visibility gap for Visibility Orchestration demo!
                vendor="SEL",
                model="SEL-3530 RTAC",
                firmware="unknown",
                protocols=["dnp3", "iec_60870_5_104"],
                uns_prefix="",
                patchable_online=False,
                digital_physics_guarded=False,
                vulnerabilities=[
                    OtVulnerability(
                        cve_id="CVE-2024-21893",
                        cvss=8.2,
                        epss=0.52,
                        cisa_kev=False,
                        summary="Unauthenticated DNP3 control frame acceptance on legacy feeder interface.",
                        virtual_patch_available=True,
                    )
                ],
            ),
            OtAssetRecord(
                asset_id="ota-ign-01",
                name="Austin Ignition 8.1 Primary Gateway",
                site="AustinPlant",
                purdue_level=3,
                ip_address="10.10.3.10",
                mac_address="52:54:00:10:03:10",
                vendor="Inductive Automation",
                model="Ignition Gateway + Cirrus Link",
                firmware="8.1.43",
                protocols=["opc_ua", "sparkplug_b", "modbus_tcp"],
                uns_prefix=f"{ent}/AustinPlant/Operations/SCADA/IgnitionPrimary",
                patchable_online=True,
                digital_physics_guarded=True,
                vulnerabilities=[],
            ),
        ]
        for a in seeds:
            self._compute_asset_scores(a)
            self.assets[a.asset_id] = a

        self.zone_policies["zseg-it-to-l1"] = ZoneSegmentationPolicy(
            policy_id="zseg-it-to-l1",
            name="Purdue Level 4/5 IT -> Level 1 PLC Direct Write Block",
            src_purdue_level=4,
            dst_purdue_level=1,
            allowed_protocols=["sparkplug_b"],
            deny_write_functions=True,
            mode="enforced",
        )
        self.zone_policies["zseg-l3-to-l1-s7"] = ZoneSegmentationPolicy(
            policy_id="zseg-l3-to-l1-s7",
            name="Purdue Level 3 SCADA -> Level 1 S7comm/Modbus Write Guard (Dry-Run)",
            src_purdue_level=3,
            dst_purdue_level=1,
            allowed_protocols=["opc_ua", "sparkplug_b"],
            deny_write_functions=True,
            mode="dry_run",
        )

    def inspect_dpi_frame(self, frame: OtDpiFrameInput) -> OtDpiAlert:
        """Passively inspect industrial L7 protocol frames + detect Purdue violations & dangerous PLC writes."""
        proto = frame.protocol.lower()
        fn = frame.function_name.lower()
        reasons: list[str] = []
        severity = "low"
        verdict = "allow_observed"
        mitre = "T0801"  # Monitor Process State

        # 1. Check Purdue zone bypass (Level 4/5 enterprise directly touching Level 0/1 PLC)
        if frame.src_purdue_level >= 4 and frame.dst_purdue_level <= 1:
            reasons.append(f"purdue_zone_skip_violation:L{frame.src_purdue_level}->L{frame.dst_purdue_level}")
            severity = "critical"
            verdict = "alert_purdue_violation"
            mitre = "T0886"  # Remote Services

        # 2. Check dangerous industrial control / program-stop / firmware write functions
        dangerous_set = DANGEROUS_OT_FUNCTIONS.get(proto, set())
        if fn in dangerous_set and not frame.authorized_maintenance:
            reasons.append(f"unauthorized_dangerous_ot_function:{proto}:{fn}")
            severity = "critical"
            verdict = "block_dangerous_write"
            mitre = "T0816" if "stop" in fn or "restart" in fn or "reset" in fn else "T0855"  # Device Restart / Unauthorized Command

        # 3. Evaluate dry-run & enforced zone segmentation policies against live traffic
        with self._lock:
            for pol in self.zone_policies.values():
                if pol.src_purdue_level == frame.src_purdue_level and pol.dst_purdue_level == frame.dst_purdue_level:
                    would_block = (proto not in pol.allowed_protocols) or (pol.deny_write_functions and fn in dangerous_set)
                    if would_block:
                        pol.dry_run_would_block_count += 1
                        if pol.mode == "enforced":
                            reasons.append(f"enforced_zone_policy:{pol.policy_id}")
                            verdict = "block_dangerous_write"
                            severity = "critical"
                    else:
                        pol.dry_run_would_allow_count += 1

        alert = OtDpiAlert(
            protocol=proto,
            src_ip=frame.src_ip,
            dst_ip=frame.dst_ip,
            function_name=fn,
            severity=severity,
            verdict=verdict,
            mitre_ics_technique=mitre,
            reasons=reasons or ["passive_dpi_baseline_normal"],
        )

        with self._lock:
            self.dpi_alerts.append(alert)
            self.dpi_alerts = self.dpi_alerts[-150:]
            self.observed_frames.append(frame.model_dump(mode="json"))
            self.observed_frames = self.observed_frames[-200:]

        if verdict != "allow_observed":
            self.engine.security_audit_log.record(
                category="owasp_block",
                severity=severity,
                actor=frame.src_ip,
                summary=f"OT DPI ({proto.upper()}) flagged {fn} targeting {frame.dst_ip} ({mitre})",
                details={"reasons": reasons, "verdict": verdict},
            )
            if hasattr(self.engine, "uns"):
                self.engine.uns._publish_security_twin(
                    f"{self.engine.uns.enterprise}/AustinPlant/Security/GigaMesh/OtDpiAlert",
                    {"protocol": proto, "function": fn, "verdict": verdict, "mitre_ics": mitre, "dst": frame.dst_ip},
                )
        self.engine.broadcast("ot_dpi_updated", alert.model_dump(mode="json"))
        return alert

    def set_zone_policy_mode(self, policy_id: str, mode: str) -> ZoneSegmentationPolicy:
        if mode not in ("dry_run", "enforced"):
            raise ValueError("mode must be 'dry_run' or 'enforced'")
        with self._lock:
            pol = self.zone_policies.get(policy_id)
            if pol is None:
                raise KeyError(policy_id)
            pol.mode = mode
            return pol

    def simulate_ot_protocol_attacks(self) -> list[OtDpiAlert]:
        """Simulate realistic multi-protocol industrial traffic: normal Modbus read, rogue S7comm PLC_STOP, and IT->L1 DNP3 Cold Restart."""
        frames = [
            OtDpiFrameInput(
                protocol="modbus_tcp",
                src_ip="10.10.3.10",
                dst_ip="10.10.1.21",
                src_purdue_level=3,
                dst_purdue_level=1,
                function_name="read_holding_registers",
                register_or_tag="40001",
            ),
            OtDpiFrameInput(
                protocol="s7comm",
                src_ip="10.10.3.99",
                dst_ip="10.10.1.21",
                src_purdue_level=3,
                dst_purdue_level=1,
                function_name="plc_stop",
                register_or_tag="CPU_1516",
            ),
            OtDpiFrameInput(
                protocol="dnp3",
                src_ip="192.168.50.14",
                dst_ip="10.10.1.88",
                src_purdue_level=4,
                dst_purdue_level=1,
                function_name="cold_restart",
                register_or_tag="FeederRTU03",
            ),
        ]
        return [self.inspect_dpi_frame(f) for f in frames]

    def status(self) -> dict[str, Any]:
        with self._lock:
            for a in self.assets.values():
                self._compute_asset_scores(a)
            assets = list(self.assets.values())
            purdue_counts = {f"L{lvl}": sum(1 for a in assets if a.purdue_level == lvl) for lvl in range(6)}
            avg_base = round(sum(a.base_risk_score for a in assets) / max(1, len(assets)), 1)
            avg_eff = round(sum(a.effective_risk_score for a in assets) / max(1, len(assets)), 1)
            gap_assets = [a.asset_id for a in assets if a.visibility_gaps]
            return {
                "supported_protocols": list(SUPPORTED_OT_PROTOCOLS),
                "total_assets": len(assets),
                "purdue_distribution": purdue_counts,
                "avg_base_risk": avg_base,
                "avg_effective_risk": avg_eff,
                "virtual_patch_risk_reduction_pct": round(max(0.0, (1.0 - avg_eff / max(1.0, avg_base)) * 100.0), 1),
                "visibility_gap_assets": gap_assets,
                "assets": [a.model_dump(mode="json") for a in assets],
                "zone_policies": [p.model_dump(mode="json") for p in self.zone_policies.values()],
                "recent_alerts": [a.model_dump(mode="json") for a in reversed(self.dpi_alerts[-25:])],
            }
