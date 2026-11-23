"""Industrial MQTT 5.0 / Eclipse Sparkplug B / Ignition End-to-End Security Middleware.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Operates as turn-key edge-to-edge security middleware between Admin devices (Android/Web),
IT/AI agents, MQTT brokers (Cirrus Link Distributor, EMQX, HiveMQ, Mosquitto), Inductive
Automation Ignition Gateways, and factory-floor PLCs/edge nodes.

OT Safety & Security Invariants (IEC 62443 + NIST SP 800-82):
- Purdue Level 0 Safety Boundary: NEVER overrides hardware Safety Instrumented Systems (SIS/E-Stops).
- Dual-Path Failure Semantics:
  * Telemetry (`NBIRTH`, `DBIRTH`, `NDATA`, `DDATA`, `NDEATH`, `DDEATH`): inspected passively
    (fail-open) so operator HMI visibility and historians are never stalled.
  * Actuation (`NCMD`, `DCMD`): inline fail-closed cryptographic verification + Digital Physics
    Safety Envelope + IT-to-OT AI Taint Blocker + M-of-N HITL Quorum for critical writes.
- Sparkplug B Birth-Certificate SHA-256 Pinning: pins every enrolled node/device's metric schema
  on NBIRTH/DBIRTH to immediately catch rogue spoofed PLCs or shadow-tag tampering.
- Digital Physics Safety Envelopes: enforces per-tag hard min/max bounds, max slew-rate
  (delta/sec to stop Stuxnet-style slow ramp sabotage), and immutable safety-interlock locks.
- Ghost PLC Virtual Sparkplug B Deception Snare: redirects unauthorized probes/writes onto a
  harmless virtual decoy node while harvesting attacker payloads for REA dissection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import BaseModel, Field

from gigamesh.models.asef import ActorType, AsefEvent, EventType, TrustLevel

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


SPARKPLUG_TELEMETRY_TYPES = frozenset({"NBIRTH", "DBIRTH", "NDATA", "DDATA", "NDEATH", "DDEATH", "STATE"})
SPARKPLUG_COMMAND_TYPES = frozenset({"NCMD", "DCMD"})


class SafetyEnvelopeRule(BaseModel):
    """Deterministic physical safety bounds for a PLC / Ignition tag."""

    tag_path: str  # e.g. "Line3/Boiler1/PressureSetpointPSI"
    unit: str = ""
    min_value: float | None = None
    max_value: float | None = None
    max_delta_per_sec: float | None = None  # Slew-rate limit (catches slow ramp sabotage)
    safety_interlock_locked: bool = False  # If True, remote software writes are ALWAYS denied
    quorum_delta_threshold: float | None = None  # Delta exceeding this requires M-of-N HITL quorum
    last_known_value: float | None = None
    last_updated_at: datetime | None = None


class SparkplugMetric(BaseModel):
    name: str
    datatype: str = "Double"
    value: Any


class SparkplugPacketInput(BaseModel):
    """Canonical representation of an MQTT 5.0 / Sparkplug B (`spBv1.0`) frame."""

    topic: str  # e.g. spBv1.0/PlantAustin/DCMD/EdgeNode01/BoilerPLC01
    sender_id: str
    sender_role: str = "edge_node"  # admin_android | ignition_gateway | edge_node | ai_agent | unknown
    trace_id: str | None = None
    seq: int = 0
    nonce: str = ""
    signature: str = ""  # End-to-end HMAC-SHA256 / Ed25519 signature for NCMD/DCMD
    quorum_approved: bool = False
    metrics: list[SparkplugMetric] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BirthCertificatePin(BaseModel):
    node_key: str  # group/edge_node[/device]
    group_id: str
    edge_node_id: str
    device_id: str | None = None
    schema_sha256: str
    metric_names: list[str]
    pinned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tamper_alerts: int = 0
    status: str = "pinned_healthy"


class MqttInspectionVerdict(BaseModel):
    verdict_id: str = Field(default_factory=lambda: f"otv-{uuid4().hex[:10]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    topic: str
    group_id: str
    message_type: str
    edge_node_id: str
    device_id: str | None = None
    sender_id: str
    mode: str  # passive_fail_open | inline_fail_closed
    decision: str  # allow | allow_with_alert | block | quorum_required | diverted_to_ghost_plc
    reasons: list[str] = Field(default_factory=list)
    quorum_id: str | None = None
    incident_id: str | None = None
    ghost_plc_snare_id: str | None = None
    signature_verified: bool = False


def default_safety_envelopes() -> list[SafetyEnvelopeRule]:
    """Sensible starter physical safety envelopes for turn-key Ignition/factory onboarding."""
    return [
        SafetyEnvelopeRule(
            tag_path="Boiler/PressureSetpointPSI",
            unit="PSI",
            min_value=15.0,
            max_value=145.0,
            max_delta_per_sec=12.0,
            quorum_delta_threshold=20.0,
            last_known_value=95.0,
        ),
        SafetyEnvelopeRule(
            tag_path="Boiler/EmergencyReliefInterlock",
            unit="BOOL",
            safety_interlock_locked=True,
        ),
        SafetyEnvelopeRule(
            tag_path="Line3/ConveyorSpeedRPM",
            unit="RPM",
            min_value=0.0,
            max_value=180.0,
            max_delta_per_sec=35.0,
            quorum_delta_threshold=50.0,
            last_known_value=110.0,
        ),
        SafetyEnvelopeRule(
            tag_path="Turbine/CoolantValvePct",
            unit="%",
            min_value=20.0,
            max_value=100.0,
            max_delta_per_sec=15.0,
            quorum_delta_threshold=25.0,
            last_known_value=65.0,
        ),
    ]


class MqttOtSecurityMiddleware:
    """Turn-key MQTT 5.0 / Sparkplug B / Ignition inline security middleware."""

    def __init__(
        self,
        *,
        engine: GigaMeshEngine,
        broker_host: str = "mosquitto",
        broker_port: int = 8883,
        tls_enabled: bool = True,
        signing_secret: bytes | None = None,
    ) -> None:
        self.engine = engine
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.tls_enabled = tls_enabled
        self.enabled = True
        self.observe_only_onboarding = False  # True during initial discovery wizard, False when protection is active
        self._signing_secret = signing_secret or os.environ.get(
            "GIGAMESH_OT_SIGNING_SECRET", "gigamesh-ot-e2e-signing-key-v1"
        ).encode("utf-8")

        self._lock = threading.RLock()
        self.birth_pins: dict[str, BirthCertificatePin] = {}
        self.safety_envelopes: dict[str, SafetyEnvelopeRule] = {
            r.tag_path: r for r in default_safety_envelopes()
        }
        self._seen_nonces: set[str] = set()
        self.verdicts: list[MqttInspectionVerdict] = []
        self.stats = {
            "telemetry_passed": 0,
            "commands_allowed": 0,
            "commands_blocked": 0,
            "commands_quorum_gated": 0,
            "birth_tamper_alerts": 0,
            "physics_violations_blocked": 0,
            "it_to_ot_crossovers_blocked": 0,
            "ghost_plc_diversions": 0,
        }

    # ------------------------------------------------------------------
    # Sparkplug B Topic Parser & End-to-End Command Signing
    # ------------------------------------------------------------------
    @staticmethod
    def parse_sparkplug_topic(topic: str) -> tuple[str, str, str, str | None]:
        """Parse `spBv1.0/<group_id>/<message_type>/<edge_node_id>[/<device_id>]`."""
        parts = [p for p in topic.strip().split("/") if p]
        if len(parts) < 4 or parts[0] != "spBv1.0":
            raise ValueError(
                f"Invalid Sparkplug B topic '{topic}'. Expected spBv1.0/<group>/<msg_type>/<edge_node>[/<device>]."
            )
        group_id, msg_type, edge_node_id = parts[1], parts[2].upper(), parts[3]
        device_id = parts[4] if len(parts) >= 5 else None
        return group_id, msg_type, edge_node_id, device_id

    def sign_command(
        self,
        *,
        topic: str,
        sender_id: str,
        nonce: str,
        metrics: list[SparkplugMetric] | list[dict[str, Any]],
    ) -> str:
        """Produce an end-to-end HMAC-SHA256 command signature (verifiable offline on edge nodes)."""
        norm_metrics = [
            m.model_dump() if isinstance(m, SparkplugMetric) else dict(m) for m in metrics
        ]
        canonical = json.dumps(
            {"topic": topic, "sender_id": sender_id, "nonce": nonce, "metrics": norm_metrics},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hmac.new(self._signing_secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def upsert_safety_envelope(self, rule: SafetyEnvelopeRule) -> SafetyEnvelopeRule:
        with self._lock:
            self.safety_envelopes[rule.tag_path] = rule
            return rule

    # ------------------------------------------------------------------
    # Core Inspection Pipeline
    # ------------------------------------------------------------------
    def inspect_packet(self, pkt: SparkplugPacketInput) -> MqttInspectionVerdict:
        group_id, msg_type, edge_node_id, device_id = self.parse_sparkplug_topic(pkt.topic)
        node_key = f"{group_id}/{edge_node_id}" + (f"/{device_id}" if device_id else "")

        if msg_type in SPARKPLUG_TELEMETRY_TYPES:
            return self._inspect_telemetry_passive(pkt, group_id, msg_type, edge_node_id, device_id, node_key)
        if msg_type in SPARKPLUG_COMMAND_TYPES:
            return self._inspect_command_inline(pkt, group_id, msg_type, edge_node_id, device_id, node_key)

        return self._record_verdict(
            MqttInspectionVerdict(
                topic=pkt.topic,
                group_id=group_id,
                message_type=msg_type,
                edge_node_id=edge_node_id,
                device_id=device_id,
                sender_id=pkt.sender_id,
                mode="inline_fail_closed",
                decision="block",
                reasons=[f"unsupported_sparkplug_message_type:{msg_type}"],
            )
        )

    def _inspect_telemetry_passive(
        self,
        pkt: SparkplugPacketInput,
        group_id: str,
        msg_type: str,
        edge_node_id: str,
        device_id: str | None,
        node_key: str,
    ) -> MqttInspectionVerdict:
        """Fail-Open passive inspection: NEVER drops plant visibility, pins Birth schemas, tracks last values."""
        reasons: list[str] = []
        decision = "allow"
        incident_id: str | None = None

        with self._lock:
            self.stats["telemetry_passed"] += 1

            # 1. Sparkplug B Birth-Certificate SHA-256 Pinning (NBIRTH / DBIRTH)
            if msg_type in ("NBIRTH", "DBIRTH"):
                schema_items = sorted(f"{m.name}:{m.datatype}" for m in pkt.metrics)
                schema_sha = hashlib.sha256("|".join(schema_items).encode("utf-8")).hexdigest()
                prev = self.birth_pins.get(node_key)
                if prev is None:
                    self.birth_pins[node_key] = BirthCertificatePin(
                        node_key=node_key,
                        group_id=group_id,
                        edge_node_id=edge_node_id,
                        device_id=device_id,
                        schema_sha256=schema_sha,
                        metric_names=[m.name for m in pkt.metrics],
                    )
                    reasons.append(f"birth_certificate_pinned:{schema_sha[:10]}")
                elif prev.schema_sha256 != schema_sha:
                    prev.tamper_alerts += 1
                    prev.status = "tamper_alert"
                    prev.last_seen_at = datetime.now(timezone.utc)
                    self.stats["birth_tamper_alerts"] += 1
                    decision = "allow_with_alert"
                    reasons.append(
                        f"birth_certificate_schema_mutated:expected={prev.schema_sha256[:10]},got={schema_sha[:10]}"
                    )
                    self.engine.security_audit_log.record(
                        category="owasp_block",
                        severity="critical",
                        actor=pkt.sender_id,
                        summary=f"Sparkplug B {msg_type} schema tampered on {node_key} (possible spoofed PLC)",
                        details={"node_key": node_key, "expected": prev.schema_sha256, "got": schema_sha},
                    )
                    # Correlate into GigaMesh SIEM
                    ev = AsefEvent(
                        trace_id=pkt.trace_id or f"ot-birth-{uuid4().hex[:8]}",
                        use_case="zero-trust-critical",
                        event_type=EventType.TOOL_MCP_CALL,
                        actor_type=ActorType.RED_HAT_SUSPECT,
                        actor_id=pkt.sender_id,
                        target_resource=pkt.topic,
                        source_trust_level=TrustLevel.UNTRUSTED,
                        privilege_level=8,
                        payload_preview=f"Spoofed Sparkplug B {msg_type} schema mismatch on {node_key}: {schema_items}",
                        metadata={"tool_signature_verified": False},
                    )
                    incident_id = self.engine.ingest_event(ev, attacker_family="ot-birth-spoofer").get("incident_id")
                else:
                    prev.last_seen_at = datetime.now(timezone.utc)
                    reasons.append("birth_certificate_verified")

            # 2. Update last-known physical telemetry baselines for slew-rate tracking
            now = datetime.now(timezone.utc)
            for m in pkt.metrics:
                env = self.safety_envelopes.get(m.name)
                if env is not None and isinstance(m.value, (int, float)):
                    env.last_known_value = float(m.value)
                    env.last_updated_at = now

        verdict = self._record_verdict(
            MqttInspectionVerdict(
                topic=pkt.topic,
                group_id=group_id,
                message_type=msg_type,
                edge_node_id=edge_node_id,
                device_id=device_id,
                sender_id=pkt.sender_id,
                mode="passive_fail_open",
                decision=decision,
                reasons=reasons or ["telemetry_clean"],
                incident_id=incident_id,
            )
        )
        if hasattr(self.engine, "uns"):
            self.engine.uns.project_sparkplug_event(
                group_id=group_id,
                msg_type=msg_type,
                edge_node_id=edge_node_id,
                device_id=device_id,
                sender_id=pkt.sender_id,
                metrics=[m.model_dump() for m in pkt.metrics],
                decision=verdict.decision,
                reasons=verdict.reasons,
            )
        return verdict

    def _inspect_command_inline(
        self,
        pkt: SparkplugPacketInput,
        group_id: str,
        msg_type: str,
        edge_node_id: str,
        device_id: str | None,
        node_key: str,
    ) -> MqttInspectionVerdict:
        """Fail-Closed inline actuation gate: UNS Lockdown -> Taint -> Crypto Sig -> Replay -> Digital Physics -> Quorum."""
        reasons: list[str] = []
        sig_ok = False
        quorum_id: str | None = None
        incident_id: str | None = None
        ghost_snare_id: str | None = None

        def _finish(v: MqttInspectionVerdict) -> MqttInspectionVerdict:
            recorded = self._record_verdict(v)
            if hasattr(self.engine, "uns"):
                self.engine.uns.project_sparkplug_event(
                    group_id=group_id,
                    msg_type=msg_type,
                    edge_node_id=edge_node_id,
                    device_id=device_id,
                    sender_id=pkt.sender_id,
                    metrics=[m.model_dump() for m in pkt.metrics],
                    decision=recorded.decision,
                    reasons=recorded.reasons,
                )
            return recorded

        # 0. Unified Namespace Site / Branch Read-Only Lockdown Enforcement
        if hasattr(self.engine, "uns"):
            uns_prefix = self.engine.uns.map_sparkplug_to_uns_prefix(group_id, edge_node_id, device_id)
            _, branch_eff = self.engine.uns.resolve_effective_policies(f"{uns_prefix}/Commands/Check")
            if branch_eff.get("read_only_lockdown"):
                reasons.append("uns_site_read_only_lockdown_active")
                with self._lock:
                    self.stats["commands_blocked"] += 1
                self.engine.security_audit_log.record(
                    category="owasp_block",
                    severity="high",
                    actor=pkt.sender_id,
                    summary=f"UNS Site Read-Only Lockdown blocked Sparkplug {msg_type} on {node_key}",
                    details={"uns_prefix": uns_prefix, "topic": pkt.topic},
                )
                return _finish(
                    MqttInspectionVerdict(
                        topic=pkt.topic,
                        group_id=group_id,
                        message_type=msg_type,
                        edge_node_id=edge_node_id,
                        device_id=device_id,
                        sender_id=pkt.sender_id,
                        mode="inline_fail_closed",
                        decision="block",
                        reasons=reasons,
                    )
                )

        # 1. IT-to-OT AI Crossover Barrier (untrusted IT agent / tainted trace cannot write to PLCs)
        trace_tainted = False
        if pkt.trace_id and pkt.trace_id in self.engine.provenance.graph:
            trace_tainted = bool(self.engine.provenance.graph.nodes[pkt.trace_id].get("tainted", False))
        is_tainted_agent = (
            pkt.sender_role == "ai_agent"
            or pkt.metadata.get("it_tainted") is True
            or trace_tainted
        )
        if is_tainted_agent and not pkt.quorum_approved:
            reasons.append("it_to_ot_ai_crossover_blocked")
            with self._lock:
                self.stats["it_to_ot_crossovers_blocked"] += 1
                self.stats["commands_blocked"] += 1
                self.stats["ghost_plc_diversions"] += 1
            ghost_snare_id, incident_id = self._divert_to_ghost_plc(pkt, node_key, reasons)
            return _finish(
                MqttInspectionVerdict(
                    topic=pkt.topic,
                    group_id=group_id,
                    message_type=msg_type,
                    edge_node_id=edge_node_id,
                    device_id=device_id,
                    sender_id=pkt.sender_id,
                    mode="inline_fail_closed",
                    decision="diverted_to_ghost_plc",
                    reasons=reasons,
                    incident_id=incident_id,
                    ghost_plc_snare_id=ghost_snare_id,
                )
            )

        # 2. End-to-End Cryptographic Command Signature + Anti-Replay Nonce Verification
        expected_sig = (
            self.sign_command(topic=pkt.topic, sender_id=pkt.sender_id, nonce=pkt.nonce, metrics=pkt.metrics)
            if pkt.nonce
            else ""
        )
        if not pkt.nonce or not pkt.signature or not hmac.compare_digest(pkt.signature, expected_sig):
            reasons.append("invalid_or_missing_e2e_command_signature")
            with self._lock:
                self.stats["commands_blocked"] += 1
                self.stats["ghost_plc_diversions"] += 1
            ghost_snare_id, incident_id = self._divert_to_ghost_plc(pkt, node_key, reasons)
            return _finish(
                MqttInspectionVerdict(
                    topic=pkt.topic,
                    group_id=group_id,
                    message_type=msg_type,
                    edge_node_id=edge_node_id,
                    device_id=device_id,
                    sender_id=pkt.sender_id,
                    mode="inline_fail_closed",
                    decision="diverted_to_ghost_plc",
                    reasons=reasons,
                    incident_id=incident_id,
                    ghost_plc_snare_id=ghost_snare_id,
                )
            )
        sig_ok = True

        with self._lock:
            if pkt.nonce in self._seen_nonces:
                reasons.append(f"replayed_command_nonce:{pkt.nonce}")
                self.stats["commands_blocked"] += 1
                return _finish(
                    MqttInspectionVerdict(
                        topic=pkt.topic,
                        group_id=group_id,
                        message_type=msg_type,
                        edge_node_id=edge_node_id,
                        device_id=device_id,
                        sender_id=pkt.sender_id,
                        mode="inline_fail_closed",
                        decision="block",
                        reasons=reasons,
                        signature_verified=True,
                    )
                )
            self._seen_nonces.add(pkt.nonce)

        # 3. Digital Physics Safety Envelope Check (Hard Min/Max, Slew Rate, Interlock Lock, Quorum Delta)
        physics_violations: list[str] = []
        needs_quorum: list[str] = []
        now = datetime.now(timezone.utc)

        with self._lock:
            for m in pkt.metrics:
                env = self.safety_envelopes.get(m.name)
                if env is None:
                    continue
                if env.safety_interlock_locked:
                    physics_violations.append(f"safety_interlock_immutable:{m.name}")
                    continue
                if isinstance(m.value, (int, float)):
                    val = float(m.value)
                    if env.min_value is not None and val < env.min_value:
                        physics_violations.append(f"below_min_bound:{m.name}={val}<{env.min_value}{env.unit}")
                    if env.max_value is not None and val > env.max_value:
                        physics_violations.append(f"above_max_bound:{m.name}={val}>{env.max_value}{env.unit}")
                    if env.last_known_value is not None:
                        delta = abs(val - env.last_known_value)
                        elapsed = (
                            max(1.0, (now - env.last_updated_at).total_seconds())
                            if env.last_updated_at
                            else 1.0
                        )
                        rate = delta / elapsed
                        if env.max_delta_per_sec is not None and rate > env.max_delta_per_sec and not pkt.quorum_approved:
                            physics_violations.append(
                                f"slew_rate_exceeded:{m.name} delta={delta:.1f} ({rate:.1f}/s>{env.max_delta_per_sec}/s)"
                            )
                        elif env.quorum_delta_threshold is not None and delta >= env.quorum_delta_threshold and not pkt.quorum_approved:
                            needs_quorum.append(
                                f"large_setpoint_shift:{m.name} {env.last_known_value}->{val} (delta={delta:.1f})"
                            )

        if physics_violations:
            with self._lock:
                self.stats["physics_violations_blocked"] += 1
                self.stats["commands_blocked"] += 1
            self.engine.security_audit_log.record(
                category="owasp_block",
                severity="critical",
                actor=pkt.sender_id,
                summary=f"Digital Physics Envelope blocked unsafe OT {msg_type} on {node_key}",
                details={"violations": physics_violations, "topic": pkt.topic},
            )
            return _finish(
                MqttInspectionVerdict(
                    topic=pkt.topic,
                    group_id=group_id,
                    message_type=msg_type,
                    edge_node_id=edge_node_id,
                    device_id=device_id,
                    sender_id=pkt.sender_id,
                    mode="inline_fail_closed",
                    decision="block",
                    reasons=physics_violations,
                    signature_verified=sig_ok,
                )
            )

        if needs_quorum:
            q = self.engine.human_hub.open_quorum(
                action_kind="ot_sparkplug_dcmd",
                target_id=pkt.topic,
                use_case="zero-trust-critical",
                summary=f"Approve major factory setpoint shift from {pkt.sender_id}: {'; '.join(needs_quorum)}",
                evidence_refs=[pkt.nonce],
            )
            quorum_id = q.quorum_id
            with self._lock:
                self.stats["commands_quorum_gated"] += 1
            return _finish(
                MqttInspectionVerdict(
                    topic=pkt.topic,
                    group_id=group_id,
                    message_type=msg_type,
                    edge_node_id=edge_node_id,
                    device_id=device_id,
                    sender_id=pkt.sender_id,
                    mode="inline_fail_closed",
                    decision="quorum_required",
                    reasons=needs_quorum,
                    quorum_id=quorum_id,
                    signature_verified=sig_ok,
                )
            )

        # Command verified end-to-end and within physical safety envelope!
        with self._lock:
            self.stats["commands_allowed"] += 1
            for m in pkt.metrics:
                env = self.safety_envelopes.get(m.name)
                if env is not None and isinstance(m.value, (int, float)):
                    env.last_known_value = float(m.value)
                    env.last_updated_at = now

        return _finish(
            MqttInspectionVerdict(
                topic=pkt.topic,
                group_id=group_id,
                message_type=msg_type,
                edge_node_id=edge_node_id,
                device_id=device_id,
                sender_id=pkt.sender_id,
                mode="inline_fail_closed",
                decision="allow",
                reasons=["e2e_signature_verified", "within_physical_safety_envelope"],
                signature_verified=True,
            )
        )

    def _divert_to_ghost_plc(
        self, pkt: SparkplugPacketInput, node_key: str, reasons: list[str]
    ) -> tuple[str, str | None]:
        champ = self.engine.store.get_champion("stealth-intel-snare")
        trace = pkt.trace_id or f"ot-snare-{uuid4().hex[:8]}"
        session = self.engine.snare.ensnare(
            attacker_id=pkt.sender_id,
            attacker_family="ot-sparkplug-intruder",
            trace_id=trace,
            fork_id=champ.fork_id,
        )
        raw_payload = json.dumps(pkt.model_dump(mode="json")).encode("utf-8")
        artifact = self.engine.snare.harvest_artifact(
            session=session,
            artifact_kind="mcp_payload",
            filename=f"ghost_plc_{node_key.replace('/', '_')}.json",
            content_bytes=raw_payload,
            metadata={"topic": pkt.topic, "reasons": reasons},
        )
        dossier = self.engine.rea_bridge.dissect(artifact, depth=0.75)
        self.engine.autopoiesis.dossiers[dossier.dossier_id] = dossier
        self.engine.security_audit_log.record(
            category="owasp_block",
            severity="critical",
            actor=pkt.sender_id,
            summary=f"Diverted unauthorized OT command on {pkt.topic} to Ghost PLC snare ({session.session_id})",
            details={"reasons": reasons, "rea_dossier": dossier.dossier_id},
        )
        return session.session_id, dossier.dossier_id

    def _record_verdict(self, verdict: MqttInspectionVerdict) -> MqttInspectionVerdict:
        with self._lock:
            self.verdicts.append(verdict)
            self.verdicts = self.verdicts[-200:]
        self.engine.broadcast("ot_mqtt_verdict", verdict.model_dump(mode="json"))
        return verdict

    # ------------------------------------------------------------------
    # Turn-Key Ignition Simulation & Drop-In Setup Guide
    # ------------------------------------------------------------------
    def simulate_ignition_factory_scenario(self) -> list[MqttInspectionVerdict]:
        """Demonstrate full Ignition + Sparkplug B lifecycle:
        1. Legit NBIRTH pins BoilerPLC01 schema (fail-open telemetry).
        2. Rogue AI copilot tainted by email attempts DCMD Boiler/PressureSetpointPSI=260 PSI -> Diverted to Ghost PLC!
        3. Signed admin attempt to disable safety interlock -> Blocked by Digital Physics Envelope!
        4. Valid signed admin setpoint adjustment (95 -> 102 PSI) -> Allowed end-to-end!
        """
        v1 = self.inspect_packet(
            SparkplugPacketInput(
                topic="spBv1.0/PlantAustin/DBIRTH/EdgeNode01/BoilerPLC01",
                sender_id="ignition-edge-01",
                sender_role="edge_node",
                metrics=[
                    SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=95.0),
                    SparkplugMetric(name="Boiler/EmergencyReliefInterlock", datatype="Boolean", value=True),
                ],
            )
        )
        v2 = self.inspect_packet(
            SparkplugPacketInput(
                topic="spBv1.0/PlantAustin/DCMD/EdgeNode01/BoilerPLC01",
                sender_id="ai-maintenance-copilot",
                sender_role="ai_agent",
                metrics=[SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=260.0)],
                metadata={"it_tainted": True, "source": "poisoned_vendor_pdf"},
            )
        )
        n3 = f"nonce-interlock-{uuid4().hex[:8]}"
        m3 = [SparkplugMetric(name="Boiler/EmergencyReliefInterlock", datatype="Boolean", value=False)]
        v3 = self.inspect_packet(
            SparkplugPacketInput(
                topic="spBv1.0/PlantAustin/DCMD/EdgeNode01/BoilerPLC01",
                sender_id="compromised-designer-session",
                sender_role="ignition_gateway",
                nonce=n3,
                signature=self.sign_command(
                    topic="spBv1.0/PlantAustin/DCMD/EdgeNode01/BoilerPLC01",
                    sender_id="compromised-designer-session",
                    nonce=n3,
                    metrics=m3,
                ),
                metrics=m3,
            )
        )
        n4 = f"nonce-safe-{uuid4().hex[:8]}"
        m4 = [SparkplugMetric(name="Boiler/PressureSetpointPSI", datatype="Double", value=102.0)]
        v4 = self.inspect_packet(
            SparkplugPacketInput(
                topic="spBv1.0/PlantAustin/DCMD/EdgeNode01/BoilerPLC01",
                sender_id="plant-engineer-android-01",
                sender_role="admin_android",
                nonce=n4,
                signature=self.sign_command(
                    topic="spBv1.0/PlantAustin/DCMD/EdgeNode01/BoilerPLC01",
                    sender_id="plant-engineer-android-01",
                    nonce=n4,
                    metrics=m4,
                ),
                metrics=m4,
            )
        )
        return [v1, v2, v3, v4]

    def ignition_turnkey_config(self) -> dict[str, Any]:
        """Turn-key drop-in configuration for Inductive Automation Ignition & Cirrus Link MQTT modules."""
        ent = self.engine.uns.enterprise if hasattr(self.engine, "uns") else "QuanumisCorp"
        return {
            "integration_mode": "dual_mode_sparkplug_b_and_isa95_uns_middleware",
            "zero_ignition_plugin_required": True,
            "mqtt_server_url": f"{'ssl' if self.tls_enabled else 'tcp'}://{self.broker_host}:{self.broker_port}",
            "sparkplug_namespace": "spBv1.0/#",
            "uns_namespace": f"{ent}/#",
            "uns_security_twin_namespace": f"{ent}/+/Security/GigaMesh/#",
            "perspective_hmi_embed_url": "/embed/hmi",
            "cirrus_link_steps": [
                "1. In Ignition Gateway → Config → MQTT Engine / MQTT Transmission → Servers, point Server URL to GigaMesh's mTLS proxy on port 8883.",
                f"2. Subscribe MQTT Engine to both `spBv1.0/#` AND `{ent}/#` (ISA-95 Unified Namespace) for automatic dual-mode projection.",
                f"3. Bind Ignition Perspective alarm banners directly to `{ent}/+/Security/GigaMesh/#` for live Security Digital Twin status.",
                "4. Optional: Drop an Ignition Perspective IFrame component pointing to /embed/hmi for live shield & 1-click site lockdown controls.",
            ],
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "broker_host": self.broker_host,
                "broker_port": self.broker_port,
                "tls_enabled": self.tls_enabled,
                "observe_only_onboarding": self.observe_only_onboarding,
                "stats": dict(self.stats),
                "birth_pins": [p.model_dump(mode="json") for p in self.birth_pins.values()],
                "safety_envelopes": [r.model_dump(mode="json") for r in self.safety_envelopes.values()],
                "recent_verdicts": [v.model_dump(mode="json") for v in reversed(self.verdicts[-30:])],
                "ignition_turnkey": self.ignition_turnkey_config(),
            }
