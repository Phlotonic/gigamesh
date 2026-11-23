"""Security-First Unified Namespace (S-UNS) — ISA-95 + Sparkplug B Dual-Mode Hub for GigaMesh.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Implements a true Industry 4.0 Unified Namespace (ISA-95 hierarchy):
    <Enterprise>/<Site>/<Area>/<Line>/<Cell>[/<Asset>]/<Layer>/<Metric>

Capabilities:
- Dual-Protocol Native: ingests BOTH raw ISA-95 semantic UNS topics AND Eclipse Sparkplug B
  (`spBv1.0/...`) edge frames, projecting all OT, IT, Cloud (AWS/RHEL), Mobile (Android),
  and AI Agent telemetry into ONE canonical hierarchical state tree.
- Hierarchical MQTT Wildcard Policy Inheritance (`+` single-level, `#` multi-level):
  attach Digital Physics Safety Envelopes, IT-to-OT AI taint locks, E2E command-signing
  requirements, M-of-N HITL quorum rules, or 1-click Site Read-Only Lockdowns at ANY level
  of the enterprise tree; child nodes inherit parent rules monotonically (can tighten, never
  weaken an enterprise safety invariant).
- Live UNS Security Digital Twin: automatically publishes retained security posture, alerts,
  blocked writes, and pending quorums into `<Enterprise>/<Site>/.../Security/GigaMesh/...`
  so Ignition Perspective, MES, ERP, and historians subscribe to real-time security state
  natively with zero custom glue code.
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

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


TELEMETRY_LAYERS = frozenset({"telemetry", "state", "security", "diagnostics", "cloud", "devices", "metrics"})
COMMAND_LAYERS = frozenset({"commands", "command", "cmd", "setpoints", "control"})


def mqtt_topic_matches(pattern: str, topic: str) -> bool:
    """Standard MQTT 5.0 wildcard matcher supporting `+` (single level) and `#` (multi-level)."""
    p_parts = [p for p in pattern.strip().split("/") if p != ""]
    t_parts = [t for t in topic.strip().split("/") if t != ""]

    pi = 0
    ti = 0
    while pi < len(p_parts):
        p = p_parts[pi]
        if p == "#":
            return pi == len(p_parts) - 1
        if ti >= len(t_parts):
            return False
        if p != "+" and p != t_parts[ti]:
            return False
        pi += 1
        ti += 1
    return ti == len(t_parts)


def policy_specificity(pattern: str) -> int:
    """Rank wildcard patterns so more specific branches sort after broader enterprise defaults."""
    parts = [p for p in pattern.strip().split("/") if p]
    score = 0
    for p in parts:
        if p == "#":
            score += 1
        elif p == "+":
            score += 5
        else:
            score += 20
    return score


class UnsPolicyRule(BaseModel):
    """Hierarchical security & physics policy attached to any ISA-95 wildcard topic pattern."""

    policy_id: str = Field(default_factory=lambda: f"unsp-{uuid4().hex[:8]}")
    name: str
    topic_pattern: str  # e.g. "QuanumisCorp/+/+/+/+/Commands/#" or "QuanumisCorp/AustinPlant/#"
    scope_level: str = "Enterprise"  # Enterprise | Site | Area | Line | Cell | Asset
    enabled: bool = True
    require_e2e_signature: bool = False
    block_ai_tainted: bool = False
    read_only_lockdown: bool = False  # Freezes ALL Commands/* writes under this branch while telemetry flows
    safety_interlock_locked: bool = False
    min_value: float | None = None
    max_value: float | None = None
    max_delta_per_sec: float | None = None
    quorum_delta_threshold: float | None = None
    unit: str = ""
    description: str = ""


class UnsMessageInput(BaseModel):
    """Semantic ISA-95 Unified Namespace publish event."""

    topic: str  # e.g. QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Commands/PressureSetpointPSI
    value: Any
    datatype: str = "Double"
    sender_id: str = "uns-publisher"
    sender_role: str = "edge_node"  # admin_android | ignition_gateway | edge_node | ai_agent | gigamesh_security
    nonce: str = ""
    signature: str = ""
    quorum_approved: bool = False
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UnsNodeState(BaseModel):
    """Retained semantic leaf/node state inside the Unified Namespace."""

    topic: str
    enterprise: str
    site: str
    area: str
    line: str
    cell: str
    asset: str
    layer: str
    metric: str
    value: Any
    datatype: str = "Double"
    source_protocol: str = "isa95_uns"  # isa95_uns | sparkplug_b | aws_toolkit | edge_fleet | gigamesh_security
    last_sender: str = ""
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    security_state: str = "healthy"  # healthy | alert | blocked | quorum_pending | lockdown
    matched_policies: list[str] = Field(default_factory=list)


class UnsPublishVerdict(BaseModel):
    verdict_id: str = Field(default_factory=lambda: f"unsv-{uuid4().hex[:10]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    topic: str
    layer: str
    mode: str  # passive_fail_open | inline_fail_closed
    decision: str  # allow | allow_with_alert | block | quorum_required | diverted_to_ghost_plc
    matched_policies: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    quorum_id: str | None = None
    ghost_plc_snare_id: str | None = None
    security_twin_topic: str | None = None


class UnsSecurityTwinEvent(BaseModel):
    """Retained security event published by GigaMesh back into the UNS `<...>/Security/GigaMesh/...`."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    topic: str
    payload: dict[str, Any]
    retained: bool = True


def default_uns_policies(enterprise: str = "QuanumisCorp") -> list[UnsPolicyRule]:
    return [
        UnsPolicyRule(
            policy_id="unsp-ent-commands-zero-trust",
            name="Enterprise Zero-Trust Command Guard",
            topic_pattern=f"{enterprise}/+/+/+/+/+/Commands/#",
            scope_level="Enterprise",
            require_e2e_signature=True,
            block_ai_tainted=True,
            description="Every actuation write across all sites requires an end-to-end signed command and blocks tainted AI agents.",
        ),
        UnsPolicyRule(
            policy_id="unsp-ent-interlock-lock",
            name="Enterprise Safety Interlock Immutability",
            topic_pattern=f"{enterprise}/+/+/+/+/+/Commands/EmergencyReliefInterlock",
            scope_level="Enterprise",
            safety_interlock_locked=True,
            description="Level-0 hardware safety interlocks can never be overridden over the network at any plant.",
        ),
        UnsPolicyRule(
            policy_id="unsp-austin-boiler-physics",
            name="Austin Thermal Area Boiler Pressure Envelope",
            topic_pattern=f"{enterprise}/AustinPlant/ThermalArea/+/+/+/Commands/PressureSetpointPSI",
            scope_level="Area",
            min_value=15.0,
            max_value=145.0,
            max_delta_per_sec=12.0,
            quorum_delta_threshold=20.0,
            unit="PSI",
            description="Inherits across every line and boiler cell in AustinPlant/ThermalArea.",
        ),
        UnsPolicyRule(
            policy_id="unsp-munich-robotics-speed",
            name="Munich Robotics Line Speed Envelope",
            topic_pattern=f"{enterprise}/MunichPlant/AssemblyArea/+/+/+/Commands/ConveyorSpeedRPM",
            scope_level="Area",
            min_value=0.0,
            max_value=160.0,
            max_delta_per_sec=30.0,
            quorum_delta_threshold=45.0,
            unit="RPM",
            description="Protects high-speed assembly lines in MunichPlant against runaway speed writes.",
        ),
    ]


class UnifiedNamespaceHub:
    """Canonical ISA-95 + Sparkplug B Unified Namespace (S-UNS) with wildcard policy inheritance."""

    def __init__(
        self,
        *,
        engine: GigaMeshEngine,
        enterprise: str = "QuanumisCorp",
        signing_secret: bytes | None = None,
    ) -> None:
        self.engine = engine
        self.enterprise = enterprise
        self._secret = signing_secret or os.environ.get(
            "GIGAMESH_OT_SIGNING_SECRET", "gigamesh-ot-e2e-signing-key-v1"
        ).encode("utf-8")

        self._lock = threading.RLock()
        self.policies: dict[str, UnsPolicyRule] = {
            p.policy_id: p for p in default_uns_policies(enterprise)
        }
        self.nodes: dict[str, UnsNodeState] = {}
        self.verdicts: list[UnsPublishVerdict] = []
        self.security_twin_feed: list[UnsSecurityTwinEvent] = []
        self._seen_nonces: set[str] = set()

        # Sparkplug B `<group>/<edge_node>[/<device>]` -> canonical ISA-95 asset prefix
        self.sparkplug_to_uns_map: dict[str, str] = {
            "PlantAustin/EdgeNode01/BoilerPLC01": f"{enterprise}/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01",
            "PlantAustin/EdgeNode01": f"{enterprise}/AustinPlant/ThermalArea/Line3/BoilerCell/EdgeNode01",
            "PlantMunich/EdgeNode02/RobotCell04": f"{enterprise}/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04",
        }
        self._seed_initial_namespace()

    def _seed_initial_namespace(self) -> None:
        """Populate initial ISA-95 structure so the live UNS tree is immediately browsable."""
        e = self.enterprise
        seeds = [
            (f"{e}/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Telemetry/PressureSetpointPSI", 95.0, "Double", "ignition-edge-01", "sparkplug_b"),
            (f"{e}/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/State/EmergencyReliefInterlock", True, "Boolean", "ignition-edge-01", "sparkplug_b"),
            (f"{e}/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Security/GigaMesh/ShieldState", "PROTECTED", "String", "gigamesh_security", "gigamesh_security"),
            (f"{e}/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Telemetry/ConveyorSpeedRPM", 112.0, "Double", "ignition-edge-munich", "isa95_uns"),
            (f"{e}/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Security/GigaMesh/ShieldState", "PROTECTED", "String", "gigamesh_security", "gigamesh_security"),
            (f"{e}/Cloud/AWS/us-east-1/SecurityHub/AgentToolkit/State/ReadOnlyGuardrail", "ENFORCED", "String", "aws_toolkit", "aws_toolkit"),
            (f"{e}/AustinPlant/Operations/Mobile/Android/Pixel9Pro/Devices/VpnShieldState", "ACTIVE_OFFLINE_READY", "String", "edge_fleet", "edge_fleet"),
        ]
        for topic, val, dtype, sender, proto in seeds:
            self._upsert_node_unlocked(topic=topic, value=val, datatype=dtype, sender=sender, protocol=proto, security_state="healthy")

    # ------------------------------------------------------------------
    # Topic Parsing, Mapping & Signing
    # ------------------------------------------------------------------
    def parse_isa95_topic(self, topic: str) -> dict[str, str]:
        parts = [p for p in topic.strip().split("/") if p]
        if len(parts) < 3:
            raise ValueError(
                f"Invalid UNS topic '{topic}'. Expected ISA-95 path like "
                f"'{self.enterprise}/Site/Area/Line/Cell/Asset/Layer/Metric'."
            )
        # Pad gracefully if a shorter enterprise/site/layer/metric path is used
        ent = parts[0]
        site = parts[1] if len(parts) > 1 else "GlobalSite"
        area = parts[2] if len(parts) > 2 else "GeneralArea"
        line = parts[3] if len(parts) > 3 else "Line0"
        cell = parts[4] if len(parts) > 4 else "Cell0"
        asset = parts[5] if len(parts) > 5 else cell

        # Detect functional layer anywhere in the tail
        layer = "Telemetry"
        metric = parts[-1]
        for idx in range(len(parts) - 1, 0, -1):
            low = parts[idx].lower()
            if low in TELEMETRY_LAYERS or low in COMMAND_LAYERS:
                layer = parts[idx]
                metric = "/".join(parts[idx + 1 :]) if idx + 1 < len(parts) else parts[-1]
                if idx >= 6:
                    asset = parts[idx - 1]
                break

        return {
            "enterprise": ent,
            "site": site,
            "area": area,
            "line": line,
            "cell": cell,
            "asset": asset,
            "layer": layer,
            "metric": metric,
        }

    def map_sparkplug_to_uns_prefix(self, group_id: str, edge_node_id: str, device_id: str | None) -> str:
        full_key = f"{group_id}/{edge_node_id}" + (f"/{device_id}" if device_id else "")
        if full_key in self.sparkplug_to_uns_map:
            return self.sparkplug_to_uns_map[full_key]
        node_key = f"{group_id}/{edge_node_id}"
        if node_key in self.sparkplug_to_uns_map:
            base = self.sparkplug_to_uns_map[node_key]
            return f"{base}/{device_id}" if device_id else base
        asset = device_id or edge_node_id
        return f"{self.enterprise}/{group_id}/EdgeArea/{edge_node_id}/Cell0/{asset}"

    def sign_uns_command(self, *, topic: str, sender_id: str, nonce: str, value: Any) -> str:
        canonical = json.dumps(
            {"topic": topic, "sender_id": sender_id, "nonce": nonce, "value": value},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hmac.new(self._secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # Hierarchical Wildcard Policy Resolution (Monotonic Strictest-Wins)
    # ------------------------------------------------------------------
    def resolve_effective_policies(self, topic: str) -> tuple[list[UnsPolicyRule], dict[str, Any]]:
        """Collect all matching wildcard policies sorted from Enterprise -> Asset and merge monotonically."""
        with self._lock:
            matched = [
                p for p in self.policies.values() if p.enabled and mqtt_topic_matches(p.topic_pattern, topic)
            ]
        matched.sort(key=lambda p: policy_specificity(p.topic_pattern))

        eff: dict[str, Any] = {
            "require_e2e_signature": False,
            "block_ai_tainted": False,
            "read_only_lockdown": False,
            "safety_interlock_locked": False,
            "min_value": None,
            "max_value": None,
            "max_delta_per_sec": None,
            "quorum_delta_threshold": None,
            "unit": "",
        }
        for p in matched:
            eff["require_e2e_signature"] = eff["require_e2e_signature"] or p.require_e2e_signature
            eff["block_ai_tainted"] = eff["block_ai_tainted"] or p.block_ai_tainted
            eff["read_only_lockdown"] = eff["read_only_lockdown"] or p.read_only_lockdown
            eff["safety_interlock_locked"] = eff["safety_interlock_locked"] or p.safety_interlock_locked
            if p.min_value is not None:
                eff["min_value"] = p.min_value if eff["min_value"] is None else max(eff["min_value"], p.min_value)
            if p.max_value is not None:
                eff["max_value"] = p.max_value if eff["max_value"] is None else min(eff["max_value"], p.max_value)
            if p.max_delta_per_sec is not None:
                eff["max_delta_per_sec"] = (
                    p.max_delta_per_sec
                    if eff["max_delta_per_sec"] is None
                    else min(eff["max_delta_per_sec"], p.max_delta_per_sec)
                )
            if p.quorum_delta_threshold is not None:
                eff["quorum_delta_threshold"] = (
                    p.quorum_delta_threshold
                    if eff["quorum_delta_threshold"] is None
                    else min(eff["quorum_delta_threshold"], p.quorum_delta_threshold)
                )
            if p.unit:
                eff["unit"] = p.unit
        return matched, eff

    def upsert_policy(self, rule: UnsPolicyRule) -> UnsPolicyRule:
        with self._lock:
            self.policies[rule.policy_id] = rule
        self.engine.broadcast("uns_updated", {"event": "policy_updated", "policy_id": rule.policy_id})
        return rule

    def set_site_read_only_lockdown(self, site: str, locked: bool) -> UnsPolicyRule:
        """1-click Site-Wide Read-Only Lockdown: freezes all Commands/* writes while telemetry keeps flowing."""
        pid = f"unsp-lockdown-{site.lower()}"
        rule = UnsPolicyRule(
            policy_id=pid,
            name=f"{site} Read-Only Lockdown",
            topic_pattern=f"{self.enterprise}/{site}/#",
            scope_level="Site",
            enabled=locked,
            read_only_lockdown=locked,
            description=f"Emergency read-only freeze for all remote commands under {self.enterprise}/{site}/#.",
        )
        self.upsert_policy(rule)
        self._publish_security_twin(
            f"{self.enterprise}/{site}/Security/GigaMesh/ReadOnlyLockdown",
            {"site": site, "read_only_lockdown": locked, "telemetry_flowing": True},
        )
        return rule

    # ------------------------------------------------------------------
    # Publish / Inspect ISA-95 Semantic UNS Messages
    # ------------------------------------------------------------------
    def publish_uns_message(self, msg: UnsMessageInput, *, source_protocol: str = "isa95_uns") -> UnsPublishVerdict:
        parsed = self.parse_isa95_topic(msg.topic)
        layer_low = parsed["layer"].lower()
        is_command = layer_low in COMMAND_LAYERS
        matched, eff = self.resolve_effective_policies(msg.topic)
        policy_ids = [p.policy_id for p in matched]

        # 1. Fail-Open Telemetry / State / Security path (never stalls visibility)
        if not is_command:
            with self._lock:
                self._upsert_node_unlocked(
                    topic=msg.topic,
                    value=msg.value,
                    datatype=msg.datatype,
                    sender=msg.sender_id,
                    protocol=source_protocol,
                    security_state="healthy",
                    matched_policies=policy_ids,
                )
            verdict = UnsPublishVerdict(
                topic=msg.topic,
                layer=parsed["layer"],
                mode="passive_fail_open",
                decision="allow",
                matched_policies=policy_ids,
                reasons=["uns_telemetry_updated"],
            )
            return self._record_verdict(verdict)

        # 2. Fail-Closed Actuation (`Commands/*`) path governed by merged hierarchical policies
        reasons: list[str] = []
        twin_topic = f"{parsed['enterprise']}/{parsed['site']}/{parsed['area']}/{parsed['line']}/{parsed['cell']}/{parsed['asset']}/Security/GigaMesh/LastCommandVerdict"

        # 2a. Site / Area Read-Only Lockdown check
        if eff["read_only_lockdown"]:
            reasons.append("site_or_branch_read_only_lockdown_active")
            self._publish_security_twin(twin_topic, {"decision": "block", "target": msg.topic, "reasons": reasons})
            return self._record_verdict(
                UnsPublishVerdict(
                    topic=msg.topic,
                    layer=parsed["layer"],
                    mode="inline_fail_closed",
                    decision="block",
                    matched_policies=policy_ids,
                    reasons=reasons,
                    security_twin_topic=twin_topic,
                )
            )

        # 2b. Enterprise IT-to-OT AI Crossover Barrier
        is_tainted = msg.sender_role == "ai_agent" or msg.metadata.get("it_tainted") is True
        if eff["block_ai_tainted"] and is_tainted and not msg.quorum_approved:
            reasons.append("uns_enterprise_policy_blocked_it_to_ot_ai_write")
            champ = self.engine.store.get_champion("stealth-intel-snare")
            sess = self.engine.snare.ensnare(
                attacker_id=msg.sender_id,
                attacker_family="uns-ai-ot-crossover",
                trace_id=msg.trace_id or f"uns-{uuid4().hex[:8]}",
                fork_id=champ.fork_id,
            )
            self._publish_security_twin(
                twin_topic,
                {"decision": "diverted_to_ghost_plc", "sender": msg.sender_id, "snare": sess.session_id, "reasons": reasons},
            )
            self.engine.security_audit_log.record(
                category="owasp_block",
                severity="critical",
                actor=msg.sender_id,
                summary=f"UNS policy diverted AI-tainted command on {msg.topic} to Ghost PLC snare",
                details={"policies": policy_ids, "snare": sess.session_id},
            )
            return self._record_verdict(
                UnsPublishVerdict(
                    topic=msg.topic,
                    layer=parsed["layer"],
                    mode="inline_fail_closed",
                    decision="diverted_to_ghost_plc",
                    matched_policies=policy_ids,
                    reasons=reasons,
                    ghost_plc_snare_id=sess.session_id,
                    security_twin_topic=twin_topic,
                )
            )

        # 2c. End-to-End Signature + Anti-Replay Nonce
        if eff["require_e2e_signature"]:
            expected = self.sign_uns_command(topic=msg.topic, sender_id=msg.sender_id, nonce=msg.nonce, value=msg.value) if msg.nonce else ""
            if not msg.nonce or not msg.signature or not hmac.compare_digest(msg.signature, expected):
                reasons.append("missing_or_invalid_uns_e2e_signature")
                self._publish_security_twin(twin_topic, {"decision": "block", "target": msg.topic, "reasons": reasons})
                return self._record_verdict(
                    UnsPublishVerdict(
                        topic=msg.topic,
                        layer=parsed["layer"],
                        mode="inline_fail_closed",
                        decision="block",
                        matched_policies=policy_ids,
                        reasons=reasons,
                        security_twin_topic=twin_topic,
                    )
                )
            with self._lock:
                if msg.nonce in self._seen_nonces:
                    reasons.append(f"replayed_uns_nonce:{msg.nonce}")
                    return self._record_verdict(
                        UnsPublishVerdict(
                            topic=msg.topic,
                            layer=parsed["layer"],
                            mode="inline_fail_closed",
                            decision="block",
                            matched_policies=policy_ids,
                            reasons=reasons,
                            security_twin_topic=twin_topic,
                        )
                    )
                self._seen_nonces.add(msg.nonce)

        # 2d. Inherited Digital Physics Safety Envelope
        if eff["safety_interlock_locked"]:
            reasons.append("inherited_safety_interlock_immutable")
            self._publish_security_twin(twin_topic, {"decision": "block", "target": msg.topic, "reasons": reasons})
            return self._record_verdict(
                UnsPublishVerdict(
                    topic=msg.topic,
                    layer=parsed["layer"],
                    mode="inline_fail_closed",
                    decision="block",
                    matched_policies=policy_ids,
                    reasons=reasons,
                    security_twin_topic=twin_topic,
                )
            )

        if isinstance(msg.value, (int, float)):
            val = float(msg.value)
            if eff["min_value"] is not None and val < eff["min_value"]:
                reasons.append(f"below_inherited_min:{val}<{eff['min_value']}{eff['unit']}")
            if eff["max_value"] is not None and val > eff["max_value"]:
                reasons.append(f"above_inherited_max:{val}>{eff['max_value']}{eff['unit']}")
            if reasons:
                self._publish_security_twin(twin_topic, {"decision": "block", "target": msg.topic, "reasons": reasons})
                return self._record_verdict(
                    UnsPublishVerdict(
                        topic=msg.topic,
                        layer=parsed["layer"],
                        mode="inline_fail_closed",
                        decision="block",
                        matched_policies=policy_ids,
                        reasons=reasons,
                        security_twin_topic=twin_topic,
                    )
                )

            # Check last telemetry value on the matching Telemetry/<metric> sibling for slew-rate & quorum delta
            telem_sibling = msg.topic.replace(f"/{parsed['layer']}/", "/Telemetry/")
            prev_node = self.nodes.get(telem_sibling) or self.nodes.get(msg.topic)
            if prev_node is not None and isinstance(prev_node.value, (int, float)):
                delta = abs(val - float(prev_node.value))
                if eff["max_delta_per_sec"] is not None and delta > eff["max_delta_per_sec"] and not msg.quorum_approved:
                    if eff["quorum_delta_threshold"] is not None and delta >= eff["quorum_delta_threshold"]:
                        q = self.engine.human_hub.open_quorum(
                            action_kind="uns_command_write",
                            target_id=msg.topic,
                            use_case="zero-trust-critical",
                            summary=f"Approve major UNS setpoint change ({prev_node.value} → {val} {eff['unit']}) on {msg.topic}",
                            evidence_refs=[msg.nonce or "uns"],
                        )
                        reasons.append(f"quorum_required_delta:{delta:.1f}{eff['unit']}")
                        self._publish_security_twin(
                            twin_topic,
                            {"decision": "quorum_required", "quorum_id": q.quorum_id, "target": msg.topic},
                        )
                        return self._record_verdict(
                            UnsPublishVerdict(
                                topic=msg.topic,
                                layer=parsed["layer"],
                                mode="inline_fail_closed",
                                decision="quorum_required",
                                matched_policies=policy_ids,
                                reasons=reasons,
                                quorum_id=q.quorum_id,
                                security_twin_topic=twin_topic,
                            )
                        )
                    reasons.append(f"slew_rate_exceeded:delta={delta:.1f}>{eff['max_delta_per_sec']}")
                    self._publish_security_twin(twin_topic, {"decision": "block", "target": msg.topic, "reasons": reasons})
                    return self._record_verdict(
                        UnsPublishVerdict(
                            topic=msg.topic,
                            layer=parsed["layer"],
                            mode="inline_fail_closed",
                            decision="block",
                            matched_policies=policy_ids,
                            reasons=reasons,
                            security_twin_topic=twin_topic,
                        )
                    )

        # Command verified cleanly across all inherited UNS policies!
        with self._lock:
            self._upsert_node_unlocked(
                topic=msg.topic,
                value=msg.value,
                datatype=msg.datatype,
                sender=msg.sender_id,
                protocol=source_protocol,
                security_state="healthy",
                matched_policies=policy_ids,
            )
        self._publish_security_twin(
            twin_topic,
            {"decision": "allow", "sender": msg.sender_id, "value": msg.value, "policies": policy_ids},
        )
        return self._record_verdict(
            UnsPublishVerdict(
                topic=msg.topic,
                layer=parsed["layer"],
                mode="inline_fail_closed",
                decision="allow",
                matched_policies=policy_ids,
                reasons=["uns_hierarchical_policies_verified"],
                security_twin_topic=twin_topic,
            )
        )

    def project_sparkplug_event(
        self,
        *,
        group_id: str,
        msg_type: str,
        edge_node_id: str,
        device_id: str | None,
        sender_id: str,
        metrics: list[dict[str, Any]],
        decision: str,
        reasons: list[str],
    ) -> None:
        """Project any Sparkplug B event into the canonical ISA-95 UNS tree + Security Twin."""
        prefix = self.map_sparkplug_to_uns_prefix(group_id, edge_node_id, device_id)
        layer = "Commands" if msg_type in ("NCMD", "DCMD") else "Telemetry"
        sec_state = "healthy" if decision == "allow" else "alert" if decision == "allow_with_alert" else "blocked"
        with self._lock:
            for m in metrics:
                metric_name = str(m.get("name", "value")).split("/")[-1]
                uns_topic = f"{prefix}/{layer}/{metric_name}"
                if decision in ("allow", "allow_with_alert"):
                    self._upsert_node_unlocked(
                        topic=uns_topic,
                        value=m.get("value"),
                        datatype=str(m.get("datatype", "Double")),
                        sender=sender_id,
                        protocol="sparkplug_b",
                        security_state=sec_state,
                    )
        self._publish_security_twin(
            f"{prefix}/Security/GigaMesh/LastSparkplugVerdict",
            {"sparkplug_type": msg_type, "decision": decision, "sender": sender_id, "reasons": reasons},
        )

    def _upsert_node_unlocked(
        self,
        *,
        topic: str,
        value: Any,
        datatype: str,
        sender: str,
        protocol: str,
        security_state: str,
        matched_policies: list[str] | None = None,
    ) -> None:
        p = self.parse_isa95_topic(topic)
        self.nodes[topic] = UnsNodeState(
            topic=topic,
            enterprise=p["enterprise"],
            site=p["site"],
            area=p["area"],
            line=p["line"],
            cell=p["cell"],
            asset=p["asset"],
            layer=p["layer"],
            metric=p["metric"],
            value=value,
            datatype=datatype,
            source_protocol=protocol,
            last_sender=sender,
            security_state=security_state,
            matched_policies=matched_policies or [],
        )

    def _publish_security_twin(self, topic: str, payload: dict[str, Any]) -> None:
        ev = UnsSecurityTwinEvent(topic=topic, payload=payload)
        with self._lock:
            self.security_twin_feed.append(ev)
            self.security_twin_feed = self.security_twin_feed[-100:]
            sec_state = "healthy" if payload.get("decision") in (None, "allow") and not payload.get("read_only_lockdown") else "blocked"
            self._upsert_node_unlocked(
                topic=topic,
                value=payload.get("decision") or ("LOCKDOWN" if payload.get("read_only_lockdown") else "ACTIVE"),
                datatype="JSON",
                sender="gigamesh_security",
                protocol="gigamesh_security",
                security_state=sec_state,
            )

    def _record_verdict(self, verdict: UnsPublishVerdict) -> UnsPublishVerdict:
        with self._lock:
            self.verdicts.append(verdict)
            self.verdicts = self.verdicts[-200:]
        self.engine.broadcast("uns_updated", verdict.model_dump(mode="json"))
        return verdict

    # ------------------------------------------------------------------
    # Multi-Plant Enterprise Simulation & Hierarchical Tree Builder
    # ------------------------------------------------------------------
    def simulate_enterprise_uns(self) -> list[UnsPublishVerdict]:
        """Run a multi-plant ISA-95 UNS scenario (Austin + Munich) proving wildcard inheritance & Security Twin."""
        e = self.enterprise
        v1 = self.publish_uns_message(
            UnsMessageInput(
                topic=f"{e}/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Telemetry/ConveyorSpeedRPM",
                value=120.0,
                sender_id="munich-ignition-edge",
                sender_role="edge_node",
            )
        )
        # AI copilot tries to push Munich conveyor to 240 RPM -> caught by Enterprise wildcard AI barrier!
        v2 = self.publish_uns_message(
            UnsMessageInput(
                topic=f"{e}/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM",
                value=240.0,
                sender_id="ai-supply-copilot",
                sender_role="ai_agent",
                metadata={"it_tainted": True},
            )
        )
        # Signed engineer attempts large setpoint jump (95 -> 130 PSI) in Austin -> routed to HITL Quorum!
        t3 = f"{e}/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Commands/PressureSetpointPSI"
        n3 = f"uns-q-{uuid4().hex[:8]}"
        v3 = self.publish_uns_message(
            UnsMessageInput(
                topic=t3,
                value=130.0,
                sender_id="plant-engineer-android",
                sender_role="admin_android",
                nonce=n3,
                signature=self.sign_uns_command(topic=t3, sender_id="plant-engineer-android", nonce=n3, value=130.0),
            )
        )
        # Signed engineer makes safe small adjustment in Munich (120 -> 132 RPM) -> allowed!
        t4 = f"{e}/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM"
        n4 = f"uns-ok-{uuid4().hex[:8]}"
        v4 = self.publish_uns_message(
            UnsMessageInput(
                topic=t4,
                value=132.0,
                sender_id="munich-lead-android",
                sender_role="admin_android",
                nonce=n4,
                signature=self.sign_uns_command(topic=t4, sender_id="munich-lead-android", nonce=n4, value=132.0),
            )
        )
        return [v1, v2, v3, v4]

    def build_tree(self) -> dict[str, Any]:
        """Build a clean nested ISA-95 JSON tree ready for interactive UI browsing."""
        root: dict[str, Any] = {"name": self.enterprise, "path": self.enterprise, "children": {}, "leaves": []}
        with self._lock:
            all_nodes = list(self.nodes.values())
        for node in sorted(all_nodes, key=lambda n: n.topic):
            parts = [p for p in node.topic.split("/") if p]
            if not parts:
                continue
            cur = root
            acc = parts[0]
            for seg in parts[1:-1]:
                acc = f"{acc}/{seg}"
                children = cur["children"]
                if seg not in children:
                    children[seg] = {"name": seg, "path": acc, "children": {}, "leaves": []}
                cur = children[seg]
            cur["leaves"].append(node.model_dump(mode="json"))

        def _collapse(n: dict[str, Any]) -> dict[str, Any]:
            kids = [_collapse(v) for v in n["children"].values()]
            return {"name": n["name"], "path": n["path"], "children": kids, "leaves": n["leaves"]}

        return _collapse(root)

    def status(self) -> dict[str, Any]:
        with self._lock:
            sites = sorted({n.site for n in self.nodes.values()})
            return {
                "enterprise": self.enterprise,
                "sites": sites,
                "total_nodes": len(self.nodes),
                "total_policies": len(self.policies),
                "active_lockdowns": [p.topic_pattern for p in self.policies.values() if p.enabled and p.read_only_lockdown],
                "policies": [p.model_dump(mode="json") for p in self.policies.values()],
                "sparkplug_to_uns_map": dict(self.sparkplug_to_uns_map),
                "recent_verdicts": [v.model_dump(mode="json") for v in reversed(self.verdicts[-30:])],
                "security_twin_feed": [s.model_dump(mode="json") for s in reversed(self.security_twin_feed[-20:])],
                "tree": self.build_tree(),
            }
