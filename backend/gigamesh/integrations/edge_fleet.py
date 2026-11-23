"""Edge Device Fleet Manager & Cryptographically Signed Offline Policy Bundles.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Manages enrolled Android phones/tablets, iOS devices, Ignition Gateways, RHEL/OpenShift
hosts, and ARM64/IoT `gigamesh-edge` nodes. Compiles HMAC-SHA256-signed offline policy
bundles containing active champion defenses, threat-crawler IOC domain blocklists (for
Android `VpnService`), and Physical Safety Envelopes so every edge device stays protected
even if WAN/cloud connectivity drops.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


class EdgeEnrollRequest(BaseModel):
    device_name: str
    platform: str = "linux_arm64"  # android | ios | ignition_gateway | linux_arm64 | rhel_openshift | windows
    site_or_plant: str = "Default Site"
    edge_runtime: str = "gigamesh-edge"  # gigamesh-edge-go | gigamesh-edge-rust | capacitor-android
    capabilities: list[str] = Field(default_factory=list)


class EdgeDeviceRecord(BaseModel):
    device_id: str = Field(default_factory=lambda: f"edg-{uuid4().hex[:10]}")
    device_name: str
    platform: str
    site_or_plant: str
    edge_runtime: str
    capabilities: list[str] = Field(default_factory=list)
    enrolled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "online"  # online | offline_autonomous | quarantined | revoked
    policy_version: str = ""
    blocked_threats_local: int = 0
    vpn_shield_active: bool = False
    biometric_key_registered: bool = False
    token_sha256: str = ""


class EdgeHeartbeatRequest(BaseModel):
    device_id: str
    policy_version: str = ""
    blocked_threats_delta: int = 0
    vpn_shield_active: bool = False
    offline_buffered_events: int = 0
    metrics: dict[str, Any] = Field(default_factory=dict)


class SignedOfflinePolicyBundle(BaseModel):
    bundle_version: str
    issued_at: str
    champion_fork_id: str
    blocked_domains_for_vpn: list[str]
    blocked_patterns: list[str]
    safety_envelopes: list[dict[str, Any]]
    pinned_birth_schemas: dict[str, str]
    bundle_sha256: str
    signature: str


class EdgeFleetManager:
    """Enrolls multi-platform edge devices and compiles signed offline defense bundles."""

    def __init__(self, *, engine: GigaMeshEngine, signing_secret: bytes | None = None) -> None:
        self.engine = engine
        self._secret = signing_secret or os.environ.get(
            "GIGAMESH_EDGE_BUNDLE_SECRET", "gigamesh-edge-offline-bundle-v1"
        ).encode("utf-8")
        self._lock = threading.RLock()
        self.devices: dict[str, EdgeDeviceRecord] = {}
        self._seed_demo_fleet()

    def _seed_demo_fleet(self) -> None:
        # Provide initial ready-to-inspect reference entries for novice onboarding
        for name, plat, site, rt, caps, vpn, bio in [
            (
                "Plant Engineer Pixel 9 Pro",
                "android",
                "Austin Factory",
                "capacitor-android",
                ["biometric_quorum", "vpn_dns_shield", "push_alerts"],
                True,
                True,
            ),
            (
                "Line-3 Ignition Edge Gateway (ARM64)",
                "ignition_gateway",
                "Austin Factory",
                "gigamesh-edge-rust",
                ["sparkplug_b_guard", "physics_envelope", "offline_verify"],
                False,
                False,
            ),
        ]:
            rec = EdgeDeviceRecord(
                device_name=name,
                platform=plat,
                site_or_plant=site,
                edge_runtime=rt,
                capabilities=caps,
                vpn_shield_active=vpn,
                biometric_key_registered=bio,
            )
            self.devices[rec.device_id] = rec

    def enroll_device(self, req: EdgeEnrollRequest) -> dict[str, Any]:
        raw_token = f"gm_edge_{secrets.token_urlsafe(24)}"
        tok_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        rec = EdgeDeviceRecord(
            device_name=req.device_name,
            platform=req.platform,
            site_or_plant=req.site_or_plant,
            edge_runtime=req.edge_runtime,
            capabilities=req.capabilities,
            token_sha256=tok_hash,
            vpn_shield_active=req.platform == "android",
            biometric_key_registered=req.platform in ("android", "ios"),
        )
        with self._lock:
            self.devices[rec.device_id] = rec
        self.engine.security_audit_log.record(
            category="access_denied" if False else "owasp_block",
            severity="low",
            actor=req.device_name,
            summary=f"Enrolled edge device {rec.device_id} ({req.platform} @ {req.site_or_plant})",
            details={"device_id": rec.device_id, "platform": req.platform},
        )
        self.engine.broadcast("edge_fleet_updated", {"event": "enrolled", "device_id": rec.device_id})
        return {
            "device": rec.model_dump(mode="json"),
            "device_token_once": raw_token,
            "policy_bundle_url": "/api/edge/policy-bundle",
        }

    def record_heartbeat(self, req: EdgeHeartbeatRequest) -> EdgeDeviceRecord:
        with self._lock:
            dev = self.devices.get(req.device_id)
            if dev is None:
                raise KeyError(req.device_id)
            if dev.status == "revoked":
                raise PermissionError(f"Device {req.device_id} is revoked")
            dev.last_heartbeat_at = datetime.now(timezone.utc)
            dev.status = "online"
            if req.policy_version:
                dev.policy_version = req.policy_version
            dev.blocked_threats_local += max(0, req.blocked_threats_delta)
            dev.vpn_shield_active = req.vpn_shield_active
            return dev

    def revoke_device(self, device_id: str) -> EdgeDeviceRecord:
        with self._lock:
            dev = self.devices.get(device_id)
            if dev is None:
                raise KeyError(device_id)
            dev.status = "revoked"
            dev.token_sha256 = ""
            self.engine.security_audit_log.record(
                category="access_denied",
                severity="high",
                actor="operator",
                summary=f"Revoked edge device credentials for {dev.device_name} ({device_id})",
            )
            return dev

    def compile_signed_policy_bundle(self) -> SignedOfflinePolicyBundle:
        """Compile an HMAC-SHA256-signed offline policy bundle from Champion + Threat Crawler + OT Envelopes."""
        champ = self.engine.store.get_champion("enterprise-balanced")
        # Gather IOC domains from threat crawler + base malicious C2 domains for Android VpnService
        domains = {
            "c2.red-beacon.invalid",
            "exfil.attacker.invalid",
            "drop.evil.invalid",
            "sync-node.shadow-relay.top",
        }
        patterns: set[str] = set()
        for f in self.engine.threat_crawler.findings[-100:]:
            for p in f.extracted_patterns:
                if "." in p and not p.startswith("cve-"):
                    domains.add(p.lower())
                else:
                    patterns.add(p)
        for mod in self.engine.store.list_modules():
            if mod.safety_verified:
                for p in mod.match_patterns:
                    patterns.add(p)

        envelopes = [r.model_dump(mode="json") for r in self.engine.mqtt_ot.safety_envelopes.values()]
        births = {k: v.schema_sha256 for k, v in self.engine.mqtt_ot.birth_pins.items()}
        issued_at = datetime.now(timezone.utc).isoformat()
        body = {
            "champion_fork_id": champ.fork_id,
            "blocked_domains_for_vpn": sorted(domains)[:200],
            "blocked_patterns": sorted(patterns)[:200],
            "safety_envelopes": envelopes,
            "pinned_birth_schemas": births,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        sig = hmac.new(self._secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return SignedOfflinePolicyBundle(
            bundle_version=f"pol-{digest[:12]}",
            issued_at=issued_at,
            champion_fork_id=champ.fork_id,
            blocked_domains_for_vpn=body["blocked_domains_for_vpn"],
            blocked_patterns=body["blocked_patterns"],
            safety_envelopes=envelopes,
            pinned_birth_schemas=births,
            bundle_sha256=digest,
            signature=sig,
        )

    def verify_policy_bundle(self, bundle: SignedOfflinePolicyBundle) -> bool:
        body = {
            "champion_fork_id": bundle.champion_fork_id,
            "blocked_domains_for_vpn": bundle.blocked_domains_for_vpn,
            "blocked_patterns": bundle.blocked_patterns,
            "safety_envelopes": bundle.safety_envelopes,
            "pinned_birth_schemas": bundle.pinned_birth_schemas,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        expected_sig = hmac.new(self._secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(bundle.bundle_sha256, digest) and hmac.compare_digest(bundle.signature, expected_sig)

    def status(self) -> dict[str, Any]:
        with self._lock:
            devs = list(self.devices.values())
            return {
                "total_devices": len(devs),
                "online_devices": sum(1 for d in devs if d.status == "online"),
                "android_devices": sum(1 for d in devs if d.platform == "android"),
                "industrial_gateways": sum(1 for d in devs if d.platform in ("ignition_gateway", "linux_arm64", "rhel_openshift")),
                "devices": [d.model_dump(mode="json") for d in devs],
            }
