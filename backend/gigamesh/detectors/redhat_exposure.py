"""Dual Red-Hat Exposure Detector:
1. Exposes covert offensive / "red-hat" autonomous agentic systems (loop cadence, C2 proxy, canary trips).
2. Exposes Red Hat Enterprise Linux / OpenShift host compromise (auditd, SELinux AVC, pod-exec).
"""

from __future__ import annotations

from gigamesh.detectors.base import DetectorContext
from gigamesh.models.asef import ActorType, AsefEvent, DetectionHit, EventType, Severity

DANGEROUS_SYSCALLS = ("ptrace", "memfd_create", "setuid", "init_module", "execveat", "bpf")


class RedHatExposureDetector:
    detector_id = "det-redhat-exposure"
    attack_class = "redhat_exposure"

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        score = 0.0
        indicators: list[str] = []
        payload = (event.payload_preview or "").lower()
        egress = (event.egress_destination or "").lower()

        # (A) Autonomous offensive / "red-hat" agentic loop exposure
        if event.actor_type == ActorType.RED_HAT_SUSPECT:
            score += 0.28
            indicators.append("red_hat_suspect_actor")

        if event.loop_cadence_ms is not None and event.loop_cadence_ms <= 350.0:
            score += 0.34
            indicators.append(f"machine_speed_offensive_loop:{event.loop_cadence_ms:.0f}ms")

        if event.event_type == EventType.CANARY_TRIP:
            score += 0.65
            indicators.append("canary_credential_tripped")

        if event.event_type == EventType.NETWORK_EGRESS and any(
            k in egress or k in payload
            for k in ("c2.", "llm-proxy", "onion", "raw-socket", "exfil.", "beacon", "tor2web")
        ):
            score += 0.42
            indicators.append(f"covert_c2_or_llm_proxy:{egress}")

        # (B) Red Hat Enterprise Linux / OpenShift infrastructure exposure
        if event.event_type == EventType.SELINUX_AVC_DENIAL:
            score += 0.46
            indicators.append(f"selinux_avc_denial:{event.selinux_context or 'unconfined'}")
            if "setenforce 0" in payload or "permissive" in payload:
                score += 0.35
                indicators.append("selinux_tampering_attempt")

        if event.event_type == EventType.HOST_AUDITD_SYSCALL:
            if event.auditd_syscall in DANGEROUS_SYSCALLS:
                score += 0.42
                indicators.append(f"auditd_syscall:{event.auditd_syscall}")
            if "auditctl -d" in payload or "auditd stop" in payload:
                score += 0.45
                indicators.append("auditd_blinding_attempt")

        if event.event_type == EventType.OPENSHIFT_POD_EXEC:
            score += 0.32
            indicators.append("openshift_pod_exec")
            if "hostpath" in payload or "privileged: true" in payload or "cluster-admin" in payload:
                score += 0.36
                indicators.append("openshift_container_escape_vector")

        # Metabolized behavioral loop counters and RHEL hardening modules increase exposure accuracy
        if any(
            m.capability_kind in ("behavioral_loop_detector", "rhel_hardening")
            for m in ctx.metabolized_modules
        ):
            if event.loop_cadence_ms is not None or event.host_id is not None:
                score += 0.16
                indicators.append("metabolized_redhat_exposure_boost")

        score = min(1.0, round(score, 4))
        if score < ctx.fork.detector_threshold:
            return None

        # Trade-off decides whether to ensnare for REA dissection or apply hard RHEL isolation
        if ctx.fork.trade_offs.deception_dwell_budget >= 0.50:
            action = "ensnare_and_rea_dissect"
        else:
            action = "rhel_selinux_nftables_isolate"

        return DetectionHit(
            detector_id=self.detector_id,
            attack_class=self.attack_class,
            severity=Severity.CRITICAL if score >= 0.78 else Severity.HIGH,
            confidence=score,
            title="Red-Hat Offensive Agent / RHEL-OpenShift Infrastructure Exposure",
            rationale=(
                f"Exposed high-risk offensive loop or RHEL/OpenShift boundary violation on "
                f"{event.host_id or event.actor_id} ({', '.join(indicators[:3])})."
            ),
            event_id=event.event_id,
            trace_id=event.trace_id,
            fork_id=ctx.fork.fork_id,
            recommended_action=action,
            indicators=indicators,
        )
