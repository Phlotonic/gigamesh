"""Human Security Aggregation Hub:
1. Collective Analyst Defense (weighted voting & rule synthesis)
2. Human-Identity & Delegation Risk Correlation (MFA/phishing/OAuth -> agent risk)
3. Cryptographic HITL Quorum Gate (M-of-N approval & fail-closed quarantine)
4. Federated Crowdsourced STIX 2.1 Graph-Motif Exchange
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from gigamesh.models.asef import AsefEvent, EventType
from gigamesh.models.governance import (
    AnalystVote,
    FederatedStixBundle,
    HumanIdentityRisk,
    HumanSynthesizedRule,
    QuorumRequest,
    QuorumSignature,
)
from gigamesh.models.rea import MetabolizedDefenseModule


class HumanSecurityHub:
    """Aggregates human security intelligence, risk signals, and quorum authority."""

    def __init__(self, default_quorum_threshold: int = 2) -> None:
        self.default_quorum_threshold = default_quorum_threshold
        self.identities: dict[str, HumanIdentityRisk] = {}
        self.votes: list[AnalystVote] = []
        self.rules: dict[str, HumanSynthesizedRule] = {}
        self.quorum_requests: dict[str, QuorumRequest] = {}
        self.stix_bundles: dict[str, FederatedStixBundle] = {}
        self._seed_identities()

    def _seed_identities(self) -> None:
        seeds = [
            HumanIdentityRisk(
                human_principal_id="alice.chen@corp.local",
                display_name="Alice Chen",
                department="platform-sre",
                risk_score=0.08,
                active_delegated_agents=["agent-triage-01", "agent-doc-summarizer"],
            ),
            HumanIdentityRisk(
                human_principal_id="marcus.diaz@corp.local",
                display_name="Marcus Diaz",
                department="secops-rhel",
                risk_score=0.12,
                active_delegated_agents=["agent-openshift-ops", "agent-ci-runner"],
            ),
            HumanIdentityRisk(
                human_principal_id="priya.nair@corp.local",
                display_name="Priya Nair",
                department="finops",
                risk_score=0.06,
                active_delegated_agents=["agent-invoice-bot"],
            ),
        ]
        for ident in seeds:
            self.identities[ident.human_principal_id] = ident

    # ------------------------------------------------------------------
    # Pillar 2: Human-Identity & Delegation Risk Correlation
    # ------------------------------------------------------------------
    def ingest_human_signal(self, event: AsefEvent) -> HumanIdentityRisk | None:
        principal = event.human_principal_id
        if not principal:
            return None

        ident = self.identities.get(principal)
        if not ident:
            ident = HumanIdentityRisk(
                human_principal_id=principal,
                display_name=principal.split("@")[0].replace(".", " ").title(),
                risk_score=0.10,
            )
            self.identities[principal] = ident

        if event.actor_id and event.actor_id not in ident.active_delegated_agents and event.actor_id != principal:
            ident.active_delegated_agents.append(event.actor_id)

        if event.event_type == EventType.HUMAN_MFA_ANOMALY:
            ident.mfa_anomalies += 1
            ident.risk_score = min(1.0, round(ident.risk_score + 0.42, 4))
            ident.notes.append(f"MFA fatigue/anomaly detected: {event.payload_preview[:80]}")
        elif event.event_type == EventType.HUMAN_PHISHING_REPORT:
            ident.phishing_reports += 1
            ident.risk_score = min(1.0, round(ident.risk_score + 0.35, 4))
            ident.notes.append(f"User reported phishing/poisoned doc: {event.payload_preview[:80]}")
        elif event.event_type == EventType.OAUTH_DELEGATION_GRANT:
            if any(k in event.payload_preview.lower() for k in ("admin", "wildcard", "*", "offline_access")):
                ident.suspicious_oauth_grants += 1
                ident.risk_score = min(1.0, round(ident.risk_score + 0.38, 4))
                ident.notes.append(f"High-scope OAuth delegation grant: {event.payload_preview[:80]}")

        ident.last_signal_at = datetime.now(timezone.utc)
        return ident

    def get_human_risk(self, principal_id: str | None) -> float:
        if not principal_id:
            return 0.0
        ident = self.identities.get(principal_id)
        return ident.risk_score if ident else 0.0

    # ------------------------------------------------------------------
    # Pillar 1: Collective Analyst Defense & Rule Synthesis
    # ------------------------------------------------------------------
    def record_vote(self, vote: AnalystVote) -> dict[str, Any]:
        self.votes.append(vote)
        compiled_rule: HumanSynthesizedRule | None = None

        # Aggregate weighted consensus for votes proposing a pattern
        if vote.proposed_pattern:
            matching_votes = [
                v
                for v in self.votes
                if v.proposed_pattern == vote.proposed_pattern and v.verdict in ("confirm_threat", "approve_promotion")
            ]
            total_weight = round(sum(v.analyst_reputation for v in matching_votes), 4)
            if total_weight >= 1.5:
                existing = next(
                    (r for r in self.rules.values() if r.pattern == vote.proposed_pattern),
                    None,
                )
                if existing:
                    existing.consensus_weight = total_weight
                    if vote.analyst_id not in existing.author_analysts:
                        existing.author_analysts.append(vote.analyst_id)
                    compiled_rule = existing
                else:
                    compiled_rule = HumanSynthesizedRule(
                        title=f"Collective Rule: {vote.annotation[:48] or vote.proposed_pattern[:36]}",
                        attack_class="collective_human_intel",
                        pattern=vote.proposed_pattern,
                        author_analysts=sorted({v.analyst_id for v in matching_votes}),
                        consensus_weight=total_weight,
                    )
                    self.rules[compiled_rule.rule_id] = compiled_rule

        # Compute net reward signal for the target
        target_votes = [v for v in self.votes if v.target_id == vote.target_id]
        net_weight = sum(
            v.analyst_reputation if v.verdict in ("confirm_threat", "approve_promotion") else -v.analyst_reputation
            for v in target_votes
        )
        consensus_label = (
            "confirmed_threat" if net_weight >= 1.0 else ("false_positive" if net_weight <= -1.0 else "under_review")
        )
        return {
            "vote": vote,
            "target_net_weight": round(net_weight, 4),
            "consensus_label": consensus_label,
            "compiled_rule": compiled_rule,
        }

    # ------------------------------------------------------------------
    # Pillar 3: Cryptographic HITL Quorum Gate
    # ------------------------------------------------------------------
    def open_quorum(
        self,
        *,
        action_kind: str,
        target_id: str,
        use_case: str,
        summary: str,
        evidence_refs: list[str] | None = None,
        required_approvals: int | None = None,
    ) -> QuorumRequest:
        req = QuorumRequest(
            action_kind=action_kind,
            target_id=target_id,
            use_case=use_case,
            required_approvals=required_approvals or self.default_quorum_threshold,
            summary=summary,
            evidence_refs=evidence_refs or [],
        )
        self.quorum_requests[req.quorum_id] = req
        return req

    def sign_quorum(
        self,
        *,
        quorum_id: str,
        analyst_id: str,
        decision: str,
        comment: str = "",
    ) -> QuorumRequest:
        req = self.quorum_requests.get(quorum_id)
        if not req:
            raise KeyError(f"Unknown quorum request: {quorum_id}")
        if req.status != "pending":
            return req
        if any(sig.analyst_id == analyst_id for sig in req.signatures):
            raise ValueError(f"Analyst {analyst_id} already signed quorum {quorum_id}")

        digest = hashlib.sha256(
            f"{quorum_id}|{analyst_id}|{decision}|{req.target_id}".encode("utf-8")
        ).hexdigest()
        req.signatures.append(
            QuorumSignature(
                analyst_id=analyst_id,
                decision=decision,
                signature_digest=digest,
                comment=comment,
            )
        )

        approvals = sum(1 for s in req.signatures if s.decision == "approve")
        rejections = sum(1 for s in req.signatures if s.decision == "reject")
        if approvals >= req.required_approvals:
            req.status = "approved"
        elif rejections >= req.required_approvals:
            req.status = "rejected"
        return req

    def fail_closed_timeout(self, quorum_id: str) -> QuorumRequest:
        """Fail-closed quarantine if human quorum SLA expires without resolution."""
        req = self.quorum_requests[quorum_id]
        if req.status == "pending":
            req.status = "fail_closed_quarantined"
        return req

    def is_quorum_approved(self, quorum_id: str | None) -> bool:
        if not quorum_id:
            return False
        req = self.quorum_requests.get(quorum_id)
        return bool(req and req.status == "approved")

    # ------------------------------------------------------------------
    # Pillar 4: Federated Crowdsourced STIX 2.1 Bundle Exchange
    # ------------------------------------------------------------------
    def export_stix_bundle(
        self,
        *,
        origin_org: str,
        modules: list[MetabolizedDefenseModule],
        rules: list[HumanSynthesizedRule],
    ) -> FederatedStixBundle:
        """Export PII-scrubbed, signed STIX 2.1 graph motifs for peer organizations."""
        org_hash = hashlib.sha256(origin_org.encode("utf-8")).hexdigest()[:16]
        motifs: list[dict[str, Any]] = []
        for mod in modules:
            if not mod.safety_verified:
                continue
            motifs.append(
                {
                    "type": "indicator",
                    "name": mod.name,
                    "capability_kind": mod.capability_kind,
                    "patterns": list(mod.match_patterns),
                    "target_attack_classes": list(mod.target_attack_classes),
                    "cross_attacker_hits": dict(mod.cross_attacker_hits),
                }
            )
        for rule in rules:
            if rule.active:
                motifs.append(
                    {
                        "type": "human-consensus-indicator",
                        "name": rule.title,
                        "attack_class": rule.attack_class,
                        "patterns": [rule.pattern],
                        "consensus_weight": rule.consensus_weight,
                    }
                )
        sig_payload = json.dumps({"org": org_hash, "motifs": motifs}, sort_keys=True)
        signature = hashlib.sha256(sig_payload.encode("utf-8")).hexdigest()
        bundle = FederatedStixBundle(
            origin_org_hash=org_hash,
            signature=signature,
            motifs=motifs,
            imported=False,
        )
        self.stix_bundles[bundle.bundle_id] = bundle
        return bundle

    def import_stix_bundle(self, bundle: FederatedStixBundle) -> list[HumanSynthesizedRule]:
        """Verify signature & ingest peer-org motifs into active defensive rules."""
        expected_sig = hashlib.sha256(
            json.dumps({"org": bundle.origin_org_hash, "motifs": bundle.motifs}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if bundle.signature != expected_sig:
            raise ValueError("Invalid STIX bundle signature — rejected by neutral verification gate")

        bundle.imported = True
        self.stix_bundles[bundle.bundle_id] = bundle
        imported_rules: list[HumanSynthesizedRule] = []
        for motif in bundle.motifs:
            for pat in motif.get("patterns", [])[:2]:
                if any(r.pattern == pat for r in self.rules.values()):
                    continue
                rule = HumanSynthesizedRule(
                    title=f"Federated STIX: {motif.get('name', 'peer-motif')[:44]}",
                    attack_class=motif.get("attack_class")
                    or (motif.get("target_attack_classes") or ["federated_intel"])[0],
                    pattern=pat,
                    author_analysts=[f"federated:{bundle.origin_org_hash[:8]}"],
                    consensus_weight=round(bundle.trust_score * 2.0, 2),
                )
                self.rules[rule.rule_id] = rule
                imported_rules.append(rule)
        return imported_rules
