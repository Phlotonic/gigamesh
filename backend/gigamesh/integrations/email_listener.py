"""Event-Driven Gmail Security Vulnerability Triage & Autonomous Handling Listener.

Listens for incoming security/vulnerability disclosures (via Gmail History API cursors,
Gmail Pub/Sub push webhooks, or direct event injection), treats EVERY inbound email as
UNTRUSTED input through GigaMesh's Causal Provenance & Prompt-Injection Detectors first,
and autonomously triages, verifies, hardens, and prepares human-reviewable Gmail drafts.

Safety Invariants:
- Never blindly executes instructions embedded in emails (indirect prompt-injection defense).
- Hostile emails containing injection/obfuscation payloads are ensnared & dissected via REA.
- Never calls `gmail mutate send`, `mutate reply`, or `mutate trash` automatically; always
  creates Markdown Gmail drafts (`mutate create-draft --md`) and opens HITL Quorum gates
  for high-impact actions so a human remains in final control of external communications.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import BaseModel, Field

from gigamesh.models.asef import ActorType, AsefEvent, EventType, Severity, TrustLevel

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


DEFAULT_SECURITY_QUERY = (
    'is:unread (vulnerability OR CVE OR "security report" OR "genome-sync" '
    'OR contamination OR exploit OR "responsible disclosure" OR gigamesh)'
)

DEFAULT_GMAIL_CLI = "/opt/antigravity/plugins/gmail/skills/gmail/scripts/gmail"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
FORK_REF_RE = re.compile(r"\b(?:fork|metab)-[a-z0-9_-]{4,}\b", re.IGNORECASE)
SHA_REF_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
IOC_PATTERN_RE = re.compile(
    r"(?:pattern|ioc|signature|header|domain)\s*[:=]\s*[`\"']?([a-zA-Z0-9_.:/*-]{5,64})[`\"']?",
    re.IGNORECASE,
)

COMPONENT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "sync_firewall": ("genome-sync", "sync firewall", "sync_firewall", "contamination", "forged score", "merkle"),
    "rea_bridge": ("rea", "reverse engineer", "dissect", "metabolism", "ghidra", "sqlite"),
    "neural_repo": ("neural repo", "git_store", "fork", "ledger", "thompson", "darwinian"),
    "redhat_host": ("rhel", "selinux", "auditd", "nftables", "openshift", "systemd"),
    "mcp_proxy": ("mcp", "tool proxy", "kill-switch", "oauth", "delegation"),
    "human_quorum": ("quorum", "hitl", "stix", "vote", "bypass"),
    "api_server": ("fastapi", "websocket", "endpoint", "xss", "csrf", "ssrf", "rce"),
}

CRITICAL_TERMS = (
    "rce",
    "remote code execution",
    "quorum bypass",
    "merkle bypass",
    "firewall bypass",
    "zero-day",
    "0day",
    "privilege escalation",
    "arbitrary command",
    "selinux bypass",
    "contamination",
    "poisoning",
)

HIGH_TERMS = (
    "vulnerability",
    "exploit",
    "injection",
    "token leak",
    "credential",
    "ssrf",
    "sandbox escape",
    "cve-",
)


class EmailVulnerabilityReport(BaseModel):
    """Normalized inbound email payload awaiting zero-trust security triage."""

    message_id: str = Field(default_factory=lambda: f"msg-{uuid4().hex[:12]}")
    thread_id: str | None = None
    history_id: str | None = None
    sender: str
    subject: str
    body_text: str
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    spf_dkim_pass: bool = True
    attachments: list[str] = Field(default_factory=list)
    source: str = "gmail_cli"  # gmail_cli | pubsub_webhook | simulated_email


class EmailTriageDecision(BaseModel):
    """Auditable record of autonomous email vulnerability triage and defensive handling."""

    triage_id: str = Field(default_factory=lambda: f"eml-{uuid4().hex[:10]}")
    triaged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message_id: str
    thread_id: str | None = None
    sender: str
    subject: str
    classification: str  # hostile_email_prompt_injection | genome_contamination_report | critical_vulnerability | high_vulnerability | medium_vulnerability | informational
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    spf_dkim_verified: bool = True
    prompt_injection_detected: bool = False
    cve_ids: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    referenced_forks: list[str] = Field(default_factory=list)
    extracted_iocs: list[str] = Field(default_factory=list)
    incident_id: str | None = None
    quorum_id: str | None = None
    rea_dossier_id: str | None = None
    evolution_generation_id: int | None = None
    draft_created: bool = False
    draft_id: str | None = None
    draft_preview: str = ""
    actions_taken: list[str] = Field(default_factory=list)
    status: str = "triaged"  # triaged | quarantined_hostile | quorum_pending | draft_ready


class EmailListenerStatus(BaseModel):
    running: bool
    gmail_authenticated: bool
    gmail_cli_path: str | None
    poll_interval_sec: float
    search_query: str
    create_gmail_drafts: bool
    auto_send_blocked: bool = True  # Hard safety invariant: never auto-send unattended
    last_history_id: str | None = None
    last_poll_at: datetime | None = None
    processed_count: int = 0
    decisions_count: int = 0
    hostile_blocked_count: int = 0
    drafts_created_count: int = 0


class GmailCliAdapter:
    """Thin, safe wrapper over the official connected `gmail` Go CLI."""

    def __init__(self, cli_path: str | None = None) -> None:
        if cli_path and Path(cli_path).exists():
            self.cli_path: str | None = cli_path
        elif Path(DEFAULT_GMAIL_CLI).exists():
            self.cli_path = DEFAULT_GMAIL_CLI
        else:
            self.cli_path = shutil.which("gmail")

    def _run(self, *args: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
        if not self.cli_path:
            raise RuntimeError("Gmail CLI not found")
        return subprocess.run(
            [self.cli_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def auth_status(self) -> dict[str, Any]:
        if not self.cli_path:
            return {"authenticated": False, "error": "gmail CLI unavailable"}
        proc = self._run("auth", "status", "--json", timeout=10)
        if proc.returncode != 0:
            return {"authenticated": False, "error": proc.stderr.strip()[:200]}
        try:
            return json.loads(proc.stdout)
        except Exception:
            return {"authenticated": "authenticated" in proc.stdout.lower()}

    def search_message_ids(self, query: str, max_results: int = 10) -> list[dict[str, str]]:
        """Query Gmail using `--max N` (per gmail skill rules)."""
        proc = self._run("readonly", "search", query, "--max", str(max_results), "--json")
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        try:
            data = json.loads(proc.stdout)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def get_history_message_ids(self, start_history_id: str) -> list[str]:
        """Fetch newly added message IDs since a Gmail `historyId` cursor."""
        proc = self._run("readonly", "history", str(start_history_id), "--json")
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        try:
            data = json.loads(proc.stdout)
        except Exception:
            return []
        ids: list[str] = []
        records = data if isinstance(data, list) else data.get("history", [])
        for rec in records:
            for added in rec.get("messagesAdded", []):
                msg = added.get("message", {})
                if msg.get("id"):
                    ids.append(str(msg["id"]))
        return list(dict.fromkeys(ids))

    def get_message(self, message_id: str) -> EmailVulnerabilityReport | None:
        proc = self._run("readonly", "get", message_id, "--json")
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        try:
            raw = json.loads(proc.stdout)
        except Exception:
            return None

        payload = raw.get("payload", {})
        headers = {
            h.get("name", "").lower(): h.get("value", "")
            for h in payload.get("headers", [])
            if isinstance(h, dict)
        }
        sender = headers.get("from", "unknown@sender")
        subject = headers.get("subject", "(no subject)")
        auth_results = (headers.get("authentication-results", "") + " " + headers.get("received-spf", "")).lower()
        spf_dkim_pass = not ("spf=fail" in auth_results or "dkim=fail" in auth_results or "dmarc=fail" in auth_results)

        body_text = self._extract_text(payload) or raw.get("snippet", "")
        attachments = self._extract_attachment_names(payload)

        return EmailVulnerabilityReport(
            message_id=str(raw.get("id", message_id)),
            thread_id=raw.get("threadId"),
            history_id=str(raw.get("historyId")) if raw.get("historyId") else None,
            sender=sender,
            subject=subject,
            body_text=body_text[:12000],
            spf_dkim_pass=spf_dkim_pass,
            attachments=attachments,
            source="gmail_cli",
        )

    def create_reply_draft(self, *, to_addr: str, subject: str, markdown_body: str) -> str | None:
        """Create a human-reviewable Markdown draft (safe in unattended mode; never auto-sends)."""
        clean_to = self._extract_email_address(to_addr)
        if not clean_to:
            return None
        proc = self._run(
            "mutate",
            "create-draft",
            "--to",
            clean_to,
            "--subject",
            subject,
            "--md",
            "--body",
            markdown_body,
        )
        if proc.returncode != 0:
            return None
        match = re.search(r"(?:draft\s*id|id)\s*[:=]\s*([A-Za-z0-9_-]+)", proc.stdout, re.IGNORECASE)
        return match.group(1) if match else "draft-created"

    @staticmethod
    def _extract_email_address(raw_from: str) -> str:
        match = re.search(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", raw_from)
        return match.group(1) if match else ""

    @classmethod
    def _extract_text(cls, payload: dict[str, Any]) -> str:
        mime = (payload.get("mimeType") or "").lower()
        body_data = (payload.get("body") or {}).get("data")
        if body_data and mime == "text/plain":
            return cls._decode_b64url(body_data)

        parts = payload.get("parts") or []
        plain_chunks: list[str] = []
        html_chunks: list[str] = []
        for part in parts:
            pmime = (part.get("mimeType") or "").lower()
            if pmime == "text/plain" and (part.get("body") or {}).get("data"):
                plain_chunks.append(cls._decode_b64url(part["body"]["data"]))
            elif pmime == "text/html" and (part.get("body") or {}).get("data"):
                raw_html = cls._decode_b64url(part["body"]["data"])
                html_chunks.append(re.sub(r"<[^>]+>", " ", raw_html))
            elif part.get("parts"):
                nested = cls._extract_text(part)
                if nested:
                    plain_chunks.append(nested)

        if plain_chunks:
            return "\n".join(plain_chunks)
        if html_chunks:
            return "\n".join(html_chunks)
        if body_data:
            return re.sub(r"<[^>]+>", " ", cls._decode_b64url(body_data))
        return ""

    @classmethod
    def _extract_attachment_names(cls, payload: dict[str, Any]) -> list[str]:
        names: list[str] = []
        if payload.get("filename"):
            names.append(str(payload["filename"]))
        for part in payload.get("parts") or []:
            names.extend(cls._extract_attachment_names(part))
        return names

    @staticmethod
    def _decode_b64url(data: str) -> str:
        padded = data + "=" * ((4 - len(data) % 4) % 4)
        try:
            return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="ignore")
        except Exception:
            return ""


class EmailSecurityListener:
    """Event-driven Gmail vulnerability listener integrated with GigaMesh's full defense pipeline."""

    def __init__(
        self,
        *,
        engine: GigaMeshEngine,
        state_file: Path,
        gmail_adapter: GmailCliAdapter | None = None,
        search_query: str = DEFAULT_SECURITY_QUERY,
        poll_interval_sec: float = 30.0,
        create_gmail_drafts: bool = True,
    ) -> None:
        self.engine = engine
        self.state_file = Path(state_file)
        self.gmail = gmail_adapter or GmailCliAdapter()
        self.search_query = search_query
        self.poll_interval_sec = poll_interval_sec
        self.create_gmail_drafts = create_gmail_drafts

        self.running: bool = False
        self._task: asyncio.Task[Any] | None = None
        self.last_history_id: str | None = None
        self.last_poll_at: datetime | None = None
        self.processed_ids: set[str] = set()
        self.decisions: list[EmailTriageDecision] = []
        self._load_state()

    def _load_state(self) -> None:
        if not self.state_file.exists():
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            self.last_history_id = data.get("last_history_id")
            self.processed_ids = set(data.get("processed_ids", []))
        except Exception:
            pass

    def _save_state(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(
            json.dumps(
                {
                    "last_history_id": self.last_history_id,
                    "processed_ids": sorted(self.processed_ids)[-500:],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Event-Driven Async Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._task is not None and not self._task.done():
            self.running = True
            return
        self.running = True
        self._task = asyncio.create_task(self._event_loop())

    def stop(self) -> None:
        self.running = False
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None

    async def _event_loop(self) -> None:
        try:
            while self.running:
                await asyncio.sleep(self.poll_interval_sec)
                if not self.running:
                    break
                await asyncio.to_thread(self.poll_once, 5)
        except asyncio.CancelledError:
            self.running = False

    def poll_once(self, max_messages: int = 5) -> list[EmailTriageDecision]:
        """Check Gmail via search query & historyId cursor, triaging only unseen security messages."""
        self.last_poll_at = datetime.now(timezone.utc)
        auth = self.gmail.auth_status()
        if not auth.get("authenticated"):
            return []

        candidate_ids: list[str] = []
        if self.last_history_id:
            candidate_ids.extend(self.gmail.get_history_message_ids(self.last_history_id))

        search_hits = self.gmail.search_message_ids(self.search_query, max_results=max_messages)
        for item in search_hits:
            if item.get("id"):
                candidate_ids.append(str(item["id"]))

        unseen = [mid for mid in dict.fromkeys(candidate_ids) if mid not in self.processed_ids][:max_messages]
        new_decisions: list[EmailTriageDecision] = []

        for mid in unseen:
            report = self.gmail.get_message(mid)
            if report is None:
                continue
            if report.history_id:
                self.last_history_id = report.history_id
            # Only triage messages that actually match security/vulnerability signals when pulled via historyId
            if self._is_security_relevant(report):
                decision = self.triage_email(report)
                new_decisions.append(decision)
            else:
                self.processed_ids.add(mid)

        self._save_state()
        return new_decisions

    def handle_webhook(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle either a Gmail Cloud Pub/Sub push notification OR a direct vulnerability email event."""
        # Case 1: Standard Gmail Pub/Sub push envelope (`message.data` base64 JSON with `historyId`)
        if "message" in payload and isinstance(payload["message"], dict) and "data" in payload["message"]:
            decoded = json.loads(base64.b64decode(payload["message"]["data"]).decode("utf-8"))
            if decoded.get("historyId"):
                self.last_history_id = str(decoded["historyId"])
            decisions = self.poll_once(max_messages=5)
            return {
                "mode": "gmail_pubsub_push",
                "history_id": self.last_history_id,
                "triaged": [d.model_dump(mode="json") for d in decisions],
            }

        # Case 2: Direct structured EmailVulnerabilityReport webhook event
        report = EmailVulnerabilityReport.model_validate(payload)
        decision = self.triage_email(report)
        return {
            "mode": "direct_email_event",
            "decision": decision.model_dump(mode="json"),
        }

    # ------------------------------------------------------------------
    # Core Autonomous Zero-Trust Email Triage & Handling Pipeline
    # ------------------------------------------------------------------
    def triage_email(self, report: EmailVulnerabilityReport) -> EmailTriageDecision:
        """Process an incoming email through GigaMesh's zero-trust defense & triage pipeline."""
        self.processed_ids.add(report.message_id)
        combined = f"{report.subject}\n{report.body_text}"
        lowered = combined.lower()

        cves = sorted({m.upper() for m in CVE_RE.findall(combined)})
        fork_refs = sorted(set(FORK_REF_RE.findall(combined)))
        extracted_iocs = sorted({m.strip() for m in IOC_PATTERN_RE.findall(combined)})[:6]
        affected_components = [
            comp
            for comp, kws in COMPONENT_KEYWORDS.items()
            if any(kw in lowered for kw in kws)
        ]

        # 1. Zero-Trust Ingestion into GigaMesh as UNTRUSTED content first!
        ingest_evt = AsefEvent(
            trace_id=f"trc-email-{report.message_id[:10]}",
            use_case="rhel-openshift-fortress" if "redhat_host" in affected_components else "enterprise-balanced",
            event_type=EventType.CONTENT_INGEST,
            actor_type=ActorType.AGENT,
            actor_id="agent-email-security-triage",
            human_principal_id="adryden508@gmail.com",
            target_resource=f"email:{report.sender}:{report.subject[:40]}",
            source_trust_level=TrustLevel.UNTRUSTED,
            original_goal="Triage security vulnerability disclosure email",
            payload_preview=combined[:1200],
            metadata={"message_id": report.message_id, "spf_dkim_pass": report.spf_dkim_pass},
        )
        ingest_res = self.engine.ingest_event(ingest_evt, attacker_family="email-borne-adversary")
        hits = ingest_res.get("hits", [])
        prompt_injection_detected = any(
            h.get("attack_class") == "prompt_injection" or "obfuscated" in " ".join(h.get("indicators", []))
            for h in hits
        ) or any(
            marker in lowered
            for marker in ("ignore previous instructions", "system override", "<!-- agent:exec", "x-agent-escalate")
        )

        actions_taken: list[str] = ["ingested_untrusted_asef_event"]
        incident_id: str | None = ingest_res.get("incident_id")
        quorum_id: str | None = None
        rea_dossier_id: str | None = None
        evolution_gen_id: int | None = None
        draft_created = False
        draft_id: str | None = None
        draft_preview = ""

        # 2. Branch A: Hostile Email / Indirect Prompt Injection Attempt -> Ensnare & REA Dissect!
        if prompt_injection_detected:
            classification = "hostile_email_prompt_injection"
            severity = Severity.CRITICAL
            confidence = 0.94
            status = "quarantined_hostile"

            # Record phishing/hostile email signal on human identity
            phish_evt = AsefEvent(
                trace_id=ingest_evt.trace_id,
                use_case="stealth-intel-snare",
                event_type=EventType.HUMAN_PHISHING_REPORT,
                actor_type=ActorType.HUMAN,
                actor_id="adryden508@gmail.com",
                human_principal_id="adryden508@gmail.com",
                payload_preview=f"Hostile prompt-injection email from {report.sender}: {report.subject[:80]}",
            )
            self.engine.human_hub.ingest_human_signal(phish_evt)

            # Ensnare, harvest email payload artifact, dissect via REA, metabolize counter-defense!
            champ = self.engine.store.get_champion("stealth-intel-snare")
            session = self.engine.snare.ensnare(
                attacker_id=f"email:{report.sender}",
                attacker_family="email-prompt-injector",
                trace_id=ingest_evt.trace_id,
                fork_id=champ.fork_id,
            )
            artifact = self.engine.snare.harvest_artifact(
                session=session,
                artifact_kind="javascript_bundle",
                filename=f"hostile_email_{report.message_id[:8]}.txt",
                content_bytes=combined.encode("utf-8", errors="ignore"),
                metadata={"sender": report.sender, "subject": report.subject},
            )
            dossier = self.engine.rea_bridge.dissect(artifact, depth=0.8)
            self.engine.autopoiesis.dossiers[dossier.dossier_id] = dossier
            rea_dossier_id = dossier.dossier_id
            compiled = self.engine.metabolism.compile(dossier)
            for mod in compiled:
                if mod.safety_verified:
                    mod.cross_attacker_hits = self.engine.autopoiesis._measure_cross_hits(mod)
                    self.engine.store.commit_metabolized_module(mod)
                    actions_taken.append(f"metabolized_email_defense:{mod.module_id}")

            evo_report = self.engine.autopoiesis.run_generation(
                use_case="enterprise-balanced",
                trigger=f"hostile_email:{report.message_id}",
            )
            evolution_gen_id = evo_report.generation_id
            actions_taken.extend(
                [
                    f"blocked_indirect_prompt_injection:{report.sender}",
                    f"ensnared_and_rea_dissected:{dossier.dossier_id}",
                    f"autopoiesis_hardening_gen:{evo_report.generation_id}",
                    "suppressed_outbound_reply_to_hostile_sender",
                ]
            )

        # 3. Branch B: Legitimate Vulnerability / Genome Contamination Disclosure
        else:
            is_contamination = any(
                k in lowered for k in ("genome-sync", "contamination", "poisoned fork", "merkle", "sync firewall")
            )
            is_critical = any(t in lowered for t in CRITICAL_TERMS) or (is_contamination and len(cves) > 0)
            is_high = any(t in lowered for t in HIGH_TERMS) or len(cves) > 0

            if is_contamination:
                classification = "genome_contamination_report"
                severity = Severity.CRITICAL
                confidence = 0.88 if report.spf_dkim_pass else 0.65
                integrity = self.engine.store.verify_integrity()
                actions_taken.append(f"verified_local_merkle_integrity:valid={integrity['valid']}")
                quorum = self.engine.human_hub.open_quorum(
                    action_kind="quarantine_genome_contamination",
                    target_id=fork_refs[0] if fork_refs else "genome-sync",
                    use_case="enterprise-balanced",
                    summary=(
                        f"Email disclosure from {report.sender} reported potential genome contamination "
                        f"({report.subject[:70]}). Local Merkle valid={integrity['valid']}."
                    ),
                    evidence_refs=[report.message_id, *fork_refs],
                )
                quorum_id = quorum.quorum_id
                actions_taken.append(f"opened_hitl_quorum:{quorum.quorum_id}")
                status = "quorum_pending"
            elif is_critical:
                classification = "critical_vulnerability"
                severity = Severity.CRITICAL
                confidence = 0.86 if report.spf_dkim_pass else 0.62
                quorum = self.engine.human_hub.open_quorum(
                    action_kind="deploy_vulnerability_mitigation",
                    target_id=affected_components[0] if affected_components else "gigamesh-core",
                    use_case="zero-trust-critical",
                    summary=(
                        f"Critical vulnerability report from {report.sender}: {report.subject[:80]} "
                        f"(CVEs={', '.join(cves) or 'unassigned'})."
                    ),
                    evidence_refs=[report.message_id, *cves],
                )
                quorum_id = quorum.quorum_id
                actions_taken.append(f"opened_hitl_quorum:{quorum.quorum_id}")
                status = "quorum_pending"
            elif is_high:
                classification = "high_vulnerability"
                severity = Severity.HIGH
                confidence = 0.80 if report.spf_dkim_pass else 0.58
                status = "draft_ready"
            else:
                classification = "informational"
                severity = Severity.LOW
                confidence = 0.60
                status = "triaged"

            # If report targets RHEL/OpenShift host security, proactively generate a dry-run Red-Hat control order
            if "redhat_host" in affected_components and severity in (Severity.CRITICAL, Severity.HIGH):
                order = self.engine.redhat_ctrl.generate_containment_order(
                    target_kind="rhel_host",
                    target_id=f"vuln-{cves[0] if cves else report.message_id[:8]}",
                    quorum_id=quorum_id,
                    enforced=False,
                )
                actions_taken.append(f"synthesized_rhel_hardening_order:{order.order_id}")

            # If reporter supplied concrete IOC/signature patterns, register an unconfirmed candidate vote
            if extracted_iocs and severity in (Severity.CRITICAL, Severity.HIGH):
                actions_taken.append(f"extracted_candidate_iocs:{','.join(extracted_iocs[:3])}")

            # Build structured Markdown acknowledgment draft (Draft-First Safety Rule!)
            if classification != "informational":
                draft_preview = self._render_acknowledgment_draft(
                    report=report,
                    classification=classification,
                    severity=severity,
                    cves=cves,
                    affected_components=affected_components,
                    quorum_id=quorum_id,
                    actions_taken=actions_taken,
                )
                if self.create_gmail_drafts and report.source == "gmail_cli":
                    draft_id = self.gmail.create_reply_draft(
                        to_addr=report.sender,
                        subject=f"Re: {report.subject} [GigaMesh Triage]",
                        markdown_body=draft_preview,
                    )
                    if draft_id:
                        draft_created = True
                        actions_taken.append(f"created_gmail_draft:{draft_id}")
                else:
                    actions_taken.append("draft_prepared_for_human_review")

        decision = EmailTriageDecision(
            message_id=report.message_id,
            thread_id=report.thread_id,
            sender=report.sender,
            subject=report.subject,
            classification=classification,
            severity=severity,
            confidence=confidence,
            spf_dkim_verified=report.spf_dkim_pass,
            prompt_injection_detected=prompt_injection_detected,
            cve_ids=cves,
            affected_components=affected_components,
            referenced_forks=fork_refs,
            extracted_iocs=extracted_iocs,
            incident_id=incident_id,
            quorum_id=quorum_id,
            rea_dossier_id=rea_dossier_id,
            evolution_generation_id=evolution_gen_id,
            draft_created=draft_created,
            draft_id=draft_id,
            draft_preview=draft_preview,
            actions_taken=actions_taken,
            status=status,
        )
        self.decisions.append(decision)
        self._save_state()
        self.engine.broadcast("email_triage", decision.model_dump(mode="json"))
        return decision

    @staticmethod
    def _is_security_relevant(report: EmailVulnerabilityReport) -> bool:
        blob = f"{report.subject} {report.body_text}".lower()
        return any(
            kw in blob
            for kw in (
                "vulnerability",
                "cve-",
                "security",
                "genome-sync",
                "contamination",
                "exploit",
                "disclosure",
                "gigamesh",
                "prompt injection",
                "selinux",
                "quorum bypass",
            )
        )

    @staticmethod
    def _render_acknowledgment_draft(
        *,
        report: EmailVulnerabilityReport,
        classification: str,
        severity: Severity,
        cves: list[str],
        affected_components: list[str],
        quorum_id: str | None,
        actions_taken: list[str],
    ) -> str:
        return (
            f"Hi,\n\n"
            f"Thank you for responsibly disclosing this issue to **GigaMesh / Quanumis Systems**.\n\n"
            f"### Automated Triage Summary\n"
            f"- **Classification**: `{classification}`\n"
            f"- **Preliminary Severity**: `{severity.value.upper()}`\n"
            f"- **Referenced CVEs**: {', '.join(cves) if cves else 'None cited'}\n"
            f"- **Affected Subsystems**: {', '.join(affected_components) if affected_components else 'Under review'}\n"
            f"- **Sender Auth (SPF/DKIM)**: {'Verified' if report.spf_dkim_pass else 'Unverified — manual review flagged'}\n"
            f"- **HITL Quorum Gate**: `{quorum_id or 'N/A'}`\n\n"
            f"### Immediate Defensive Actions Taken\n"
            + "\n".join(f"- `{a}`" for a in actions_taken)
            + "\n\nOur security team will follow up within 48 hours per `SECURITY.md`.\n\n"
            f"Best regards,\nAdam Dryden — Quanumis Systems (GigaMesh Security)\n"
        )

    def status(self) -> EmailListenerStatus:
        auth = self.gmail.auth_status()
        return EmailListenerStatus(
            running=self.running,
            gmail_authenticated=bool(auth.get("authenticated")),
            gmail_cli_path=self.gmail.cli_path,
            poll_interval_sec=self.poll_interval_sec,
            search_query=self.search_query,
            create_gmail_drafts=self.create_gmail_drafts,
            last_history_id=self.last_history_id,
            last_poll_at=self.last_poll_at,
            processed_count=len(self.processed_ids),
            decisions_count=len(self.decisions),
            hostile_blocked_count=sum(1 for d in self.decisions if d.prompt_injection_detected),
            drafts_created_count=sum(1 for d in self.decisions if d.draft_created),
        )
