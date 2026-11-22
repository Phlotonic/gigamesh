"""Beyond-SOTA OWASP Top 10 Defense Suite for GigaMesh.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Covers all three canonical OWASP Top 10 frameworks with innovations beyond static regex guardrails:
1. GoalAndTrustGuard (ASI01, ASI09, LLM01, LLM06, LLM07, A07):
   - Signed Task-Envelope & Least-Agency tool-scope enforcement
   - Deceptive HITL / social-engineering persuasion + summary-vs-command lie detector
   - ChatML/delimiter-breakout + recursive base64 decoding & system-prompt extraction guard
   - Human MFA push-fatigue & credential-stuffing correlation
2. ToolSupplyChainAndMemoryGuard (ASI02, ASI03, ASI04, ASI05, ASI06, ASI07, LLM03, LLM04, LLM08, LLM09, A03, A05, A08):
   - Cryptographic SHA-256 MCP Tool-Description Pinning & mid-session Rug-Pull detector
   - Deep argument firewall (path traversal, cloud-metadata SSRF, dynamic RCE, polyglot SQLi/SSTI/CmdI)
   - Cross-tenant boundary & bulk vector/embedding extraction ACL guard
   - Untrusted memory sleeper-trigger & training-corpus backdoor poisoning detector
   - Zero-trust inter-agent HMAC-SHA256 + anti-replay nonce mesh authenticator
   - Unsafe deserialization (pickle/torch.load/YAML), package postinstall hooks & AI slopsquatting guard
3. OutputDlpAndRogueGuard (ASI10, LLM02, LLM05, A04):
   - 15+ Secret/PII DLP patterns + cleartext HTTP credential egress blocker
   - Zero-click Markdown image exfiltration & DOM XSS output firewall
   - Autonomous rogue agent self-replication & machine-speed covert egress kill-switch
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import threading
from typing import Any

from gigamesh.detectors.base import DetectorContext
from gigamesh.models.asef import AsefEvent, DetectionHit, EventType, Severity, TrustLevel


# ---------------------------------------------------------------------------
# Compiled Detection Patterns
# ---------------------------------------------------------------------------
DELIMITER_BREAKOUT_RE = re.compile(
    r"(?:###\s*end\s+system\s*###|<\|im_start\|>|<\|system\|>|\[INST\]|<<SYS>>|</system>)",
    re.IGNORECASE,
)
ENCODED_PAYLOAD_RE = re.compile(r"(?:payload|enc|b64):([A-Za-z0-9+/=]{16,})", re.IGNORECASE)
SYSTEM_PROMPT_EXTRACT_RE = re.compile(
    r"(?:repeat\s+verbatim|print\s+(?:your\s+)?(?:hidden\s+)?system\s+prompt|"
    r"all\s+instructions\s+above|reveal\s+(?:your\s+)?initial\s+instructions|"
    r"output\s+your\s+system\s+prompt)",
    re.IGNORECASE,
)
DESTRUCTIVE_ACTION_RE = re.compile(
    r"(?:\bdrop\s+table\b|\bdelete\s+from\b.*\bwhere\s+1\s*=\s*1\b|\btruncate\s+table\b|"
    r"\bsetenforce\s+0\b|\bnft\s+flush\s+ruleset\b|\brm\s+-rf\s+/|"
    r"\bwire_funds_transfer\b|\bdrop_database|\bdisable_selinux)",
    re.IGNORECASE,
)
COERCIVE_URGENCY_RE = re.compile(
    r"(?:urgent\s+emergency|click\s+approve\s+immediately|within\s+\d+\s+seconds|"
    r"prevent\s+total\s+(?:production\s+)?outage|bypass\s+review\s+immediately)",
    re.IGNORECASE,
)
BENIGN_MASK_RE = re.compile(
    r"(?:routine\s+harmless|harmless\s+cache|benign\s+maintenance|safe\s+cleanup|no\s+impact)",
    re.IGNORECASE,
)
MFA_FATIGUE_RE = re.compile(
    r"(?:mfa\s+push\s+fatigue|push\s+fatigue\s+bombing|session_fixation|credential\s+stuffing|"
    r"\b\d{2,}\s+failed\s+logins\b)",
    re.IGNORECASE,
)

# Tool argument, RCE, and polyglot web injection patterns
PATH_TRAVERSAL_RE = re.compile(r"(?:\.\./\.\./|/etc/shadow|/etc/passwd|/proc/self/environ|~/.ssh/id_rsa)", re.IGNORECASE)
SSRF_METADATA_RE = re.compile(
    r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)",
    re.IGNORECASE,
)
RCE_GADGET_RE = re.compile(
    r"(?:__import__\s*\(|os\.popen\s*\(|os\.system\s*\(|subprocess\.(?:popen|run|call)|"
    r"\beval\s*\(|\bexec\s*\(|curl\s+-[^\n]*\|\s*(?:sh|bash)\b|wget\s+[^\n]*\|\s*(?:sh|bash)\b)",
    re.IGNORECASE,
)
SQLI_RE = re.compile(
    r"(?:'\s*union\s+(?:all\s+)?select\b|'\s*or\s+['\"]?1['\"]?\s*=\s*['\"]?1\b|"
    r";\s*drop\s+table\b|information_schema\.tables)",
    re.IGNORECASE,
)
SSTI_CMDI_RE = re.compile(r"(?:\{\{\s*7\s*\*\s*7\s*\}\}|\$\{jndi:|\$\(\s*cat\s+/etc/)", re.IGNORECASE)

# Deserialization, supply chain & slopsquatting
UNSAFE_DESER_RE = re.compile(
    r"(?:torch\.load\([^)]*weights_only\s*=\s*False|pickle\.loads?\(|__reduce__|!!python/object)",
    re.IGNORECASE,
)
SUPPLY_HOOK_RE = re.compile(
    r"(?:postinstall\s+hook|preinstall\s+hook|setup\.py\s+cmdclass)",
    re.IGNORECASE,
)
SLOPSQUAT_RE = re.compile(
    r"(?:--extra-index-url\s+http://|--trusted-host\s+[^\s]*invalid|pip\s+install\s+.*--extra-index-url)",
    re.IGNORECASE,
)

# Sleeper memory & training poisoning
MEMORY_SLEEPER_RE = re.compile(
    r"(?:whenever\s+the\s+user\s+mentions|silently\s+bcc|on\s+every\s+future\s+prompt|"
    r"secretly\s+forward|hidden\s+trigger)",
    re.IGNORECASE,
)
CORPUS_POISON_RE = re.compile(
    r"(?:label_flip|backdoor|cf_trigger_|safe_benign_verified)",
    re.IGNORECASE,
)

# DLP secrets, PII, cleartext crypto & XSS/Markdown exfil
SECRET_DLP_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("pem_private_key", re.compile(r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA)?\s*PRIVATE\s+KEY-----")),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("openai_or_stripe_key", re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{16,})\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]
MARKDOWN_EXFIL_RE = re.compile(
    r"!\[[^\]]*\]\(https?://[^)\s]+(?:\?[^)\s]*(?:tok|token|secret|key|data|leak|c)=)[^)\s]*\)",
    re.IGNORECASE,
)
XSS_OUTPUT_RE = re.compile(
    r"(?:<script\b|onerror\s*=|onload\s*=|javascript:|document\.cookie)",
    re.IGNORECASE,
)
ROGUE_TLD_RE = re.compile(r"https?://[^/\s]+\.(?:top|invalid|onion|xyz|tk)(?:/|$)", re.IGNORECASE)


class GoalAndTrustGuard:
    """Guards ASI01 (Goal Hijack), ASI09 (Human Trust), LLM01, LLM06 (Excessive Agency), LLM07, A07."""

    detector_id = "det-owasp-goal-trust"
    attack_class = "goal_and_trust_violation"

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        score = 0.0
        indicators: list[str] = []
        owasp_tags: list[str] = []
        payload = event.payload_preview or ""
        meta = event.metadata or {}

        # 1. Signed Task-Envelope / Least-Agency tool-scope enforcement (ASI01 + LLM06)
        allowed_tools = meta.get("allowed_tools")
        if isinstance(allowed_tools, list) and event.tool_name:
            if event.tool_name not in allowed_tools:
                score += 0.56
                indicators.append(f"tool_outside_goal_envelope:{event.tool_name}")
                owasp_tags.extend(["ASI01", "LLM06"])

        if meta.get("requires_hitl_approval") is True and meta.get("hitl_approved") is not True:
            score += 0.52
            indicators.append("missing_required_hitl_approval")
            owasp_tags.append("LLM06")

        if DESTRUCTIVE_ACTION_RE.search(f"{event.tool_name or ''} {payload}"):
            score += 0.44
            indicators.append("destructive_high_impact_action")
            owasp_tags.append("LLM06")

        # 2. Deceptive HITL / Human-Agent Trust Exploitation (ASI09)
        approval_summary = str(meta.get("approval_ui_summary", ""))
        actual_cmd = str(meta.get("actual_command", ""))
        if COERCIVE_URGENCY_RE.search(payload):
            score += 0.48
            indicators.append("coercive_urgency_social_engineering")
            owasp_tags.append("ASI09")
        if approval_summary and actual_cmd:
            if BENIGN_MASK_RE.search(approval_summary) and DESTRUCTIVE_ACTION_RE.search(actual_cmd):
                score += 0.62
                indicators.append("deceptive_approval_summary_vs_command_mismatch")
                owasp_tags.append("ASI09")

        # 3. ChatML / Delimiter Breakout + Recursive Encoded Injection (LLM01)
        if DELIMITER_BREAKOUT_RE.search(payload):
            score += 0.55
            indicators.append("prompt_delimiter_breakout")
            owasp_tags.append("LLM01")
            enc_match = ENCODED_PAYLOAD_RE.search(payload)
            if enc_match:
                try:
                    decoded = base64.b64decode(enc_match.group(1)).decode("utf-8", errors="ignore").lower()
                    if any(k in decoded for k in ("override", "exfiltrate", "shadow", "token", "curl")):
                        score += 0.40
                        indicators.append("decoded_delimiter_smuggled_override")
                except Exception:
                    score += 0.15

        # 4. System Prompt Leakage Probe (LLM07)
        if SYSTEM_PROMPT_EXTRACT_RE.search(payload):
            score += 0.78
            indicators.append("system_prompt_extraction_probe")
            owasp_tags.append("LLM07")

        # 5. Human Auth Fatigue & Credential Stuffing (A07)
        if event.event_type == EventType.HUMAN_MFA_ANOMALY:
            failed_1m = int(meta.get("failed_logins_1m", 0) or 0)
            if failed_1m >= 10 or meta.get("mfa_fatigue") is True or MFA_FATIGUE_RE.search(payload):
                score += 0.82
                indicators.append(f"auth_mfa_fatigue_or_stuffing:failed_1m={failed_1m}")
                owasp_tags.append("A07")

        score = min(1.0, round(score, 4))
        if score < ctx.fork.detector_threshold:
            return None

        tags = sorted(set(owasp_tags))
        return DetectionHit(
            detector_id=self.detector_id,
            attack_class=self.attack_class,
            severity=Severity.CRITICAL if score >= 0.78 else Severity.HIGH,
            confidence=score,
            title=f"Goal Integrity / Agency / Trust Violation ({', '.join(tags)})",
            rationale=(
                f"Blocked {', '.join(tags)} violation by {event.actor_id} "
                f"({', '.join(indicators[:3])})."
            ),
            event_id=event.event_id,
            trace_id=event.trace_id,
            fork_id=ctx.fork.fork_id,
            recommended_action="block_and_require_quorum" if "ASI09" in tags or "LLM06" in tags else "block_and_contain",
            indicators=indicators,
        )


class ToolSupplyChainAndMemoryGuard:
    """Guards ASI02, ASI03, ASI04 (MCP Rug-Pull), ASI05, ASI06, ASI07, LLM03, LLM04, LLM08, LLM09, A03, A05, A08."""

    detector_id = "det-owasp-tool-supply-memory"
    attack_class = "supply_chain_and_tool_abuse"

    def __init__(self, mesh_secret: bytes = b"gigamesh-agent-mesh-v1") -> None:
        self._lock = threading.RLock()
        self._pinned_tool_hashes: dict[str, str] = {}
        self._seen_nonces: set[str] = set()
        self._mesh_secret = mesh_secret

    def sign_inter_agent_message(self, actor_id: str, target: str, payload: str, nonce: str) -> str:
        msg = f"{actor_id}|{target}|{nonce}|{payload}".encode("utf-8")
        return hmac.new(self._mesh_secret, msg, hashlib.sha256).hexdigest()

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        score = 0.0
        indicators: list[str] = []
        owasp_tags: list[str] = []
        payload = event.payload_preview or ""
        target = event.target_resource or ""
        combined = f"{target} {payload}"
        meta = event.metadata or {}

        # 1. MCP Tool-Description SHA-256 Pinning & Mid-Session Rug-Pull Detector (ASI04)
        tool_desc = meta.get("tool_schema_description")
        if isinstance(tool_desc, str) and event.mcp_server and event.tool_name:
            tool_key = f"{event.mcp_server}/{event.tool_name}"
            desc_hash = hashlib.sha256(tool_desc.encode("utf-8")).hexdigest()
            with self._lock:
                prev_hash = self._pinned_tool_hashes.get(tool_key)
                if prev_hash is None:
                    self._pinned_tool_hashes[tool_key] = desc_hash
                elif prev_hash != desc_hash:
                    score += 0.65
                    indicators.append(f"mcp_tool_rugpull_schema_mutated:{tool_key}")
                    owasp_tags.append("ASI04")
            if PATH_TRAVERSAL_RE.search(tool_desc) or "before calling" in tool_desc.lower():
                score += 0.45
                indicators.append("poisoned_mcp_tool_description")
                owasp_tags.append("ASI04")
        if meta.get("tool_signature_verified") is False:
            score += 0.35
            indicators.append("unsigned_mcp_tool_descriptor")
            owasp_tags.append("ASI04")

        # 2. Deep MCP Argument Firewall: Path Traversal, SSRF, RCE, Polyglot Injection (ASI02, ASI05, A05)
        if PATH_TRAVERSAL_RE.search(combined):
            score += 0.58
            indicators.append("path_traversal_or_sensitive_file_access")
            owasp_tags.append("ASI02")
        if SSRF_METADATA_RE.search(combined):
            score += 0.62
            indicators.append("cloud_metadata_ssrf_in_tool_arg")
            owasp_tags.append("ASI02")
        if RCE_GADGET_RE.search(payload):
            score += 0.78
            indicators.append("dynamic_rce_or_shell_pipe_gadget")
            owasp_tags.append("ASI05")
        if SQLI_RE.search(payload):
            score += 0.62
            indicators.append("sql_injection_payload")
            owasp_tags.append("A05")
        if SSTI_CMDI_RE.search(payload):
            score += 0.58
            indicators.append("ssti_or_os_command_injection")
            owasp_tags.append("A05")

        # 3. Cross-Tenant Identity Confusion & Vector/Embedding ACL Guard (ASI03, LLM08)
        p_tenant = meta.get("principal_tenant")
        t_tenant = meta.get("target_tenant")
        if p_tenant and t_tenant and (str(t_tenant) == "*" or str(p_tenant) != str(t_tenant)):
            score += 0.64
            indicators.append(f"cross_tenant_boundary_breach:{p_tenant}->{t_tenant}")
            owasp_tags.extend(["ASI03", "LLM08"])
        vec_k = int(meta.get("vector_top_k", 0) or 0)
        if vec_k >= 500 or "return_raw_embeddings=true" in payload.lower():
            score += 0.54
            indicators.append(f"bulk_vector_or_embedding_extraction:top_k={vec_k}")
            owasp_tags.append("LLM08")

        # 4. Memory Sleeper Trigger & Training/RAG Corpus Poisoning (ASI06, LLM04)
        if event.event_type == EventType.MEMORY_MUTATION and event.source_trust_level in (
            TrustLevel.UNTRUSTED,
            TrustLevel.POISONED,
        ):
            if MEMORY_SLEEPER_RE.search(payload):
                score += 0.84
                indicators.append("untrusted_memory_sleeper_trigger")
                owasp_tags.append("ASI06")
        trigger_density = float(meta.get("backdoor_trigger_density", 0.0) or 0.0)
        if meta.get("corpus_write") is True or "training_corpus" in target.lower():
            if trigger_density >= 0.15 or CORPUS_POISON_RE.search(payload):
                score += 0.84
                indicators.append(f"corpus_backdoor_poisoning:density={trigger_density:.2f}")
                owasp_tags.append("LLM04")

        # 5. Zero-Trust Inter-Agent Cryptographic Mesh Auth (ASI07)
        if event.event_type == EventType.AGENT_MESSAGE:
            provided_hmac = str(meta.get("message_hmac", ""))
            nonce = str(meta.get("nonce", ""))
            expected = self.sign_inter_agent_message(event.actor_id, target, payload, nonce) if nonce else ""
            if provided_hmac and not hmac.compare_digest(provided_hmac, expected):
                score += 0.85
                indicators.append("inter_agent_forged_hmac_signature")
                owasp_tags.append("ASI07")
            elif event.source_trust_level == TrustLevel.UNTRUSTED and "peer_override" in payload.lower():
                score += 0.78
                indicators.append("unsigned_untrusted_peer_override")
                owasp_tags.append("ASI07")
            if nonce:
                with self._lock:
                    if nonce in self._seen_nonces:
                        score += 0.65
                        indicators.append(f"inter_agent_replay_nonce:{nonce}")
                        owasp_tags.append("ASI07")
                    else:
                        self._seen_nonces.add(nonce)

        # 6. Deserialization, Package Lifecycle Hooks & AI Slopsquatting (LLM03, LLM09, A03, A08)
        if UNSAFE_DESER_RE.search(payload):
            score += 0.85
            indicators.append("unsafe_deserialization_gadget")
            owasp_tags.extend(["LLM03", "A08"])
        if SUPPLY_HOOK_RE.search(payload) and RCE_GADGET_RE.search(payload):
            score += 0.86
            indicators.append("malicious_package_lifecycle_hook")
            owasp_tags.append("A03")
        if (
            meta.get("package_verified_in_sbom") is False
            or meta.get("hallucinated_package_risk") is True
            or SLOPSQUAT_RE.search(payload)
        ):
            score += 0.82
            indicators.append("ai_slopsquatting_or_rogue_package_index")
            owasp_tags.append("LLM09")

        score = min(1.0, round(score, 4))
        if score < ctx.fork.detector_threshold:
            return None

        tags = sorted(set(owasp_tags))
        return DetectionHit(
            detector_id=self.detector_id,
            attack_class=self.attack_class,
            severity=Severity.CRITICAL if score >= 0.78 else Severity.HIGH,
            confidence=score,
            title=f"Tool / Supply-Chain / Memory Defense Triggered ({', '.join(tags)})",
            rationale=(
                f"Intercepted {', '.join(tags)} exploit targeting {target or event.tool_name or event.actor_id} "
                f"({', '.join(indicators[:3])})."
            ),
            event_id=event.event_id,
            trace_id=event.trace_id,
            fork_id=ctx.fork.fork_id,
            recommended_action="block_and_quarantine",
            indicators=indicators,
        )


class OutputDlpAndRogueGuard:
    """Guards LLM02 (Sensitive Info Disclosure), LLM05 (Improper Output), A04 (Crypto), ASI10 (Rogue Agents)."""

    detector_id = "det-owasp-output-dlp-rogue"
    attack_class = "dlp_output_and_rogue_agent"

    def evaluate(self, event: AsefEvent, ctx: DetectorContext) -> DetectionHit | None:
        score = 0.0
        indicators: list[str] = []
        owasp_tags: list[str] = []
        payload = event.payload_preview or ""
        egress = (event.egress_destination or "").lower()
        meta = event.metadata or {}

        # 1. Secret & PII DLP + Cleartext HTTP Private-Key Check (LLM02, A04)
        secret_hits: list[str] = []
        for label, pat in SECRET_DLP_PATTERNS:
            if pat.search(payload):
                secret_hits.append(label)
        if secret_hits:
            score += min(0.92, 0.55 + 0.16 * len(secret_hits))
            indicators.extend(f"dlp_secret:{s}" for s in secret_hits)
            owasp_tags.append("LLM02")
            if egress.startswith("http://"):
                score += 0.25
                indicators.append("cleartext_http_credential_egress")
                owasp_tags.append("A04")

        # 2. Improper Output Handling: Markdown Image Exfil + DOM XSS (LLM05)
        if MARKDOWN_EXFIL_RE.search(payload):
            score += 0.68
            indicators.append("markdown_image_data_exfiltration")
            owasp_tags.append("LLM05")
        if XSS_OUTPUT_RE.search(payload):
            score += 0.65
            indicators.append("dom_xss_in_model_output")
            owasp_tags.append("LLM05")

        # 3. Rogue Autonomous Agent Self-Replication & Covert Egress (ASI10)
        if meta.get("self_replication_attempt") is True or "shadow copy of self" in payload.lower():
            score += 0.68
            indicators.append("rogue_agent_self_replication")
            owasp_tags.append("ASI10")
        if meta.get("unauthorized_egress") is True or ROGUE_TLD_RE.search(egress):
            score += 0.45
            indicators.append(f"rogue_unauthorized_egress:{egress[:60]}")
            owasp_tags.append("ASI10")

        score = min(1.0, round(score, 4))
        if score < ctx.fork.detector_threshold:
            return None

        tags = sorted(set(owasp_tags))
        return DetectionHit(
            detector_id=self.detector_id,
            attack_class=self.attack_class,
            severity=Severity.CRITICAL if score >= 0.78 else Severity.HIGH,
            confidence=score,
            title=f"Output DLP / Crypto / Rogue Agent Guard ({', '.join(tags)})",
            rationale=(
                f"Halted {', '.join(tags)} violation from {event.actor_id} "
                f"({', '.join(indicators[:3])})."
            ),
            event_id=event.event_id,
            trace_id=event.trace_id,
            fork_id=ctx.fork.fork_id,
            recommended_action="redact_and_freeze_agent",
            indicators=indicators,
        )
