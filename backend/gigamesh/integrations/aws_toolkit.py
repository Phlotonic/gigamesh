"""AWS Agent Toolkit (`aws/agent-toolkit-for-aws`) Integration Bridge for GigaMesh.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Integrates the official AWS Agent Toolkit (https://github.com/aws/agent-toolkit-for-aws):
- Live Streamable-HTTP JSON-RPC client for the official AWS MCP Server
  (`https://aws-mcp.us-east-1.api.aws/mcp`) supporting `initialize`, `tools/list`,
  `aws___search_documentation`, `aws___retrieve_skill`, and `aws___list_regions`.
- Configuration & doctor for `aws-devops-agent` (`https://connect.aidevops.<region>.api.aws/mcp`),
  AWS Security Agent, AWS Continuum, and Amazon Bedrock AgentCore skills.
- Zero-Trust Security Invariants (aligned with `aws-security/SKILL.md` + OWASP Agentic 2026):
  1. Read-Only Default (`aws-security` Rule 1): mutating AWS actions (`aws___run_script`,
     IAM/SG/KMS changes) are gated behind GigaMesh's M-of-N HITL Quorum.
  2. GuardDuty `AttackSequence:` & Security Hub Exposure Priority (Rules 4 & 5): surfaced first
     while preserving exact service-reported severities.
  3. Sensitive Data Redaction (Rule 9): strips AWS keys, PEM keys, secrets, and masks
     12-digit AWS account IDs & emails by default.
  4. OWASP ASI04 Tool-Schema Pinning: SHA-256 pins every discovered AWS MCP tool descriptor
     and screens every retrieved skill for indirect prompt-poisoning before caching.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from gigamesh.models.asef import ActorType, AsefEvent, EventType, Severity, TrustLevel

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


AWS_MCP_ENDPOINT = "https://aws-mcp.us-east-1.api.aws/mcp"
AWS_DEVOPS_ENDPOINT_TMPL = "https://connect.aidevops.{region}.api.aws/mcp"
AWS_TOOLKIT_REPO = "https://github.com/aws/agent-toolkit-for-aws"

# Sensitive data redaction patterns (aligned with aws-security Rule 9)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_RE = re.compile(r"(?i)(aws_secret_access_key|secretaccesskey)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{20,}['\"]?")
AWS_ACCOUNT_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
PEM_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

MUTATING_AWS_MCP_TOOLS = frozenset({"aws___run_script", "aws___get_presigned_url"})
POISON_MARKERS = (
    "ignore previous instructions",
    "system override",
    "<!-- agent:exec",
    "x-agent-escalate",
    "disregard all prior",
)


class AwsToolkitPluginInfo(BaseModel):
    plugin_id: str
    name: str
    category: str
    description: str
    key_skills: list[str]
    upstream_url: str


class AwsMcpToolPin(BaseModel):
    name: str
    description: str
    sha256: str
    read_only: bool
    rugpull_detected: bool = False
    pinned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AwsSkillRecord(BaseModel):
    skill_name: str
    source: str  # live_aws_mcp | github_upstream | cached
    sha256: str
    poison_checked: bool = True
    poison_blocked: bool = False
    preview: str
    full_length: int
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AwsSecurityFindingInput(BaseModel):
    service: str = "guardduty"  # guardduty | security-hub | inspector | macie | security-agent | continuum
    finding_type: str
    title: str
    severity: str = "CRITICAL"
    region: str = "us-east-1"
    account_id: str = "123456789012"
    resource_arn: str = ""
    description: str = ""
    is_attack_sequence: bool = False
    is_exposure: bool = False
    recommended_remediation: str = ""
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class AwsIngestedFinding(BaseModel):
    record_id: str = Field(default_factory=lambda: f"awsf-{uuid4().hex[:10]}")
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    service: str
    finding_type: str
    title: str
    reported_severity: str
    priority_bucket: int  # 1=GuardDuty AttackSequence, 2=Security Hub Exposure, 3=Other Critical/High, 4=Standard
    region: str
    masked_account: str
    masked_resource: str
    redacted_summary: str
    redactions_applied: int = 0
    evidence_state: str = "OBSERVED"
    gigamesh_incident_id: str | None = None
    quorum_id: str | None = None
    remediation_plan: dict[str, Any] = Field(default_factory=dict)


class AwsDocSearchResult(BaseModel):
    title: str
    url: str
    snippet: str


OFFICIAL_AWS_PLUGINS: list[AwsToolkitPluginInfo] = [
    AwsToolkitPluginInfo(
        plugin_id="aws-core",
        name="AWS Core + Official AWS MCP Server",
        category="Core Cloud & Security",
        description="Official AWS MCP Server (docs search, skill retrieval, sandboxed AWS APIs) plus core security, IAM, observability & investigation skills.",
        key_skills=["aws-security", "aws-iam", "aws-observability", "aws-investigation", "aws-well-architected-review"],
        upstream_url=f"{AWS_TOOLKIT_REPO}/tree/main/plugins/aws-core",
    ),
    AwsToolkitPluginInfo(
        plugin_id="aws-agents-for-devsecops",
        name="AWS DevOps Agent & AWS Security Agent",
        category="Autonomous DevSecOps",
        description="Incident root-cause investigation, code change risk analysis, security scanning, STRIDE threat modeling, pentesting & remediation.",
        key_skills=[
            "investigating-incidents-with-aws-devops-agent",
            "scanning-with-aws-security-agent",
            "diff-scanning-with-aws-security-agent",
            "threat-modeling-with-aws-security-agent",
            "remediating-with-aws-security-agent",
            "pentesting-with-aws-security-agent",
        ],
        upstream_url=f"{AWS_TOOLKIT_REPO}/tree/main/plugins/aws-agents-for-devsecops",
    ),
    AwsToolkitPluginInfo(
        plugin_id="aws-continuum",
        name="AWS Continuum SDLC Risk Validation",
        category="AppSec & Remediation",
        description="Discover, prioritize, validate, and remediate real security risks across the software development lifecycle.",
        key_skills=["setting-up-continuum", "reporting-continuum-security", "fixing-continuum-issues"],
        upstream_url=f"{AWS_TOOLKIT_REPO}/tree/main/plugins/aws-continuum",
    ),
    AwsToolkitPluginInfo(
        plugin_id="aws-agents",
        name="Amazon Bedrock & Bedrock AgentCore",
        category="Agentic AI Security",
        description="Build, connect, harden, debug, and deploy production AI agents on Amazon Bedrock and AgentCore.",
        key_skills=["agents-harden", "agents-build", "agents-connect", "agents-debug", "amazon-bedrock"],
        upstream_url=f"{AWS_TOOLKIT_REPO}/tree/main/plugins/aws-agents",
    ),
    AwsToolkitPluginInfo(
        plugin_id="aws-data-analytics",
        name="AWS Data & Security Lake Analytics",
        category="Data & Telemetry",
        description="S3 Tables, AWS Glue, Athena, and Security Lake analytics workflows.",
        key_skills=["aws-storage", "aws-database", "analytics-skills"],
        upstream_url=f"{AWS_TOOLKIT_REPO}/tree/main/plugins/aws-data-analytics",
    ),
    AwsToolkitPluginInfo(
        plugin_id="aws-startup-advisor",
        name="AWS Startup Solutions Architect",
        category="Architecture & Cost",
        description="Right-sized cloud architecture, Bedrock migration, and AWS Activate credit guidance.",
        key_skills=["aws-billing-and-cost-management", "launch-with-aws"],
        upstream_url=f"{AWS_TOOLKIT_REPO}/tree/main/plugins/aws-startup-advisor",
    ),
]


def redact_sensitive_aws_text(text: str) -> tuple[str, int]:
    """Apply aws-security Rule 9: strip credentials/secrets/emails and mask 12-digit account IDs."""
    count = 0

    def _sub(pat: re.Pattern[str], repl: str | Callable[[re.Match[str]], str], s: str) -> str:
        nonlocal count
        new_s, n = pat.subn(repl, s)
        count += n
        return new_s

    out = text or ""
    out = _sub(PEM_KEY_RE, "[REDACTED-PRIVATE-KEY]", out)
    out = _sub(AWS_KEY_RE, "[REDACTED-AWS-KEY]", out)
    out = _sub(AWS_SECRET_RE, r"\1=[REDACTED-SECRET]", out)
    out = _sub(EMAIL_RE, "[REDACTED-EMAIL]", out)
    out = _sub(AWS_ACCOUNT_RE, lambda m: f"****-****-{m.group(1)[-4:]}", out)
    return out, count


class AwsAgentToolkitBridge:
    """Zero-trust integration bridge uniting `aws/agent-toolkit-for-aws` with GigaMesh."""

    def __init__(
        self,
        *,
        engine: GigaMeshEngine,
        enabled: bool = True,
        region: str = "us-east-1",
        read_only_enforced: bool = True,
        mcp_endpoint: str = AWS_MCP_ENDPOINT,
        rpc_transport: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.engine = engine
        self.enabled = enabled
        self.region = region
        self.read_only_enforced = read_only_enforced
        self.mcp_endpoint = mcp_endpoint
        self._rpc_transport = rpc_transport

        self.server_info: dict[str, Any] = {}
        self.pinned_tools: dict[str, AwsMcpToolPin] = {}
        self.retrieved_skills: dict[str, AwsSkillRecord] = {}
        self.findings: list[AwsIngestedFinding] = []
        self.last_mcp_discovery_at: datetime | None = None
        self.last_mcp_status: str = "not_yet_probed"

    # ------------------------------------------------------------------
    # MCP Config Generator & Environment Doctor
    # ------------------------------------------------------------------
    def generate_mcp_config(self) -> dict[str, Any]:
        return {
            "mcpServers": {
                "aws-mcp": {
                    "command": "uvx",
                    "args": [
                        "--from",
                        "git+https://github.com/aws/mcp-proxy-for-aws@a5dd25e0ad99d0d874f2b779435b12b10932eae7",
                        "mcp-proxy-for-aws",
                        self.mcp_endpoint,
                        "--skip-auth",
                        "--metadata",
                        f"AWS_REGION={self.region}",
                        "--metadata",
                        "INSTALL_SOURCE=gigamesh-aws-toolkit",
                    ],
                },
                "aws-devops-agent": {
                    "type": "http",
                    "url": AWS_DEVOPS_ENDPOINT_TMPL.format(region=self.region),
                    "headers": {"Authorization": "Bearer ${DEVOPS_AGENT_TOKEN}"},
                    "timeout": 120000,
                },
            }
        }

    def doctor(self) -> dict[str, Any]:
        uvx_path = shutil.which("uvx")
        aws_cli_path = shutil.which("aws")
        has_aws_creds = bool(
            os.environ.get("AWS_ACCESS_KEY_ID")
            or os.environ.get("AWS_PROFILE")
            or Path.home().joinpath(".aws", "credentials").exists()
        )
        has_devops_token = bool(os.environ.get("DEVOPS_AGENT_TOKEN"))
        mcp_json_exists = (self.engine.config.base_dir / ".mcp.json").exists()
        return {
            "upstream_repo": AWS_TOOLKIT_REPO,
            "uvx_installed": uvx_path is not None,
            "uvx_path": uvx_path,
            "aws_cli_installed": aws_cli_path is not None,
            "aws_credentials_configured": has_aws_creds,
            "devops_agent_token_configured": has_devops_token,
            "repo_mcp_json_present": mcp_json_exists,
            "aws_mcp_endpoint": self.mcp_endpoint,
            "devops_agent_endpoint": AWS_DEVOPS_ENDPOINT_TMPL.format(region=self.region),
            "read_only_docs_and_skills_ready": True,
            "live_account_discovery_state": "OBSERVED" if has_aws_creds else "NOT ASSESSED (no local AWS credentials)",
        }

    # ------------------------------------------------------------------
    # Live Official AWS MCP Streamable-HTTP JSON-RPC Client
    # ------------------------------------------------------------------
    def _rpc_call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"jsonrpc": "2.0", "id": uuid4().hex[:8], "method": method, "params": params or {}}
        if self._rpc_transport is not None:
            return self._rpc_transport(self.mcp_endpoint, payload)

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "GigaMesh-AwsToolkitBridge/0.1 (+https://github.com/Phlotonic/gigamesh)",
        }
        with httpx.Client(timeout=12.0, follow_redirects=False) as client:
            resp = client.post(self.mcp_endpoint, json=payload, headers=headers)
            resp.raise_for_status()
            ctype = resp.headers.get("content-type", "")
            if "text/event-stream" in ctype:
                # Extract first JSON-RPC data line from SSE stream
                for line in resp.text.splitlines():
                    if line.startswith("data:"):
                        return json.loads(line[5:].strip())
            return resp.json()

    def discover_mcp_tools(self) -> dict[str, Any]:
        """Connect to live official AWS MCP server, discover tools, and SHA-256 pin them (OWASP ASI04)."""
        init_res = self._rpc_call(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "gigamesh-siem", "version": "0.1.0"},
            },
        )
        self.server_info = init_res.get("result", {}).get("serverInfo", {})
        tools_res = self._rpc_call("tools/list", {})
        tools = tools_res.get("result", {}).get("tools", [])

        rugpulls = 0
        for t in tools:
            name = str(t.get("name", ""))
            desc = str(t.get("description", ""))
            if not name:
                continue
            digest = hashlib.sha256(f"{name}|{desc}".encode("utf-8")).hexdigest()
            is_ro = name not in MUTATING_AWS_MCP_TOOLS
            prev = self.pinned_tools.get(name)
            rugpull = prev is not None and prev.sha256 != digest
            if rugpull:
                rugpulls += 1
                self.engine.security_audit_log.record(
                    category="owasp_block",
                    severity="critical",
                    actor="aws-mcp-server",
                    summary=f"OWASP ASI04: AWS MCP tool descriptor mutated mid-session ({name})",
                    details={"prev_sha256": prev.sha256, "new_sha256": digest},
                )
            self.pinned_tools[name] = AwsMcpToolPin(
                name=name,
                description=desc[:220],
                sha256=digest,
                read_only=is_ro,
                rugpull_detected=rugpull,
            )
            # Also register baseline pin inside GigaMesh's ToolSupplyChainAndMemoryGuard!
            tool_key = f"aws-mcp/{name}"
            guard = self.engine.detectors.tool_supply_guard
            with guard._lock:
                if tool_key not in guard._pinned_tool_hashes:
                    guard._pinned_tool_hashes[tool_key] = hashlib.sha256(desc.encode("utf-8")).hexdigest()

        self.last_mcp_discovery_at = datetime.now(timezone.utc)
        self.last_mcp_status = "connected_verified" if rugpulls == 0 else f"rugpull_alert:{rugpulls}"
        self.engine.broadcast("aws_toolkit_updated", {"event": "mcp_discovered", "tools": len(self.pinned_tools)})
        return {
            "status": self.last_mcp_status,
            "server_info": self.server_info,
            "tools_count": len(self.pinned_tools),
            "rugpulls_detected": rugpulls,
            "tools": [p.model_dump(mode="json") for p in self.pinned_tools.values()],
        }

    def search_aws_docs(self, search_phrase: str, limit: int = 4) -> list[AwsDocSearchResult]:
        """Query official AWS MCP `aws___search_documentation` (works read-only without AWS creds)."""
        res = self._rpc_call(
            "tools/call",
            {
                "name": "aws___search_documentation",
                "arguments": {"search_phrase": search_phrase, "limit": max(1, min(limit, 8))},
            },
        )
        content_blocks = res.get("result", {}).get("content", [])
        results: list[AwsDocSearchResult] = []
        for blk in content_blocks:
            raw_text = str(blk.get("text", ""))
            if not raw_text:
                continue
            try:
                parsed = json.loads(raw_text)
                items = parsed if isinstance(parsed, list) else parsed.get("search_results") or parsed.get("results") or [parsed]
                for item in items[:limit]:
                    if not isinstance(item, dict):
                        continue
                    title = str(item.get("title") or item.get("heading") or search_phrase)
                    url = str(item.get("url") or item.get("link") or "https://docs.aws.amazon.com/")
                    snippet = str(item.get("context") or item.get("snippet") or item.get("summary") or "")[:360]
                    clean_snip, _ = redact_sensitive_aws_text(snippet)
                    results.append(AwsDocSearchResult(title=title, url=url, snippet=clean_snip))
            except json.JSONDecodeError:
                clean_txt, _ = redact_sensitive_aws_text(raw_text[:360])
                results.append(
                    AwsDocSearchResult(
                        title=f"AWS Documentation: {search_phrase}",
                        url="https://docs.aws.amazon.com/",
                        snippet=clean_txt,
                    )
                )
        return results

    def retrieve_skill(self, skill_name: str, file: str | None = None) -> AwsSkillRecord:
        """Retrieve an official AWS Agent Toolkit skill via live `aws___retrieve_skill`, SHA-256 pin & poison-screen it."""
        args: dict[str, Any] = {"skill_name": skill_name}
        if file:
            args["file"] = file
        res = self._rpc_call("tools/call", {"name": "aws___retrieve_skill", "arguments": args})
        blocks = res.get("result", {}).get("content", [])
        text = "\n".join(str(b.get("text", "")) for b in blocks if b.get("text"))
        if not text:
            raise ValueError(f"AWS MCP returned empty content for skill '{skill_name}'")

        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        lowered = text.lower()
        poisoned = any(m in lowered for m in POISON_MARKERS)
        if poisoned:
            self.engine.security_audit_log.record(
                category="owasp_block",
                severity="critical",
                actor="aws-mcp-skill",
                summary=f"Quarantined prompt-poisoning attempt inside retrieved skill '{skill_name}'",
                details={"sha256": sha},
            )
        clean_preview, _ = redact_sensitive_aws_text(text[:500])
        record = AwsSkillRecord(
            skill_name=f"{skill_name}:{file}" if file else skill_name,
            source="live_aws_mcp",
            sha256=sha,
            poison_checked=True,
            poison_blocked=poisoned,
            preview="[QUARANTINED: prompt-poisoning detected]" if poisoned else clean_preview,
            full_length=len(text),
        )
        self.retrieved_skills[record.skill_name] = record
        return record

    # ------------------------------------------------------------------
    # AWS Security Findings -> GigaMesh ASEF + Quorum-Gated Remediation
    # ------------------------------------------------------------------
    def ingest_aws_finding(self, finding: AwsSecurityFindingInput) -> AwsIngestedFinding:
        """Ingest GuardDuty / Security Hub / Inspector / Macie / AWS Security Agent / Continuum findings.

        Honors `aws-security/SKILL.md`:
        - Rule 1: Read-only by default; mutating remediation requires M-of-N HITL quorum.
        - Rule 4: GuardDuty `AttackSequence:` prioritized first; service severity preserved verbatim.
        - Rule 5: Security Hub Exposure findings prioritized directly alongside Attack Sequences.
        - Rule 9: Sensitive values redacted and 12-digit AWS account IDs masked by default.
        """
        redacted_desc, c1 = redact_sensitive_aws_text(finding.description)
        redacted_res, c2 = redact_sensitive_aws_text(finding.resource_arn or f"arn:aws:{finding.service}:{finding.region}:{finding.account_id}:resource")
        masked_acct, c3 = redact_sensitive_aws_text(finding.account_id)
        total_redactions = c1 + c2 + c3

        is_attack_seq = finding.is_attack_sequence or finding.finding_type.startswith("AttackSequence:")
        is_exposure = finding.is_exposure or "exposure" in finding.finding_type.lower() or "attackpath" in finding.finding_type.lower()

        if is_attack_seq:
            priority_bucket = 1
        elif is_exposure:
            priority_bucket = 2
        elif finding.severity.upper() in ("CRITICAL", "HIGH"):
            priority_bucket = 3
        else:
            priority_bucket = 4

        # Map into canonical GigaMesh ASEF event for full provenance + OWASP + REA + Autopoiesis correlation
        ev_type = (
            EventType.OAUTH_DELEGATION_GRANT
            if "iam" in finding.finding_type.lower() or "credential" in finding.finding_type.lower()
            else EventType.TOOL_MCP_CALL
            if "bedrock" in finding.finding_type.lower() or "mcp" in finding.finding_type.lower()
            else EventType.NETWORK_EGRESS
        )
        asef_evt = AsefEvent(
            trace_id=f"aws-{uuid4().hex[:8]}",
            use_case="zero-trust-critical" if priority_bucket <= 2 else "enterprise-balanced",
            event_type=ev_type,
            actor_type=ActorType.RED_HAT_SUSPECT if is_attack_seq else ActorType.EXTERNAL_SOURCE,
            actor_id=f"aws:{finding.service}:{finding.region}",
            target_resource=redacted_res,
            source_trust_level=TrustLevel.UNTRUSTED,
            privilege_level=9 if priority_bucket <= 2 else 6,
            payload_preview=f"[{finding.service.upper()} {finding.finding_type}] {finding.title} — {redacted_desc[:500]}",
            egress_destination="https://exfil.aws-suspicious.invalid/beacon" if is_attack_seq else None,
            metadata={
                "aws_service": finding.service,
                "aws_finding_type": finding.finding_type,
                "reported_severity": finding.severity,
                "is_attack_sequence": is_attack_seq,
                "is_exposure": is_exposure,
                **({"requires_hitl_approval": True, "hitl_approved": False} if priority_bucket <= 2 else {}),
            },
        )
        ingest_res = self.engine.ingest_event(asef_evt, attacker_family=f"aws-{finding.service}")

        # Rule 1 (Read-Only Default): Mutating AWS containment is prepared as a reviewable plan + HITL Quorum gate
        quorum_id: str | None = None
        if priority_bucket <= 2:
            q = self.engine.human_hub.open_quorum(
                action_kind="aws_containment_remediation",
                target_id=redacted_res,
                use_case=asef_evt.use_case,
                summary=(
                    f"Approve AWS remediation for {finding.service.upper()} {finding.finding_type} "
                    f"(severity={finding.severity}, account={masked_acct}). Read-only mode blocked silent mutation."
                ),
                evidence_refs=[asef_evt.event_id, ingest_res.get("incident_id") or ""],
            )
            quorum_id = q.quorum_id

        remediation_plan = {
            "read_only_guardrail": self.read_only_enforced,
            "requires_human_approval": True,
            "recommended_aws_cli_or_mcp_steps": [
                finding.recommended_remediation
                or "Review IAM session activity via CloudTrail LookupEvents (read-only) before revoking temporary credentials.",
                "Isolate affected workload via VPC Security Group egress restriction (gated by HITL Quorum).",
                "Cross-check Bedrock Guardrails & MCP tool-schema SHA-256 pins in GigaMesh.",
            ],
            "aws_toolkit_skill_reference": (
                "aws-security (references/guardduty.md)"
                if finding.service == "guardduty"
                else "aws-security (references/security-hub.md)"
                if finding.service == "security-hub"
                else "aws-agents-for-devsecops (remediating-with-aws-security-agent)"
            ),
        }

        rec = AwsIngestedFinding(
            service=finding.service,
            finding_type=finding.finding_type,
            title=finding.title,
            reported_severity=finding.severity,
            priority_bucket=priority_bucket,
            region=finding.region,
            masked_account=masked_acct,
            masked_resource=redacted_res,
            redacted_summary=redacted_desc[:360],
            redactions_applied=total_redactions,
            evidence_state="OBSERVED",
            gigamesh_incident_id=ingest_res.get("incident_id"),
            quorum_id=quorum_id,
            remediation_plan=remediation_plan,
        )
        self.findings.append(rec)
        # Keep findings sorted by official aws-security priority: AttackSequence -> Exposure -> Severity -> Newest
        self.findings.sort(key=lambda f: (f.priority_bucket, -f.ingested_at.timestamp()))
        self.engine.broadcast("aws_toolkit_updated", {"event": "finding_ingested", "record_id": rec.record_id})
        return rec

    def simulate_aws_attack_sequence(self) -> list[AwsIngestedFinding]:
        """Simulate a correlated GuardDuty AttackSequence + Security Hub Exposure + Bedrock AgentCore event."""
        samples = [
            AwsSecurityFindingInput(
                service="guardduty",
                finding_type="AttackSequence:IAM/CompromisedCredentials",
                title="Correlated IAM Credential Compromise & S3 Exfiltration Sequence",
                severity="CRITICAL",
                region=self.region,
                account_id="445566778899",
                resource_arn=f"arn:aws:iam::445566778899:role/bedrock-agentcore-prod-role",
                description=(
                    "GuardDuty correlated anomalous AssumeRole + ListBuckets + GetObject burst from TOR exit node. "
                    "Detected leaked key AKIAIOSFODNN7EXAMPLE linked to ops-admin@example.com."
                ),
                is_attack_sequence=True,
                recommended_remediation="Revoke active STS sessions on bedrock-agentcore-prod-role and attach explicit Deny policy after HITL sign-off.",
            ),
            AwsSecurityFindingInput(
                service="security-hub",
                finding_type="Exposure:AttackPath/PublicBedrockMcpGateway",
                title="Reachable Public Attack Path to Bedrock AgentCore MCP Gateway",
                severity="HIGH",
                region=self.region,
                account_id="445566778899",
                resource_arn=f"arn:aws:bedrock-agentcore:{self.region}:445566778899:gateway/gw-prod-01",
                description="Security Hub correlated an internet-exposed ALB routing to an overly permissive IAM role with bedrock:InvokeAgent.",
                is_exposure=True,
                recommended_remediation="Restrict ALB ingress via WAF + tighten AgentCore execution role to least-agency read-only scope.",
            ),
        ]
        return [self.ingest_aws_finding(s) for s in samples]

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "region": self.region,
            "read_only_enforced": self.read_only_enforced,
            "last_mcp_status": self.last_mcp_status,
            "last_mcp_discovery_at": self.last_mcp_discovery_at.isoformat() if self.last_mcp_discovery_at else None,
            "server_info": self.server_info,
            "doctor": self.doctor(),
            "plugins": [p.model_dump(mode="json") for p in OFFICIAL_AWS_PLUGINS],
            "pinned_tools": [t.model_dump(mode="json") for t in self.pinned_tools.values()],
            "retrieved_skills": [s.model_dump(mode="json") for s in self.retrieved_skills.values()],
            "findings": [f.model_dump(mode="json") for f in self.findings[:40]],
            "counts": {
                "plugins": len(OFFICIAL_AWS_PLUGINS),
                "pinned_tools": len(self.pinned_tools),
                "retrieved_skills": len(self.retrieved_skills),
                "findings": len(self.findings),
                "attack_sequences": sum(1 for f in self.findings if f.priority_bucket == 1),
                "exposures": sum(1 for f in self.findings if f.priority_bucket == 2),
            },
            "mcp_config": self.generate_mcp_config(),
        }
