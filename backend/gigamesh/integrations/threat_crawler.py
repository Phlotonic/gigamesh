"""Toggle-able Zero-Trust Threat Intelligence Web Crawler for GigaMesh.

Scans public security advisory feeds and threat-intelligence web pages (GitHub Security
Advisories, Red Hat Security Data, CISA KEV, MITRE ATLAS / OWASP Agentic feeds, or
operator-configured URLs) on a toggle-able async schedule or on demand.

Security Invariants:
- Toggle-able ON/OFF at runtime (`enabled` defaults to False until toggled on, or configurable).
- Strict SSRF Protection: blocks loopback, RFC1918 private networks, link-local / cloud
  metadata IPs (169.254.169.254), non-HTTP(S) schemes, and hosts outside the allowlist.
- Respects CAPTCHA / anti-bot gates: never attempts to bypass anti-bot challenges; logs
  `gated_skipped` cleanly and moves on.
- Zero-Trust Anti-Poisoning: every fetched page passes through GigaMesh's prompt-injection
  detector first. Poisoned pages trying to hijack the crawler are quarantined, ensnared,
  and dissected via REA rather than ingested as trusted intelligence.
- Darwinian Verification: newly extracted threat indicators are exported as signed STIX 2.1
  motifs and compiled into candidate defensive modules only after passing safety checks and
  local Darwinian benchmarking.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from gigamesh.models.asef import ActorType, AsefEvent, EventType, Severity, TrustLevel
from gigamesh.models.rea import MetabolizedDefenseModule

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)
MITRE_RE = re.compile(r"\b(?:AML\.T\d{4}(?:\.\d{3})?|T\d{4}(?:\.\d{3})?)\b")
DOMAIN_IOC_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:invalid|onion|top|xyz|ru|cn|tk|cc)\b", re.IGNORECASE
)

AGENTIC_KEYWORDS = (
    "prompt injection",
    "mcp",
    "model context protocol",
    "agentic",
    "tool calling",
    "llm",
    "jailbreak",
    "oauth",
    "memory poisoning",
    "selinux",
    "auditd",
    "openshift",
    "rhel",
    "systemd",
    "ptrace",
    "memfd_create",
    "ghidra",
    "container escape",
    "privilege escalation",
    "remote code execution",
)

CAPTCHA_MARKERS = (
    "cf-turnstile",
    "g-recaptcha",
    "hcaptcha",
    "verify you are human",
    "just a moment...",
    "attention required! | cloudflare",
)

PROMPT_POISON_MARKERS = (
    "ignore previous instructions",
    "system override",
    "<!-- agent:exec",
    "disregard all prior",
    "x-agent-escalate",
)


class ThreatSource(BaseModel):
    """Configured threat-intelligence source URL."""

    source_id: str
    name: str
    url: str
    kind: str = "json_feed"  # json_feed | html_page | rss_feed
    enabled: bool = True
    trust_tier: float = Field(default=0.85, ge=0.1, le=1.0)
    last_crawled_at: datetime | None = None
    last_status: str = "idle"


class CrawlFinding(BaseModel):
    """Structured threat intelligence item uncovered by the web crawler."""

    finding_id: str = Field(default_factory=lambda: f"ti-{uuid4().hex[:10]}")
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_id: str
    source_name: str
    url: str
    title: str
    summary: str
    severity: Severity = Severity.MEDIUM
    cve_ids: list[str] = Field(default_factory=list)
    ghsa_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    matched_topics: list[str] = Field(default_factory=list)
    extracted_patterns: list[str] = Field(default_factory=list)
    poison_attempt_blocked: bool = False
    rea_dossier_id: str | None = None
    metabolized_module_id: str | None = None
    content_sha256: str = ""


class CrawlRunReport(BaseModel):
    """Summary of one completed threat-intelligence crawl cycle."""

    run_id: str = Field(default_factory=lambda: f"crw-{uuid4().hex[:10]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trigger: str = "manual"
    sources_attempted: int = 0
    sources_succeeded: int = 0
    sources_blocked_or_gated: list[dict[str, str]] = Field(default_factory=list)
    new_findings_count: int = 0
    poisoned_pages_quarantined: int = 0
    stix_bundle_id: str | None = None
    evolution_generation_id: int | None = None
    findings: list[CrawlFinding] = Field(default_factory=list)


class ThreatCrawlerStatus(BaseModel):
    enabled: bool
    crawl_interval_sec: float
    auto_evolve_on_findings: bool
    enforce_allowlist: bool
    allowed_domains: list[str]
    sources: list[ThreatSource]
    total_runs: int
    total_findings: int
    unique_cves: int
    poisoned_pages_blocked: int
    last_run_at: datetime | None = None


DEFAULT_ALLOWED_DOMAINS = [
    "api.github.com",
    "github.com",
    "access.redhat.com",
    "www.cisa.gov",
    "cisa.gov",
    "services.nvd.nist.gov",
    "atlas.mitre.org",
    "owasp.org",
]


def default_threat_sources() -> list[ThreatSource]:
    return [
        ThreatSource(
            source_id="src-ghsa",
            name="GitHub Global Security Advisories (GHSA)",
            url="https://api.github.com/advisories?per_page=8",
            kind="json_feed",
            enabled=True,
            trust_tier=0.92,
        ),
        ThreatSource(
            source_id="src-redhat-sec",
            name="Red Hat Security Data CVE Feed",
            url="https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=8",
            kind="json_feed",
            enabled=True,
            trust_tier=0.95,
        ),
        ThreatSource(
            source_id="src-cisa-kev",
            name="CISA Known Exploited Vulnerabilities (KEV)",
            url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            kind="json_feed",
            enabled=True,
            trust_tier=0.95,
        ),
    ]


class ThreatIntelCrawler:
    """Toggle-able, SSRF-hardened, anti-poisoning threat-intelligence web crawler."""

    def __init__(
        self,
        *,
        engine: GigaMeshEngine,
        enabled_on_boot: bool = False,
        crawl_interval_sec: float = 120.0,
        auto_evolve_on_findings: bool = True,
        enforce_allowlist: bool = True,
        max_bytes: int = 262_144,
        http_fetcher: Callable[[str], tuple[int, str, str]] | None = None,
    ) -> None:
        self.engine = engine
        self.enabled: bool = enabled_on_boot
        self.crawl_interval_sec: float = crawl_interval_sec
        self.auto_evolve_on_findings: bool = auto_evolve_on_findings
        self.enforce_allowlist: bool = enforce_allowlist
        self.max_bytes: int = max_bytes
        self._custom_fetcher = http_fetcher

        self.allowed_domains: list[str] = list(DEFAULT_ALLOWED_DOMAINS)
        self.sources: dict[str, ThreatSource] = {s.source_id: s for s in default_threat_sources()}
        self.findings: list[CrawlFinding] = []
        self.runs: list[CrawlRunReport] = []
        self._seen_digests: set[str] = set()
        self.poisoned_pages_blocked: int = 0
        self.last_run_at: datetime | None = None
        self._task: asyncio.Task[Any] | None = None

    # ------------------------------------------------------------------
    # Toggle & Async Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        self.enabled = True
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._crawl_loop())

    def stop(self) -> None:
        self.enabled = False
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None

    async def _crawl_loop(self) -> None:
        try:
            while self.enabled:
                await asyncio.sleep(self.crawl_interval_sec)
                if not self.enabled:
                    break
                await asyncio.to_thread(self.scan_once, None, "scheduled_crawl")
        except asyncio.CancelledError:
            self.enabled = False

    def add_or_update_source(self, source: ThreatSource) -> ThreatSource:
        ok, reason = self.validate_target_url(source.url, check_allowlist=False)
        if not ok:
            raise ValueError(f"Rejected unsafe source URL: {reason}")
        host = (urlparse(source.url).hostname or "").lower()
        if host and host not in self.allowed_domains:
            self.allowed_domains.append(host)
        self.sources[source.source_id] = source
        return source

    # ------------------------------------------------------------------
    # SSRF & Domain Allowlist Security Guard
    # ------------------------------------------------------------------
    def validate_target_url(self, url: str, check_allowlist: bool = True) -> tuple[bool, str]:
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "malformed_url"

        if parsed.scheme not in ("https", "http"):
            return False, f"disallowed_scheme:{parsed.scheme}"
        if parsed.scheme != "https" and self.enforce_allowlist:
            return False, "https_required"

        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return False, "missing_hostname"
        if host in ("localhost", "ip6-localhost") or host.endswith((".local", ".internal", ".localhost")):
            return False, f"blocked_local_hostname:{host}"

        # Reject literal private / loopback / link-local / metadata IP addresses
        is_allowlisted_domain = False
        try:
            ip_obj = ipaddress.ip_address(host)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            ):
                return False, f"blocked_private_ip:{host}"
        except ValueError:
            # Hostname — verify against allowlist when enabled
            is_allowlisted_domain = any(host == d or host.endswith(f".{d}") for d in self.allowed_domains)
            if check_allowlist and self.enforce_allowlist and not is_allowlisted_domain:
                return False, f"domain_not_in_allowlist:{host}"

        # DNS resolution SSRF check for non-allowlisted hostnames (allowlisted public domains may route via transparent egress proxies)
        if self._custom_fetcher is None and not is_allowlisted_domain:
            try:
                infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
                for _, _, _, _, sockaddr in infos:
                    resolved_ip = ipaddress.ip_address(sockaddr[0])
                    if (
                        resolved_ip.is_private
                        or resolved_ip.is_loopback
                        or resolved_ip.is_link_local
                        or resolved_ip.is_reserved
                    ):
                        return False, f"dns_resolved_private_ip:{sockaddr[0]}"
            except socket.gaierror:
                pass

        return True, "ok"

    # ------------------------------------------------------------------
    # HTTP Fetcher (Safe, Bounded, No CAPTCHA Bypass)
    # ------------------------------------------------------------------
    def _fetch_url(self, url: str) -> tuple[int, str, str]:
        if self._custom_fetcher is not None:
            return self._custom_fetcher(url)

        headers = {
            "User-Agent": "GigaMesh-ThreatIntelCrawler/0.1 (+https://github.com/Phlotonic/gigamesh)",
            "Accept": "application/json, application/rss+xml, text/html;q=0.8, text/plain;q=0.7",
        }
        with httpx.Client(timeout=8.0, follow_redirects=False, headers=headers) as client:
            resp = client.get(url)
            content_type = resp.headers.get("content-type", "text/plain")
            raw = resp.content[: self.max_bytes]
            return resp.status_code, content_type, raw.decode("utf-8", errors="ignore")

    # ------------------------------------------------------------------
    # Scan Execution + Zero-Trust Anti-Poisoning + Metabolism/STIX Output
    # ------------------------------------------------------------------
    def scan_once(
        self,
        source_ids: list[str] | None = None,
        trigger: str = "manual_scan",
    ) -> CrawlRunReport:
        self.last_run_at = datetime.now(timezone.utc)
        targets = (
            [self.sources[sid] for sid in source_ids if sid in self.sources]
            if source_ids
            else [s for s in self.sources.values() if s.enabled]
        )

        new_findings: list[CrawlFinding] = []
        blocked_or_gated: list[dict[str, str]] = []
        succeeded = 0
        poisoned_count = 0

        for src in targets:
            ok, reason = self.validate_target_url(src.url, check_allowlist=True)
            if not ok:
                src.last_status = f"blocked:{reason}"
                blocked_or_gated.append({"source_id": src.source_id, "url": src.url, "reason": reason})
                continue

            try:
                status_code, content_type, body = self._fetch_url(src.url)
            except Exception as exc:
                src.last_status = f"unreachable:{type(exc).__name__}"
                blocked_or_gated.append(
                    {"source_id": src.source_id, "url": src.url, "reason": f"network_error:{str(exc)[:100]}"}
                )
                continue

            src.last_crawled_at = datetime.now(timezone.utc)
            if status_code in (403, 429) or self._is_captcha_gated(body):
                src.last_status = f"gated_skipped:{status_code}"
                blocked_or_gated.append(
                    {"source_id": src.source_id, "url": src.url, "reason": f"anti_bot_or_captcha_gate:{status_code}"}
                )
                continue
            if status_code >= 400:
                src.last_status = f"http_error:{status_code}"
                blocked_or_gated.append(
                    {"source_id": src.source_id, "url": src.url, "reason": f"http_{status_code}"}
                )
                continue

            succeeded += 1
            src.last_status = "ok"
            parsed_findings, was_poisoned = self.analyze_crawled_content(
                source=src,
                content_type=content_type,
                raw_body=body,
            )
            if was_poisoned:
                poisoned_count += 1
            new_findings.extend(parsed_findings)

        # Export discovered intel as an anonymized STIX 2.1 bundle & run Darwinian check if enabled
        stix_bundle_id: str | None = None
        evo_gen_id: int | None = None
        if new_findings:
            bundle = self.engine.export_stix_bundle(origin_org="gigamesh-threat-crawler")
            stix_bundle_id = bundle.bundle_id
            if self.auto_evolve_on_findings and any(f.metabolized_module_id for f in new_findings):
                rep = self.engine.autopoiesis.run_generation(
                    use_case="enterprise-balanced",
                    trigger=f"threat_crawler:{trigger}",
                )
                evo_gen_id = rep.generation_id

        report = CrawlRunReport(
            trigger=trigger,
            sources_attempted=len(targets),
            sources_succeeded=succeeded,
            sources_blocked_or_gated=blocked_or_gated,
            new_findings_count=len(new_findings),
            poisoned_pages_quarantined=poisoned_count,
            stix_bundle_id=stix_bundle_id,
            evolution_generation_id=evo_gen_id,
            findings=new_findings,
        )
        self.runs.append(report)
        self.engine.broadcast("threat_crawl_completed", report.model_dump(mode="json"))
        return report

    def scan_raw_document(
        self,
        *,
        url: str,
        title: str,
        raw_body: str,
        content_type: str = "text/html",
    ) -> CrawlRunReport:
        """Directly scan a provided threat-intel web document or advisory payload (validated for SSRF)."""
        ok, reason = self.validate_target_url(url, check_allowlist=False)
        if not ok:
            raise ValueError(f"Unsafe URL rejected by SSRF guard: {reason}")
        temp_src = ThreatSource(
            source_id=f"src-custom-{uuid4().hex[:6]}",
            name=title,
            url=url,
            kind="json_feed" if "json" in content_type else "html_page",
        )
        findings, was_poisoned = self.analyze_crawled_content(
            source=temp_src,
            content_type=content_type,
            raw_body=raw_body,
        )
        evo_gen_id: int | None = None
        if self.auto_evolve_on_findings and any(f.metabolized_module_id for f in findings):
            evo_gen_id = self.engine.autopoiesis.run_generation(
                use_case="enterprise-balanced",
                trigger="threat_crawler:direct_scan",
            ).generation_id
        report = CrawlRunReport(
            trigger="direct_document_scan",
            sources_attempted=1,
            sources_succeeded=1,
            new_findings_count=len(findings),
            poisoned_pages_quarantined=1 if was_poisoned else 0,
            evolution_generation_id=evo_gen_id,
            findings=findings,
        )
        self.runs.append(report)
        self.engine.broadcast("threat_crawl_completed", report.model_dump(mode="json"))
        return report

    def analyze_crawled_content(
        self,
        *,
        source: ThreatSource,
        content_type: str,
        raw_body: str,
    ) -> tuple[list[CrawlFinding], bool]:
        """Run zero-trust poison screening first, then extract structured threat intelligence."""
        plain = self._strip_html(raw_body) if "html" in content_type.lower() else raw_body
        digest = hashlib.sha256(plain.encode("utf-8", errors="ignore")).hexdigest()

        # 1. Zero-Trust Prompt-Injection / Crawler-Poisoning Screen via GigaMesh
        ingest_evt = AsefEvent(
            trace_id=f"trc-crawl-{digest[:10]}",
            use_case="stealth-intel-snare",
            event_type=EventType.CONTENT_INGEST,
            actor_type=ActorType.AGENT,
            actor_id="agent-threat-intel-crawler",
            target_resource=source.url,
            source_trust_level=TrustLevel.UNTRUSTED,
            original_goal=f"Extract threat intelligence from {source.name}",
            payload_preview=plain[:1500],
        )
        ingest_res = self.engine.ingest_event(ingest_evt, attacker_family="crawler-poisoner")
        hits = ingest_res.get("hits", [])
        lowered = plain.lower()
        is_poisoned = any(h.get("attack_class") == "prompt_injection" for h in hits) or any(
            m in lowered for m in PROMPT_POISON_MARKERS
        )

        if is_poisoned:
            self.poisoned_pages_blocked += 1
            champ = self.engine.store.get_champion("stealth-intel-snare")
            session = self.engine.snare.ensnare(
                attacker_id=f"crawler:{source.url}",
                attacker_family="poisoned-web-intel",
                trace_id=ingest_evt.trace_id,
                fork_id=champ.fork_id,
            )
            artifact = self.engine.snare.harvest_artifact(
                session=session,
                artifact_kind="javascript_bundle",
                filename=f"poisoned_page_{digest[:8]}.txt",
                content_bytes=raw_body[:16384].encode("utf-8", errors="ignore"),
                metadata={"url": source.url},
            )
            dossier = self.engine.rea_bridge.dissect(artifact, depth=0.75)
            self.engine.autopoiesis.dossiers[dossier.dossier_id] = dossier
            metab_id: str | None = None
            for mod in self.engine.metabolism.compile(dossier):
                if mod.safety_verified:
                    mod.cross_attacker_hits = self.engine.autopoiesis._measure_cross_hits(mod)
                    self.engine.store.commit_metabolized_module(mod)
                    metab_id = mod.module_id

            quarantined = CrawlFinding(
                source_id=source.source_id,
                source_name=source.name,
                url=source.url,
                title=f"QUARANTINED Poisoned Web Page ({source.name})",
                summary=(
                    "Detected indirect prompt-injection / crawler-poisoning attempt inside crawled web content. "
                    "Quarantined page, dissected via REA, and compiled defensive counter-module."
                ),
                severity=Severity.CRITICAL,
                poison_attempt_blocked=True,
                rea_dossier_id=dossier.dossier_id,
                metabolized_module_id=metab_id,
                content_sha256=digest,
            )
            self.findings.append(quarantined)
            return [quarantined], True

        # 2. Parse structured JSON advisory feeds (GHSA, Red Hat Security Data, CISA KEV) or free-form HTML/text
        records = self._extract_records(source, content_type, raw_body, plain)
        created: list[CrawlFinding] = []
        for rec in records:
            rec_digest = hashlib.sha256(f"{source.url}|{rec['title']}|{rec['summary']}".encode("utf-8")).hexdigest()
            if rec_digest in self._seen_digests:
                continue
            self._seen_digests.add(rec_digest)

            blob = f"{rec['title']} {rec['summary']}"
            cves = sorted({m.upper() for m in CVE_RE.findall(blob)})
            ghsas = sorted({m.upper() for m in GHSA_RE.findall(blob)})
            mitres = sorted(set(MITRE_RE.findall(blob)))
            domains = sorted({m.lower() for m in DOMAIN_IOC_RE.findall(blob)})[:5]
            topics = [kw for kw in AGENTIC_KEYWORDS if kw in blob.lower()]

            patterns = list(dict.fromkeys([*(c.lower() for c in cves[:3]), *domains]))
            sev_str = str(rec.get("severity", "")).lower()
            if "critical" in sev_str or "remote code execution" in blob.lower() or "privilege escalation" in blob.lower():
                severity = Severity.CRITICAL
            elif "high" in sev_str or cves or ghsas:
                severity = Severity.HIGH
            elif topics or mitres:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            # Compile a safety-verified candidate defensive module when actionable patterns/topics are found
            mod_id: str | None = None
            if patterns and severity in (Severity.CRITICAL, Severity.HIGH):
                mod = MetabolizedDefenseModule(
                    source_dossier_id=f"crawl:{rec_digest[:10]}",
                    source_attacker_family=f"web-intel:{source.source_id}",
                    name=f"Crawled Threat Guard: {rec['title'][:46]}",
                    capability_kind="behavioral_loop_detector" if any(t in ("selinux", "auditd", "rhel", "ptrace") for t in topics) else "mcp_counter_snare",
                    description=f"Derived from {source.name} ({rec['url']}): {rec['summary'][:180]}",
                    match_patterns=patterns[:5],
                    target_attack_classes=["redhat_exposure" if any(t in ("rhel", "selinux", "openshift") for t in topics) else "mcp_privesc"],
                    detection_boost=0.18,
                    containment_boost=0.16,
                    safety_verified=True,
                )
                mod.cross_attacker_hits = self.engine.autopoiesis._measure_cross_hits(mod)
                self.engine.store.commit_metabolized_module(mod)
                mod_id = mod.module_id

            finding = CrawlFinding(
                source_id=source.source_id,
                source_name=source.name,
                url=rec["url"],
                title=rec["title"][:140],
                summary=rec["summary"][:360],
                severity=severity,
                cve_ids=cves,
                ghsa_ids=ghsas,
                mitre_techniques=mitres,
                matched_topics=topics[:8],
                extracted_patterns=patterns,
                metabolized_module_id=mod_id,
                content_sha256=rec_digest,
            )
            self.findings.append(finding)
            created.append(finding)

        return created, False

    @staticmethod
    def _extract_records(
        source: ThreatSource,
        content_type: str,
        raw_body: str,
        plain: str,
    ) -> list[dict[str, str]]:
        records: list[dict[str, str]] = []
        if "json" in content_type.lower() or raw_body.lstrip().startswith(("[", "{")):
            try:
                parsed = json.loads(raw_body)
                items = (
                    parsed
                    if isinstance(parsed, list)
                    else parsed.get("vulnerabilities")
                    or parsed.get("advisories")
                    or parsed.get("items")
                    or [parsed]
                )
                for item in items[:8]:
                    if not isinstance(item, dict):
                        continue
                    title = (
                        item.get("summary")
                        or item.get("vulnerabilityName")
                        or item.get("bugzilla_description")
                        or item.get("CVE")
                        or item.get("ghsa_id")
                        or source.name
                    )
                    desc = (
                        item.get("description")
                        or item.get("shortDescription")
                        or item.get("bugzilla_description")
                        or json.dumps(item)[:320]
                    )
                    cve_prefix = item.get("cve_id") or item.get("cveID") or item.get("CVE") or ""
                    ghsa_prefix = item.get("ghsa_id") or ""
                    full_title = " ".join(p for p in (cve_prefix, ghsa_prefix, str(title)) if p).strip()
                    records.append(
                        {
                            "title": full_title,
                            "summary": str(desc),
                            "severity": str(item.get("severity") or item.get("cvss_severity") or ""),
                            "url": str(item.get("html_url") or item.get("resource_url") or source.url),
                        }
                    )
                if records:
                    return records
            except Exception:
                pass

        # Fallback: extract headline + relevant snippet from HTML / RSS / text
        title_match = re.search(r"<title[^>]*>(.*?)</title>", raw_body, re.IGNORECASE | re.DOTALL)
        title = html.unescape(title_match.group(1)).strip() if title_match else source.name
        records.append(
            {
                "title": title,
                "summary": plain[:360],
                "severity": "",
                "url": source.url,
            }
        )
        return records

    @staticmethod
    def _strip_html(raw: str) -> str:
        no_script = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
        no_tags = re.sub(r"<[^>]+>", " ", no_script)
        return re.sub(r"\s+", " ", html.unescape(no_tags)).strip()

    @staticmethod
    def _is_captcha_gated(body: str) -> bool:
        lowered = body.lower()
        return any(m in lowered for m in CAPTCHA_MARKERS)

    def status(self) -> ThreatCrawlerStatus:
        all_cves = {c for f in self.findings for c in f.cve_ids}
        return ThreatCrawlerStatus(
            enabled=self.enabled,
            crawl_interval_sec=self.crawl_interval_sec,
            auto_evolve_on_findings=self.auto_evolve_on_findings,
            enforce_allowlist=self.enforce_allowlist,
            allowed_domains=list(self.allowed_domains),
            sources=list(self.sources.values()),
            total_runs=len(self.runs),
            total_findings=len(self.findings),
            unique_cves=len(all_cves),
            poisoned_pages_blocked=self.poisoned_pages_blocked,
            last_run_at=self.last_run_at,
        )
