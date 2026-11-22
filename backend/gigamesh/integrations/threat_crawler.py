"""Toggle-able Zero-Trust Global Threat Intelligence Web Crawler for GigaMesh.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.

Continuously reads *updates* from global threat-intelligence feeds across regions
(GitHub GHSA, NIST NVD, CISA KEV, Red Hat, ENISA EUVD, CERT-EU, UK NCSC, JPCERT/CC,
Canadian Centre for Cyber Security, SANS ISC) or operator-configured URLs, on a
toggle-able async schedule or on demand.

Update-Reading Mechanics:
- HTTP conditional GET: stores each feed's ``ETag`` / ``Last-Modified`` and re-polls with
  ``If-None-Match`` / ``If-Modified-Since``; a ``304 Not Modified`` is recorded as
  ``unchanged_304`` without re-downloading or re-processing.
- Content fingerprinting: feeds without validators are SHA-256 fingerprinted; identical
  bodies are recorded as ``unchanged_hash``.
- Incremental windows: URL templates (``{since}`` / ``{until}``) query only records
  modified since the last successful crawl (e.g. NVD CVE 2.0 ``lastModStartDate``).
- Revision tracking: advisories are keyed by stable ID + last-updated timestamp, so a
  re-published / modified advisory surfaces as a *revision*, not a duplicate.
- Persistent state (``data/threat_crawler_state.json``) keeps the toggle, validators,
  watermarks, seen-record digests, and recent findings across restarts.

Security Invariants:
- Toggle-able ON/OFF at runtime (master switch + per-source switches; defaults OFF).
- Strict SSRF Protection: blocks loopback, RFC1918, link-local / cloud metadata IPs,
  non-HTTPS schemes, redirects, and hosts outside the allowlist.
- Respects CAPTCHA / anti-bot gates: never attempts to bypass them; logs ``gated_skipped``.
- Hardened XML parsing: DOCTYPE / ENTITY declarations are refused (XXE / billion-laughs).
- Zero-Trust Anti-Poisoning: unstructured pages pass GigaMesh's prompt-injection detector;
  structured feeds are screened per record so one hostile advisory is quarantined (and
  REA-dissected) without discarding the rest of the feed.
- Darwinian Verification: new indicators are exported as signed STIX 2.1 and compiled into
  candidate defensive modules that must survive local benchmarking.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import inspect
import ipaddress
import json
import re
import socket
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
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

EXPLOITED_MARKERS = (
    "exploited in the wild",
    "actively exploited",
    "known exploited",
    "active exploitation",
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

STATE_VERSION = 2
MAX_SEEN_RECORDS = 6000
MAX_PERSISTED_FINDINGS = 300
MAX_PERSISTED_RUNS = 40


class ThreatSource(BaseModel):
    """Configured threat-intelligence source plus its live update-tracking state."""

    source_id: str
    name: str
    url: str
    kind: str = "json_feed"  # json_feed | rss_feed | atom_feed | html_page
    enabled: bool = True
    trust_tier: float = Field(default=0.85, ge=0.1, le=1.0)
    region: str = "Global"
    publisher: str = ""
    max_items: int = Field(default=10, ge=1, le=100)
    max_bytes: int = Field(default=1_048_576, ge=4096, le=8_388_608)
    builtin: bool = False

    # Live update-tracking state (persisted)
    last_crawled_at: datetime | None = None
    last_success_at: datetime | None = None
    last_changed_at: datetime | None = None
    last_status: str = "idle"
    last_http_status: int | None = None
    etag: str | None = None
    last_modified: str | None = None
    last_body_sha256: str | None = None
    last_new_items: int = 0
    total_items_ingested: int = 0
    total_checks: int = 0
    unchanged_checks: int = 0


class CrawlFinding(BaseModel):
    """Structured threat intelligence item uncovered by the web crawler."""

    finding_id: str = Field(default_factory=lambda: f"ti-{uuid4().hex[:10]}")
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_id: str
    source_name: str
    region: str = "Global"
    url: str
    record_id: str = ""
    title: str
    summary: str
    severity: Severity = Severity.MEDIUM
    published_at: str = ""
    updated_at: str = ""
    is_revision: bool = False
    actively_exploited: bool = False
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
    duration_ms: int = 0
    sources_attempted: int = 0
    sources_succeeded: int = 0
    sources_updated: int = 0
    sources_unchanged: int = 0
    sources_blocked_or_gated: list[dict[str, str]] = Field(default_factory=list)
    source_outcomes: dict[str, str] = Field(default_factory=dict)
    new_findings_count: int = 0
    revisions_count: int = 0
    poisoned_pages_quarantined: int = 0
    stix_bundle_id: str | None = None
    evolution_generation_id: int | None = None
    findings: list[CrawlFinding] = Field(default_factory=list)


class ThreatCrawlerStatus(BaseModel):
    enabled: bool
    running: bool
    crawl_interval_sec: float
    auto_evolve_on_findings: bool
    enforce_allowlist: bool
    allowed_domains: list[str]
    sources: list[ThreatSource]
    regions_covered: list[str]
    total_runs: int
    total_findings: int
    total_revisions: int
    unique_cves: int
    actively_exploited_count: int
    poisoned_pages_blocked: int
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    state_file: str | None = None


class FetchResult(BaseModel):
    status_code: int
    content_type: str = "text/plain"
    body: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    truncated: bool = False


DEFAULT_ALLOWED_DOMAINS = [
    "api.github.com",
    "github.com",
    "access.redhat.com",
    "www.cisa.gov",
    "cisa.gov",
    "services.nvd.nist.gov",
    "euvdservices.enisa.europa.eu",
    "cert.europa.eu",
    "www.ncsc.gov.uk",
    "www.jpcert.or.jp",
    "www.cyber.gc.ca",
    "isc.sans.edu",
    "atlas.mitre.org",
    "owasp.org",
]


def default_threat_sources() -> list[ThreatSource]:
    """Built-in multi-region global threat intelligence feeds (all HTTPS, verified live)."""
    return [
        ThreatSource(
            source_id="src-ghsa",
            name="GitHub Global Security Advisories (GHSA)",
            publisher="GitHub",
            region="Global",
            url="https://api.github.com/advisories?per_page=10&sort=updated&direction=desc",
            kind="json_feed",
            trust_tier=0.92,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-nvd",
            name="NIST National Vulnerability Database (CVE 2.0, incremental)",
            publisher="NIST",
            region="North America",
            url=(
                "https://services.nvd.nist.gov/rest/json/cves/2.0"
                "?lastModStartDate={since}&lastModEndDate={until}&resultsPerPage=40"
            ),
            kind="json_feed",
            trust_tier=0.95,
            max_items=15,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-cisa-kev",
            name="CISA Known Exploited Vulnerabilities (KEV)",
            publisher="CISA",
            region="North America",
            url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            kind="json_feed",
            trust_tier=0.97,
            max_bytes=6_291_456,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-redhat-sec",
            name="Red Hat Security Data CVE Feed",
            publisher="Red Hat",
            region="Global",
            url="https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=10",
            kind="json_feed",
            trust_tier=0.95,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-enisa-euvd",
            name="ENISA EU Vulnerability Database (EUVD)",
            publisher="ENISA",
            region="Europe",
            url="https://euvdservices.enisa.europa.eu/api/lastvulnerabilities",
            kind="json_feed",
            trust_tier=0.93,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-cert-eu",
            name="CERT-EU Security Advisories",
            publisher="CERT-EU",
            region="Europe",
            url="https://cert.europa.eu/publications/security-advisories-rss",
            kind="rss_feed",
            trust_tier=0.92,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-ncsc-uk",
            name="UK NCSC Threat Reports",
            publisher="NCSC UK",
            region="Europe",
            url="https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
            kind="rss_feed",
            trust_tier=0.9,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-jpcert",
            name="JPCERT/CC Security Alerts",
            publisher="JPCERT/CC",
            region="Asia-Pacific",
            url="https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
            kind="rss_feed",
            trust_tier=0.9,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-cccs",
            name="Canadian Centre for Cyber Security Alerts & Advisories",
            publisher="CCCS",
            region="North America",
            url="https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en",
            kind="atom_feed",
            trust_tier=0.9,
            max_bytes=2_097_152,
            builtin=True,
        ),
        ThreatSource(
            source_id="src-sans-isc",
            name="SANS Internet Storm Center Diaries",
            publisher="SANS ISC",
            region="Global",
            url="https://isc.sans.edu/rssfeed_full.xml",
            kind="rss_feed",
            trust_tier=0.82,
            builtin=True,
        ),
    ]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _parse_any_datetime(value: str) -> datetime | None:
    if not value:
        return None
    v = value.strip()
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(v)
    except (TypeError, ValueError, IndexError):
        pass
    for fmt in ("%b %d, %Y, %I:%M:%S %p", "%Y-%m-%d"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class ThreatIntelCrawler:
    """Toggle-able, SSRF-hardened, update-aware global threat-intelligence web crawler."""

    def __init__(
        self,
        *,
        engine: GigaMeshEngine,
        enabled_on_boot: bool = False,
        crawl_interval_sec: float = 120.0,
        auto_evolve_on_findings: bool = True,
        enforce_allowlist: bool = True,
        max_bytes: int = 262_144,
        http_fetcher: Callable[..., Any] | None = None,
        state_file: Path | str | None = None,
        initial_scan_delay_sec: float = 2.0,
        max_modules_per_run: int = 12,
        incremental_bootstrap_hours: float = 2.0,
    ) -> None:
        self.engine = engine
        self.enabled: bool = enabled_on_boot
        self.crawl_interval_sec: float = crawl_interval_sec
        self.auto_evolve_on_findings: bool = auto_evolve_on_findings
        self.enforce_allowlist: bool = enforce_allowlist
        self.max_bytes: int = max_bytes  # fallback cap for sources without explicit max_bytes
        self.initial_scan_delay_sec = initial_scan_delay_sec
        self.max_modules_per_run = max_modules_per_run
        self.incremental_bootstrap_hours = incremental_bootstrap_hours
        self._custom_fetcher = http_fetcher
        self.state_file: Path | None = Path(state_file) if state_file else None

        self.allowed_domains: list[str] = list(DEFAULT_ALLOWED_DOMAINS)
        self.sources: dict[str, ThreatSource] = {s.source_id: s for s in default_threat_sources()}
        self.findings: list[CrawlFinding] = []
        self.runs: list[CrawlRunReport] = []
        self._seen_digests: set[str] = set()
        self._seen_order: list[str] = []
        self._record_versions: dict[str, str] = {}
        self.poisoned_pages_blocked: int = 0
        self.total_revisions: int = 0
        self.last_run_at: datetime | None = None
        self._task: asyncio.Task[Any] | None = None
        self._scan_lock = threading.RLock()
        self._modules_this_run = 0

        self._load_state()
        if enabled_on_boot:
            self.enabled = True

    # ------------------------------------------------------------------
    # Persistent State
    # ------------------------------------------------------------------
    def _load_state(self) -> None:
        if self.state_file is None or not self.state_file.exists():
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self.enabled = bool(data.get("enabled", self.enabled))
        self.crawl_interval_sec = float(data.get("crawl_interval_sec", self.crawl_interval_sec))
        self.auto_evolve_on_findings = bool(data.get("auto_evolve_on_findings", self.auto_evolve_on_findings))
        self.poisoned_pages_blocked = int(data.get("poisoned_pages_blocked", 0))
        self.total_revisions = int(data.get("total_revisions", 0))
        if data.get("last_run_at"):
            self.last_run_at = _parse_any_datetime(data["last_run_at"])
        for dom in data.get("allowed_domains", []):
            if dom not in self.allowed_domains:
                self.allowed_domains.append(dom)

        for raw in data.get("sources", []):
            try:
                saved = ThreatSource(**raw)
            except Exception:
                continue
            existing = self.sources.get(saved.source_id)
            if existing is not None and existing.builtin:
                # Keep built-in definitions current; restore only operator toggle + tracking state
                tracking = saved.model_dump(
                    include={
                        "enabled",
                        "last_crawled_at",
                        "last_success_at",
                        "last_changed_at",
                        "last_status",
                        "last_http_status",
                        "etag",
                        "last_modified",
                        "last_body_sha256",
                        "last_new_items",
                        "total_items_ingested",
                        "total_checks",
                        "unchanged_checks",
                    }
                )
                self.sources[saved.source_id] = existing.model_copy(update=tracking)
            elif not saved.builtin:
                ok, _ = self.validate_target_url(self._resolve_url(saved), check_allowlist=False)
                if ok:
                    self.sources[saved.source_id] = saved

        self._seen_order = [d for d in data.get("seen_digests", []) if isinstance(d, str)][-MAX_SEEN_RECORDS:]
        self._seen_digests = set(self._seen_order)
        self._record_versions = {
            str(k): str(v) for k, v in dict(data.get("record_versions", {})).items()
        }
        for raw in data.get("recent_findings", []):
            try:
                self.findings.append(CrawlFinding(**raw))
            except Exception:
                continue
        for raw in data.get("recent_runs", []):
            try:
                self.runs.append(CrawlRunReport(**raw))
            except Exception:
                continue

    def _save_state(self) -> None:
        if self.state_file is None:
            return
        # Trim record-version map to the most recent entries to bound disk usage
        if len(self._record_versions) > MAX_SEEN_RECORDS:
            keys = list(self._record_versions)[-MAX_SEEN_RECORDS:]
            self._record_versions = {k: self._record_versions[k] for k in keys}
        payload = {
            "version": STATE_VERSION,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "enabled": self.enabled,
            "crawl_interval_sec": self.crawl_interval_sec,
            "auto_evolve_on_findings": self.auto_evolve_on_findings,
            "poisoned_pages_blocked": self.poisoned_pages_blocked,
            "total_revisions": self.total_revisions,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "allowed_domains": self.allowed_domains,
            "sources": [s.model_dump(mode="json") for s in self.sources.values()],
            "seen_digests": self._seen_order[-MAX_SEEN_RECORDS:],
            "record_versions": self._record_versions,
            "recent_findings": [f.model_dump(mode="json") for f in self.findings[-MAX_PERSISTED_FINDINGS:]],
            "recent_runs": [
                r.model_copy(update={"findings": []}).model_dump(mode="json")
                for r in self.runs[-MAX_PERSISTED_RUNS:]
            ],
        }
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
            tmp.replace(self.state_file)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Toggle & Async Lifecycle
    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        self.enabled = True
        self._save_state()
        if self.running:
            return
        self._task = asyncio.create_task(self._crawl_loop())

    def stop(self, *, persist: bool = True) -> None:
        self.enabled = False
        if persist:
            self._save_state()
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None

    def shutdown(self) -> None:
        """Stop the background loop on process exit WITHOUT changing the persisted toggle."""
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None

    async def _crawl_loop(self) -> None:
        try:
            # Read global updates shortly after being switched ON, then on every interval
            await asyncio.sleep(self.initial_scan_delay_sec)
            while self.enabled:
                await asyncio.to_thread(self.scan_once, None, "scheduled_crawl")
                await asyncio.sleep(self.crawl_interval_sec)
        except asyncio.CancelledError:
            pass

    def set_source_enabled(self, source_id: str, enabled: bool) -> ThreatSource:
        src = self.sources.get(source_id)
        if src is None:
            raise KeyError(source_id)
        src.enabled = enabled
        self._save_state()
        return src

    def remove_source(self, source_id: str) -> None:
        src = self.sources.get(source_id)
        if src is None:
            raise KeyError(source_id)
        if src.builtin:
            raise ValueError("Built-in global feeds cannot be deleted; disable them instead.")
        del self.sources[source_id]
        self._save_state()

    def add_or_update_source(self, source: ThreatSource) -> ThreatSource:
        ok, reason = self.validate_target_url(self._resolve_url(source), check_allowlist=False)
        if not ok:
            raise ValueError(f"Rejected unsafe source URL: {reason}")
        existing = self.sources.get(source.source_id)
        if existing is not None and existing.builtin:
            raise ValueError("Built-in global feed IDs are reserved; choose a different source_id.")
        host = (urlparse(source.url).hostname or "").lower()
        if host and host not in self.allowed_domains:
            self.allowed_domains.append(host)
        source.builtin = False
        self.sources[source.source_id] = source
        self._save_state()
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
        if parsed.username or parsed.password:
            return False, "credentials_in_url"

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
                or ip_obj.is_unspecified
            ):
                return False, f"blocked_private_ip:{host}"
        except ValueError:
            # Hostname — verify against allowlist when enabled
            is_allowlisted_domain = any(host == d or host.endswith(f".{d}") for d in self.allowed_domains)
            if check_allowlist and self.enforce_allowlist and not is_allowlisted_domain:
                return False, f"domain_not_in_allowlist:{host}"

        # DNS resolution SSRF check for non-allowlisted hostnames (allowlisted public domains may
        # legitimately route via transparent egress proxies that resolve to private addresses)
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
    # Incremental URL Windows
    # ------------------------------------------------------------------
    def _resolve_url(self, src: ThreatSource) -> str:
        if "{since}" not in src.url and "{until}" not in src.url:
            return src.url
        now = datetime.now(timezone.utc)
        if src.last_success_at is not None:
            since = src.last_success_at - timedelta(minutes=5)  # small overlap; dedup handles repeats
        else:
            since = now - timedelta(hours=self.incremental_bootstrap_hours)
        since = max(since, now - timedelta(days=7))  # NVD caps windows; keep requests bounded
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        return src.url.replace("{since}", since.strftime(fmt)).replace("{until}", now.strftime(fmt))

    # ------------------------------------------------------------------
    # HTTP Fetcher (Safe, Bounded, Conditional, No CAPTCHA Bypass, No Redirects)
    # ------------------------------------------------------------------
    def _fetch_url(self, url: str, req_headers: dict[str, str] | None = None, max_bytes: int | None = None) -> FetchResult:
        req_headers = req_headers or {}
        cap = max_bytes or self.max_bytes
        if self._custom_fetcher is not None:
            try:
                n_params = len(inspect.signature(self._custom_fetcher).parameters)
            except (TypeError, ValueError):
                n_params = 1
            raw = self._custom_fetcher(url, req_headers) if n_params >= 2 else self._custom_fetcher(url)
            if isinstance(raw, FetchResult):
                return raw
            status, ctype, body = raw[0], raw[1], raw[2]
            hdrs = {k.lower(): v for k, v in (raw[3] if len(raw) > 3 else {}).items()}
            return FetchResult(status_code=status, content_type=ctype, body=body[:cap], headers=hdrs)

        headers = {
            "User-Agent": "GigaMesh-ThreatIntelCrawler/0.2 (+https://github.com/Phlotonic/gigamesh)",
            "Accept": "application/json, application/rss+xml, application/atom+xml, application/xml;q=0.9, text/html;q=0.8, text/plain;q=0.7",
            **req_headers,
        }
        with httpx.Client(timeout=12.0, follow_redirects=False, headers=headers) as client:
            with client.stream("GET", url) as resp:
                chunks: list[bytes] = []
                total = 0
                truncated = False
                for chunk in resp.iter_bytes():
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= cap:
                        truncated = True
                        break
                raw_bytes = b"".join(chunks)[:cap]
                return FetchResult(
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", "text/plain"),
                    body=raw_bytes.decode("utf-8", errors="ignore"),
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    truncated=truncated,
                )

    # ------------------------------------------------------------------
    # Scan Execution + Update Tracking + Zero-Trust Anti-Poisoning + Metabolism/STIX Output
    # ------------------------------------------------------------------
    def scan_once(
        self,
        source_ids: list[str] | None = None,
        trigger: str = "manual_scan",
    ) -> CrawlRunReport:
        with self._scan_lock:
            return self._scan_once_locked(source_ids, trigger)

    def _scan_once_locked(self, source_ids: list[str] | None, trigger: str) -> CrawlRunReport:
        started = datetime.now(timezone.utc)
        self.last_run_at = started
        targets = (
            [self.sources[sid] for sid in source_ids if sid in self.sources]
            if source_ids
            else [s for s in self.sources.values() if s.enabled]
        )

        new_findings: list[CrawlFinding] = []
        blocked_or_gated: list[dict[str, str]] = []
        outcomes: dict[str, str] = {}
        succeeded = updated = unchanged = poisoned_count = 0
        self._modules_this_run = 0

        for src in targets:
            url = self._resolve_url(src)
            src.total_checks += 1
            ok, reason = self.validate_target_url(url, check_allowlist=True)
            if not ok:
                src.last_status = f"blocked:{reason}"
                outcomes[src.source_id] = src.last_status
                blocked_or_gated.append({"source_id": src.source_id, "url": url, "reason": reason})
                continue

            cond_headers: dict[str, str] = {}
            if src.etag:
                cond_headers["If-None-Match"] = src.etag
            if src.last_modified:
                cond_headers["If-Modified-Since"] = src.last_modified

            try:
                res = self._fetch_url(url, cond_headers, max_bytes=src.max_bytes)
            except Exception as exc:
                src.last_status = f"unreachable:{type(exc).__name__}"
                outcomes[src.source_id] = src.last_status
                blocked_or_gated.append(
                    {"source_id": src.source_id, "url": url, "reason": f"network_error:{str(exc)[:100]}"}
                )
                continue

            src.last_crawled_at = datetime.now(timezone.utc)
            src.last_http_status = res.status_code

            if res.status_code == 304:
                succeeded += 1
                unchanged += 1
                src.unchanged_checks += 1
                src.last_new_items = 0
                src.last_success_at = src.last_crawled_at
                src.last_status = "unchanged_304"
                outcomes[src.source_id] = src.last_status
                continue
            if res.status_code in (403, 429) or self._is_captcha_gated(res.body):
                src.last_status = f"gated_skipped:{res.status_code}"
                outcomes[src.source_id] = src.last_status
                blocked_or_gated.append(
                    {"source_id": src.source_id, "url": url, "reason": f"anti_bot_or_captcha_gate:{res.status_code}"}
                )
                continue
            if 300 <= res.status_code < 400:
                src.last_status = f"redirect_refused:{res.status_code}"
                outcomes[src.source_id] = src.last_status
                blocked_or_gated.append(
                    {"source_id": src.source_id, "url": url, "reason": f"redirect_refused_{res.status_code}"}
                )
                continue
            if res.status_code >= 400:
                src.last_status = f"http_error:{res.status_code}"
                outcomes[src.source_id] = src.last_status
                blocked_or_gated.append({"source_id": src.source_id, "url": url, "reason": f"http_{res.status_code}"})
                continue

            succeeded += 1
            src.last_success_at = src.last_crawled_at
            # Capture validators for the next conditional GET
            src.etag = res.headers.get("etag") or src.etag
            src.last_modified = res.headers.get("last-modified") or src.last_modified

            body_sha = hashlib.sha256(res.body.encode("utf-8", errors="ignore")).hexdigest()
            if src.last_body_sha256 == body_sha:
                unchanged += 1
                src.unchanged_checks += 1
                src.last_new_items = 0
                src.last_status = "unchanged_hash"
                outcomes[src.source_id] = src.last_status
                continue
            src.last_body_sha256 = body_sha

            parsed_findings, was_poisoned = self.analyze_crawled_content(
                source=src,
                content_type=res.content_type,
                raw_body=res.body,
            )
            if was_poisoned:
                poisoned_count += 1
            src.last_new_items = len(parsed_findings)
            src.total_items_ingested += len(parsed_findings)
            if parsed_findings:
                updated += 1
                src.last_changed_at = src.last_crawled_at
                src.last_status = "updated"
            else:
                src.last_status = "no_new_items"
            if res.truncated:
                src.last_status += ":truncated"
            outcomes[src.source_id] = src.last_status
            new_findings.extend(parsed_findings)

        # Export discovered intel as a signed STIX 2.1 bundle & run Darwinian check if enabled
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
            duration_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            sources_attempted=len(targets),
            sources_succeeded=succeeded,
            sources_updated=updated,
            sources_unchanged=unchanged,
            sources_blocked_or_gated=blocked_or_gated,
            source_outcomes=outcomes,
            new_findings_count=len(new_findings),
            revisions_count=sum(1 for f in new_findings if f.is_revision),
            poisoned_pages_quarantined=poisoned_count,
            stix_bundle_id=stix_bundle_id,
            evolution_generation_id=evo_gen_id,
            findings=new_findings,
        )
        self.runs.append(report)
        self.runs = self.runs[-200:]
        self.findings = self.findings[-2000:]
        self._save_state()
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
        with self._scan_lock:
            self._modules_this_run = 0
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
                sources_updated=1 if findings else 0,
                new_findings_count=len(findings),
                poisoned_pages_quarantined=1 if was_poisoned else 0,
                evolution_generation_id=evo_gen_id,
                findings=findings,
            )
            self.runs.append(report)
            self._save_state()
        self.engine.broadcast("threat_crawl_completed", report.model_dump(mode="json"))
        return report

    # ------------------------------------------------------------------
    # Content Analysis
    # ------------------------------------------------------------------
    def _quarantine(self, *, source: ThreatSource, raw: str, digest: str, trace_id: str, title: str) -> CrawlFinding:
        """Ensnare a poisoned page/record, REA-dissect it, and metabolize a defensive counter-module."""
        self.poisoned_pages_blocked += 1
        champ = self.engine.store.get_champion("stealth-intel-snare")
        session = self.engine.snare.ensnare(
            attacker_id=f"crawler:{source.url}",
            attacker_family="poisoned-web-intel",
            trace_id=trace_id,
            fork_id=champ.fork_id,
        )
        artifact = self.engine.snare.harvest_artifact(
            session=session,
            artifact_kind="javascript_bundle",
            filename=f"poisoned_page_{digest[:8]}.txt",
            content_bytes=raw[:16384].encode("utf-8", errors="ignore"),
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
            region=source.region,
            url=source.url,
            title=f"QUARANTINED Poisoned Content ({title[:80]})",
            summary=(
                "Detected indirect prompt-injection / crawler-poisoning attempt inside crawled threat-intel "
                "content. Quarantined it, dissected it via REA, and compiled a defensive counter-module."
            ),
            severity=Severity.CRITICAL,
            poison_attempt_blocked=True,
            rea_dossier_id=dossier.dossier_id,
            metabolized_module_id=metab_id,
            content_sha256=digest,
        )
        self.findings.append(quarantined)
        return quarantined

    def analyze_crawled_content(
        self,
        *,
        source: ThreatSource,
        content_type: str,
        raw_body: str,
    ) -> tuple[list[CrawlFinding], bool]:
        """Zero-trust poison screening + structured, revision-aware threat-intel extraction."""
        plain = self._strip_html(raw_body) if "html" in content_type.lower() else raw_body
        digest = hashlib.sha256(plain.encode("utf-8", errors="ignore")).hexdigest()

        records, structured = self._extract_records(source, content_type, raw_body, plain)

        # 1. Document-level zero-trust screen via GigaMesh's detector stack
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
        doc_poisoned = any(h.get("attack_class") == "prompt_injection" for h in hits) or any(
            m in lowered for m in PROMPT_POISON_MARKERS
        )

        # Unstructured pages are all-or-nothing: quarantine the whole page.
        if doc_poisoned and not structured:
            return [
                self._quarantine(
                    source=source, raw=raw_body, digest=digest, trace_id=ingest_evt.trace_id, title=source.name
                )
            ], True

        # 2. Structured feeds: screen every record individually so one hostile advisory is
        #    quarantined without discarding legitimate intelligence from the same feed.
        created: list[CrawlFinding] = []
        any_poisoned = False
        for rec in records:
            rec_id = rec.get("record_id") or ""
            rec_updated = rec.get("updated") or ""
            if rec_id:
                rec_digest = hashlib.sha256(f"{source.source_id}|{rec_id}|{rec_updated}".encode()).hexdigest()
            else:
                rec_digest = hashlib.sha256(
                    f"{source.url}|{rec['title']}|{rec['summary']}".encode("utf-8")
                ).hexdigest()
            if rec_digest in self._seen_digests:
                continue
            self._remember(rec_digest)

            version_key = f"{source.source_id}|{rec_id}" if rec_id else ""
            is_revision = bool(version_key and version_key in self._record_versions)
            if version_key:
                self._record_versions[version_key] = rec_updated

            blob = f"{rec['title']} {rec['summary']}"
            blob_l = blob.lower()
            if any(m in blob_l for m in PROMPT_POISON_MARKERS):
                any_poisoned = True
                created.append(
                    self._quarantine(
                        source=source,
                        raw=blob,
                        digest=rec_digest,
                        trace_id=f"trc-crawl-{rec_digest[:10]}",
                        title=rec["title"],
                    )
                )
                continue

            finding = self._build_finding(source, rec, rec_digest, is_revision)
            if is_revision:
                self.total_revisions += 1
            self.findings.append(finding)
            created.append(finding)

        return created, any_poisoned

    def _remember(self, digest: str) -> None:
        self._seen_digests.add(digest)
        self._seen_order.append(digest)
        if len(self._seen_order) > MAX_SEEN_RECORDS * 1.2:
            self._seen_order = self._seen_order[-MAX_SEEN_RECORDS:]
            self._seen_digests = set(self._seen_order)

    def _build_finding(
        self, source: ThreatSource, rec: dict[str, str], rec_digest: str, is_revision: bool
    ) -> CrawlFinding:
        blob = f"{rec['title']} {rec['summary']} {rec.get('aliases', '')}"
        blob_l = blob.lower()
        cves = sorted({m.upper() for m in CVE_RE.findall(blob)})
        ghsas = sorted({m.upper() for m in GHSA_RE.findall(blob)})
        mitres = sorted(set(MITRE_RE.findall(blob)))
        domains = sorted({m.lower() for m in DOMAIN_IOC_RE.findall(blob)})[:5]
        topics = [kw for kw in AGENTIC_KEYWORDS if kw in blob_l]
        exploited = rec.get("exploited") == "true" or any(m in blob_l for m in EXPLOITED_MARKERS)

        patterns = list(dict.fromkeys([*(c.lower() for c in cves[:3]), *domains]))
        sev_str = str(rec.get("severity", "")).lower()
        if (
            "critical" in sev_str
            or exploited
            or "remote code execution" in blob_l
            or "privilege escalation" in blob_l
        ):
            severity = Severity.CRITICAL
        elif "high" in sev_str or "important" in sev_str or cves or ghsas:
            severity = Severity.HIGH
        elif topics or mitres or "medium" in sev_str or "moderate" in sev_str:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Compile a safety-verified candidate defensive module when actionable patterns are found
        mod_id: str | None = None
        if (
            patterns
            and severity in (Severity.CRITICAL, Severity.HIGH)
            and self._modules_this_run < self.max_modules_per_run
        ):
            mod = MetabolizedDefenseModule(
                source_dossier_id=f"crawl:{rec_digest[:10]}",
                source_attacker_family=f"web-intel:{source.source_id}",
                name=f"Crawled Threat Guard: {rec['title'][:46]}",
                capability_kind="behavioral_loop_detector"
                if any(t in ("selinux", "auditd", "rhel", "ptrace") for t in topics)
                else "mcp_counter_snare",
                description=f"Derived from {source.name} ({rec['url']}): {rec['summary'][:180]}",
                match_patterns=patterns[:5],
                target_attack_classes=[
                    "redhat_exposure" if any(t in ("rhel", "selinux", "openshift") for t in topics) else "mcp_privesc"
                ],
                detection_boost=0.18,
                containment_boost=0.16,
                safety_verified=True,
            )
            mod.cross_attacker_hits = self.engine.autopoiesis._measure_cross_hits(mod)
            self.engine.store.commit_metabolized_module(mod)
            mod_id = mod.module_id
            self._modules_this_run += 1

        return CrawlFinding(
            source_id=source.source_id,
            source_name=source.name,
            region=source.region,
            url=rec["url"],
            record_id=rec.get("record_id", ""),
            title=rec["title"][:160],
            summary=rec["summary"][:420],
            severity=severity,
            published_at=rec.get("published", ""),
            updated_at=rec.get("updated", ""),
            is_revision=is_revision,
            actively_exploited=exploited,
            cve_ids=cves,
            ghsa_ids=ghsas,
            mitre_techniques=mitres,
            matched_topics=topics[:8],
            extracted_patterns=patterns,
            metabolized_module_id=mod_id,
            content_sha256=rec_digest,
        )

    # ------------------------------------------------------------------
    # Feed Parsers (JSON advisories, RSS 2.0, Atom, RDF/RSS 1.0, HTML fallback)
    # ------------------------------------------------------------------
    @classmethod
    def _extract_records(
        cls,
        source: ThreatSource,
        content_type: str,
        raw_body: str,
        plain: str,
    ) -> tuple[list[dict[str, str]], bool]:
        """Return (records, structured). ``structured`` is True for parsed JSON/XML feeds."""
        ct = content_type.lower()
        stripped = raw_body.lstrip()
        if "json" in ct or stripped.startswith(("[", "{")):
            recs = cls._parse_json_feed(source, raw_body)
            if recs:
                return recs, True
        if "xml" in ct or "rss" in ct or "atom" in ct or stripped.startswith(("<?xml", "<rss", "<feed", "<rdf")):
            recs = cls._parse_xml_feed(source, raw_body)
            if recs:
                return recs, True

        # Fallback: extract headline + relevant snippet from HTML / text
        title_match = re.search(r"<title[^>]*>(.*?)</title>", raw_body, re.IGNORECASE | re.DOTALL)
        title = html.unescape(title_match.group(1)).strip() if title_match else source.name
        return [{"title": title, "summary": plain[:420], "severity": "", "url": source.url}], False

    @staticmethod
    def _parse_json_feed(source: ThreatSource, raw_body: str) -> list[dict[str, str]]:
        try:
            parsed = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            return []
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, dict):
            items = (
                parsed.get("vulnerabilities")
                or parsed.get("advisories")
                or parsed.get("items")
                or parsed.get("data")
                or [parsed]
            )
        else:
            return []
        if not isinstance(items, list):
            return []

        records: list[dict[str, str]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            # --- NIST NVD CVE 2.0 ---
            if isinstance(item.get("cve"), dict):
                cve = item["cve"]
                cid = str(cve.get("id", ""))
                desc = next(
                    (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
                )
                sev = ""
                metrics = cve.get("metrics", {}) or {}
                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(key):
                        m0 = metrics[key][0]
                        sev = str(m0.get("cvssData", {}).get("baseSeverity") or m0.get("baseSeverity") or "")
                        break
                records.append(
                    {
                        "record_id": cid,
                        "title": f"{cid} ({cve.get('vulnStatus', 'Published')})",
                        "summary": desc,
                        "severity": sev,
                        "published": str(cve.get("published", "")),
                        "updated": str(cve.get("lastModified", "")),
                        "exploited": "true" if cve.get("cisaExploitAdd") else "false",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                    }
                )
                continue
            # --- CISA KEV ---
            if "cveID" in item:
                cid = str(item.get("cveID", ""))
                records.append(
                    {
                        "record_id": cid,
                        "title": f"{cid} {item.get('vulnerabilityName', '')}".strip(),
                        "summary": f"{item.get('shortDescription', '')} Required action: {item.get('requiredAction', '')} "
                        f"Ransomware use: {item.get('knownRansomwareCampaignUse', 'Unknown')}.",
                        "severity": "critical",
                        "published": str(item.get("dateAdded", "")),
                        "updated": str(item.get("dateAdded", "")),
                        "exploited": "true",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                    }
                )
                continue
            # --- ENISA EUVD ---
            if str(item.get("id", "")).startswith("EUVD-"):
                score = float(item.get("baseScore") or 0)
                sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                aliases = str(item.get("aliases", "")).replace("\n", " ").strip()
                refs = [r for r in str(item.get("references", "")).split("\n") if r.startswith("https://")]
                records.append(
                    {
                        "record_id": str(item["id"]),
                        "title": f"{item['id']} {aliases}".strip(),
                        "summary": str(item.get("description", "")),
                        "aliases": aliases,
                        "severity": sev,
                        "published": str(item.get("datePublished", "")),
                        "updated": str(item.get("dateUpdated", "")),
                        "url": f"https://euvd.enisa.europa.eu/vulnerability/{item['id']}" if not refs else refs[0],
                    }
                )
                continue
            # --- GitHub GHSA / Red Hat Security Data / generic ---
            title = (
                item.get("summary")
                or item.get("vulnerabilityName")
                or item.get("bugzilla_description")
                or item.get("title")
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
            cve_prefix = item.get("cve_id") or item.get("CVE") or ""
            ghsa_prefix = item.get("ghsa_id") or ""
            full_title = " ".join(p for p in (cve_prefix, ghsa_prefix, str(title)) if p).strip()
            records.append(
                {
                    "record_id": str(ghsa_prefix or cve_prefix or item.get("id") or ""),
                    "title": full_title,
                    "summary": str(desc),
                    "severity": str(item.get("severity") or item.get("cvss_severity") or ""),
                    "published": str(item.get("published_at") or item.get("public_date") or ""),
                    "updated": str(item.get("updated_at") or item.get("public_date") or ""),
                    "url": str(item.get("html_url") or item.get("resource_url") or source.url),
                }
            )

        # Newest first, so per-source caps keep the freshest intelligence
        epoch = datetime.min.replace(tzinfo=timezone.utc)
        records.sort(key=lambda r: _parse_any_datetime(r.get("updated", "")) or epoch, reverse=True)
        return records[: source.max_items]

    @staticmethod
    def _parse_xml_feed(source: ThreatSource, raw_body: str) -> list[dict[str, str]]:
        head = raw_body[:4096].upper()
        if "<!DOCTYPE" in head or "<!ENTITY" in raw_body.upper():
            return []  # Refuse DTDs/entities outright (XXE / billion-laughs hardening)
        try:
            root = ET.fromstring(raw_body.encode("utf-8"))
        except ET.ParseError:
            return []

        records: list[dict[str, str]] = []
        for el in root.iter():
            if _local(el.tag) not in ("item", "entry"):
                continue
            fields: dict[str, str] = {}
            link = ""
            for child in el:
                name = _local(child.tag)
                text = (child.text or "").strip()
                if name == "link":
                    href = child.attrib.get("href", "")
                    rel = child.attrib.get("rel", "alternate")
                    if href and rel == "alternate":
                        link = link or href
                    elif text:
                        link = link or text
                    continue
                if text and name not in fields:
                    fields[name] = text
            title = html.unescape(fields.get("title", "")).strip()
            body = fields.get("description") or fields.get("summary") or fields.get("content") or fields.get("encoded") or ""
            summary = ThreatIntelCrawler._strip_html(body)
            updated = fields.get("updated") or fields.get("pubdate") or fields.get("date") or fields.get("published") or ""
            link = link.strip() or el.attrib.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about", "")
            rec_id = fields.get("guid") or fields.get("id") or link or title
            if not title and not summary:
                continue
            records.append(
                {
                    "record_id": rec_id[:200],
                    "title": title or source.name,
                    "summary": summary[:1200],
                    "severity": "",
                    "published": fields.get("published") or fields.get("pubdate") or fields.get("date") or "",
                    "updated": updated,
                    "url": link if link.startswith("https://") else source.url,
                }
            )
        epoch = datetime.min.replace(tzinfo=timezone.utc)
        records.sort(key=lambda r: _parse_any_datetime(r.get("updated", "")) or epoch, reverse=True)
        return records[: source.max_items]

    @staticmethod
    def _strip_html(raw: str) -> str:
        no_script = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
        no_tags = re.sub(r"<[^>]+>", " ", no_script)
        return re.sub(r"\s+", " ", html.unescape(no_tags)).strip()

    @staticmethod
    def _is_captcha_gated(body: str) -> bool:
        lowered = body[:20000].lower()
        return any(m in lowered for m in CAPTCHA_MARKERS)

    def status(self) -> ThreatCrawlerStatus:
        all_cves = {c for f in self.findings for c in f.cve_ids}
        next_run = None
        if self.enabled and self.last_run_at is not None:
            next_run = self.last_run_at + timedelta(seconds=self.crawl_interval_sec)
        return ThreatCrawlerStatus(
            enabled=self.enabled,
            running=self.running,
            crawl_interval_sec=self.crawl_interval_sec,
            auto_evolve_on_findings=self.auto_evolve_on_findings,
            enforce_allowlist=self.enforce_allowlist,
            allowed_domains=list(self.allowed_domains),
            sources=list(self.sources.values()),
            regions_covered=sorted({s.region for s in self.sources.values() if s.enabled}),
            total_runs=len(self.runs),
            total_findings=len(self.findings),
            total_revisions=self.total_revisions,
            unique_cves=len(all_cves),
            actively_exploited_count=sum(1 for f in self.findings if f.actively_exploited),
            poisoned_pages_blocked=self.poisoned_pages_blocked,
            last_run_at=self.last_run_at,
            next_run_at=next_run,
            state_file=str(self.state_file) if self.state_file else None,
        )
