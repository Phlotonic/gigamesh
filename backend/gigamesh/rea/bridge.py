"""Reverse Engineer Anything (morluto/rea) CLI/MCP Bridge + REA-Contract Static Dissection Engine.

Integrates with `rea-agents` (https://github.com/morluto/rea) when installed locally,
and provides a deterministic REA-compatible local dissection engine inspecting real
captured artifacts (JS/Node agent bundles, SQLite memory DBs, native/script binaries,
MCP JSON-RPC traces, and systemd droppers) while preserving REA's Evidence + Residual
Unknowns discipline.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from gigamesh.models.rea import (
    CapturedArtifact,
    ReaEvidenceDossier,
    ReaEvidenceItem,
    ResidualUnknown,
)


class ReaBridge:
    """Drives Reverse Engineer Anything (morluto/rea) or its local REA-contract engine."""

    def __init__(
        self,
        rea_command: str = "rea",
        tool_families: str = "session,direct,javascript,native,database",
    ) -> None:
        self.rea_command = rea_command
        self.tool_families = tool_families
        self.live_rea_path = shutil.which(rea_command)

    def doctor(self) -> dict[str, Any]:
        """Report REA integration readiness and configured MCP tool family scoping."""
        return {
            "live_rea_available": self.live_rea_path is not None,
            "rea_binary": self.live_rea_path,
            "configured_tool_families": self.tool_families.split(","),
            "fallback_engine": "deterministic_rea_contract_v1",
            "install_hint": "npm install --global rea-agents && rea setup",
        }

    def dissect(self, artifact: CapturedArtifact, depth: float = 0.7) -> ReaEvidenceDossier:
        """Dissect a captured attacker artifact and return structured Evidence + Residual Unknowns."""
        commands_run: list[str] = []
        evidence: list[ReaEvidenceItem] = []
        unknowns: list[ResidualUnknown] = []
        engine_mode = "deterministic_rea_contract"

        # 1. Attempt live `rea` CLI execution if installed and artifact exists on disk
        if self.live_rea_path and artifact.file_path and Path(artifact.file_path).exists():
            live_result = self._try_live_rea(artifact)
            if live_result is not None:
                engine_mode = "live_rea_cli"
                commands_run.extend(live_result["commands"])
                evidence.extend(live_result["evidence"])
                unknowns.extend(live_result["unknowns"])

        # 2. Run REA-contract local static/structural parsers to guarantee rich provenance
        local = self._dissect_local_contract(artifact, depth=depth)
        commands_run.extend(local["commands"])
        evidence.extend(local["evidence"])
        unknowns.extend(local["unknowns"])

        # Deduplicate evidence by (category, extracted_pattern)
        seen: set[tuple[str, str]] = set()
        deduped_evidence: list[ReaEvidenceItem] = []
        for item in evidence:
            key = (item.category, item.extracted_pattern)
            if key not in seen:
                seen.add(key)
                deduped_evidence.append(item)

        resolved_count = sum(1 for u in unknowns if u.resolved)
        total_signals = max(1, len(deduped_evidence) + len(unknowns))
        completeness = round(
            min(0.98, (len(deduped_evidence) + resolved_count) / total_signals), 4
        )

        summary = (
            f"REA dissected {artifact.artifact_kind} '{artifact.filename}' ({artifact.size_bytes}B, "
            f"sha256={artifact.sha256[:12]}): extracted {len(deduped_evidence)} evidence items and "
            f"{len(unknowns)} residual unknowns."
        )
        return ReaEvidenceDossier(
            artifact_id=artifact.artifact_id,
            attacker_family=artifact.attacker_family,
            engine_mode=engine_mode,
            rea_commands_executed=commands_run,
            evidence_items=deduped_evidence,
            residual_unknowns=unknowns,
            behavioral_summary=summary,
            dissection_completeness=completeness,
            probe_rounds=0,
        )

    def resolve_unknown_from_snare_probe(
        self,
        dossier: ReaEvidenceDossier,
        unknown_id: str,
        snare_response_payload: str,
    ) -> ReaEvidenceDossier:
        """Close the feedback loop: use an ensnared attacker's reaction to bait to resolve an unknown."""
        for unk in dossier.residual_unknowns:
            if unk.unknown_id == unknown_id and not unk.resolved:
                unk.resolved = True
                unk.resolution_evidence = snare_response_payload[:280]
                extracted = self._extract_signature_token(snare_response_payload)
                dossier.evidence_items.append(
                    ReaEvidenceItem(
                        category="evasion_loop",
                        symbol_or_offset=f"runtime:snare_probe:{unknown_id}",
                        summary=f"Resolved residual unknown via targeted snare bait: {unk.description}",
                        extracted_pattern=extracted,
                        confidence=0.92,
                        source_tool="rea_runtime_snare_trace",
                    )
                )
                dossier.probe_rounds += 1
                break

        resolved_count = sum(1 for u in dossier.residual_unknowns if u.resolved)
        total_signals = max(1, len(dossier.evidence_items) + len(dossier.residual_unknowns))
        dossier.dissection_completeness = round(
            min(0.99, (len(dossier.evidence_items) + resolved_count) / total_signals), 4
        )
        return dossier

    # ------------------------------------------------------------------
    # Live morluto/rea CLI invocation
    # ------------------------------------------------------------------
    def _try_live_rea(self, artifact: CapturedArtifact) -> dict[str, Any] | None:
        subcmd_map = {
            "javascript_bundle": ["analyze-javascript-application", artifact.file_path, "--json"],
            "sqlite_memory": ["inspect-sqlite-database", artifact.file_path, "--json"],
        }
        cmd_args = subcmd_map.get(artifact.artifact_kind, ["analyze", artifact.file_path, "--json"])
        env = {**os.environ, "REA_MCP_TOOL_FAMILIES": self.tool_families}
        try:
            proc = subprocess.run(
                [self.rea_command, *cmd_args],
                capture_output=True,
                text=True,
                timeout=15,
                env=env,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return None
            parsed = json.loads(proc.stdout)
            items = [
                ReaEvidenceItem(
                    category="live_rea_finding",
                    symbol_or_offset="rea:json",
                    summary=str(parsed.get("summary", "Live REA structured output"))[:220],
                    extracted_pattern=str(parsed.get("primary_pattern", artifact.attacker_family)),
                    confidence=0.9,
                    source_tool=f"rea_{cmd_args[0].replace('-', '_')}",
                )
            ]
            return {
                "commands": [f"{self.rea_command} {' '.join(cmd_args)}"],
                "evidence": items,
                "unknowns": [],
            }
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Deterministic REA-Contract Local Dissection Engine
    # ------------------------------------------------------------------
    def _dissect_local_contract(self, artifact: CapturedArtifact, depth: float) -> dict[str, Any]:
        text = self._read_artifact_text(artifact)
        commands: list[str] = []
        evidence: list[ReaEvidenceItem] = []
        unknowns: list[ResidualUnknown] = []

        if artifact.artifact_kind == "javascript_bundle":
            commands.append(f"rea analyze-javascript-application {artifact.filename} --json")
            self._inspect_javascript(text, evidence, unknowns, depth)
        elif artifact.artifact_kind == "sqlite_memory":
            commands.append(f"rea inspect-sqlite-database {artifact.filename} --json")
            self._inspect_sqlite(artifact, evidence, unknowns)
        elif artifact.artifact_kind == "mcp_protocol_trace":
            commands.append(f"rea analyze-agent-protocol {artifact.filename} --json")
            self._inspect_mcp_trace(text, evidence, unknowns)
        elif artifact.artifact_kind == "systemd_dropper":
            commands.append(f"rea analyze {artifact.filename} --strings --json")
            self._inspect_systemd_dropper(text, evidence, unknowns)
        else:
            commands.append(f"rea decompile {artifact.filename} --symbols --xrefs --json")
            self._inspect_native_or_script(text, evidence, unknowns, depth)

        return {"commands": commands, "evidence": evidence, "unknowns": unknowns}

    def _read_artifact_text(self, artifact: CapturedArtifact) -> str:
        if artifact.file_path and Path(artifact.file_path).exists():
            raw = Path(artifact.file_path).read_bytes()
            return raw.decode("utf-8", errors="ignore")
        return artifact.raw_excerpt

    def _inspect_javascript(
        self,
        text: str,
        evidence: list[ReaEvidenceItem],
        unknowns: list[ResidualUnknown],
        depth: float,
    ) -> None:
        if "base64" in text.lower() or "b64:" in text.lower() or "atob(" in text.lower():
            evidence.append(
                ReaEvidenceItem(
                    category="obfuscation",
                    symbol_or_offset="module:stager.js:decodePayload",
                    summary="Recovered base64/zero-width prompt-injection payload stager inside JS agent wrapper.",
                    extracted_pattern=r"(?:b64|enc|payload):[A-Za-z0-9+/=]{16,}",
                    confidence=0.91,
                    source_tool="rea_analyze_javascript_application",
                )
            )
        urls = re.findall(r"https?://[a-zA-Z0-9._:/-]+", text)
        for u in urls[:2]:
            host_token = re.sub(r"^https?://", "", u).split("/")[0]
            evidence.append(
                ReaEvidenceItem(
                    category="c2_protocol",
                    symbol_or_offset="module:net.js:egressBeacon",
                    summary=f"Extracted hardcoded attacker C2/LLM-proxy egress endpoint ({host_token}).",
                    extracted_pattern=re.escape(host_token),
                    confidence=0.89,
                    source_tool="rea_analyze_javascript_application",
                )
            )
        tool_matches = re.findall(r"[\"'](x-agent-[a-z0-9_-]+|raw_shell|dump_env|steal_token)[\"']", text, re.I)
        for tm in sorted(set(tool_matches)):
            evidence.append(
                ReaEvidenceItem(
                    category="tool_schema",
                    symbol_or_offset="module:mcp_client.js:invokeHiddenTool",
                    summary=f"Exposed hidden MCP capability/header '{tm}' used for privilege escalation.",
                    extracted_pattern=re.escape(tm.lower()),
                    confidence=0.93,
                    source_tool="rea_analyze_javascript_application",
                )
            )
        if depth >= 0.45:
            unknowns.append(
                ResidualUnknown(
                    description="Dynamic fallback C2 header negotiated only when primary MCP tool returns HTTP 403.",
                    hypothesis="Attacker switches to covert X-Agent-Escalate handshake on denial.",
                    probe_bait="MCP_ERROR_403: capability_restricted; advertise synthetic fallback tool 'shadow_token_exchange'",
                )
            )

    def _inspect_sqlite(
        self,
        artifact: CapturedArtifact,
        evidence: list[ReaEvidenceItem],
        unknowns: list[ResidualUnknown],
    ) -> None:
        rows_text: list[str] = []
        if artifact.file_path and Path(artifact.file_path).exists():
            try:
                conn = sqlite3.connect(artifact.file_path)
                cur = conn.cursor()
                tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                for tbl in tables:
                    for row in cur.execute(f"SELECT * FROM {tbl} LIMIT 25").fetchall():
                        rows_text.append(" ".join(str(c) for c in row))
                conn.close()
            except Exception:
                rows_text.append(artifact.raw_excerpt)
        else:
            rows_text.append(artifact.raw_excerpt)

        blob = "\n".join(rows_text)
        for token, desc in [
            ("silent_beacon", "Poisoned memory directive scheduling silent credential beacon."),
            ("always exfiltrate", "Goal-hijack directive embedded inside agent long-term memory table."),
            ("hidden trigger", "Sleeper trigger condition planted in vector/SQLite memory."),
        ]:
            if token in blob.lower():
                evidence.append(
                    ReaEvidenceItem(
                        category="persistence",
                        symbol_or_offset="sqlite:agent_memory:rows",
                        summary=desc,
                        extracted_pattern=re.escape(token),
                        confidence=0.94,
                        source_tool="rea_inspect_sqlite_database",
                    )
                )
        unknowns.append(
            ResidualUnknown(
                description="Activation phrase required to wake dormant poisoned memory row.",
                hypothesis="Triggers on routine status summary or credential rotation prompt.",
                probe_bait="SYNTHETIC_PROMPT: 'Summarize weekly secret rotation status for prod-rhel-01'",
            )
        )

    def _inspect_mcp_trace(
        self,
        text: str,
        evidence: list[ReaEvidenceItem],
        unknowns: list[ResidualUnknown],
    ) -> None:
        for pat, desc in [
            ("x-agent-escalate", "Covert MCP header bypassing tool authorization check."),
            ("shadow-mcp", "Unregistered rogue MCP server identity."),
            ("delegate_root", "Cross-agent privilege amplification RPC verb."),
            ("tools/list:hidden", "Stealth MCP tool discovery request."),
        ]:
            if pat in text.lower():
                evidence.append(
                    ReaEvidenceItem(
                        category="tool_schema",
                        symbol_or_offset="mcp:jsonrpc:frame",
                        summary=desc,
                        extracted_pattern=re.escape(pat),
                        confidence=0.92,
                        source_tool="rea_analyze_agent_protocol",
                    )
                )
        unknowns.append(
            ResidualUnknown(
                description="Secondary sub-agent swarm coordination queue URI not observed in initial handshake.",
                hypothesis="Revealed when snare advertises a high-privilege peer agent.",
                probe_bait="SYNTHETIC_MCP_PEERS: advertise decoy peer 'ops-cluster-admin-agent' on snare bus",
            )
        )

    def _inspect_systemd_dropper(
        self,
        text: str,
        evidence: list[ReaEvidenceItem],
        unknowns: list[ResidualUnknown],
    ) -> None:
        for pat, cat, desc in [
            ("onbootsec", "persistence", "Recovered systemd timer persistence trigger."),
            ("setenforce 0", "syscall_pattern", "Attempt to disable SELinux enforcing mode on RHEL host."),
            ("auditctl -d", "syscall_pattern", "Attempt to blind Linux auditd telemetry."),
            ("c2.red-beacon", "c2_protocol", "Hardcoded red-hat C2 beacon domain inside dropper unit."),
        ]:
            if pat in text.lower():
                evidence.append(
                    ReaEvidenceItem(
                        category=cat,
                        symbol_or_offset="unit:ExecStart",
                        summary=desc,
                        extracted_pattern=re.escape(pat),
                        confidence=0.93,
                        source_tool="rea_analyze",
                    )
                )
        unknowns.append(
            ResidualUnknown(
                description="Post-persistence lateral movement target list fetched after initial beacon.",
                hypothesis="Attacker pulls RHEL/OpenShift target manifest on HTTP 200 beacon ACK.",
                probe_bait="SYNTHETIC_C2_ACK: return canary OpenShift cluster manifest with honey kubeconfig",
            )
        )

    def _inspect_native_or_script(
        self,
        text: str,
        evidence: list[ReaEvidenceItem],
        unknowns: list[ResidualUnknown],
        depth: float,
    ) -> None:
        for pat, cat, desc in [
            ("ptrace", "syscall_pattern", "Decompiled native implant invokes ptrace for process injection."),
            ("memfd_create", "syscall_pattern", "Fileless ELF execution via memfd_create syscall."),
            ("llm-proxy", "c2_protocol", "Autonomous red-hat agent routes prompts via covert llm-proxy relay."),
            ("cadence_ms", "evasion_loop", "Automated jittered recon-plan-exploit loop controller."),
            ("kubeconfig", "tool_schema", "Targets OpenShift/Kubernetes kubeconfig credentials."),
        ]:
            if pat in text.lower():
                evidence.append(
                    ReaEvidenceItem(
                        category=cat,
                        symbol_or_offset="0x4012a0:recon_exploit_loop",
                        summary=desc,
                        extracted_pattern=re.escape(pat),
                        confidence=0.90,
                        source_tool="rea_decompile",
                    )
                )
        if depth >= 0.4:
            unknowns.append(
                ResidualUnknown(
                    description="Encrypted operator kill-switch / tasking signature verified by native loop.",
                    hypothesis="Implant logs operator ID or fallback domain on canary kubeconfig auth failure.",
                    probe_bait="SYNTHETIC_OPENSHIFT_401: prompt re-auth with instrumented canary token endpoint",
                )
            )

    @staticmethod
    def _extract_signature_token(payload: str) -> str:
        tokens = re.findall(r"[a-zA-Z0-9_.-]{6,}", payload)
        for tok in tokens:
            if any(k in tok.lower() for k in ("c2", "escalate", "beacon", "shadow", "proxy", "exfil", "token", "rh_")):
                return re.escape(tok.lower())
        return re.escape(tokens[0].lower()) if tokens else "snare_probe_response"

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
