"""Metabolism Compiler: transforms REA Evidence Dossiers into sanitized defensive modules.

Every attacker inner working dissected by REA (obfuscation stagers, hidden MCP tool
schemas, red-hat recon-exploit loop cadences, persistence droppers) is metabolized into
purely in-perimeter defensive capabilities—detectors, decoders, synthetic counter-snares,
and RHEL/OpenShift hardening rules—ready to be forked, cross-tested against DIFFERENT
attackers, and promoted via Darwinian selection + Human Quorum.
"""

from __future__ import annotations

from gigamesh.models.rea import MetabolizedDefenseModule, ReaEvidenceDossier

FORBIDDEN_OFFENSIVE_PATTERNS = (
    "rm -rf /",
    "reverse_shell",
    "exploit_remote",
    "ddos",
    "hack_back",
)


class MetabolismCompiler:
    """Compiles REA Evidence into verified, reusable defensive modules."""

    def compile(self, dossier: ReaEvidenceDossier) -> list[MetabolizedDefenseModule]:
        if not dossier.evidence_items:
            return []

        categories = {item.category for item in dossier.evidence_items}
        patterns = [item.extracted_pattern for item in dossier.evidence_items if item.extracted_pattern]
        modules: list[MetabolizedDefenseModule] = []

        # 1. Obfuscation / stager -> Canonical De-Obfuscation & Prompt-Injection Decoder
        if "obfuscation" in categories:
            mod = MetabolizedDefenseModule(
                source_dossier_id=dossier.dossier_id,
                source_attacker_family=dossier.attacker_family,
                name=f"De-Obfuscator & Taint Decoder ({dossier.attacker_family})",
                capability_kind="decoder_preprocessor",
                description=(
                    f"Metabolized from REA JS/payload dissection of {dossier.attacker_family}: "
                    "decodes base64/hidden-unicode stagers before prompt & tool evaluation, "
                    "generalizing across indirect prompt-injection families."
                ),
                match_patterns=self._safe_patterns(patterns + [r"(?:b64|enc|payload):[A-Za-z0-9+/=]{16,}"]),
                target_attack_classes=["prompt_injection", "lateral_movement"],
                detection_boost=0.26,
                containment_boost=0.20,
                snare_bait_templates=["SYNTHETIC_DOC_TRAP: advertise fake internal prompt token to expose decoder bypass"],
            )
            modules.append(self._verify_safety(mod))

        # 2. Rogue MCP / tool schema -> MCP Policy Signature + Counter-Snare
        if "tool_schema" in categories:
            mod = MetabolizedDefenseModule(
                source_dossier_id=dossier.dossier_id,
                source_attacker_family=dossier.attacker_family,
                name=f"MCP Protocol Counter-Snare ({dossier.attacker_family})",
                capability_kind="mcp_counter_snare",
                description=(
                    f"Metabolized from REA protocol inversion of {dossier.attacker_family}: "
                    "intercepts covert MCP capability escalations and advertises realistic decoy "
                    "tools to ensnare unrelated autonomous swarms."
                ),
                match_patterns=self._safe_patterns(patterns + ["x-agent-escalate", "shadow-mcp", "delegate_root"]),
                target_attack_classes=["mcp_privesc", "lateral_movement"],
                detection_boost=0.24,
                containment_boost=0.24,
                snare_bait_templates=[
                    "DECOY_MCP_TOOL: shadow_token_exchange (returns tracked canary JWT)",
                    "DECOY_MCP_PEER: ops-cluster-admin-agent (records lateral delegation chain)",
                ],
            )
            modules.append(self._verify_safety(mod))

        # 3. C2 / Evasion loop / Red-Hat native implant -> Behavioral Loop Counter & Tarpit
        if "c2_protocol" in categories or "evasion_loop" in categories or "syscall_pattern" in categories:
            mod = MetabolizedDefenseModule(
                source_dossier_id=dossier.dossier_id,
                source_attacker_family=dossier.attacker_family,
                name=f"Red-Hat Loop Counter & RHEL Shield ({dossier.attacker_family})",
                capability_kind="behavioral_loop_detector",
                description=(
                    f"Metabolized from REA native/C2 dissection of {dossier.attacker_family}: "
                    "fingerprints machine-speed recon-exploit loops, covert LLM-proxy relays, "
                    "and RHEL syscall/SELinux tampering across diverse red-hat actors."
                ),
                match_patterns=self._safe_patterns(
                    patterns + ["llm-proxy", "c2\\.", "setenforce 0", "auditctl -d", "ptrace", "memfd_create"]
                ),
                target_attack_classes=["redhat_exposure", "mcp_privesc"],
                detection_boost=0.25,
                containment_boost=0.26,
                snare_bait_templates=["DECOY_C2_ACK: serve canary OpenShift kubeconfig manifest"],
                rhel_hardening_snippet=(
                    "# Metabolized RHEL auditd + SELinux guard\n"
                    "-a always,exit -F arch=b64 -S ptrace,memfd_create,execveat -k gigamesh_redhat_guard\n"
                    "-w /etc/selinux/config -p wa -k gigamesh_selinux_tamper\n"
                ),
            )
            modules.append(self._verify_safety(mod))

        # 4. Persistence / SQLite memory poisoning -> Persistence Integrity Guard
        if "persistence" in categories:
            mod = MetabolizedDefenseModule(
                source_dossier_id=dossier.dossier_id,
                source_attacker_family=dossier.attacker_family,
                name=f"Memory & Systemd Persistence Guard ({dossier.attacker_family})",
                capability_kind="persistence_guard",
                description=(
                    f"Metabolized from REA SQLite/unit dissection of {dossier.attacker_family}: "
                    "detects sleeper prompt triggers, poisoned memory tables, and rogue systemd timers."
                ),
                match_patterns=self._safe_patterns(
                    patterns + ["silent_beacon", "always exfiltrate", "onbootsec", "hidden trigger"]
                ),
                target_attack_classes=["goal_hijacking_persistence", "redhat_exposure"],
                detection_boost=0.24,
                containment_boost=0.22,
                rhel_hardening_snippet=(
                    "# Metabolized systemd persistence watch\n"
                    "-w /etc/systemd/system/ -p wa -k gigamesh_systemd_persist\n"
                ),
            )
            modules.append(self._verify_safety(mod))

        # Fallback generic module if REA produced custom/live findings
        if not modules:
            mod = MetabolizedDefenseModule(
                source_dossier_id=dossier.dossier_id,
                source_attacker_family=dossier.attacker_family,
                name=f"Adaptive Counter-Signature ({dossier.attacker_family})",
                capability_kind="behavioral_loop_detector",
                description=f"Metabolized defensive signature compiled from REA dossier {dossier.dossier_id}.",
                match_patterns=self._safe_patterns(patterns),
                target_attack_classes=["redhat_exposure", "prompt_injection"],
                detection_boost=0.20,
                containment_boost=0.18,
            )
            modules.append(self._verify_safety(mod))

        return modules

    @staticmethod
    def _safe_patterns(patterns: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for p in patterns:
            if not p or p in seen:
                continue
            if any(bad in p.lower() for bad in FORBIDDEN_OFFENSIVE_PATTERNS):
                continue
            seen.add(p)
            cleaned.append(p)
        return cleaned[:10]

    @staticmethod
    def _verify_safety(mod: MetabolizedDefenseModule) -> MetabolizedDefenseModule:
        blob = " ".join([mod.description, *mod.match_patterns, *mod.snare_bait_templates]).lower()
        if any(bad in blob for bad in FORBIDDEN_OFFENSIVE_PATTERNS):
            mod.safety_verified = False
            mod.safety_notes = "Blocked by static defensive safety invariant."
        else:
            mod.safety_verified = True
            mod.safety_notes = "Verified strictly in-perimeter defensive capability; safe for shadow A/B testing."
        return mod
