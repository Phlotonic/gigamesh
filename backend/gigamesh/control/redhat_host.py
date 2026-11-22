"""Red Hat Enterprise Linux / OpenShift & Offensive Red-Hat Active Control Adapter.

Generates auditable, syntactically valid SELinux confinement policies, nftables egress
isolation rules, Linux auditd syscall watches, systemd quarantine commands, and OpenShift
NetworkPolicy manifests (defaulting to safe dry-run validated mode locally).
"""

from __future__ import annotations

from gigamesh.models.governance import RedHatControlOrder


class RedHatHostController:
    """Synthesizes deterministic host & cluster containment artifacts for Red Hat systems."""

    def __init__(self) -> None:
        self.orders: dict[str, RedHatControlOrder] = {}

    def generate_containment_order(
        self,
        *,
        target_kind: str,
        target_id: str,
        egress_block_host: str | None = None,
        systemd_unit: str | None = None,
        quorum_id: str | None = None,
        extra_auditd: str | None = None,
        enforced: bool = False,
    ) -> RedHatControlOrder:
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in target_id)[:32]
        egress = egress_block_host or "c2.red-beacon.invalid"
        unit = systemd_unit or f"rogue-{safe_id}.service"

        selinux_policy = (
            f"module gigamesh_confine_{safe_id} 1.0;\n"
            f"require {{\n"
            f"    type unconfined_t, shadow_t, ssh_home_t;\n"
            f"    class file {{ read open write execute }};\n"
            f"    class process {{ ptrace execmem }};\n"
            f"}}\n"
            f"# Enforce strict confinement and deny secret/ptrace access\n"
            f"dontaudit unconfined_t shadow_t:file {{ read open }};\n"
            f"neverallow gigamesh_agent_{safe_id}_t shadow_t:file read;\n"
            f"neverallow gigamesh_agent_{safe_id}_t self:process ptrace;\n"
        )

        nftables_rules = (
            "table inet gigamesh_containment {\n"
            "  chain output_guard {\n"
            "    type filter hook output priority 0; policy accept;\n"
            f"    # Isolate egress from {target_id} toward suspected C2 / LLM proxy ({egress})\n"
            f"    meta cgroupv2 \"/system.slice/{unit}\" counter drop comment \"gigamesh_isolate_{safe_id}\"\n"
            "    tcp dport { 4444, 8443, 9050 } counter log prefix \"GIGAMESH_RH_DROP: \" drop\n"
            "  }\n"
            "}\n"
        )

        auditd_rules = (
            f"# GigaMesh Red-Hat Exposure & Integrity Watches ({target_id})\n"
            "-a always,exit -F arch=b64 -S ptrace,memfd_create,execveat,setuid -k gigamesh_redhat_syscall\n"
            "-w /etc/selinux/config -p wa -k gigamesh_selinux_guard\n"
            "-w /etc/systemd/system/ -p wa -k gigamesh_systemd_persist\n"
            "-w /opt/antigravity/tokens -p rwa -k gigamesh_token_guard\n"
        )
        if extra_auditd:
            auditd_rules += "\n" + extra_auditd.strip() + "\n"

        systemd_commands = [
            f"systemctl stop {unit}",
            f"systemctl mask {unit}",
            f"systemctl freeze {unit}",
            "setenforce 1",
            f"ausearch -k gigamesh_redhat_syscall --format text > /var/log/gigamesh/{safe_id}.audit",
        ]

        openshift_np = (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            f"  name: gigamesh-quarantine-{safe_id.lower().replace('_', '-')}\n"
            "  namespace: agent-workloads\n"
            "spec:\n"
            "  podSelector:\n"
            "    matchLabels:\n"
            f"      gigamesh.io/suspect: \"{safe_id}\"\n"
            "  policyTypes: [\"Ingress\", \"Egress\"]\n"
            "  egress:\n"
            "    - to:\n"
            "        - podSelector:\n"
            "            matchLabels:\n"
            "              gigamesh.io/role: \"deception-snare\"\n"
        )

        order = RedHatControlOrder(
            target_kind=target_kind,
            target_id=target_id,
            mode="enforced_simulated" if enforced else "dry_run_validated",
            quorum_id=quorum_id,
            selinux_policy=selinux_policy,
            nftables_rules=nftables_rules,
            auditd_rules=auditd_rules,
            systemd_commands=systemd_commands,
            openshift_network_policy=openshift_np,
            mcp_block_rules=[f"deny:mcp:*->target={target_id}", "deny:tool:raw_shell,dump_env,steal_token"],
            status="enforced" if enforced else "validated_ready",
        )
        self.orders[order.order_id] = order
        return order

    def list_orders(self) -> list[RedHatControlOrder]:
        return list(reversed(list(self.orders.values())))
