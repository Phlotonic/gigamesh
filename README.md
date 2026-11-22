# GigaMesh

**Non-Linear, Self-Evolving, Human-Aggregated Agentic SIEM**

GigaMesh aggregates human security intelligence, causal multi-hop provenance tracing, Red-Hat exposure/control, and **Reverse Engineer Anything ([`morluto/rea`](https://github.com/morluto/rea))** into a **non-linear evolutionary defense system** whose Git repository functions as an **immutable neural/neutral network**.

Every defensive option is exhaustively benchmarked across multi-attacker and benign workloads. **Only options that achieve strictly higher success rates survive**; inferior or false-positive-violating forks are archived as immutable Git tombstones (`culled/<fork_id>`).

---

## Core Architecture

| Subsystem | Module | Responsibility |
| :--- | :--- | :--- |
| **Immutable Git Neural Repo** | `backend/gigamesh/neural_repo/git_store.py` | Real Git DAG storing immutable fork manifests (`forks/*.yaml`), metabolized REA modules (`modules/*.json`), and SHA-256 Merkle-chained empirical weight ledgers (`ledger/neural_weights.jsonl`). |
| **Mutual Genome Sync Firewall** | `backend/gigamesh/neural_repo/sync_firewall.py` | Zero-trust bidirectional sync between local `genome_repo/` and GitHub's isolated `genome-sync` branch. Outbound blocks tampered ledgers, secret/token leaks (DLP), and FP-violating forks; inbound quarantines remote payloads, enforces strict path/manifest/Merkle checks, and independently re-benchmarks every fork locally so forged remote scores cannot contaminate the local node. |
| **Contextual MoE Router** | `backend/gigamesh/neural_repo/router.py` | Thompson Sampling router selecting active + shadow A/B forks per use case (`enterprise-balanced`, `stealth-intel-snare`, `zero-trust-critical`, `rhel-openshift-fortress`), dynamically shifting under elevated human-identity risk. |
| **Causal Provenance Graph** | `backend/gigamesh/provenance/graph.py` | NetworkX multi-hop graph linking `Human → Delegation → Agent → SubAgent → MCP Tool → RHEL Host → Egress`, propagating taint and tracing patient zero & blast radius. |
| **Modular Detection Suite** | `backend/gigamesh/detectors/` | Prompt Injection & Taint-to-Tool, Rogue MCP/PrivEsc, Multi-Agent Lateral Movement, Goal Hijacking & Persistence, and Dual Red-Hat Exposure (offensive agent loops + RHEL `auditd`/SELinux/OpenShift). |
| **REA Dissection & Metabolism** | `backend/gigamesh/rea/` | Bridges to `morluto/rea` (`rea-agents` CLI/MCP with scoped `REA_MCP_TOOL_FAMILIES`) plus a deterministic REA-contract static engine. Dissects ensnared attacker artifacts, resolves residual unknowns via targeted snare bait probes, and compiles attacker inner workings into verified defensive modules tested for cross-attacker immunity. |
| **Darwinian Autopoiesis** | `backend/gigamesh/evolution/` | Perpetual autonomous evolution loop: harvests ensnared artifacts → REA dissects → metabolizes → spawns recursive A/B trade-off forks → benchmarks every candidate → promotes strict winners & culls losers in perpetuity. |
| **Human Security Hub** | `backend/gigamesh/human_sec/hub.py` | Collective analyst voting & rule synthesis, human-identity risk correlation (MFA/phishing/OAuth), cryptographic M-of-N HITL quorum gates, and signed STIX 2.1 federated motif exchange. |
| **Active Control Plane** | `backend/gigamesh/control/` | Adaptive Deception Snare & forensic harvester, Dynamic MCP Policy Proxy & kill-switch, and Red-Hat Host Controller generating SELinux, `nftables`, `auditd`, `systemd`, and OpenShift `NetworkPolicy` containment artifacts. |
| **Email Vulnerability Listener** | `backend/gigamesh/integrations/email_listener.py` | Event-driven Gmail History/PubSub listener triaging security disclosures through zero-trust prompt-injection detection first: ensnares & REA-dissects hostile emails, opens HITL Quorums for critical/contamination reports, synthesizes RHEL hardening orders, and prepares human-reviewable Markdown Gmail drafts (never auto-sends unattended). |

---

## Quickstart

### 1. Run the Test Suite
```bash
PYTHONPATH=/home/antigravity/gigamesh/backend /home/antigravity/gigamesh/.venv/bin/pytest -v backend/tests
```

### 2. Run the Backend API & Live SOC Command Center
```bash
# Build frontend
cd frontend && npm run build && cd ..

# Launch GigaMesh (serves both REST/WebSocket API and built SOC UI on port 8000)
PYTHONPATH=/home/antigravity/gigamesh/backend /home/antigravity/gigamesh/.venv/bin/uvicorn gigamesh.api.server:app --host 0.0.0.0 --port 8000
```

### 3. Optional: Attach Live `morluto/rea` (`rea-agents`)
```bash
npm install --global rea-agents
rea doctor
```
When `rea` is present on `PATH`, `ReaBridge` automatically uses live `rea` CLI invocations scoped by `REA_MCP_TOOL_FAMILIES`; otherwise it runs its deterministic REA-contract local dissection engine seamlessly.

---

## Licensing & Commercial Use

**Copyright (C) 2026 Adam Dryden and Quanumis Systems.**

- **Open Source Code (`main`)**: Dual-licensed under **GNU AGPL-3.0** ([`LICENSE`](./LICENSE)) for open-source mutual research & development.
- **Commercial Dual-License & Enterprise Genome Feeds**: Organizations requiring proprietary modifications without AGPL-3.0 obligations, real-time zero-day metabolized genome feeds, or enterprise fleet add-ons can obtain a commercial license from **Quanumis Systems** — see [`COMMERCIAL_LICENSE.md`](./COMMERCIAL_LICENSE.md) or email [adryden508@gmail.com](mailto:adryden508@gmail.com).
- **Community Genome Data (`genome-sync`)**: Licensed under **CC-BY-SA-4.0** (see `DATA_LICENSE` on the `genome-sync` branch).
- **Contributions & CLA**: See [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **Defensive Scope & Security**: See [`DISCLAIMER.md`](./DISCLAIMER.md) and [`SECURITY.md`](./SECURITY.md).

