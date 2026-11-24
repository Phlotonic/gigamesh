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
| **Threat Intel Web Crawler** | `backend/gigamesh/integrations/threat_crawler.py` | Toggle-able, SSRF-hardened 10-feed multi-region threat crawler (GHSA, NIST NVD, CISA KEV, Red Hat, ENISA EUVD, CERT-EU, UK NCSC, JPCERT/CC, Canada CCCS, SANS ISC) with HTTP `304`/ETag delta sync and per-record poison quarantine. |
| **OWASP Triple-Framework Defense** | `backend/gigamesh/benchmarks/owasp_benchmark.py` + `detectors/owasp_agentic_guard.py` | Live 30-category benchmark covering OWASP Agentic AI 2026 (`ASI01`–`ASI10`), LLM 2025 (`LLM01`–`LLM10`), and Web 2025 (`A01`–`A10`) achieving **30/30 (100%) with 0% benign false positives**, backed by an Agentic Circuit Breaker and Hash-Chained Security Audit Log. |
| **Security-First Unified Namespace (S-UNS)** | `backend/gigamesh/integrations/uns.py` | Canonical ISA-95 (`<Enterprise>/<Site>/<Area>/<Line>/<Cell>/<Asset>/<Layer>/<Metric>`) + Sparkplug B dual-mode hub with monotonic MQTT `+`/`#` wildcard policy inheritance, versioned **UNS Data Contracts** (schema validation), **1-click Site Read-Only Lockdown**, and live **UNS Security Digital Twin** publishing (`.../Security/GigaMesh/...`). |
| **Industrial MQTT 5.0 / Ignition & Rust Edge Proxy** | `backend/gigamesh/integrations/mqtt_ot_middleware.py` + `edge/rust/src/main.rs` | Drop-in Ignition / Cirrus Link middleware (fail-open telemetry + Birth-Certificate SHA-256 pinning; fail-closed E2E signed `NCMD`/`DCMD` + Digital Physics Envelopes + Ghost PLC snare) plus a **441 KB GC-free Rust edge binary** featuring a live wire-level **TCP MQTT 3.1.1/5.0 inline proxy (`--proxy`)** and **Ed25519 + HMAC-SHA256** signed offline policy bundles for Android/ARM64 edge nodes. |
| **Passive Multi-Protocol OT DPI & Binary PCAP** | `backend/gigamesh/integrations/ot_dpi_inventory.py` + `ot_wire_capture.py` | Passive L7 DPI and binary wire decoders across **Modbus/TCP, OPC-UA, Siemens S7comm, DNP3, EtherNet/IP, BACnet/IP, IEC 60870-5-104 & Sparkplug B** (including direct `.pcap` SPAN-port ingestion), Purdue 0–5 inventory, CVSS×EPSS×KEV exploitability scoring with virtual-patching risk reduction, Visibility Gap detection, and dry-run-tested zone segmentation. |
| **Zero-Trust JIT Vendor SRA Bastion** | `backend/gigamesh/integrations/secure_remote_access.py` | Eliminates standing vendor VPNs with Quorum-gated, time-boxed, single-asset Just-in-Time sessions, a live socket-enforced **WebSocket bastion (`/ws/sra/{session_id}`)**, cryptographically hash-chained command transcripts, and a **1-click Instant Kill-Switch**. |
| **Inline AI Gateway, AI-SPM & Red-Team** | `backend/gigamesh/integrations/ai_gateway_spm.py` | Sub-millisecond inline prompt/response/tool **DSPM PII & Secret Scrubber**, Shadow-AI detection & blocking, and **1-click 6-vector Automated Red-Teaming** across Bedrock, OpenAI, Anthropic, Gemini, and local vLLM. |
| **Official AWS Agent Toolkit Bridge** | `backend/gigamesh/integrations/aws_toolkit.py` + `.mcp.json` | Streamable-HTTP MCP bridge to `https://aws-mcp.us-east-1.api.aws/mcp` with SHA-256 MCP tool pinning, read-only default remediation (`aws-security` Rules 1/4/5/9), and automatic UNS Cloud projection. |
| **5-Framework Compliance, MITRE, OCSF & Sigma** | `backend/gigamesh/integrations/compliance_suite.py` | Continuous automated compliance evidence across **IEC 62443, NIST SP 800-82r3, NERC CIP (CIP-005/015), NIST CSF 2.0, and EU NIS2/CRA**, live **MITRE Triple-Matrix** (Enterprise + ICS + ATLAS), **OCSF v1.3** event exporter, and **Sigma Detection-as-Code** compiler. |
| **Air-Gapped Copilot & SOAR Rollback** | `backend/gigamesh/integrations/soar_copilot.py` | Local deterministic **"Ask GigaMesh"** plain-English assistant (zero external LLM, zero hallucination) plus declarative SOAR playbooks supporting **Dry-Run preview** and **1-click Safe Rollback**. |
| **Durable Storage & Security Authority** | `backend/gigamesh/storage/db.py` + `security/auth_rbac.py` | Dual-engine **PostgreSQL 16 / SQLite WAL** persistence preserving UNS state, incidents, edge devices, SRA transcripts, and unbroken SHA-256 audit chains across restarts; **Ed25519 asymmetric keypairs**, multi-tenant **JWT RBAC** (`viewer` → `super_admin`), and fail-closed `GIGAMESH_ENV=production` secret guards. |
| **Observability, Android & CI/CD** | `.github/workflows/ci-cd.yml` + `deploy/k8s/` + `frontend/android-native/` | Kubernetes `/healthz` & `/readyz` probes, Prometheus `/metrics` exposition, automated GitHub Actions CI/CD (`cargo test` + 52 `pytest` checks + PWA build + Docker image build), and native Android Capacitor/Kotlin VPN Shield + StrongBox Biometric Quorum build pipeline. |

---

## Quickstart

### 1. Run the Test Suite (52 Backend/Integration + Rust Edge Tests)
```bash
PYTHONPATH=backend .venv/bin/pytest -v backend/tests
cargo test --manifest-path edge/rust/Cargo.toml
```

### 2. Run the Backend API & Live SOC Command Center
```bash
# Build frontend (Novice-first default + Expert SOC toggle + Ignition /embed/hmi)
cd frontend && npm ci && npm run build && cd ..

# Launch GigaMesh (serves REST/WebSocket API, /healthz, /readyz, /metrics & UI on port 8000)
PYTHONPATH=backend .venv/bin/uvicorn gigamesh.api.server:app --host 0.0.0.0 --port 8000
```

### 3. Production Deployment (Docker Compose / Kubernetes / Android)
```bash
# On-Premise / Factory Stack (GigaMesh + Live Rust MQTT Inline Proxy + Mosquitto + PostgreSQL 16)
export GIGAMESH_ENV=production GIGAMESH_AUTH_REQUIRED=true
export GIGAMESH_JWT_SECRET="$(openssl rand -hex 32)"
export GIGAMESH_OT_SIGNING_SECRET="$(openssl rand -hex 32)"
export GIGAMESH_EDGE_BUNDLE_SECRET="$(openssl rand -hex 32)"
docker compose up --build -d

# Kubernetes (Non-Root Deployment + Rust MQTT Proxy Sidecar + HPA + /healthz /readyz /metrics)
kubectl apply -f deploy/k8s/gigamesh-production.yaml

# Native Android App (.aab with Kotlin VpnService Shield + StrongBox Biometric Quorum)
./scripts/build_android_release.sh
```

### 4. Optional: Attach Live `morluto/rea` (`rea-agents`)
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

