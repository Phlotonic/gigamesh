export interface GlossaryEntry {
  title: string;
  body: string;
  why?: string;
}

export const GLOSSARY = {
  // Header & System Controls
  merkleRepo: {
    title: 'Tamper-Proof Security Memory (Merkle Repo)',
    body: 'Every defense strategy GigaMesh learns is saved in a permanent history where each entry is mathematically chained to the one before it.',
    why: 'If an attacker secretly alters even one character, GigaMesh spots the tampering immediately.',
  },
  autopoiesis: {
    title: 'Self-Improving Loop (Autopoiesis)',
    body: 'GigaMesh automatically invents new defense ideas, tests them against simulated attacks, and keeps only the ones that score higher.',
    why: 'Your security gets stronger on its own around the clock without manual tuning.',
  },
  stepEvolution: {
    title: 'Evolve Next Generation',
    body: 'Runs one round of testing right now: creates new candidate defenses, tests them against attacks and normal activity, and promotes only the winners.',
  },
  toggleAutopilot: {
    title: 'Pause or Resume Automatic Learning',
    body: 'Controls whether GigaMesh keeps running background improvement rounds automatically. Pausing does not turn off your active defenses.',
  },

  // Top KPI Strip
  survivingForks: {
    title: 'Surviving Defenses (Forks)',
    body: 'Defense configurations that passed every safety and accuracy test and beat earlier versions.',
    why: 'Only proven strategies are allowed to protect your system.',
  },
  culledTombstones: {
    title: 'Retired Weak Defenses (Culled Tombstones)',
    body: 'Defense ideas that were weaker or caused too many false alarms. They are permanently disabled and archived so GigaMesh never repeats the same mistake.',
  },
  metabolizedModules: {
    title: 'Learned Counter-Defenses (Metabolized Modules)',
    body: 'New protective rules automatically built by taking apart real or simulated attacks to understand how they work.',
    why: 'One caught attacker teaches GigaMesh how to block similar attacks in the future.',
  },
  championSuccess: {
    title: 'Best Protection Score (Champion Success Rate)',
    body: 'The overall score of GigaMesh’s strongest active defense, balancing how many attacks it catches against keeping normal work uninterrupted.',
  },
  hitlQuorum: {
    title: 'Human Team Approvals (HITL Quorums)',
    body: '“Human-in-the-Loop Quorum” means big, high-impact actions wait for multiple trusted people to approve them before running.',
    why: 'Prevents any single mistake or hijacked account from making risky changes.',
  },

  // Tab 1: Neural Repo & Recursive A/B
  neuralDag: {
    title: 'Defense Family Tree (Neural Fork Topology)',
    body: 'A visual timeline showing how each defense version evolved from earlier ones. Green boxes are active champions; dashed red boxes were retired.',
    why: 'Click any box to inspect why it won or why it was rejected.',
  },
  forkGenome: {
    title: 'Defense Blueprint (Fork Genome)',
    body: 'Shows the exact settings, test scores, and history of whichever defense version you clicked in the family tree.',
  },
  tradeOffVector: {
    title: 'Protection Balance (6-Axis Trade-Offs)',
    body: 'Every defense balances six priorities—like strictness, speed, stealth, and low false alarms—tailored for different environments.',
  },
  benchmarkProof: {
    title: 'Test Scorecard (Benchmark Proof)',
    body: 'Results from testing this defense against both real attack patterns and everyday safe activity. High recall catches attacks; low false positives avoid annoying interruptions.',
  },
  darwinianLedger: {
    title: 'Survival Test Log (Darwinian Ledger)',
    body: 'A record of every candidate defense tested in each generation, how much better (or worse) it scored, and whether it survived or was retired.',
  },
  gitStream: {
    title: 'Permanent Audit Log (Git Commit Stream)',
    body: 'A chronological log of every saved change to GigaMesh’s security brain, stored like a version-controlled ledger.',
  },
  syncFirewall: {
    title: 'Two-Way Safety Firewall (Mutual Genome Sync)',
    body: 'Safely shares proven defenses between your machine and GitHub while inspecting both directions.',
    why: 'If either side is ever compromised, bad or secret-leaking data is blocked before it can spread.',
  },
  outboundSync: {
    title: 'Safe Upload to GitHub (Outbound Sync)',
    body: 'Checks your local defenses for leaked passwords, tampering, or high false alarms before pushing clean updates to the isolated genome-sync branch.',
  },
  inboundSync: {
    title: 'Quarantined Download from GitHub (Inbound Pull)',
    body: 'Downloads remote updates into an isolated sandbox, verifies integrity, and re-tests them locally before accepting anything.',
  },

  // Tab 2: Causal Provenance & Simulator
  simulator: {
    title: 'Safe Attack Practice Arena (Simulator)',
    body: 'Lets you replay realistic multi-step cyberattacks safely so you can watch GigaMesh trap, analyze, and adapt to them in real time.',
  },
  causalProvenance: {
    title: 'Attack Story Map (Causal Provenance)',
    body: 'Connects the dots from where an incident started (a user or outside source) through AI agents, tools, and servers. Red lines show where untrusted data spread.',
  },
  incidents: {
    title: 'Correlated Security Incidents',
    body: 'Grouped alerts that tell the full story of a threat—including "Patient Zero" (the very first step) and what GigaMesh did to contain it.',
  },
  patientZero: {
    title: 'Patient Zero (Origin Point)',
    body: 'The very first user, message, or file where a suspicious chain of events began.',
  },

  // Tab 3: REA Dissection & Metabolism
  reaBridge: {
    title: 'Reverse-Engineering Engine (REA Bridge)',
    body: 'Safely inspects suspicious files, scripts, and AI agent tools in a locked sandbox to see what they are actually trying to do.',
  },
  reaDossiers: {
    title: 'Investigation Reports (Dissection Dossiers)',
    body: 'Step-by-step findings from taking apart a trapped attacker’s tools, plus any "Residual Unknowns" (mysteries GigaMesh probes further to uncover).',
  },
  crossAttackerImmunity: {
    title: 'Cross-Attacker Immunity',
    body: 'Shows when a defense learned from one attacker automatically stops completely different attacker families too.',
  },
  deceptionSnares: {
    title: 'Smart Decoy Traps (Deception Snares)',
    body: 'Harmless fake environments ("honeypots") that keep attackers busy while GigaMesh safely studies their techniques and collects clues.',
  },

  // Tab 4: Human Governance & Quorum
  collectiveDefense: {
    title: 'Team Voting & Custom Rules',
    body: 'Security reviewers can confirm threats or flag false alarms. When enough trusted reviewers agree, GigaMesh compiles a new live defense rule automatically.',
  },
  humanIdentityRisk: {
    title: 'Account & AI Delegation Risk',
    body: 'Tracks warning signs on human accounts (like unusual logins or phishing) so GigaMesh watches any AI assistants acting on their behalf more closely.',
  },
  stixExchange: {
    title: 'Anonymous Threat Sharing (STIX 2.1)',
    body: 'Packages learned threat patterns in the international STIX 2.1 standard with all personal or company details scrubbed out, so defenders can protect each other.',
  },

  // Tab 5: Red-Hat Exposure & Control
  mcpProxy: {
    title: 'AI Tool Gatekeeper & Kill-Switch (MCP Proxy)',
    body: 'Sits between AI agents and the tools they call (files, databases, commands). It can instantly freeze a rogue agent, block risky tools, or cancel its access tokens.',
  },
  redhatControl: {
    title: 'Linux & Server Containment Orders',
    body: 'Ready-to-apply security rules for Red Hat Enterprise Linux and OpenShift servers to lock down rogue processes and block unauthorized network traffic.',
  },
  selinux: {
    title: 'SELinux (App Containment)',
    body: 'Strict Linux access rules that keep each program locked inside its own lane so a compromised app cannot touch sensitive files.',
  },
  nftables: {
    title: 'nftables (Network Firewall)',
    body: 'Linux firewall rules that block suspicious outbound connections so attackers cannot send stolen data out.',
  },
  auditd: {
    title: 'auditd (System Activity Camera)',
    body: 'Linux kernel auditing rules that record whenever sensitive files or commands are touched.',
  },
  systemd: {
    title: 'systemd (Background Services)',
    body: 'Commands to stop, disable, or inspect Linux background services so attackers cannot hide persistent programs on startup.',
  },
  openshift: {
    title: 'OpenShift NetworkPolicy',
    body: 'Container firewall rules that isolate affected pods inside an OpenShift/Kubernetes cluster so threats cannot spread sideways.',
  },

  // Tab 6: Email Security Triage
  emailListener: {
    title: 'Automatic Security Inbox Monitor',
    body: 'Watches your security inbox for vulnerability reports, checks whether they are real or disguised attacks, and prepares a safe draft reply.',
  },
  draftFirstSafety: {
    title: 'Draft-First Safety Guarantee',
    body: 'GigaMesh never sends, replies to, or deletes emails on its own. It only saves Markdown drafts for a human to review and send.',
  },
  spfDkim: {
    title: 'Sender Authenticity Check (SPF / DKIM)',
    body: 'Email verification checks that confirm a message truly came from the domain it claims to be from, helping spot spoofed or fake senders.',
  },
  promptInjection: {
    title: 'Prompt-Injection Attack',
    body: 'Hidden instructions tucked inside an email or webpage trying to trick an AI into ignoring its rules or leaking secrets. GigaMesh catches and quarantines these.',
  },

  // Tab 7: Global Threat Intelligence Crawler
  threatCrawler: {
    title: 'Global Threat Intelligence Crawler',
    body: 'An optional background reader that checks trusted worldwide security bulletins for brand-new vulnerabilities and turns them into protections.',
    why: 'Off by default until you flip it on; you control how often it checks and which feeds are enabled.',
  },
  deltaUpdates: {
    title: 'Smart Update-Only Checks (HTTP 304 / ETag)',
    body: 'GigaMesh asks each feed "has anything changed since last time?" If nothing changed (HTTP 304), it skips re-downloading to stay fast and polite.',
  },
  ssrfGuard: {
    title: 'Safe-URL Guard (SSRF Protection)',
    body: 'Blocks the crawler from ever visiting private network addresses, local computers, cloud metadata endpoints, or unencrypted links—and refuses redirects.',
  },
  activelyExploited: {
    title: 'Actively Exploited in the Wild',
    body: 'Vulnerabilities that real attackers are already abusing right now—not just theoretical bugs. These get highest priority.',
  },
  advisoryRevisions: {
    title: 'Revised Advisories',
    body: 'Security bulletins that were previously seen and later updated by their publisher with new details, higher severity, or patch bypasses.',
  },
  cveBadge: {
    title: 'CVE / GHSA / MITRE IDs',
    body: 'Standard tracking numbers for known security flaws (CVE, GHSA) and documented attacker tactics (MITRE ATT&CK / ATLAS).',
  },
  poisonedContent: {
    title: 'Poisoned Content Blocked',
    body: 'Web pages or advisories that tried to smuggle hidden AI-hijacking commands into the crawler. GigaMesh quarantines them instead of trusting them.',
  },
  owaspBenchmark: {
    title: 'OWASP Triple-Framework Benchmark (30 Threat Categories)',
    body: 'Tests GigaMesh live against all three international OWASP Top 10 standards: Agentic AI (2026), LLM Apps (2025), and Web Apps (2025), plus safe everyday control checks.',
    why: 'Proves GigaMesh blocks real attacks across every major category while keeping normal work uninterrupted.',
  },
  benignFpRate: {
    title: 'False-Alarm Rate (Benign Controls)',
    body: 'Measures whether GigaMesh accidentally blocks safe, everyday work. 0% means zero annoying false alarms.',
  },
  circuitBreaker: {
    title: 'Cognitive & Blast-Radius Circuit Breaker',
    body: 'Automatically halts runaway AI agent swarms, recursive delegation storms, and token/cost floods before they can cascade or drain your budget.',
  },
  awsToolkit: {
    title: 'AWS Agent Toolkit Integration',
    body: 'Connects GigaMesh directly to AWS’s official MCP server, security skills, DevOps/Security Agents, and Continuum workflows—protected by GigaMesh’s zero-trust guardrails.',
    why: 'Lets GigaMesh pull real-time AWS security guidance and defend hybrid AWS + Linux/OpenShift environments from one place.',
  },
  awsReadOnly: {
    title: 'Read-Only First Safety Guardrail',
    body: 'Following AWS Security best practices, GigaMesh only reads AWS state automatically. Any change to IAM roles, firewalls, or keys waits for human team approval (HITL Quorum).',
  },
  awsMcpPinning: {
    title: 'MCP Tool Pinning (Rug-Pull Protection)',
    body: 'Every AWS MCP tool description is cryptographically fingerprinted (SHA-256) on first discovery so GigaMesh catches any unexpected mid-session tampering immediately.',
  },
  awsPriorityFindings: {
    title: 'Prioritized AWS Findings & Redaction',
    body: 'GuardDuty Attack Sequences (multi-step attacks) and Security Hub Exposures always appear at the top. AWS account numbers, keys, and emails are automatically masked.',
  },
  mqttOtMiddleware: {
    title: 'Industrial MQTT / Ignition Security Middleware',
    body: 'Sits seamlessly in front of Ignition and Sparkplug B MQTT brokers. Sensor data flows without delay, while equipment write commands (NCMD/DCMD) must pass cryptographic and physical safety checks.',
    why: 'Protects factory machinery from hijacked AI copilots, spoofed PLCs, and unsafe setpoint changes without slowing down plant visibility.',
  },
  physicsEnvelope: {
    title: 'Digital Physics Safety Envelopes',
    body: 'Hard safety limits on factory tags (minimum, maximum, maximum speed of change, and locked safety interlocks). Even a compromised account cannot push a boiler or turbine outside safe physical bounds.',
  },
  edgeFleet: {
    title: 'Android & Factory Edge Fleet',
    body: 'Every enrolled Android phone and Rust-powered factory gateway downloads a signed offline rule bundle, keeping protection active even if the internet goes down.',
  },
  unifiedNamespace: {
    title: 'Unified Namespace (ISA-95 Live Enterprise Tree)',
    body: 'Organizes every plant, production line, machine, cloud account, and mobile device into one clean folder-like tree (Company / Plant / Area / Line / Cell / Machine) so every system speaks the same language.',
    why: 'Eliminates messy point-to-point integrations while letting GigaMesh protect OT, Cloud, AI, and Mobile from one single source of truth.',
  },
  unsWildcardPolicy: {
    title: 'Hierarchical Wildcard Policies (+ and #)',
    body: 'Attach a safety rule once at the Company, Plant, or Area level using MQTT wildcards (+ matches one level, # matches every level below). Child machines inherit parent rules automatically and can only make limits stricter—never weaker.',
  },
  unsSecurityTwin: {
    title: 'UNS Security Digital Twin',
    body: 'GigaMesh publishes live shield status, blocked commands, and pending approvals right back into your Unified Namespace (.../Security/GigaMesh/...) so Ignition HMIs, MES, and ERP dashboards display real-time security state automatically.',
  },
  unsSiteLockdown: {
    title: '1-Click Plant Read-Only Lockdown',
    body: 'Instantly freezes all remote equipment write commands across an entire factory (both ISA-95 UNS and Sparkplug B) while keeping sensor telemetry flowing and leaving other factories completely unaffected.',
  },
  otDpiPurdue: {
    title: 'Passive Industrial Protocol DPI & Purdue Model (Levels 0–5)',
    body: 'Quietly reads factory network protocols (Modbus, Siemens S7, DNP3, OPC-UA, EtherNet/IP, BACnet, IEC-104) without slowing down legacy PLCs, mapping every controller to its Purdue safety zone.',
  },
  virtualPatching: {
    title: 'Exploitability Risk Scoring & Virtual Patching',
    body: 'Combines CVE severity, real-world exploit likelihood (EPSS & CISA KEV), and shows how much GigaMesh’s Digital Physics limits reduce real danger on legacy PLCs that cannot be rebooted to patch.',
  },
  jitVendorSra: {
    title: 'Zero-Trust Just-in-Time (JIT) Vendor Remote Access',
    body: 'Replaces risky always-on vendor VPNs with time-limited, single-machine sessions approved by your team, with every command tamper-proof recorded and a 1-click instant kill-switch.',
  },
  unsDataContracts: {
    title: 'UNS Versioned Data Contracts (Schema Governance)',
    body: 'Checks that every factory sensor and AI message matches its expected data type and range, catching broken sensors or tampered payloads before they corrupt downstream analytics.',
  },
  aiGatewayDspm: {
    title: 'Inline AI Gateway, AI-SPM & DSPM Secret Scrubber',
    body: 'Sits in front of AI models (Bedrock, OpenAI, Anthropic, Gemini, local vLLM) to automatically scrub SSNs, AWS keys, and tokens before data leaves your company—and blocks unapproved Shadow AI.',
  },
  autoRedTeam: {
    title: 'Continuous Automated AI Red-Teaming',
    body: 'Safely fires real-world prompt injections, jailbreaks, secret leaks, Shadow AI bypasses, and boiler-override attempts against your own defenses to prove 100% resilience.',
  },
  continuousCompliance: {
    title: 'Continuous 5-Framework Compliance & OCSF Export',
    body: 'Automatically maps live GigaMesh proof into auditor-ready scores for IEC 62443, NIST SP 800-82, NERC CIP, NIST CSF 2.0, and EU NIS2/CRA—and exports standard OCSF v1.3 findings.',
  },
  mitreTripleMatrix: {
    title: 'MITRE Triple-Matrix & Sigma Detection-as-Code',
    body: 'Tracks active defense coverage across IT (ATT&CK Enterprise), Factories (ATT&CK for ICS), and AI (MITRE ATLAS), plus lets teams add custom Sigma detection rules.',
  },
  soarRollback: {
    title: 'SOAR Playbooks with Dry-Run & 1-Click Rollback',
    body: 'Lets you preview an automated containment workflow in safe Dry-Run mode before executing—and undo it with one click if a plant alert turns out to be routine maintenance.',
  },
  askGigaMesh: {
    title: 'Ask GigaMesh (Air-Gapped Local Assistant)',
    body: 'Answers plain-English questions directly from your live plant, compliance, and security data—100% locally with zero internet dependency and zero AI guesswork.',
  },
} as const satisfies Record<string, GlossaryEntry>;

export type GlossaryKey = keyof typeof GLOSSARY;
