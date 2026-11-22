export interface TradeOffVector {
  containment_aggressiveness: number;
  deception_dwell_budget: number;
  rea_dissection_depth: number;
  human_quorum_strictness: number;
  false_positive_tolerance: number;
  host_isolation_scope: number;
}

export interface ForkBenchmarkStats {
  detection_recall: number;
  containment_success: number;
  false_positive_rate: number;
  precision_score: number;
  snare_capture_rate: number;
  cross_attacker_transfer: number;
  latency_efficiency: number;
  composite_success_rate: number;
  scenarios_tested: number;
  benign_tested: number;
  per_attacker_scores: Record<string, number>;
}

export interface ForkGenome {
  fork_id: string;
  parent_fork_id: string | null;
  git_commit_sha: string | null;
  git_ref: string | null;
  use_case: string;
  generation: number;
  status: string;
  created_at: string;
  rationale: string;
  trade_offs: TradeOffVector;
  detector_threshold: number;
  taint_strictness: number;
  metabolized_module_ids: string[];
  human_rule_ids: string[];
  alpha_weight: number;
  beta_weight: number;
  human_reward_bonus: number;
  benchmark_stats: ForkBenchmarkStats | null;
  cull_reason: string | null;
}

export interface EvolutionCandidateOutcome {
  fork_id: string;
  parent_fork_id: string;
  use_case: string;
  mutation_kind: string;
  success_rate: number;
  incumbent_success_rate: number;
  delta: number;
  false_positive_rate: number;
  survived: boolean;
  verdict_reason: string;
  git_commit_sha: string | null;
  metabolized_modules_added: string[];
}

export interface EvolutionGenerationReport {
  generation_id: number;
  timestamp: string;
  use_case: string;
  trigger: string;
  artifacts_dissected: string[];
  modules_metabolized: string[];
  candidates_tested: EvolutionCandidateOutcome[];
  survivors: string[];
  culled: string[];
  champion_before: string | null;
  champion_after: string | null;
  champion_success_before: number;
  champion_success_after: number;
  net_improvement: number;
}

export interface NeuralRepoIntegrity {
  valid: boolean;
  head_commit: string;
  total_git_commits: number;
  ledger_entries: number;
  total_forks: number;
  surviving_forks: number;
  culled_tombstones: number;
  metabolized_modules: number;
  broken_entries: string[];
  missing_commits: string[];
}

export interface OverviewResponse {
  name: string;
  version: string;
  autopilot_running: boolean;
  autopilot_interval_sec: number;
  generation_counter: number;
  use_cases: Record<string, { name: string; description: string; weights: Record<string, number>; max_fp: number }>;
  neural_repo_integrity: NeuralRepoIntegrity;
  champions: Record<string, ForkGenome>;
  rea_doctor: {
    live_rea_available: boolean;
    rea_binary: string | null;
    configured_tool_families: string[];
    fallback_engine: string;
    install_hint: string;
  };
  counts: {
    events: number;
    incidents: number;
    active_snares: number;
    captured_artifacts: number;
    rea_dossiers: number;
    metabolized_modules: number;
    human_rules: number;
    pending_quorums: number;
    redhat_orders: number;
  };
}

export interface ProvenanceSnapshot {
  nodes: Array<{ id: string; kind?: string; label?: string; tainted?: boolean; privilege?: number; trace_id?: string }>;
  edges: Array<{ source: string; target: string; relation?: string; tainted?: boolean; privilege_amplified?: boolean }>;
  total_nodes: number;
  total_edges: number;
}

export interface IncidentCase {
  case_id: string;
  created_at: string;
  trace_id: string;
  use_case: string;
  active_fork_id: string;
  attacker_family: string;
  severity: string;
  title: string;
  summary: string;
  patient_zero: string | null;
  human_principal_id: string | null;
  blast_radius_nodes: string[];
  taint_chain: string[];
  status: string;
  containment_action: string | null;
  snare_session_id: string | null;
  rea_dossier_id: string | null;
  human_votes: number;
  human_consensus_label: string | null;
}

export interface ScenarioMeta {
  scenario_id: string;
  attacker_family: string;
  title: string;
  description: string;
  expected_attack_class: string;
  default_use_case: string;
  artifact_kind: string;
  artifact_filename: string;
}

export interface ReaEvidenceDossier {
  dossier_id: string;
  created_at: string;
  artifact_id: string;
  attacker_family: string;
  engine_mode: string;
  rea_commands_executed: string[];
  evidence_items: Array<{
    evidence_id: string;
    category: string;
    symbol_or_offset: string;
    summary: string;
    extracted_pattern: string;
    confidence: number;
    source_tool: string;
  }>;
  residual_unknowns: Array<{
    unknown_id: string;
    description: string;
    hypothesis: string;
    probe_bait: string;
    resolved: boolean;
    resolution_evidence: string | null;
  }>;
  behavioral_summary: string;
  dissection_completeness: number;
  probe_rounds: number;
}

export interface MetabolizedDefenseModule {
  module_id: string;
  source_dossier_id: string;
  source_attacker_family: string;
  name: string;
  capability_kind: string;
  description: string;
  match_patterns: string[];
  target_attack_classes: string[];
  detection_boost: number;
  containment_boost: number;
  snare_bait_templates: string[];
  rhel_hardening_snippet: string | null;
  safety_verified: boolean;
  cross_attacker_hits: Record<string, number>;
  quorum_approved: boolean;
}

export interface HumanHubData {
  identities: Array<{
    human_principal_id: string;
    display_name: string;
    department: string;
    risk_score: number;
    mfa_anomalies: number;
    phishing_reports: number;
    suspicious_oauth_grants: number;
    active_delegated_agents: string[];
    notes: string[];
  }>;
  votes: Array<{
    vote_id: string;
    analyst_id: string;
    target_kind: string;
    target_id: string;
    verdict: string;
    annotation: string;
    proposed_pattern: string | null;
  }>;
  rules: Array<{
    rule_id: string;
    title: string;
    attack_class: string;
    pattern: string;
    author_analysts: string[];
    consensus_weight: number;
    active: boolean;
  }>;
  quorums: Array<{
    quorum_id: string;
    action_kind: string;
    target_id: string;
    use_case: string;
    required_approvals: number;
    status: string;
    summary: string;
    signatures: Array<{ analyst_id: string; decision: string; signature_digest: string; comment: string }>;
    executed_result: Record<string, unknown> | null;
  }>;
  stix_bundles: Array<{
    bundle_id: string;
    origin_org_hash: string;
    signature: string;
    motifs: Array<Record<string, unknown>>;
    imported: boolean;
  }>;
}

export interface RedHatControlData {
  mcp_proxy: {
    frozen_agents: Array<{ agent_id: string; reason: string; fork_id: string; frozen_at: string }>;
    revoked_tokens: string[];
    blocked_mcp_tools: Record<string, string>;
    intercepted_count: number;
  };
  redhat_orders: Array<{
    order_id: string;
    target_kind: string;
    target_id: string;
    mode: string;
    quorum_id: string | null;
    selinux_policy: string;
    nftables_rules: string;
    auditd_rules: string;
    systemd_commands: string[];
    openshift_network_policy: string;
    mcp_block_rules: string[];
    status: string;
  }>;
  snare_sessions: Array<{
    session_id: string;
    attacker_id: string;
    attacker_family: string;
    fork_id: string;
    canary_token: string;
    status: string;
    dwell_interactions: number;
    captured_artifact_ids: string[];
    bait_probes_sent: string[];
    operator_attribution_clues: string[];
  }>;
}

export interface SyncFirewallReport {
  report_id: string;
  timestamp: string;
  direction: string;
  remote_url: string;
  remote_branch: string;
  verdict: string;
  accepted_forks: string[];
  accepted_modules: string[];
  quarantined_items: string[];
  findings: Array<{ gate: string; severity: string; item: string; reason: string }>;
  manifest_sha256: string | null;
  remote_commit_sha: string | null;
}

export interface SyncFirewallStatus {
  remote_url: string;
  remote_branch: string;
  max_claimed_score_drift: number;
  total_syncs: number;
  blocked_contaminations: number;
  recent_reports: SyncFirewallReport[];
}

export interface EmailListenerStatus {
  running: boolean;
  gmail_authenticated: boolean;
  gmail_cli_path: string | null;
  poll_interval_sec: number;
  search_query: string;
  create_gmail_drafts: boolean;
  auto_send_blocked: boolean;
  last_history_id: string | null;
  last_poll_at: string | null;
  processed_count: number;
  decisions_count: number;
  hostile_blocked_count: number;
  drafts_created_count: number;
}

export interface EmailTriageDecision {
  triage_id: string;
  triaged_at: string;
  message_id: string;
  sender: string;
  subject: string;
  classification: string;
  severity: string;
  confidence: number;
  spf_dkim_verified: boolean;
  prompt_injection_detected: boolean;
  cve_ids: string[];
  affected_components: string[];
  referenced_forks: string[];
  extracted_iocs: string[];
  incident_id: string | null;
  quorum_id: string | null;
  rea_dossier_id: string | null;
  evolution_generation_id: number | null;
  draft_created: boolean;
  draft_id: string | null;
  draft_preview: string;
  actions_taken: string[];
  status: string;
}
