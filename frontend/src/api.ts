import type {
  EvolutionGenerationReport,
  ForkGenome,
  HumanHubData,
  IncidentCase,
  MetabolizedDefenseModule,
  NeuralRepoIntegrity,
  OverviewResponse,
  ProvenanceSnapshot,
  ReaEvidenceDossier,
  RedHatControlData,
  ScenarioMeta,
  SyncFirewallReport,
  SyncFirewallStatus,
  EmailListenerStatus,
  EmailTriageDecision,
  AwsDocSearchResult,
  AwsIngestedFinding,
  AwsSkillRecord,
  AwsToolkitStatus,
  CrawlRunReport,
  EdgeDeviceRecord,
  EdgeFleetStatus,
  MqttInspectionVerdict,
  MqttOtStatus,
  OwaspBenchmarkReport,
  ThreatCrawlerData,
  ThreatCrawlerStatus,
  ThreatSource,
  UnsPolicyRule,
  UnsPublishVerdict,
  UnsStatus,
} from './types';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  getOverview: () => request<OverviewResponse>('/api/overview'),
  getForks: (useCase?: string) =>
    request<{ forks: ForkGenome[]; integrity: NeuralRepoIntegrity; git_log: Array<{ sha: string; date: string; message: string }> }>(
      useCase ? `/api/neural-repo/forks?use_case=${encodeURIComponent(useCase)}` : '/api/neural-repo/forks'
    ),
  getEvolutionReports: () =>
    request<{ autopilot_running: boolean; interval_sec: number; generation_counter: number; reports: EvolutionGenerationReport[] }>(
      '/api/evolution/reports'
    ),
  stepEvolution: (useCase?: string) =>
    request<EvolutionGenerationReport>('/api/evolution/step', {
      method: 'POST',
      body: JSON.stringify({ use_case: useCase || null }),
    }),
  toggleAutopilot: (enabled: boolean, intervalSec?: number) =>
    request<{ autopilot_running: boolean; interval_sec: number }>('/api/evolution/autopilot', {
      method: 'POST',
      body: JSON.stringify({ enabled, interval_sec: intervalSec }),
    }),
  getProvenance: () => request<ProvenanceSnapshot>('/api/provenance/graph'),
  getIncidents: () => request<{ incidents: IncidentCase[] }>('/api/incidents'),
  getScenarios: () => request<{ scenarios: ScenarioMeta[] }>('/api/simulator/scenarios'),
  runScenario: (scenarioId: string, useCase?: string) =>
    request<Record<string, unknown>>('/api/simulator/run', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: scenarioId, use_case: useCase || null, auto_dissect_and_evolve: true }),
    }),
  getReaLab: () =>
    request<{
      doctor: OverviewResponse['rea_doctor'];
      snare_sessions: RedHatControlData['snare_sessions'];
      artifacts: Array<{ artifact_id: string; attacker_family: string; artifact_kind: string; filename: string; sha256: string; size_bytes: number }>;
      dossiers: ReaEvidenceDossier[];
      metabolized_modules: MetabolizedDefenseModule[];
    }>('/api/rea/lab'),
  getHumanHub: () => request<HumanHubData>('/api/human-hub'),
  submitVote: (payload: {
    analyst_id: string;
    analyst_reputation: number;
    target_kind: string;
    target_id: string;
    verdict: string;
    annotation: string;
    proposed_pattern: string | null;
  }) =>
    request<Record<string, unknown>>('/api/human-hub/vote', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  signQuorum: (quorumId: string, payload: { analyst_id: string; decision: string; comment: string }) =>
    request<Record<string, unknown>>(`/api/human-hub/quorum/${encodeURIComponent(quorumId)}/sign`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  exportStix: () => request<Record<string, unknown>>('/api/human-hub/stix/export', { method: 'POST' }),
  getRedHatControl: () => request<RedHatControlData>('/api/control/redhat'),
  getSyncStatus: () => request<SyncFirewallStatus>('/api/neural-repo/sync/status'),
  pushGenomeSync: () => request<SyncFirewallReport>('/api/neural-repo/sync/push', { method: 'POST' }),
  pullGenomeSync: () => request<SyncFirewallReport>('/api/neural-repo/sync/pull', { method: 'POST' }),
  getEmailListener: () =>
    request<{ status: EmailListenerStatus; decisions: EmailTriageDecision[] }>('/api/email-listener/status'),
  toggleEmailListener: (enabled: boolean) =>
    request<EmailListenerStatus>('/api/email-listener/toggle', {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    }),
  pollEmailListener: () =>
    request<{ new_decisions: EmailTriageDecision[]; status: EmailListenerStatus }>('/api/email-listener/poll', {
      method: 'POST',
    }),
  sendEmailWebhook: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>('/api/email-listener/webhook', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getThreatCrawler: () => request<ThreatCrawlerData>('/api/threat-crawler/status'),
  toggleThreatCrawler: (enabled: boolean, crawl_interval_sec?: number) =>
    request<ThreatCrawlerStatus>('/api/threat-crawler/toggle', {
      method: 'POST',
      body: JSON.stringify({ enabled, crawl_interval_sec }),
    }),
  scanThreatCrawler: (source_ids?: string[]) =>
    request<CrawlRunReport>('/api/threat-crawler/scan', {
      method: 'POST',
      body: JSON.stringify({ source_ids: source_ids ?? null }),
    }),
  toggleThreatSource: (sourceId: string, enabled: boolean) =>
    request<ThreatSource>(`/api/threat-crawler/sources/${encodeURIComponent(sourceId)}/toggle`, {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    }),
  upsertThreatSource: (payload: { source_id: string; name: string; url: string; kind: string; region?: string }) =>
    request<ThreatSource>('/api/threat-crawler/sources', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteThreatSource: (sourceId: string) =>
    request<{ deleted: string }>(`/api/threat-crawler/sources/${encodeURIComponent(sourceId)}`, {
      method: 'DELETE',
    }),
  getOwaspBenchmark: () => request<OwaspBenchmarkReport>('/api/benchmarks/owasp'),
  runOwaspBenchmark: () => request<OwaspBenchmarkReport>('/api/benchmarks/owasp/run', { method: 'POST' }),
  getAwsToolkit: () => request<AwsToolkitStatus>('/api/aws-toolkit/status'),
  toggleAwsToolkit: (enabled: boolean, region?: string, read_only_enforced?: boolean) =>
    request<AwsToolkitStatus>('/api/aws-toolkit/toggle', {
      method: 'POST',
      body: JSON.stringify({ enabled, region, read_only_enforced }),
    }),
  discoverAwsMcp: () => request<Record<string, unknown>>('/api/aws-toolkit/discover-mcp', { method: 'POST' }),
  searchAwsDocs: (search_phrase: string, limit = 4) =>
    request<{ query: string; results: AwsDocSearchResult[] }>('/api/aws-toolkit/search-docs', {
      method: 'POST',
      body: JSON.stringify({ search_phrase, limit }),
    }),
  retrieveAwsSkill: (skill_name: string, file?: string) =>
    request<AwsSkillRecord>('/api/aws-toolkit/retrieve-skill', {
      method: 'POST',
      body: JSON.stringify({ skill_name, file }),
    }),
  simulateAwsAttackSequence: () =>
    request<{ ingested: AwsIngestedFinding[] }>('/api/aws-toolkit/simulate-attack-sequence', { method: 'POST' }),
  getMqttOtStatus: () => request<MqttOtStatus>('/api/ot-mqtt/status'),
  simulateIgnitionFactory: () =>
    request<{ verdicts: MqttInspectionVerdict[] }>('/api/ot-mqtt/simulate-ignition', { method: 'POST' }),
  getEdgeFleet: () => request<EdgeFleetStatus>('/api/edge/fleet'),
  enrollEdgeDevice: (payload: {
    device_name: string;
    platform: string;
    site_or_plant: string;
    edge_runtime: string;
    capabilities: string[];
  }) =>
    request<{ device: EdgeDeviceRecord; device_token_once: string }>('/api/edge/enroll', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  revokeEdgeDevice: (deviceId: string) =>
    request<EdgeDeviceRecord>(`/api/edge/devices/${encodeURIComponent(deviceId)}/revoke`, { method: 'POST' }),
  getEdgePolicyBundle: () => request<Record<string, unknown>>('/api/edge/policy-bundle'),
  getUnsStatus: () => request<UnsStatus>('/api/uns/status'),
  simulateEnterpriseUns: () =>
    request<{ verdicts: UnsPublishVerdict[] }>('/api/uns/simulate-enterprise', { method: 'POST' }),
  toggleUnsSiteLockdown: (site: string, locked: boolean) =>
    request<{ site: string; locked: boolean; active_lockdowns: string[] }>(
      `/api/uns/sites/${encodeURIComponent(site)}/lockdown`,
      {
        method: 'POST',
        body: JSON.stringify({ locked }),
      }
    ),
  upsertUnsPolicy: (payload: Partial<UnsPolicyRule> & { name: string; topic_pattern: string }) =>
    request<UnsPolicyRule>('/api/uns/policies', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};
