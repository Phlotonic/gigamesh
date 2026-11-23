import { useState } from 'react';
import type { AwsDocSearchResult, AwsSkillRecord, AwsToolkitStatus } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  status: AwsToolkitStatus | null;
  busy: boolean;
  onToggle: (enabled: boolean, region?: string, readOnly?: boolean) => Promise<void>;
  onDiscoverMcp: () => Promise<void>;
  onSearchDocs: (phrase: string) => Promise<AwsDocSearchResult[]>;
  onRetrieveSkill: (skillName: string) => Promise<AwsSkillRecord | null>;
  onSimulateAttack: () => Promise<void>;
}

const REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-northeast-1', 'ap-southeast-1'];
const FEATURED_SKILLS = ['aws-security', 'aws-iam', 'aws-observability', 'aws-investigation', 'amazon-bedrock'];

export function AwsToolkitPanel({
  status,
  busy,
  onToggle,
  onDiscoverMcp,
  onSearchDocs,
  onRetrieveSkill,
  onSimulateAttack,
}: Props) {
  const [searchPhrase, setSearchPhrase] = useState('GuardDuty AttackSequence');
  const [docResults, setDocResults] = useState<AwsDocSearchResult[]>([]);
  const [searching, setSearching] = useState(false);

  const enabled = status?.enabled ?? true;
  const region = status?.region ?? 'us-east-1';
  const readOnly = status?.read_only_enforced ?? true;

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!searchPhrase.trim()) return;
    setSearching(true);
    try {
      const res = await onSearchDocs(searchPhrase.trim());
      setDocResults(res);
    } finally {
      setSearching(false);
    }
  }

  return (
    <div className="gm-list-stack">
      {/* Hero Controls */}
      <div className="gm-panel">
        <div className="gm-panel-body gm-crawler-hero">
          <div>
            <h2 className="gm-heading-tip" style={{ margin: 0, fontFamily: 'var(--font-display)', fontSize: 18 }}>
              AWS Agent Toolkit Integration (aws/agent-toolkit-for-aws)
              <HelpTip term="awsToolkit" />
            </h2>
            <p>
              Connects GigaMesh directly to the official <strong>AWS MCP Server</strong>, <strong>AWS DevOps &amp; Security Agents</strong>,{' '}
              <strong>AWS Continuum</strong>, and <strong>Amazon Bedrock AgentCore</strong> skills — protected by SHA-256 MCP rug-pull
              pinning, automatic secret redaction, and read-only-first HITL quorum gates.
            </p>
          </div>
          <div className="gm-form-row" style={{ gap: 12 }}>
            <label className="gm-switch">
              <input
                id="toggle-aws-toolkit"
                type="checkbox"
                checked={enabled}
                disabled={busy || !status}
                onChange={(e) => onToggle(e.target.checked, region, readOnly)}
              />
              <span className="gm-switch-track" />
              <span>{enabled ? 'Toolkit ON' : 'Toolkit OFF'}</span>
            </label>
            <select
              className="gm-select"
              value={region}
              disabled={busy || !status}
              onChange={(e) => onToggle(enabled, e.target.value, readOnly)}
              aria-label="AWS Region"
            >
              {REGIONS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <button
              id="btn-discover-aws-mcp"
              type="button"
              className="gm-btn gm-btn-primary"
              disabled={busy}
              onClick={onDiscoverMcp}
            >
              {busy ? 'Connecting…' : 'Discover & Pin Live AWS MCP Tools'}
            </button>
            <button
              id="btn-sim-aws-attack"
              type="button"
              className="gm-btn gm-btn-crimson"
              disabled={busy}
              onClick={onSimulateAttack}
            >
              Simulate GuardDuty AttackSequence
            </button>
          </div>
        </div>
      </div>

      {/* KPI Strip */}
      <section className="gm-kpi-strip" aria-label="AWS Agent Toolkit Telemetry">
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            AWS MCP Status
            <HelpTip term="awsMcpPinning" />
          </div>
          <div className="gm-kpi-value tabular" style={{ fontSize: 16 }}>
            {status?.last_mcp_status === 'connected_verified' ? 'VERIFIED' : status?.last_mcp_status || 'READY'}
          </div>
          <div className="gm-kpi-sub">{status?.counts.pinned_tools ?? 0} tools SHA-256 pinned</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Read-Only Guardrail
            <HelpTip term="awsReadOnly" />
          </div>
          <div className="gm-kpi-value tabular" style={{ color: 'var(--accent-emerald)', fontSize: 18 }}>
            {readOnly ? 'ENFORCED' : 'CUSTOM'}
          </div>
          <div className="gm-kpi-sub">Mutating calls require HITL quorum</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label">Official AWS Plugins</div>
          <div className="gm-kpi-value tabular">{status?.counts.plugins ?? 6}</div>
          <div className="gm-kpi-sub">{status?.counts.retrieved_skills ?? 0} live skills fetched &amp; screened</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Attack Sequences &amp; Exposures
            <HelpTip term="awsPriorityFindings" />
          </div>
          <div className="gm-kpi-value tabular" style={{ color: 'var(--accent-crimson)' }}>
            {(status?.counts.attack_sequences ?? 0) + (status?.counts.exposures ?? 0)}
          </div>
          <div className="gm-kpi-sub">
            {status?.counts.attack_sequences ?? 0} GuardDuty seq · {status?.counts.exposures ?? 0} Security Hub
          </div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label">Local Runtime</div>
          <div className="gm-kpi-value tabular" style={{ fontSize: 16 }}>
            {status?.doctor?.uvx_installed ? 'uvx READY' : 'HTTP MCP'}
          </div>
          <div className="gm-kpi-sub">.mcp.json {status?.doctor?.repo_mcp_json_present ? 'present ✓' : 'ready'}</div>
        </div>
      </section>

      <div className="gm-grid-2">
        {/* Live AWS MCP Docs Search & Skill Retrieval */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Live AWS MCP Docs Search &amp; Official Skills
              <HelpTip term="awsToolkit" />
            </h2>
            <span className="gm-tag champion">Read-only · No AWS creds needed</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            <form onSubmit={handleSearch} className="gm-form-row">
              <input
                className="gm-input"
                style={{ flex: 1 }}
                value={searchPhrase}
                onChange={(e) => setSearchPhrase(e.target.value)}
                placeholder="Search live AWS docs via aws-mcp (e.g. GuardDuty, IAM, Bedrock AgentCore)..."
                aria-label="AWS MCP documentation search"
              />
              <button type="submit" className="gm-btn gm-btn-primary" disabled={searching || busy}>
                {searching ? 'Searching…' : 'Search AWS MCP'}
              </button>
            </form>

            {docResults.length > 0 && (
              <div className="gm-list-stack">
                {docResults.map((d, i) => (
                  <div className="gm-item-box" key={`${d.url}-${i}`}>
                    <a className="gm-finding-link" href={d.url} target="_blank" rel="noopener noreferrer nofollow">
                      <strong style={{ fontSize: 12.5 }}>{d.title}</strong>
                    </a>
                    <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--ink-secondary)' }}>{d.snippet}</p>
                  </div>
                ))}
              </div>
            )}

            <div>
              <div className="gm-muted" style={{ marginBottom: 6, fontWeight: 600 }}>
                Pull &amp; Poison-Screen Official Skill Live (`aws___retrieve_skill`):
              </div>
              <div className="gm-region-chips">
                {FEATURED_SKILLS.map((sk) => (
                  <button
                    key={sk}
                    type="button"
                    className="gm-btn"
                    disabled={busy}
                    onClick={() => onRetrieveSkill(sk)}
                  >
                    {sk}
                  </button>
                ))}
              </div>
            </div>

            {status && status.retrieved_skills.length > 0 && (
              <div className="gm-list-stack">
                {status.retrieved_skills.map((sk) => (
                  <div className="gm-item-box" key={sk.skill_name}>
                    <div className="gm-row-between">
                      <strong className="mono" style={{ fontSize: 12 }}>{sk.skill_name}</strong>
                      <span className={`gm-tag ${sk.poison_blocked ? 'critical' : 'champion'}`}>
                        {sk.poison_blocked ? 'POISON QUARANTINED' : `VERIFIED · ${sk.sha256.slice(0, 10)}`}
                      </span>
                    </div>
                    <p style={{ margin: '5px 0 0', fontSize: 11.5, color: 'var(--ink-secondary)', whiteSpace: 'pre-wrap' }}>
                      {sk.preview.slice(0, 260)}…
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Pinned AWS MCP Tools + Official Plugin Catalog */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Pinned AWS MCP Tools (OWASP ASI04) &amp; Plugins
              <HelpTip term="awsMcpPinning" />
            </h2>
            <span className="gm-tag">{status?.pinned_tools.length ?? 0} pinned</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {status && status.pinned_tools.length > 0 ? (
              status.pinned_tools.map((t) => (
                <div className="gm-item-box" key={t.name}>
                  <div className="gm-row-between">
                    <code style={{ fontWeight: 600, fontSize: 12 }}>{t.name}</code>
                    <div className="gm-form-row">
                      <span className={`gm-tag ${t.read_only ? 'champion' : 'pending'}`}>
                        {t.read_only ? 'READ-ONLY' : 'QUORUM GATED'}
                      </span>
                      <span className={`gm-tag ${t.rugpull_detected ? 'critical' : 'rea'}`}>
                        {t.rugpull_detected ? 'RUG-PULL ALERT' : `sha:${t.sha256.slice(0, 8)}`}
                      </span>
                    </div>
                  </div>
                  <div className="gm-muted" style={{ marginTop: 4 }}>{t.description}</div>
                </div>
              ))
            ) : (
              <p className="gm-muted" style={{ margin: 0 }}>
                Click <strong>Discover &amp; Pin Live AWS MCP Tools</strong> to query <code>https://aws-mcp.us-east-1.api.aws/mcp</code> and cryptographically pin all 8 official AWS MCP tools.
              </p>
            )}

            <details>
              <summary style={{ cursor: 'pointer', fontSize: 12.5, fontWeight: 600 }}>
                Inspect Bundled Official AWS Plugins ({status?.plugins.length ?? 6}) &amp; Repo `.mcp.json`
              </summary>
              <div className="gm-list-stack" style={{ marginTop: 8 }}>
                {(status?.plugins ?? []).map((p) => (
                  <div className="gm-item-box" key={p.plugin_id}>
                    <div className="gm-row-between">
                      <strong>{p.name}</strong>
                      <span className="gm-tag rea">{p.category}</span>
                    </div>
                    <div className="gm-muted" style={{ marginTop: 3 }}>{p.description}</div>
                  </div>
                ))}
                {status?.mcp_config && (
                  <pre className="gm-code-block">{JSON.stringify(status.mcp_config, null, 2)}</pre>
                )}
              </div>
            </details>
          </div>
        </div>
      </div>

      {/* Prioritized AWS Findings Feed */}
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            Prioritized AWS Security Findings (GuardDuty AttackSequence → Security Hub Exposure)
            <HelpTip term="awsPriorityFindings" />
          </h2>
          <span className="gm-tag">{status?.findings.length ?? 0} findings</span>
        </div>
        <div className="gm-panel-body gm-list-stack">
          {!status || status.findings.length === 0 ? (
            <p className="gm-muted" style={{ margin: 0 }}>
              No AWS findings ingested yet. Click <strong>Simulate GuardDuty AttackSequence</strong> above to test full
              GuardDuty + Security Hub ingestion, automatic credential/account redaction, and M-of-N HITL quorum gating.
            </p>
          ) : (
            status.findings.map((f) => (
              <div className="gm-item-box" key={f.record_id}>
                <div className="gm-row-between">
                  <div>
                    <strong style={{ fontSize: 13 }}>{f.title}</strong>
                    <div className="gm-muted mono" style={{ marginTop: 2 }}>
                      {f.service.toUpperCase()} · {f.finding_type} · account={f.masked_account} · region={f.region}
                    </div>
                  </div>
                  <div className="gm-form-row">
                    {f.priority_bucket === 1 && <span className="gm-tag critical">ATTACK SEQUENCE (P1)</span>}
                    {f.priority_bucket === 2 && <span className="gm-tag high">EXPOSURE PATH (P2)</span>}
                    <span className={`gm-tag ${f.reported_severity.toLowerCase() === 'critical' ? 'critical' : 'high'}`}>
                      {f.reported_severity}
                    </span>
                  </div>
                </div>
                <p style={{ margin: '6px 0 0', fontSize: 12.5, color: 'var(--ink-secondary)' }}>{f.redacted_summary}</p>
                <div className="gm-region-chips" style={{ marginTop: 8 }}>
                  <span className="gm-tag champion">Rule 9 Redactions: {f.redactions_applied}</span>
                  <span className="gm-tag rea">Evidence: {f.evidence_state}</span>
                  {f.gigamesh_incident_id && <span className="gm-tag">Incident: {f.gigamesh_incident_id}</span>}
                  {f.quorum_id && <span className="gm-tag pending">HITL Quorum Required: {f.quorum_id}</span>}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
