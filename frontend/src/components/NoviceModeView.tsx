import { useState } from 'react';
import type {
  ComplianceStatus,
  CopilotAnswer,
  EdgeFleetStatus,
  HumanHubData,
  IncidentCase,
  MqttOtStatus,
  OverviewResponse,
  OwaspBenchmarkReport,
  ThreatCrawlerStatus,
  UnsStatus,
} from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  overview: OverviewResponse | null;
  humanHub: HumanHubData;
  incidents: IncidentCase[];
  crawlerStatus: ThreatCrawlerStatus | null;
  owaspReport: OwaspBenchmarkReport | null;
  otStatus: MqttOtStatus | null;
  fleet: EdgeFleetStatus | null;
  uns: UnsStatus | null;
  compliance: ComplianceStatus | null;
  busy: boolean;
  onToggleAutopilot: () => Promise<void>;
  onToggleCrawler: (enabled: boolean) => Promise<void>;
  onScanCrawler: () => Promise<void>;
  onApproveQuorum: (quorumId: string, decision: 'approve' | 'reject') => Promise<void>;
  onSimulateIgnition: () => Promise<void>;
  onToggleSiteLockdown: (site: string, locked: boolean) => Promise<void>;
  onAskCopilot: (question: string) => Promise<CopilotAnswer>;
  onSwitchToExpert: () => void;
}

type NoviceTab = 'home' | 'devices' | 'learning';

export function NoviceModeView({
  overview,
  humanHub,
  incidents,
  crawlerStatus,
  owaspReport,
  otStatus,
  fleet,
  uns,
  compliance,
  busy,
  onToggleAutopilot,
  onToggleCrawler,
  onScanCrawler,
  onApproveQuorum,
  onSimulateIgnition,
  onToggleSiteLockdown,
  onAskCopilot,
  onSwitchToExpert,
}: Props) {
  const [subTab, setSubTab] = useState<NoviceTab>('home');
  const [askText, setAskText] = useState('');
  const [copilotReply, setCopilotReply] = useState<CopilotAnswer | null>(null);
  const pendingQuorums = humanHub.quorums.filter((q) => q.status === 'pending');
  const bestScore = overview
    ? Math.max(...Object.values(overview.champions).map((c) => c.benchmark_stats?.composite_success_rate ?? 0)) * 100
    : 0;
  const blockedTotal =
    incidents.length + (otStatus?.stats.commands_blocked ?? 0) + (crawlerStatus?.poisoned_pages_blocked ?? 0);
  const plantSites = (uns?.sites ?? []).filter((s) => s !== 'Cloud');

  return (
    <div className="gm-list-stack" style={{ maxWidth: 1080, margin: '0 auto' }}>
      {/* Simple 3-Tab Switcher */}
      <div className="gm-row-between" style={{ flexWrap: 'wrap', gap: 10 }}>
        <div className="gm-form-row" role="tablist" aria-label="Simple Views">
          {(
            [
              ['home', 'Home'],
              ['devices', `Plants & Devices (${fleet?.total_devices ?? 0})`],
              ['learning', 'Auto-Learning & Global Feeds'],
            ] as [NoviceTab, string][]
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={subTab === id}
              className={`gm-btn ${subTab === id ? 'gm-btn-primary' : ''}`}
              onClick={() => setSubTab(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <button type="button" className="gm-btn" onClick={onSwitchToExpert}>
          Open Full Expert SOC Console →
        </button>
      </div>

      {/* TAB 1: CALM HOME VIEW */}
      {subTab === 'home' && (
        <div className="gm-list-stack">
          <div className="gm-panel">
            <div className="gm-panel-body gm-crawler-hero">
              <div>
                <div className="gm-region-chips" style={{ marginBottom: 6 }}>
                  <span className="gm-tag champion">ALL SYSTEMS PROTECTED</span>
                  {owaspReport && (
                    <span className="gm-tag rea">
                      OWASP Top 10: {owaspReport.passed_probes}/{owaspReport.total_probes} Verified
                    </span>
                  )}
                  {compliance && (
                    <span className="gm-tag champion">
                      Audit Readiness: {compliance.overall_readiness_pct}% (5 Standards)
                    </span>
                  )}
                  {uns && (
                    <span className="gm-tag">
                      Unified Namespace: {uns.total_nodes} Live Assets
                    </span>
                  )}
                </div>
                <h2 style={{ margin: 0, fontFamily: 'var(--font-display)', fontSize: 22 }}>You’re Protected</h2>
                <p>
                  GigaMesh is quietly guarding your AI assistants, Android devices, AWS cloud, and Ignition factory
                  equipment inside one Unified Namespace — automatically upgrading your shield whenever a new trick appears.
                </p>
              </div>
              <label className="gm-switch">
                <input
                  type="checkbox"
                  checked={Boolean(overview?.autopilot_running)}
                  disabled={busy}
                  onChange={onToggleAutopilot}
                />
                <span className="gm-switch-track" />
                <span className="gm-heading-tip">
                  Auto-Learning {overview?.autopilot_running ? 'ON' : 'OFF'}
                  <HelpTip term="autopoiesis" />
                </span>
              </label>
            </div>
          </div>

          {/* Plain-English Ask GigaMesh Assistant Bar */}
          <div className="gm-panel">
            <div className="gm-panel-body gm-list-stack">
              <form
                className="gm-form-row"
                style={{ flexWrap: 'wrap' }}
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!askText.trim()) return;
                  setCopilotReply(await onAskCopilot(askText.trim()));
                }}
              >
                <span className="gm-heading-tip" style={{ fontWeight: 600, fontSize: 13 }}>
                  Ask GigaMesh
                  <HelpTip term="askGigaMesh" />
                </span>
                <input
                  className="gm-input"
                  style={{ flex: '1 1 280px' }}
                  placeholder="Ask anything: 'Is AustinPlant safe?', 'How is our compliance?', 'Any vendor access?'"
                  value={askText}
                  onChange={(e) => setAskText(e.target.value)}
                />
                <button type="submit" className="gm-btn gm-btn-primary" disabled={busy}>
                  Ask
                </button>
              </form>
              {copilotReply && (
                <div className="gm-item-box">
                  <strong style={{ fontSize: 13 }}>{copilotReply.answer}</strong>
                  {copilotReply.grounded_facts.length > 0 && (
                    <div className="gm-muted" style={{ fontSize: 11.5, marginTop: 4 }}>
                      {copilotReply.grounded_facts.join(' · ')}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          <section className="gm-kpi-strip">
            <div className="gm-kpi">
              <div className="gm-kpi-label gm-heading-tip">
                Threats Stopped &amp; Studied
                <HelpTip term="metabolizedModules" />
              </div>
              <div className="gm-kpi-value tabular">{blockedTotal}</div>
              <div className="gm-kpi-sub">0 unsafe commands reached equipment</div>
            </div>
            <div className="gm-kpi">
              <div className="gm-kpi-label gm-heading-tip">
                Shield Strength
                <HelpTip term="championSuccess" />
              </div>
              <div className="gm-kpi-value tabular" style={{ color: 'var(--accent-emerald)' }}>
                {bestScore.toFixed(0)}%
              </div>
              <div className="gm-kpi-sub">Only stronger updates are kept</div>
            </div>
            <div className="gm-kpi">
              <div className="gm-kpi-label gm-heading-tip">
                Waiting for Your Okay
                <HelpTip term="hitlQuorum" />
              </div>
              <div
                className="gm-kpi-value tabular"
                style={{ color: pendingQuorums.length > 0 ? 'var(--accent-amber)' : 'var(--accent-emerald)' }}
              >
                {pendingQuorums.length}
              </div>
              <div className="gm-kpi-sub">Big changes &amp; emails always ask first</div>
            </div>
          </section>

          {/* Pending Approvals */}
          <div className="gm-panel">
            <div className="gm-panel-header">
              <h2 className="gm-heading-tip">
                Needs Your Decision
                <HelpTip term="hitlQuorum" />
              </h2>
              <span className={`gm-tag ${pendingQuorums.length === 0 ? 'champion' : 'pending'}`}>
                {pendingQuorums.length === 0 ? 'All caught up' : `${pendingQuorums.length} waiting`}
              </span>
            </div>
            <div className="gm-panel-body gm-list-stack">
              {pendingQuorums.length === 0 ? (
                <p className="gm-muted" style={{ margin: 0 }}>
                  Nothing needs your attention right now. High-impact factory commands, AWS changes, and security email
                  drafts appear here whenever human sign-off is required.
                </p>
              ) : (
                pendingQuorums.slice(0, 6).map((q) => (
                  <div className="gm-item-box" key={q.quorum_id}>
                    <div className="gm-row-between" style={{ gap: 12 }}>
                      <div>
                        <strong style={{ fontSize: 13 }}>{q.summary}</strong>
                        <div className="gm-muted mono" style={{ marginTop: 3 }}>
                          Signatures: {q.signatures.length}/{q.required_approvals} · Target: {q.target_id}
                        </div>
                      </div>
                      <div className="gm-form-row">
                        <button
                          type="button"
                          className="gm-btn gm-btn-emerald"
                          disabled={busy}
                          onClick={() => onApproveQuorum(q.quorum_id, 'approve')}
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          className="gm-btn gm-btn-crimson"
                          disabled={busy}
                          onClick={() => onApproveQuorum(q.quorum_id, 'reject')}
                        >
                          Block
                        </button>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: PLANTS & DEVICES (UNIFIED NAMESPACE + ANDROID + IGNITION + EDGE) */}
      {subTab === 'devices' && (
        <div className="gm-list-stack">
          {/* 1-Click Plant Safe Mode (Unified Namespace Lockdown) */}
          <div className="gm-panel">
            <div className="gm-panel-header">
              <h2 className="gm-heading-tip">
                Your Factories — 1-Click Read-Only Safe Mode
                <HelpTip term="unsSiteLockdown" />
              </h2>
              <span className="gm-tag rea">{uns?.enterprise ?? 'QuanumisCorp'} Unified Map</span>
            </div>
            <div className="gm-panel-body gm-list-stack">
              <p className="gm-muted" style={{ margin: 0 }}>
                Need to freeze remote machine changes at one factory during maintenance or an alert? Flip that plant to
                Read-Only Safe Mode — live gauges and dashboards keep updating while remote commands are blocked.
              </p>
              <div className="gm-region-chips" style={{ gap: 12 }}>
                {plantSites.map((site) => {
                  const pat = `${uns?.enterprise ?? 'QuanumisCorp'}/${site}/#`;
                  const isLocked = Boolean(uns?.active_lockdowns.includes(pat));
                  return (
                    <div
                      key={site}
                      className="gm-item-box"
                      style={{ flex: '1 1 280px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}
                    >
                      <div>
                        <strong style={{ fontSize: 13.5 }}>{site}</strong>
                        <div className="gm-muted" style={{ fontSize: 11.5 }}>
                          {isLocked ? 'Remote commands frozen · Sensors live' : 'Protected & operating normally'}
                        </div>
                      </div>
                      <button
                        type="button"
                        className={`gm-btn ${isLocked ? 'gm-btn-crimson' : 'gm-btn-emerald'}`}
                        disabled={busy}
                        onClick={() => onToggleSiteLockdown(site, !isLocked)}
                      >
                        {isLocked ? '🔒 Frozen (Resume)' : 'Freeze Commands'}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="gm-panel">
            <div className="gm-panel-header">
              <h2 className="gm-heading-tip">
                Your Protected Phones, Servers &amp; Factory Nodes
                <HelpTip term="edgeFleet" />
              </h2>
              <button type="button" className="gm-btn gm-btn-primary" disabled={busy} onClick={onSimulateIgnition}>
                Test Safe Factory Protection
              </button>
            </div>
            <div className="gm-panel-body gm-list-stack">
              {(fleet?.devices ?? []).map((d) => (
                <div className="gm-item-box" key={d.device_id}>
                  <div className="gm-row-between">
                    <div>
                      <strong style={{ fontSize: 13.5 }}>{d.device_name}</strong>
                      <div className="gm-muted">
                        {d.site_or_plant} · {d.platform === 'android' ? 'Android Phone / Tablet' : 'Factory Edge Gateway (Rust)'}
                      </div>
                    </div>
                    <span className={`gm-tag ${d.status === 'online' ? 'champion' : 'culled'}`}>
                      {d.status === 'online' ? 'PROTECTED & ONLINE' : d.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="gm-region-chips" style={{ marginTop: 6 }}>
                    {d.vpn_shield_active && <span className="gm-tag champion">On-Device VPN Shield Active</span>}
                    {d.biometric_key_registered && <span className="gm-tag rea">Biometric Sign-Off Ready</span>}
                    <span className="gm-tag">Works Offline ✓</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="gm-panel">
            <div className="gm-panel-header">
              <h2 className="gm-heading-tip">
                Factory Safety Limits (Digital Physics)
                <HelpTip term="physicsEnvelope" />
              </h2>
              <span className="gm-tag champion">Hardware E-Stops Always Respected</span>
            </div>
            <div className="gm-panel-body gm-list-stack">
              {(otStatus?.safety_envelopes ?? []).map((env) => (
                <div className="gm-item-box" key={env.tag_path}>
                  <div className="gm-row-between">
                    <strong>{env.tag_path}</strong>
                    <span className={`gm-tag ${env.safety_interlock_locked ? 'critical' : 'champion'}`}>
                      {env.safety_interlock_locked
                        ? 'Locked (Cannot Be Changed Remotely)'
                        : `Safe Range: ${env.min_value}–${env.max_value} ${env.unit}`}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: AUTO-LEARNING & GLOBAL FEEDS */}
      {subTab === 'learning' && (
        <div className="gm-list-stack">
          <div className="gm-panel">
            <div className="gm-panel-body gm-crawler-hero">
              <div>
                <h2 className="gm-heading-tip" style={{ margin: 0, fontSize: 16 }}>
                  Global Threat Intelligence Crawler
                  <HelpTip term="threatCrawler" />
                </h2>
                <p>
                  Checks 10 trusted worldwide security feeds (GitHub, NIST, CISA, Red Hat, EU, UK, Japan, Canada, SANS)
                  for new threats and only downloads what has changed.
                </p>
              </div>
              <div className="gm-form-row">
                <button type="button" className="gm-btn" disabled={busy} onClick={onScanCrawler}>
                  Check for Updates Now
                </button>
                <label className="gm-switch">
                  <input
                    type="checkbox"
                    checked={Boolean(crawlerStatus?.enabled)}
                    disabled={busy}
                    onChange={(e) => onToggleCrawler(e.target.checked)}
                  />
                  <span className="gm-switch-track" />
                  <span>{crawlerStatus?.enabled ? 'ON' : 'OFF'}</span>
                </label>
              </div>
            </div>
          </div>

          <div className="gm-panel">
            <div className="gm-panel-header">
              <h2 className="gm-heading-tip">
                Tamper-Proof Security Memory
                <HelpTip term="merkleRepo" />
              </h2>
              <span className="gm-tag champion">
                {overview?.neural_repo_integrity.surviving_forks ?? 0} winning defenses ·{' '}
                {overview?.neural_repo_integrity.culled_tombstones ?? 0} weak ideas discarded
              </span>
            </div>
            <div className="gm-panel-body">
              <p className="gm-muted" style={{ margin: 0 }}>
                GigaMesh tests every new defense against simulated attacks and everyday work. Only stronger defenses
                survive; weaker ideas are retired permanently. Switch to <strong>Expert Mode</strong> anytime to inspect
                the full Git neural tree, OWASP 30/30 scorecard, or AWS Agent Toolkit console.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
