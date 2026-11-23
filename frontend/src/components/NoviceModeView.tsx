import { useState } from 'react';
import type {
  EdgeFleetStatus,
  HumanHubData,
  IncidentCase,
  MqttOtStatus,
  OverviewResponse,
  OwaspBenchmarkReport,
  ThreatCrawlerStatus,
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
  busy: boolean;
  onToggleAutopilot: () => Promise<void>;
  onToggleCrawler: (enabled: boolean) => Promise<void>;
  onScanCrawler: () => Promise<void>;
  onApproveQuorum: (quorumId: string, decision: 'approve' | 'reject') => Promise<void>;
  onSimulateIgnition: () => Promise<void>;
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
  busy,
  onToggleAutopilot,
  onToggleCrawler,
  onScanCrawler,
  onApproveQuorum,
  onSimulateIgnition,
  onSwitchToExpert,
}: Props) {
  const [subTab, setSubTab] = useState<NoviceTab>('home');
  const pendingQuorums = humanHub.quorums.filter((q) => q.status === 'pending');
  const bestScore = overview
    ? Math.max(...Object.values(overview.champions).map((c) => c.benchmark_stats?.composite_success_rate ?? 0)) * 100
    : 0;
  const blockedTotal =
    incidents.length + (otStatus?.stats.commands_blocked ?? 0) + (crawlerStatus?.poisoned_pages_blocked ?? 0);

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
                </div>
                <h2 style={{ margin: 0, fontFamily: 'var(--font-display)', fontSize: 22 }}>You’re Protected</h2>
                <p>
                  GigaMesh is quietly guarding your AI assistants, Android devices, AWS cloud, and Ignition factory
                  equipment — automatically upgrading your shield whenever a new trick appears.
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

      {/* TAB 2: PLANTS & DEVICES (ANDROID + IGNITION + EDGE) */}
      {subTab === 'devices' && (
        <div className="gm-list-stack">
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
