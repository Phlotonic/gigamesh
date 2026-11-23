import { useState } from 'react';
import type { EdgeFleetStatus, MqttOtStatus } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  otStatus: MqttOtStatus | null;
  fleet: EdgeFleetStatus | null;
  busy: boolean;
  onSimulateIgnition: () => Promise<void>;
  onEnrollDevice: (payload: {
    device_name: string;
    platform: string;
    site_or_plant: string;
    edge_runtime: string;
    capabilities: string[];
  }) => Promise<string | null>;
  onRevokeDevice: (deviceId: string) => Promise<void>;
  onFetchBundle: () => Promise<Record<string, unknown> | null>;
}

export function OtEdgeFleetPanel({
  otStatus,
  fleet,
  busy,
  onSimulateIgnition,
  onEnrollDevice,
  onRevokeDevice,
  onFetchBundle,
}: Props) {
  const [devName, setDevName] = useState('');
  const [platform, setPlatform] = useState('android');
  const [site, setSite] = useState('Austin Factory');
  const [lastToken, setLastToken] = useState<string | null>(null);
  const [bundlePreview, setBundlePreview] = useState<Record<string, unknown> | null>(null);

  async function handleEnroll(e: React.FormEvent) {
    e.preventDefault();
    if (!devName.trim()) return;
    const runtime = platform === 'android' ? 'capacitor-android' : 'gigamesh-edge-rust';
    const caps =
      platform === 'android'
        ? ['biometric_quorum', 'vpn_dns_shield', 'push_alerts']
        : ['sparkplug_b_guard', 'physics_envelope', 'offline_verify'];
    const tok = await onEnrollDevice({
      device_name: devName.trim(),
      platform,
      site_or_plant: site.trim() || 'Default Site',
      edge_runtime: runtime,
      capabilities: caps,
    });
    if (tok) {
      setLastToken(tok);
      setDevName('');
    }
  }

  return (
    <div className="gm-list-stack">
      {/* Hero */}
      <div className="gm-panel">
        <div className="gm-panel-body gm-crawler-hero">
          <div>
            <h2 className="gm-heading-tip" style={{ margin: 0, fontFamily: 'var(--font-display)', fontSize: 18 }}>
              Industrial MQTT / Sparkplug B / Ignition Middleware &amp; Android/Edge Fleet
              <HelpTip term="mqttOtMiddleware" />
            </h2>
            <p>
              End-to-end zero-trust security from <strong>Android admin phones</strong> (biometric approvals + on-device{' '}
              <code>VpnService</code>) through <strong>Ignition &amp; Sparkplug B brokers</strong> down to{' '}
              <strong>Rust-powered factory edge nodes</strong> (356 KB, GC-free, 344k msg/sec).
            </p>
          </div>
          <div className="gm-form-row">
            <button
              type="button"
              className="gm-btn gm-btn-primary"
              disabled={busy}
              onClick={onSimulateIgnition}
            >
              Simulate Ignition Factory Attack &amp; Safe Write
            </button>
            <button
              type="button"
              className="gm-btn gm-btn-emerald"
              disabled={busy}
              onClick={async () => {
                const b = await onFetchBundle();
                if (b) setBundlePreview(b);
              }}
            >
              Inspect Signed Offline Bundle
            </button>
          </div>
        </div>
      </div>

      {/* KPI Strip */}
      <section className="gm-kpi-strip" aria-label="Industrial OT and Edge Fleet Telemetry">
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Enrolled Edge Devices
            <HelpTip term="edgeFleet" />
          </div>
          <div className="gm-kpi-value tabular">
            {fleet?.online_devices ?? 0}/{fleet?.total_devices ?? 0}
          </div>
          <div className="gm-kpi-sub">
            {fleet?.android_devices ?? 0} Android · {fleet?.industrial_gateways ?? 0} factory gateways
          </div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Digital Physics Envelopes
            <HelpTip term="physicsEnvelope" />
          </div>
          <div className="gm-kpi-value tabular">{otStatus?.safety_envelopes.length ?? 0}</div>
          <div className="gm-kpi-sub">{otStatus?.stats.physics_violations_blocked ?? 0} unsafe writes blocked</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label">IT→OT AI Crossovers Blocked</div>
          <div className="gm-kpi-value tabular" style={{ color: 'var(--accent-crimson)' }}>
            {otStatus?.stats.it_to_ot_crossovers_blocked ?? 0}
          </div>
          <div className="gm-kpi-sub">{otStatus?.stats.ghost_plc_diversions ?? 0} diverted to Ghost PLC</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label">Pinned Sparkplug Nodes</div>
          <div className="gm-kpi-value tabular">{otStatus?.birth_pins.length ?? 0}</div>
          <div className="gm-kpi-sub">{otStatus?.stats.birth_tamper_alerts ?? 0} spoofed birth alerts</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label">Edge Winner (Battle-Tested)</div>
          <div className="gm-kpi-value tabular" style={{ color: 'var(--accent-emerald)', fontSize: 17 }}>
            Rust · 356 KB
          </div>
          <div className="gm-kpi-sub">344k msg/s · 136ns P50 · 0 GC pauses</div>
        </div>
      </section>

      <div className="gm-grid-2">
        {/* Digital Physics Safety Envelopes & Turn-Key Ignition Setup */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Digital Physics Safety Envelopes (PLC / Ignition Tags)
              <HelpTip term="physicsEnvelope" />
            </h2>
            <span className="gm-tag champion">Fail-Closed Actuation · Fail-Open Telemetry</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {(otStatus?.safety_envelopes ?? []).map((env) => (
              <div className="gm-item-box" key={env.tag_path}>
                <div className="gm-row-between">
                  <strong className="mono" style={{ fontSize: 12 }}>{env.tag_path}</strong>
                  {env.safety_interlock_locked ? (
                    <span className="gm-tag critical">INTERLOCK LOCKED (IMMUTABLE)</span>
                  ) : (
                    <span className="gm-tag champion">
                      {env.min_value}–{env.max_value} {env.unit} · max Δ {env.max_delta_per_sec}/s
                    </span>
                  )}
                </div>
                <div className="gm-muted mono" style={{ marginTop: 3 }}>
                  last={env.last_known_value ?? '—'} {env.unit}
                  {env.quorum_delta_threshold ? ` · HITL quorum if Δ ≥ ${env.quorum_delta_threshold}` : ''}
                </div>
              </div>
            ))}

            {otStatus?.ignition_turnkey && (
              <details>
                <summary style={{ cursor: 'pointer', fontSize: 12.5, fontWeight: 600 }}>
                  Turn-Key Ignition &amp; Cirrus Link MQTT Setup Guide (Zero Plugin Needed)
                </summary>
                <div className="gm-list-stack" style={{ marginTop: 8 }}>
                  <div className="mono gm-muted">
                    Broker: {otStatus.ignition_turnkey.mqtt_server_url} · Namespace: {otStatus.ignition_turnkey.sparkplug_namespace} · HMI Embed:{' '}
                    <code>{otStatus.ignition_turnkey.perspective_hmi_embed_url}</code>
                  </div>
                  {otStatus.ignition_turnkey.cirrus_link_steps.map((s) => (
                    <div key={s} style={{ fontSize: 12 }}>{s}</div>
                  ))}
                </div>
              </details>
            )}
          </div>
        </div>

        {/* Edge Device Fleet (Android + Factory Nodes) */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Android &amp; Factory Edge Fleet
              <HelpTip term="edgeFleet" />
            </h2>
            <span className="gm-tag">{fleet?.total_devices ?? 0} enrolled</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            <form onSubmit={handleEnroll} className="gm-form-row">
              <input
                className="gm-input"
                style={{ flex: 1 }}
                value={devName}
                onChange={(e) => setDevName(e.target.value)}
                placeholder="New device name (e.g. Plant Lead Android or Line-4 Pi)"
                aria-label="Edge device name"
              />
              <select className="gm-select" value={platform} onChange={(e) => setPlatform(e.target.value)} aria-label="Platform">
                <option value="android">Android (App + VPN)</option>
                <option value="ignition_gateway">Ignition Edge Gateway</option>
                <option value="linux_arm64">Linux ARM64 / IoT</option>
                <option value="rhel_openshift">RHEL / OpenShift</option>
              </select>
              <input
                className="gm-input"
                style={{ width: 130 }}
                value={site}
                onChange={(e) => setSite(e.target.value)}
                placeholder="Plant / Site"
                aria-label="Site or plant"
              />
              <button type="submit" className="gm-btn gm-btn-primary" disabled={busy}>
                Enroll
              </button>
            </form>

            {lastToken && (
              <div className="gm-item-box" style={{ borderColor: 'var(--accent-emerald)' }}>
                <div style={{ fontSize: 12, fontWeight: 600 }}>One-Time Device Enrollment Token (Copy Now):</div>
                <code style={{ fontSize: 11.5, wordBreak: 'break-all' }}>{lastToken}</code>
              </div>
            )}

            {(fleet?.devices ?? []).map((d) => (
              <div className="gm-item-box" key={d.device_id}>
                <div className="gm-row-between">
                  <div>
                    <strong style={{ fontSize: 13 }}>{d.device_name}</strong>
                    <div className="gm-muted mono">
                      {d.platform} · {d.site_or_plant} · {d.edge_runtime}
                    </div>
                  </div>
                  <div className="gm-form-row">
                    <span className={`gm-tag ${d.status === 'online' ? 'champion' : 'culled'}`}>
                      {d.status.toUpperCase()}
                    </span>
                    {d.status !== 'revoked' && (
                      <button
                        type="button"
                        className="gm-btn gm-btn-crimson"
                        disabled={busy}
                        onClick={() => onRevokeDevice(d.device_id)}
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </div>
                <div className="gm-region-chips" style={{ marginTop: 6 }}>
                  {d.vpn_shield_active && <span className="gm-tag champion">Android VPN Shield ON</span>}
                  {d.biometric_key_registered && <span className="gm-tag rea">StrongBox Biometric Key</span>}
                  {d.capabilities.map((c) => (
                    <span key={c} className="gm-tag">{c}</span>
                  ))}
                </div>
              </div>
            ))}

            {bundlePreview && (
              <details open>
                <summary style={{ cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                  Signed Offline Edge Policy Bundle ({String(bundlePreview.bundle_version)})
                </summary>
                <pre className="gm-code-block" style={{ marginTop: 6 }}>
                  {JSON.stringify(bundlePreview, null, 2)}
                </pre>
              </details>
            )}
          </div>
        </div>
      </div>

      {/* Live Sparkplug B Verdicts */}
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2>Recent Sparkplug B (`spBv1.0`) Inspection Verdicts</h2>
          <span className="gm-tag">{otStatus?.recent_verdicts.length ?? 0} frames</span>
        </div>
        <div className="gm-panel-body gm-table-wrap">
          {!otStatus || otStatus.recent_verdicts.length === 0 ? (
            <p className="gm-muted" style={{ margin: 0 }}>
              No Sparkplug B frames inspected yet. Click <strong>Simulate Ignition Factory Attack &amp; Safe Write</strong> above.
            </p>
          ) : (
            <table className="gm-table">
              <thead>
                <tr>
                  <th>Topic &amp; Type</th>
                  <th>Sender</th>
                  <th>Mode</th>
                  <th>Decision</th>
                  <th>Reasons</th>
                </tr>
              </thead>
              <tbody>
                {otStatus.recent_verdicts.slice(0, 15).map((v) => (
                  <tr key={v.verdict_id}>
                    <td className="mono" style={{ fontSize: 11.5 }}>{v.topic}</td>
                    <td className="mono" style={{ fontSize: 11.5 }}>{v.sender_id}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{v.mode}</td>
                    <td>
                      <span
                        className={`gm-tag ${
                          v.decision === 'allow'
                            ? 'champion'
                            : v.decision === 'quorum_required' || v.decision === 'allow_with_alert'
                            ? 'pending'
                            : 'culled'
                        }`}
                      >
                        {v.decision.toUpperCase()}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 11 }}>{v.reasons.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
