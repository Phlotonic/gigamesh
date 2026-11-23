import { useState } from 'react';
import type { OtDpiStatus, SraStatus, UnsStatus } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  otDpi: OtDpiStatus | null;
  sra: SraStatus | null;
  uns: UnsStatus | null;
  busy: boolean;
  onSimulateDpi: () => Promise<void>;
  onToggleZoneMode: (policyId: string, mode: 'dry_run' | 'enforced') => Promise<void>;
  onRequestSra: (payload: {
    vendor_name: string;
    contractor_email: string;
    site: string;
    target_uns_asset: string;
    access_mode: string;
    duration_minutes: number;
    justification: string;
  }) => Promise<void>;
  onApproveSra: (sessionId: string) => Promise<void>;
  onRunSraCommand: (sessionId: string, command: string) => Promise<void>;
  onKillSra: (sessionId: string) => Promise<void>;
}

export function OtEnterpriseSuitePanel({
  otDpi,
  sra,
  uns,
  busy,
  onSimulateDpi,
  onToggleZoneMode,
  onRequestSra,
  onApproveSra,
  onRunSraCommand,
  onKillSra,
}: Props) {
  const [vendorName, setVendorName] = useState('Siemens Field Services');
  const [vendorEmail, setVendorEmail] = useState('engineer@oem-partner.example');
  const [accessMode, setAccessMode] = useState('read_only');
  const [cmdText, setCmdText] = useState('read_diagnostics --tag PressureSetpointPSI');

  async function handleSraSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!vendorName.trim()) return;
    await onRequestSra({
      vendor_name: vendorName.trim(),
      contractor_email: vendorEmail.trim(),
      site: 'AustinPlant',
      target_uns_asset: `${uns?.enterprise ?? 'QuanumisCorp'}/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01`,
      access_mode: accessMode,
      duration_minutes: 30,
      justification: 'Scheduled pressure transmitter diagnostics',
    });
  }

  return (
    <div className="gm-list-stack">
      {/* Hero Summary */}
      <div className="gm-panel">
        <div className="gm-panel-body gm-crawler-hero">
          <div>
            <div className="gm-region-chips" style={{ marginBottom: 6 }}>
              <span className="gm-tag champion">8 INDUSTRIAL PROTOCOLS (PASSIVE L7 DPI)</span>
              <span className="gm-tag rea">
                VIRTUAL PATCHING: −{otDpi?.virtual_patch_risk_reduction_pct ?? 0}% RISK
              </span>
              <span className="gm-tag pending">
                VISIBILITY GAPS: {otDpi?.visibility_gap_assets.length ?? 0}
              </span>
            </div>
            <h2 className="gm-heading-tip" style={{ margin: 0, fontSize: 18 }}>
              Industrial OT Deep Protocol DPI, Purdue 0–5 Risk &amp; Zero-Trust Vendor SRA
              <HelpTip term="otDpiPurdue" />
            </h2>
            <p>
              Passive inspection for Modbus/TCP, S7comm, DNP3, OPC-UA, EtherNet/IP, BACnet, IEC-104 &amp; Sparkplug B,
              exploitability-adjusted virtual-patch scoring, dry-run zone segmentation, and Just-in-Time vendor access.
            </p>
          </div>
          <button type="button" className="gm-btn gm-btn-primary" disabled={busy} onClick={onSimulateDpi}>
            Simulate Multi-Protocol OT Attacks
          </button>
        </div>
      </div>

      {/* Purdue 0-5 Asset Inventory + Exploitability Risk & Visibility Gaps */}
      <div className="gm-grid-2">
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Purdue 0–5 OT Asset Inventory ({otDpi?.total_assets ?? 0})
              <HelpTip term="virtualPatching" />
            </h2>
            <span className="gm-tag champion">
              Avg Risk: {otDpi?.avg_base_risk ?? 0} → {otDpi?.avg_effective_risk ?? 0}
            </span>
          </div>
          <div className="gm-panel-body gm-list-stack" style={{ maxHeight: 420, overflowY: 'auto' }}>
            {(otDpi?.assets ?? []).map((a) => (
              <div className="gm-item-box" key={a.asset_id}>
                <div className="gm-row-between">
                  <div>
                    <strong style={{ fontSize: 13 }}>
                      [L{a.purdue_level}] {a.name}
                    </strong>
                    <div className="gm-muted mono" style={{ fontSize: 11 }}>
                      {a.ip_address} · {a.vendor} {a.model} (fw {a.firmware})
                    </div>
                  </div>
                  <div className="gm-region-chips">
                    <span className={`gm-tag ${a.effective_risk_score >= 50 ? 'critical' : 'champion'}`}>
                      Risk {a.base_risk_score} → {a.effective_risk_score}
                    </span>
                  </div>
                </div>
                <div className="gm-region-chips" style={{ marginTop: 6 }}>
                  {a.protocols.map((pr) => (
                    <span className="gm-tag" key={pr}>
                      {pr.toUpperCase()}
                    </span>
                  ))}
                  {a.digital_physics_guarded && <span className="gm-tag champion">Virtual-Patched ✓</span>}
                  {a.vulnerabilities.map((v) => (
                    <span className={`gm-tag ${v.cisa_kev ? 'critical' : 'high'}`} key={v.cve_id}>
                      {v.cve_id} {v.cisa_kev ? '· CISA KEV' : ''} (EPSS {Math.round(v.epss * 100)}%)
                    </span>
                  ))}
                  {a.visibility_gaps.length > 0 && (
                    <span className="gm-tag pending">
                      Visibility Gap ({Math.round(a.visibility_completeness * 100)}%)
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Dry-Run Zone Segmentation + Live Multi-Protocol DPI Alerts */}
        <div className="gm-list-stack">
          <div className="gm-panel">
            <div className="gm-panel-header">
              <h2 className="gm-heading-tip">
                Zone Segmentation (Dry-Run Tested Before Enforcement)
                <HelpTip term="otDpiPurdue" />
              </h2>
            </div>
            <div className="gm-panel-body gm-list-stack">
              {(otDpi?.zone_policies ?? []).map((pol) => (
                <div className="gm-item-box" key={pol.policy_id}>
                  <div className="gm-row-between">
                    <div>
                      <strong style={{ fontSize: 12.5 }}>{pol.name}</strong>
                      <div className="gm-muted mono" style={{ fontSize: 11 }}>
                        L{pol.src_purdue_level} → L{pol.dst_purdue_level} · Dry-Run Blocked:{' '}
                        {pol.dry_run_would_block_count} · Allowed: {pol.dry_run_would_allow_count}
                      </div>
                    </div>
                    <button
                      type="button"
                      className={`gm-btn ${pol.mode === 'enforced' ? 'gm-btn-crimson' : 'gm-btn-emerald'}`}
                      disabled={busy}
                      onClick={() => onToggleZoneMode(pol.policy_id, pol.mode === 'enforced' ? 'dry_run' : 'enforced')}
                    >
                      {pol.mode === 'enforced' ? 'ENFORCED (Revert Dry-Run)' : 'DRY-RUN (Promote Enforced)'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="gm-panel">
            <div className="gm-panel-header">
              <h2>Recent L7 Industrial Protocol DPI Events</h2>
              <span className="gm-tag">{otDpi?.recent_alerts.length ?? 0}</span>
            </div>
            <div className="gm-panel-body gm-list-stack" style={{ maxHeight: 220, overflowY: 'auto' }}>
              {(otDpi?.recent_alerts ?? []).length === 0 ? (
                <p className="gm-muted" style={{ margin: 0 }}>
                  Click <strong>Simulate Multi-Protocol OT Attacks</strong> to inspect Modbus, S7comm PLC_STOP, and DNP3
                  Cold Restart frames live.
                </p>
              ) : (
                (otDpi?.recent_alerts ?? []).map((al) => (
                  <div className="gm-item-box" key={al.alert_id}>
                    <div className="gm-row-between">
                      <strong className="mono" style={{ fontSize: 12 }}>
                        {al.protocol.toUpperCase()} · {al.function_name} ({al.mitre_ics_technique})
                      </strong>
                      <span className={`gm-tag ${al.verdict === 'allow_observed' ? 'champion' : 'critical'}`}>
                        {al.verdict}
                      </span>
                    </div>
                    <div className="gm-muted mono" style={{ fontSize: 11 }}>
                      {al.src_ip} → {al.dst_ip} · {al.reasons.join(', ')}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Zero-Trust JIT Vendor Secure Remote Access (SRA) + UNS Data Contracts */}
      <div className="gm-grid-2">
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Zero-Trust JIT Vendor Secure Remote Access (SRA)
              <HelpTip term="jitVendorSra" />
            </h2>
            <span className="gm-tag rea">Active: {sra?.active_sessions ?? 0}</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            <form onSubmit={handleSraSubmit} className="gm-form-row" style={{ flexWrap: 'wrap' }}>
              <input
                className="gm-input"
                value={vendorName}
                onChange={(e) => setVendorName(e.target.value)}
                placeholder="Vendor Name"
                style={{ flex: '1 1 150px' }}
              />
              <input
                className="gm-input"
                value={vendorEmail}
                onChange={(e) => setVendorEmail(e.target.value)}
                placeholder="Contractor Email"
                style={{ flex: '1 1 160px' }}
              />
              <select className="gm-select" value={accessMode} onChange={(e) => setAccessMode(e.target.value)}>
                <option value="read_only">Read-Only (30m)</option>
                <option value="supervised_write">Supervised Write (30m)</option>
              </select>
              <button type="submit" className="gm-btn gm-btn-primary" disabled={busy}>
                Request JIT Session
              </button>
            </form>

            {(sra?.sessions ?? []).map((sess) => (
              <div className="gm-item-box" key={sess.session_id}>
                <div className="gm-row-between">
                  <div>
                    <strong>{sess.vendor_name}</strong>{' '}
                    <span className="gm-muted mono" style={{ fontSize: 11 }}>
                      ({sess.access_mode} · {sess.duration_minutes}m)
                    </span>
                    <div className="gm-muted mono" style={{ fontSize: 11 }}>
                      Target: {sess.target_uns_asset}
                    </div>
                  </div>
                  <span
                    className={`gm-tag ${
                      sess.status === 'active'
                        ? 'champion'
                        : sess.status === 'killed'
                        ? 'critical'
                        : 'pending'
                    }`}
                  >
                    {sess.status.toUpperCase()}
                  </span>
                </div>
                <div className="gm-form-row" style={{ marginTop: 8, flexWrap: 'wrap' }}>
                  {sess.status === 'pending_approval' && (
                    <button
                      type="button"
                      className="gm-btn gm-btn-emerald"
                      disabled={busy}
                      onClick={() => onApproveSra(sess.session_id)}
                    >
                      Approve &amp; Activate
                    </button>
                  )}
                  {sess.status === 'active' && (
                    <>
                      <input
                        className="gm-input mono"
                        value={cmdText}
                        onChange={(e) => setCmdText(e.target.value)}
                        style={{ flex: '1 1 180px', fontSize: 11.5 }}
                      />
                      <button
                        type="button"
                        className="gm-btn"
                        disabled={busy}
                        onClick={() => onRunSraCommand(sess.session_id, cmdText)}
                      >
                        Run &amp; Hash-Log
                      </button>
                      <button
                        type="button"
                        className="gm-btn gm-btn-crimson"
                        disabled={busy}
                        onClick={() => onKillSra(sess.session_id)}
                      >
                        ⛔ 1-Click Kill-Switch
                      </button>
                    </>
                  )}
                </div>
                {sess.transcript.length > 0 && (
                  <div style={{ marginTop: 6 }}>
                    {sess.transcript.slice(-3).map((t) => (
                      <div className="mono" style={{ fontSize: 11, color: t.allowed ? 'var(--accent-emerald)' : 'var(--accent-crimson)' }} key={t.seq}>
                        #{t.seq} [{t.allowed ? 'OK' : 'BLOCKED'}] {t.command} · sha:{t.entry_hash.slice(0, 8)}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* UNS Versioned Data Contracts */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              UNS Versioned Data Contracts &amp; Schema Governance
              <HelpTip term="unsDataContracts" />
            </h2>
            <span className="gm-tag champion">{uns?.data_contracts?.length ?? 0} Contracts</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {(uns?.data_contracts ?? []).map((c) => (
              <div className="gm-item-box" key={c.contract_id}>
                <div className="gm-row-between">
                  <strong>
                    {c.name} <span className="gm-muted mono">v{c.version}</span>
                  </strong>
                  <span className={`gm-tag ${c.strict_reject_on_drift ? 'critical' : 'rea'}`}>
                    {c.strict_reject_on_drift ? 'STRICT REJECT' : 'FAIL-OPEN ALERT'}
                  </span>
                </div>
                <div className="gm-muted mono" style={{ fontSize: 11, marginTop: 3 }}>
                  {c.topic_pattern}
                </div>
                <div className="gm-region-chips" style={{ marginTop: 5 }}>
                  <span className="gm-tag">Type: {c.expected_datatype}</span>
                  {c.valid_min !== null && (
                    <span className="gm-tag champion">
                      Range: {c.valid_min}..{c.valid_max} {c.unit}
                    </span>
                  )}
                  <span className="gm-tag">Drift Violations: {c.violations_count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
