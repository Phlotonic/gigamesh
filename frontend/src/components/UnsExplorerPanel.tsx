import { useState } from 'react';
import type { UnsNodeState, UnsPolicyRule, UnsStatus, UnsTreeNode } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  uns: UnsStatus | null;
  busy: boolean;
  onSimulateEnterprise: () => Promise<void>;
  onToggleSiteLockdown: (site: string, locked: boolean) => Promise<void>;
  onAddPolicy: (policy: {
    name: string;
    topic_pattern: string;
    scope_level: string;
    require_e2e_signature: boolean;
    block_ai_tainted: boolean;
    min_value: number | null;
    max_value: number | null;
    max_delta_per_sec: number | null;
    unit: string;
    description: string;
  }) => Promise<void>;
}

function protocolBadge(proto: string): { label: string; cls: string } {
  switch (proto) {
    case 'sparkplug_b':
      return { label: 'Sparkplug B', cls: 'rea' };
    case 'aws_toolkit':
      return { label: 'AWS Cloud', cls: 'pending' };
    case 'edge_fleet':
      return { label: 'Edge Fleet', cls: 'champion' };
    case 'gigamesh_security':
      return { label: 'Security Twin', cls: 'high' };
    default:
      return { label: 'ISA-95 UNS', cls: '' };
  }
}

function collectLeaves(node: UnsTreeNode): UnsNodeState[] {
  const out = [...node.leaves];
  for (const child of node.children) {
    out.push(...collectLeaves(child));
  }
  return out;
}

function TreeBranch({
  node,
  depth,
  selectedPath,
  onSelect,
}: {
  node: UnsTreeNode;
  depth: number;
  selectedPath: string;
  onSelect: (n: UnsTreeNode) => void;
}) {
  const [open, setOpen] = useState(depth < 3);
  const allLeaves = collectLeaves(node);
  const hasAlert = allLeaves.some((l) => l.security_state === 'blocked' || l.security_state === 'alert');
  const isSelected = selectedPath === node.path;

  return (
    <div style={{ marginLeft: depth === 0 ? 0 : 14 }}>
      <div
        className="gm-row-between"
        style={{
          padding: '5px 8px',
          borderRadius: 6,
          cursor: 'pointer',
          background: isSelected ? 'rgba(56, 189, 248, 0.14)' : 'transparent',
          border: isSelected ? '1px solid rgba(56, 189, 248, 0.35)' : '1px solid transparent',
        }}
        onClick={() => onSelect(node)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
          {node.children.length > 0 ? (
            <button
              type="button"
              className="gm-btn"
              style={{ padding: '1px 6px', fontSize: 11, minWidth: 22 }}
              onClick={(e) => {
                e.stopPropagation();
                setOpen((o) => !o);
              }}
              aria-label={open ? 'Collapse branch' : 'Expand branch'}
            >
              {open ? '▾' : '▸'}
            </button>
          ) : (
            <span style={{ width: 22, textAlign: 'center', opacity: 0.5 }}>•</span>
          )}
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: hasAlert ? 'var(--accent-crimson)' : 'var(--accent-emerald)',
              flexShrink: 0,
            }}
          />
          <strong className="mono" style={{ fontSize: 12.5 }}>
            {node.name}
          </strong>
        </div>
        <span className="gm-muted mono" style={{ fontSize: 11 }}>
          {allLeaves.length} tag{allLeaves.length === 1 ? '' : 's'}
        </span>
      </div>

      {open && (
        <div>
          {node.children.map((child) => (
            <TreeBranch
              key={child.path}
              node={child}
              depth={depth + 1}
              selectedPath={selectedPath}
              onSelect={onSelect}
            />
          ))}
          {node.leaves.length > 0 && (
            <div style={{ marginLeft: 26, marginTop: 2, marginBottom: 4 }}>
              {node.leaves.map((leaf) => {
                const pb = protocolBadge(leaf.source_protocol);
                return (
                  <div
                    key={leaf.topic}
                    className="gm-row-between"
                    style={{ padding: '3px 6px', fontSize: 11.5, borderLeft: '1px solid var(--border-subtle)' }}
                  >
                    <span className="mono" style={{ color: 'var(--text-secondary)' }}>
                      {leaf.metric}:{' '}
                      <strong style={{ color: 'var(--text-primary)' }}>{String(leaf.value)}</strong>
                    </span>
                    <span className={`gm-tag ${pb.cls}`} style={{ fontSize: 10 }}>
                      {pb.label}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function UnsExplorerPanel({
  uns,
  busy,
  onSimulateEnterprise,
  onToggleSiteLockdown,
  onAddPolicy,
}: Props) {
  const [selectedBranch, setSelectedBranch] = useState<UnsTreeNode | null>(null);
  const [policyName, setPolicyName] = useState('');
  const [topicPattern, setTopicPattern] = useState(
    `${uns?.enterprise ?? 'QuanumisCorp'}/MunichPlant/AssemblyArea/+/+/+/Commands/ConveyorSpeedRPM`
  );
  const [scopeLevel, setScopeLevel] = useState('Area');
  const [maxVal, setMaxVal] = useState('150');
  const [minVal, setMinVal] = useState('0');
  const [unit, setUnit] = useState('RPM');

  const activeNode = selectedBranch ?? uns?.tree ?? null;
  const activeLeaves = activeNode ? collectLeaves(activeNode) : [];
  const plantSites = (uns?.sites ?? []).filter((s) => s !== 'Cloud');

  async function handleCreatePolicy(e: React.FormEvent) {
    e.preventDefault();
    if (!policyName.trim() || !topicPattern.trim()) return;
    await onAddPolicy({
      name: policyName.trim(),
      topic_pattern: topicPattern.trim(),
      scope_level: scopeLevel,
      require_e2e_signature: true,
      block_ai_tainted: true,
      min_value: minVal.trim() ? Number(minVal) : null,
      max_value: maxVal.trim() ? Number(maxVal) : null,
      max_delta_per_sec: null,
      unit: unit.trim(),
      description: `Hierarchical wildcard policy attached at ${scopeLevel} level.`,
    });
    setPolicyName('');
  }

  return (
    <div className="gm-list-stack">
      {/* Hero Banner */}
      <div className="gm-panel">
        <div className="gm-panel-body gm-crawler-hero">
          <div>
            <div className="gm-region-chips" style={{ marginBottom: 6 }}>
              <span className="gm-tag champion">ISA-95 + SPARKPLUG B DUAL-MODE</span>
              <span className="gm-tag rea">MQTT + / # WILDCARD INHERITANCE</span>
              <span className="gm-tag">RUST EDGE: 232k MSG/SEC · 372 KB</span>
            </div>
            <h2 className="gm-heading-tip" style={{ margin: 0, fontSize: 18 }}>
              Security-First Unified Namespace (S-UNS): {uns?.enterprise ?? 'QuanumisCorp'}
              <HelpTip term="unifiedNamespace" />
            </h2>
            <p>
              One canonical enterprise tree uniting Ignition Sparkplug B PLCs, raw ISA-95 semantic topics, AWS Cloud
              security findings, Android devices, and live GigaMesh Security Digital Twins.
            </p>
          </div>
          <button
            type="button"
            className="gm-btn gm-btn-primary"
            disabled={busy}
            onClick={onSimulateEnterprise}
          >
            Simulate Multi-Plant UNS Traffic
          </button>
        </div>
      </div>

      {/* 1-Click Site Read-Only Lockdown Controls */}
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            1-Click Plant Read-Only Lockdowns (Telemetry Keeps Flowing)
            <HelpTip term="unsSiteLockdown" />
          </h2>
          <span className="gm-tag">
            Active Lockdowns: {uns?.active_lockdowns.length ?? 0}
          </span>
        </div>
        <div className="gm-panel-body">
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
                    <div className="gm-muted mono" style={{ fontSize: 11 }}>
                      {pat}
                    </div>
                  </div>
                  <button
                    type="button"
                    className={`gm-btn ${isLocked ? 'gm-btn-crimson' : 'gm-btn-emerald'}`}
                    disabled={busy}
                    onClick={() => onToggleSiteLockdown(site, !isLocked)}
                  >
                    {isLocked ? '🔒 LOCKDOWN ACTIVE (Release)' : '🛡 Normal (Freeze Commands)'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Split Workspace: Interactive ISA-95 Tree Explorer + Branch Inspector */}
      <div className="gm-grid-2">
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Live ISA-95 Enterprise Tree ({uns?.total_nodes ?? 0} Nodes)
              <HelpTip term="unifiedNamespace" />
            </h2>
            <span className="gm-muted mono" style={{ fontSize: 11 }}>
              Click any branch to inspect
            </span>
          </div>
          <div className="gm-panel-body" style={{ maxHeight: 460, overflowY: 'auto' }}>
            {uns?.tree ? (
              <TreeBranch
                node={uns.tree}
                depth={0}
                selectedPath={activeNode?.path ?? ''}
                onSelect={setSelectedBranch}
              />
            ) : (
              <p className="gm-muted">Loading Unified Namespace tree…</p>
            )}
          </div>
        </div>

        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="mono" style={{ fontSize: 13 }}>
              Branch Inspector: {activeNode?.path ?? uns?.enterprise}
            </h2>
            <span className="gm-tag">{activeLeaves.length} Retained Metrics</span>
          </div>
          <div className="gm-panel-body gm-list-stack" style={{ maxHeight: 460, overflowY: 'auto' }}>
            {activeLeaves.map((leaf) => {
              const pb = protocolBadge(leaf.source_protocol);
              return (
                <div className="gm-item-box" key={leaf.topic}>
                  <div className="gm-row-between">
                    <strong className="mono" style={{ fontSize: 12 }}>
                      {leaf.layer}/{leaf.metric}
                    </strong>
                    <div className="gm-region-chips">
                      <span className={`gm-tag ${pb.cls}`}>{pb.label}</span>
                      <span
                        className={`gm-tag ${
                          leaf.security_state === 'healthy' ? 'champion' : 'critical'
                        }`}
                      >
                        {leaf.security_state.toUpperCase()}
                      </span>
                    </div>
                  </div>
                  <div className="gm-muted mono" style={{ fontSize: 11, marginTop: 4, wordBreak: 'break-all' }}>
                    {leaf.topic}
                  </div>
                  <div className="gm-row-between" style={{ marginTop: 6, fontSize: 12 }}>
                    <span>
                      Value: <strong className="mono">{String(leaf.value)}</strong> ({leaf.datatype})
                    </span>
                    <span className="gm-muted">Sender: {leaf.last_sender}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Hierarchical Wildcard Policy Manager (+ / #) + Security Digital Twin Feed */}
      <div className="gm-grid-2">
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Hierarchical Wildcard Policies ({uns?.total_policies ?? 0})
              <HelpTip term="unsWildcardPolicy" />
            </h2>
            <span className="gm-tag champion">Monotonic Strictest-Wins</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            <form onSubmit={handleCreatePolicy} className="gm-list-stack" style={{ paddingBottom: 8, borderBottom: '1px solid var(--border-subtle)' }}>
              <div className="gm-form-row" style={{ flexWrap: 'wrap' }}>
                <input
                  className="gm-input"
                  placeholder="Policy name (e.g. Line-2 Speed Cap)"
                  value={policyName}
                  onChange={(e) => setPolicyName(e.target.value)}
                  style={{ flex: '1 1 180px' }}
                />
                <select className="gm-select" value={scopeLevel} onChange={(e) => setScopeLevel(e.target.value)}>
                  <option value="Enterprise">Enterprise</option>
                  <option value="Site">Site</option>
                  <option value="Area">Area</option>
                  <option value="Line">Line</option>
                  <option value="Asset">Asset</option>
                </select>
              </div>
              <input
                className="gm-input mono"
                placeholder="MQTT Wildcard Pattern (+ / #)"
                value={topicPattern}
                onChange={(e) => setTopicPattern(e.target.value)}
              />
              <div className="gm-form-row" style={{ flexWrap: 'wrap' }}>
                <input className="gm-input" placeholder="Min" value={minVal} onChange={(e) => setMinVal(e.target.value)} style={{ width: 80 }} />
                <input className="gm-input" placeholder="Max" value={maxVal} onChange={(e) => setMaxVal(e.target.value)} style={{ width: 80 }} />
                <input className="gm-input" placeholder="Unit" value={unit} onChange={(e) => setUnit(e.target.value)} style={{ width: 70 }} />
                <button type="submit" className="gm-btn gm-btn-primary" disabled={busy}>
                  Attach Wildcard Policy
                </button>
              </div>
            </form>

            {(uns?.policies ?? []).map((p: UnsPolicyRule) => (
              <div className="gm-item-box" key={p.policy_id}>
                <div className="gm-row-between">
                  <strong style={{ fontSize: 12.5 }}>{p.name}</strong>
                  <div className="gm-region-chips">
                    <span className="gm-tag">{p.scope_level}</span>
                    <span className={`gm-tag ${p.enabled ? (p.read_only_lockdown ? 'critical' : 'champion') : 'culled'}`}>
                      {p.read_only_lockdown && p.enabled ? 'LOCKDOWN' : p.enabled ? 'ACTIVE' : 'DISABLED'}
                    </span>
                  </div>
                </div>
                <div className="mono gm-muted" style={{ fontSize: 11, marginTop: 4 }}>
                  {p.topic_pattern}
                </div>
                <div className="gm-region-chips" style={{ marginTop: 5 }}>
                  {p.require_e2e_signature && <span className="gm-tag rea">E2E Signed</span>}
                  {p.block_ai_tainted && <span className="gm-tag high">AI-Taint Barrier</span>}
                  {p.safety_interlock_locked && <span className="gm-tag critical">Interlock Immutable</span>}
                  {(p.min_value !== null || p.max_value !== null) && (
                    <span className="gm-tag champion">
                      Bounds: {p.min_value ?? '−∞'}..{p.max_value ?? '+∞'} {p.unit}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Live UNS Security Digital Twin Feed
              <HelpTip term="unsSecurityTwin" />
            </h2>
            <span className="gm-tag rea">Retained for Ignition / MES / ERP</span>
          </div>
          <div className="gm-panel-body gm-list-stack" style={{ maxHeight: 480, overflowY: 'auto' }}>
            {(uns?.security_twin_feed ?? []).length === 0 ? (
              <p className="gm-muted">
                Click <strong>Simulate Multi-Plant UNS Traffic</strong> or toggle a Site Lockdown to watch retained
                Security Digital Twin topics publish live.
              </p>
            ) : (
              (uns?.security_twin_feed ?? []).map((ev, i) => (
                <div className="gm-item-box" key={`${ev.topic}-${i}`}>
                  <div className="gm-row-between">
                    <span className="gm-tag champion">RETAINED</span>
                    <span className="gm-muted mono" style={{ fontSize: 10.5 }}>
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="mono" style={{ fontSize: 11.5, marginTop: 4, color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>
                    {ev.topic}
                  </div>
                  <pre className="gm-code" style={{ marginTop: 6, fontSize: 11 }}>
                    {JSON.stringify(ev.payload, null, 2)}
                  </pre>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
