import { useState } from 'react';
import type { RedHatControlData } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  data: RedHatControlData;
}

type PolicyTab = 'selinux' | 'nftables' | 'auditd' | 'systemd' | 'openshift';

export function RedHatControlPanel({ data }: Props) {
  const [policyTab, setPolicyTab] = useState<PolicyTab>('selinux');

  return (
    <div className="gm-list-stack">
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            Dynamic MCP Policy Proxy &amp; Agent Kill-Switch
            <HelpTip term="mcpProxy" />
          </h2>
          <span className="gm-tag">
            {data.mcp_proxy.frozen_agents.length} frozen · {Object.keys(data.mcp_proxy.blocked_mcp_tools).length} blocked tools
          </span>
        </div>
        <div className="gm-panel-body gm-grid-equal">
          <div>
            <h3 style={{ fontSize: 13, marginBottom: 8 }}>Frozen Agent Sessions</h3>
            {data.mcp_proxy.frozen_agents.length === 0 ? (
              <p className="gm-muted" style={{ margin: 0 }}>No frozen agents yet.</p>
            ) : (
              data.mcp_proxy.frozen_agents.map((a) => (
                <div className="gm-item-box" key={a.agent_id} style={{ marginBottom: 6 }}>
                  <div className="gm-row-between">
                    <strong className="mono">{a.agent_id}</strong>
                    <span className="gm-tag culled">FROZEN</span>
                  </div>
                  <div className="gm-muted" style={{ marginTop: 2 }}>{a.reason} ({a.fork_id})</div>
                </div>
              ))
            )}
          </div>

          <div>
            <h3 style={{ fontSize: 13, marginBottom: 8 }}>Blocked MCP Capabilities &amp; Revoked Tokens</h3>
            {Object.keys(data.mcp_proxy.blocked_mcp_tools).length === 0 && data.mcp_proxy.revoked_tokens.length === 0 ? (
              <p className="gm-muted" style={{ margin: 0 }}>No blocked tools or revoked OAuth tokens yet.</p>
            ) : (
              <div className="gm-list-stack">
                {Object.entries(data.mcp_proxy.blocked_mcp_tools).map(([tool, reason]) => (
                  <div className="gm-item-box" key={tool}>
                    <span className="gm-tag critical" style={{ marginRight: 8 }}>DENY TOOL</span>
                    <code style={{ fontWeight: 600 }}>{tool}</code> — <span className="gm-muted">{reason}</span>
                  </div>
                ))}
                {data.mcp_proxy.revoked_tokens.map((tok) => (
                  <div className="gm-item-box" key={tok}>
                    <span className="gm-tag critical" style={{ marginRight: 8 }}>REVOKED</span>
                    <code>{tok}</code>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            Red Hat Enterprise Linux / OpenShift &amp; Offensive Red-Hat Control Orders
            <HelpTip term="redhatControl" />
          </h2>
          <div className="gm-form-row">
            {(['selinux', 'nftables', 'auditd', 'systemd', 'openshift'] as PolicyTab[]).map((t) => (
              <HelpTip key={t} term={t}>
                <button
                  type="button"
                  className={`gm-btn ${policyTab === t ? 'gm-btn-primary' : ''}`}
                  onClick={() => setPolicyTab(t)}
                >
                  {t.toUpperCase()}
                </button>
              </HelpTip>
            ))}
          </div>
        </div>
        <div className="gm-panel-body gm-list-stack">
          {data.redhat_orders.length === 0 ? (
            <p className="gm-muted" style={{ margin: 0 }}>
              Run the Red-Hat Offensive Loop or Systemd Persistence scenario to synthesize SELinux confinement policies, nftables egress locks, auditd syscall watches, and OpenShift NetworkPolicy manifests.
            </p>
          ) : (
            data.redhat_orders.map((order) => {
              const snippet =
                policyTab === 'selinux'
                  ? order.selinux_policy
                  : policyTab === 'nftables'
                  ? order.nftables_rules
                  : policyTab === 'auditd'
                  ? order.auditd_rules
                  : policyTab === 'systemd'
                  ? order.systemd_commands.join('\n')
                  : order.openshift_network_policy;
              return (
                <div className="gm-item-box" key={order.order_id}>
                  <div className="gm-row-between" style={{ marginBottom: 8 }}>
                    <div>
                      <strong className="mono">{order.target_id}</strong>{' '}
                      <span className="gm-muted">({order.target_kind})</span>
                    </div>
                    <div className="gm-form-row">
                      <span className={`gm-tag ${order.status === 'enforced' ? 'champion' : 'pending'}`}>
                        {order.status.toUpperCase()} · {order.mode}
                      </span>
                      {order.quorum_id && <span className="gm-tag">quorum: {order.quorum_id}</span>}
                    </div>
                  </div>
                  <pre className="gm-code-block">{snippet}</pre>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
