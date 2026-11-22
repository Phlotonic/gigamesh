import { useState } from 'react';
import type { ForkGenome, HumanHubData } from '../types';

interface Props {
  data: HumanHubData;
  forks: ForkGenome[];
  onVote: (payload: {
    analyst_id: string;
    analyst_reputation: number;
    target_kind: string;
    target_id: string;
    verdict: string;
    annotation: string;
    proposed_pattern: string | null;
  }) => Promise<void>;
  onSignQuorum: (quorumId: string, analystId: string, decision: string) => Promise<void>;
  onExportStix: () => Promise<void>;
}

export function HumanGovernanceHub({ data, forks, onVote, onSignQuorum, onExportStix }: Props) {
  const survivingForks = forks.filter((f) => f.status !== 'culled');
  const [analystId, setAnalystId] = useState('soc-lead-maya');
  const [targetId, setTargetId] = useState(survivingForks[0]?.fork_id || 'fork-genesis-balanced');
  const [verdict, setVerdict] = useState('confirm_threat');
  const [annotation, setAnnotation] = useState('Verified red-hat evasion signature across RHEL cluster');
  const [pattern, setPattern] = useState('x-covert-relay');
  const [quorumSigner, setQuorumSigner] = useState('soc-lead-maya');
  const [busy, setBusy] = useState(false);

  async function handleSubmitVote(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await onVote({
        analyst_id: analystId,
        analyst_reputation: 1.5,
        target_kind: 'fork',
        target_id: targetId || survivingForks[0]?.fork_id || 'fork-genesis-balanced',
        verdict,
        annotation,
        proposed_pattern: pattern.trim() || null,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gm-list-stack">
      <div className="gm-grid-equal">
        {/* Cryptographic HITL Quorum Gate */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2>Cryptographic HITL Quorum Gate</h2>
            <div className="gm-form-row">
              <label className="gm-muted" htmlFor="quorum-signer">Signer:</label>
              <select
                id="quorum-signer"
                className="gm-select"
                value={quorumSigner}
                onChange={(e) => setQuorumSigner(e.target.value)}
              >
                <option value="soc-lead-maya">soc-lead-maya</option>
                <option value="ir-director-kenji">ir-director-kenji</option>
                <option value="rhel-sec-elena">rhel-sec-elena</option>
              </select>
            </div>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {data.quorums.length === 0 ? (
              <p className="gm-muted" style={{ margin: 0 }}>
                No high-impact Tier-2 quorum gates open yet. Run an attack scenario or evolution generation to trigger cryptographic M-of-N review.
              </p>
            ) : (
              data.quorums.map((q) => (
                <div className="gm-item-box" key={q.quorum_id}>
                  <div className="gm-row-between">
                    <strong className="mono" style={{ fontSize: 12 }}>{q.action_kind} → {q.target_id}</strong>
                    <span className={`gm-tag ${q.status}`}>{q.status.toUpperCase()}</span>
                  </div>
                  <p style={{ margin: '6px 0', fontSize: 12.5 }}>{q.summary}</p>
                  <div className="gm-row-between">
                    <span className="gm-muted mono">
                      Signatures: {q.signatures.length}/{q.required_approvals} ({q.signatures.map((s) => s.analyst_id).join(', ') || 'none'})
                    </span>
                    {q.status === 'pending' && (
                      <div className="gm-form-row">
                        <button
                          type="button"
                          className="gm-btn gm-btn-emerald"
                          onClick={() => onSignQuorum(q.quorum_id, quorumSigner, 'approve')}
                        >
                          Sign Approve
                        </button>
                        <button
                          type="button"
                          className="gm-btn gm-btn-crimson"
                          onClick={() => onSignQuorum(q.quorum_id, quorumSigner, 'reject')}
                        >
                          Reject
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Collective Analyst Defense & Rule Compiler */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2>Collective Analyst Defense & Rule Compiler</h2>
            <span className="gm-tag champion">{data.rules.length} active rules</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            <form onSubmit={handleSubmitVote} className="gm-list-stack">
              <div className="gm-form-row">
                <input
                  className="gm-input"
                  value={analystId}
                  onChange={(e) => setAnalystId(e.target.value)}
                  placeholder="Analyst ID"
                  aria-label="Analyst ID"
                />
                <select className="gm-select" value={targetId} onChange={(e) => setTargetId(e.target.value)} aria-label="Target fork">
                  {survivingForks.map((f) => (
                    <option key={f.fork_id} value={f.fork_id}>{f.fork_id} ({f.use_case})</option>
                  ))}
                </select>
                <select className="gm-select" value={verdict} onChange={(e) => setVerdict(e.target.value)} aria-label="Verdict">
                  <option value="confirm_threat">Confirm Threat (+Reward)</option>
                  <option value="approve_promotion">Approve Promotion (+Reward)</option>
                  <option value="false_positive">False Positive (-Reward)</option>
                </select>
              </div>
              <div className="gm-form-row">
                <input
                  className="gm-input"
                  style={{ flex: 1 }}
                  value={annotation}
                  onChange={(e) => setAnnotation(e.target.value)}
                  placeholder="Analyst intelligence annotation"
                  aria-label="Annotation"
                />
                <input
                  className="gm-input mono"
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="Proposed regex/IOC pattern"
                  aria-label="Proposed pattern"
                />
                <button type="submit" className="gm-btn gm-btn-primary" disabled={busy}>
                  Submit Consensus Vote
                </button>
              </div>
            </form>

            {data.rules.length > 0 && (
              <div className="gm-list-stack" style={{ marginTop: 6 }}>
                {data.rules.map((r) => (
                  <div className="gm-item-box" key={r.rule_id}>
                    <div className="gm-row-between">
                      <strong>{r.title}</strong>
                      <span className="gm-tag champion">weight {r.consensus_weight}</span>
                    </div>
                    <div className="mono gm-muted" style={{ marginTop: 3 }}>
                      pattern=/{r.pattern}/i · authors={r.author_analysts.join(', ')}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Human Identity Telemetry + Federated STIX 2.1 */}
      <div className="gm-grid-equal">
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2>Human-Identity & Delegation Risk Correlation</h2>
          </div>
          <div className="gm-panel-body gm-table-wrap">
            <table className="gm-table">
              <thead>
                <tr>
                  <th>Human Principal</th>
                  <th>Risk Score</th>
                  <th>MFA / Phish / OAuth</th>
                  <th>Delegated Agents</th>
                </tr>
              </thead>
              <tbody>
                {data.identities.map((id) => (
                  <tr key={id.human_principal_id}>
                    <td>
                      <strong>{id.display_name}</strong>
                      <div className="gm-muted mono">{id.human_principal_id}</div>
                    </td>
                    <td className="tabular">
                      <span className={`gm-tag ${id.risk_score >= 0.5 ? 'critical' : id.risk_score >= 0.25 ? 'pending' : 'champion'}`}>
                        {(id.risk_score * 100).toFixed(0)}%
                      </span>
                    </td>
                    <td className="mono tabular">
                      {id.mfa_anomalies} / {id.phishing_reports} / {id.suspicious_oauth_grants}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {id.active_delegated_agents.join(', ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2>Federated Crowdsourced STIX 2.1 Exchange</h2>
            <button type="button" className="gm-btn gm-btn-primary" onClick={onExportStix}>
              Export Signed STIX 2.1 Bundle
            </button>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {data.stix_bundles.length === 0 ? (
              <p className="gm-muted" style={{ margin: 0 }}>
                Export anonymized, PII-scrubbed graph motifs from metabolized REA modules and collective human rules to share herd immunity across federated defenders.
              </p>
            ) : (
              data.stix_bundles.slice(0, 3).map((b) => (
                <div className="gm-item-box" key={b.bundle_id}>
                  <div className="gm-row-between">
                    <span className="mono" style={{ fontSize: 11.5 }}>{b.bundle_id}</span>
                    <span className="gm-tag rea">{b.motifs.length} motifs</span>
                  </div>
                  <div className="gm-muted mono" style={{ marginTop: 4 }}>
                    org_hash={b.origin_org_hash} · sig={b.signature.slice(0, 18)}…
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
