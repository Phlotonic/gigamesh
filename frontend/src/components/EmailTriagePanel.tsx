import type { EmailListenerStatus, EmailTriageDecision } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  status: EmailListenerStatus | null;
  decisions: EmailTriageDecision[];
  busy: boolean;
  onToggle: (enabled: boolean) => Promise<void>;
  onPollNow: () => Promise<void>;
  onSimulateLegitCve: () => Promise<void>;
  onSimulateHostileInjection: () => Promise<void>;
}

export function EmailTriagePanel({
  status,
  decisions,
  busy,
  onToggle,
  onPollNow,
  onSimulateLegitCve,
  onSimulateHostileInjection,
}: Props) {
  return (
    <div className="gm-list-stack">
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            Event-Driven Gmail Security Vulnerability Listener
            <HelpTip term="emailListener" />
          </h2>
          <div className="gm-form-row">
            <span className={`gm-tag ${status?.gmail_authenticated ? 'champion' : 'pending'}`}>
              Gmail Auth: {status?.gmail_authenticated ? 'CONNECTED' : 'OFFLINE'}
            </span>
            <span className={`gm-tag ${status?.running ? 'champion' : 'pending'}`}>
              Listener: {status?.running ? `ACTIVE (${status.poll_interval_sec}s + Webhook)` : 'PAUSED'}
            </span>
            <button
              type="button"
              className="gm-btn"
              disabled={busy || !status}
              onClick={() => status && onToggle(!status.running)}
            >
              {status?.running ? 'Pause Listener' : 'Start Listener'}
            </button>
            <button
              type="button"
              className="gm-btn gm-btn-primary"
              disabled={busy}
              onClick={onPollNow}
            >
              Poll Gmail Inbox Now
            </button>
          </div>
        </div>
        <div className="gm-panel-body gm-list-stack">
          <div className="gm-row-between">
            <div>
              <div className="gm-muted gm-heading-tip">
                Active Gmail Search Filter &amp; Draft-First Safety
                <HelpTip term="draftFirstSafety" />
              </div>
              <div className="mono" style={{ fontSize: 11.5, marginTop: 3 }}>
                query={status?.search_query}
              </div>
              <div className="gm-muted mono" style={{ marginTop: 3 }}>
                historyId={status?.last_history_id || 'initial'} · processed={status?.processed_count ?? 0} · drafts={status?.drafts_created_count ?? 0} · hostile_blocked={status?.hostile_blocked_count ?? 0} · auto_send=BLOCKED (Draft-First Safety)
              </div>
            </div>
            <div className="gm-form-row">
              <button type="button" className="gm-btn gm-btn-emerald" disabled={busy} onClick={onSimulateLegitCve}>
                Test Webhook: Legit CVE Disclosure
              </button>
              <HelpTip term="promptInjection">
                <button type="button" className="gm-btn gm-btn-crimson" disabled={busy} onClick={onSimulateHostileInjection}>
                  Test Webhook: Hostile Prompt-Injection Email
                </button>
              </HelpTip>
            </div>
          </div>
        </div>
      </div>

      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            Autonomous Email Triage Decisions &amp; Draft Queue
            <HelpTip term="spfDkim" />
          </h2>
          <span className="gm-tag">{decisions.length} triaged</span>
        </div>
        <div className="gm-panel-body gm-list-stack">
          {decisions.length === 0 ? (
            <p className="gm-muted" style={{ margin: 0 }}>
              No security vulnerability emails triaged yet. Click <strong>Poll Gmail Inbox Now</strong> to scan unread security disclosures, or test the webhook pipeline with a simulated CVE or hostile prompt-injection email above.
            </p>
          ) : (
            decisions.map((d) => (
              <div className="gm-item-box" key={d.triage_id}>
                <div className="gm-row-between">
                  <div>
                    <strong style={{ fontSize: 13.5 }}>{d.subject}</strong>
                    <div className="gm-muted mono">
                      from={d.sender} · SPF/DKIM={d.spf_dkim_verified ? 'PASS' : 'FAIL'} · msg={d.message_id}
                    </div>
                  </div>
                  <div className="gm-form-row">
                    <span className={`gm-tag ${d.prompt_injection_detected ? 'critical' : d.severity}`}>
                      {d.classification}
                    </span>
                    <span className="gm-tag">{d.status}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                  {d.cve_ids.map((c) => (
                    <span key={c} className="gm-tag critical">{c}</span>
                  ))}
                  {d.affected_components.map((comp) => (
                    <span key={comp} className="gm-tag rea">{comp}</span>
                  ))}
                  {d.quorum_id && <span className="gm-tag pending">HITL Quorum: {d.quorum_id}</span>}
                  {d.rea_dossier_id && <span className="gm-tag rea">REA Dissected: {d.rea_dossier_id}</span>}
                  {d.evolution_generation_id && <span className="gm-tag champion">Auto-Hardened Gen #{d.evolution_generation_id}</span>}
                  {d.draft_created && <span className="gm-tag champion">Gmail Draft Saved ({d.draft_id})</span>}
                </div>

                <div className="gm-muted mono" style={{ marginTop: 8 }}>
                  Actions: {d.actions_taken.join(' → ')}
                </div>

                {d.draft_preview && (
                  <details style={{ marginTop: 8 }}>
                    <summary style={{ cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                      Inspect Prepared Researcher Reply Draft (Human Review Required Before Send)
                    </summary>
                    <pre className="gm-code-block" style={{ marginTop: 6 }}>{d.draft_preview}</pre>
                  </details>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
