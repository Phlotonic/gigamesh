import { useState } from 'react';
import type { AiGatewayStatus, ComplianceStatus, CopilotAnswer, SoarStatus } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  aiGateway: AiGatewayStatus | null;
  compliance: ComplianceStatus | null;
  soar: SoarStatus | null;
  busy: boolean;
  onRunRedTeam: () => Promise<void>;
  onInspectAiSample: (content: string, provider: string) => Promise<void>;
  onExportOcsf: () => Promise<Record<string, unknown>>;
  onRunPlaybook: (playbookId: string, target: string, dryRun: boolean) => Promise<void>;
  onRollbackPlaybook: (executionId: string) => Promise<void>;
  onAskCopilot: (question: string) => Promise<CopilotAnswer>;
}

export function EnterpriseSocSuitePanel({
  aiGateway,
  compliance,
  soar,
  busy,
  onRunRedTeam,
  onInspectAiSample,
  onExportOcsf,
  onRunPlaybook,
  onRollbackPlaybook,
  onAskCopilot,
}: Props) {
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState<CopilotAnswer | null>(null);
  const [aiSample, setAiSample] = useState('Analyze invoice for alice@corp.io with key AKIAIOSFODNN7EXAMPLE');
  const [aiProvider, setAiProvider] = useState('bedrock');
  const [ocsfPreview, setOcsfPreview] = useState<string | null>(null);

  async function ask(q: string) {
    if (!q.trim()) return;
    const res = await onAskCopilot(q.trim());
    setAnswer(res);
  }

  return (
    <div className="gm-list-stack">
      {/* 1. Air-Gapped 'Ask GigaMesh' Plain-English SOC Copilot */}
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            Ask GigaMesh — Air-Gapped Local SOC Assistant
            <HelpTip term="askGigaMesh" />
          </h2>
          <span className="gm-tag champion">100% LOCAL · ZERO HALLUCINATION</span>
        </div>
        <div className="gm-panel-body gm-list-stack">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              ask(question);
            }}
            className="gm-form-row"
            style={{ flexWrap: 'wrap' }}
          >
            <input
              className="gm-input"
              placeholder="Ask in plain English: e.g. 'How is our IEC 62443 compliance?' or 'Is AustinPlant safe?'"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              style={{ flex: '1 1 340px' }}
            />
            <button type="submit" className="gm-btn gm-btn-primary" disabled={busy}>
              Ask GigaMesh
            </button>
          </form>
          <div className="gm-region-chips">
            {[
              'Give me an overall security summary',
              'How is our IEC 62443 compliance?',
              'Is AustinPlant safe?',
              'Check AI & Shadow AI security',
              'Any vendor remote sessions?',
            ].map((chip) => (
              <button
                key={chip}
                type="button"
                className="gm-btn"
                style={{ fontSize: 11.5, padding: '4px 10px' }}
                onClick={() => {
                  setQuestion(chip);
                  ask(chip);
                }}
              >
                {chip}
              </button>
            ))}
          </div>
          {answer && (
            <div className="gm-item-box">
              <strong style={{ fontSize: 13.5 }}>{answer.answer}</strong>
              {answer.grounded_facts.length > 0 && (
                <ul style={{ margin: '8px 0 4px 18px', fontSize: 12, color: 'var(--text-secondary)' }}>
                  {answer.grounded_facts.map((f, i) => (
                    <li key={i}>{f}</li>
                  ))}
                </ul>
              )}
              {answer.recommended_actions.length > 0 && (
                <div className="gm-muted" style={{ fontSize: 11.5, marginTop: 4 }}>
                  Next step: {answer.recommended_actions[0]}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* 2. Inline AI Runtime Gateway, DSPM Redaction, AI-SPM & Automated Red-Teaming */}
      <div className="gm-grid-2">
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Inline AI Gateway, AI-SPM &amp; DSPM Secret Scrubber
              <HelpTip term="aiGatewayDspm" />
            </h2>
            <span className="gm-tag rea">
              Inspected: {aiGateway?.stats.total_inspected ?? 0} · Redacted: {aiGateway?.stats.redacted_count ?? 0}
            </span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            <div className="gm-form-row" style={{ flexWrap: 'wrap' }}>
              <select className="gm-select" value={aiProvider} onChange={(e) => setAiProvider(e.target.value)}>
                <option value="bedrock">AWS Bedrock (Approved)</option>
                <option value="anthropic">Anthropic (Approved)</option>
                <option value="local_vllm">Air-Gapped vLLM (Approved)</option>
                <option value="shadow_untrusted">Shadow External LLM (Unapproved)</option>
              </select>
              <input
                className="gm-input"
                value={aiSample}
                onChange={(e) => setAiSample(e.target.value)}
                style={{ flex: '1 1 200px' }}
              />
              <button
                type="button"
                className="gm-btn gm-btn-primary"
                disabled={busy}
                onClick={() => onInspectAiSample(aiSample, aiProvider)}
              >
                Test Inline DSPM
              </button>
            </div>
            {(aiGateway?.recent_verdicts ?? []).slice(0, 3).map((v) => (
              <div className="gm-item-box" key={v.request_id}>
                <div className="gm-row-between">
                  <strong className="mono" style={{ fontSize: 11.5 }}>
                    {v.provider}/{v.model} ({v.latency_us} µs)
                  </strong>
                  <span className={`gm-tag ${v.decision === 'block' ? 'critical' : 'champion'}`}>
                    {v.decision.toUpperCase()}
                  </span>
                </div>
                <div className="mono gm-muted" style={{ fontSize: 11, marginTop: 4 }}>
                  Sanitized: {v.sanitized_content}
                </div>
              </div>
            ))}
            <div className="gm-region-chips">
              {(aiGateway?.assets ?? []).map((a) => (
                <span className={`gm-tag ${a.approved ? 'champion' : 'critical'}`} key={a.asset_id}>
                  {a.approved ? '✓' : '⚠ SHADOW'} {a.name}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Continuous Automated AI Red-Teaming
              <HelpTip term="autoRedTeam" />
            </h2>
            <button type="button" className="gm-btn gm-btn-primary" disabled={busy} onClick={onRunRedTeam}>
              Run 6-Vector Red-Team Campaign
            </button>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {aiGateway?.last_red_team ? (
              <>
                <div className="gm-row-between">
                  <strong>
                    Resilience Score: {aiGateway.last_red_team.blocked_probes}/{aiGateway.last_red_team.total_probes}{' '}
                    Blocked
                  </strong>
                  <span className="gm-tag champion">{aiGateway.last_red_team.resilience_score_pct}% RESILIENT</span>
                </div>
                {aiGateway.last_red_team.results.map((r) => (
                  <div className="gm-item-box" key={r.probe_id}>
                    <div className="gm-row-between">
                      <strong style={{ fontSize: 12 }}>
                        {r.probe_id}: {r.attack_name}
                      </strong>
                      <span className={`gm-tag ${r.blocked ? 'champion' : 'critical'}`}>
                        {r.blocked ? 'BLOCKED' : 'GAP'} ({r.latency_ms}ms)
                      </span>
                    </div>
                    <div className="gm-muted" style={{ fontSize: 11 }}>
                      {r.defense_layer} · {r.detail}
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <p className="gm-muted" style={{ margin: 0 }}>
                Launch a live 6-vector adversarial campaign testing jailbreaks, Shadow AI exfiltration, MCP shell abuse,
                AI-to-OT boiler sabotage, hardware interlock overrides, and multi-secret DSPM scrubbing.
              </p>
            )}
          </div>
        </div>
      </div>

      {/* 3. Continuous 5-Framework Compliance + MITRE Triple-Matrix + OCSF v1.3 + Sigma */}
      <div className="gm-grid-2">
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              5-Framework Continuous Compliance ({compliance?.overall_readiness_pct ?? 0}%)
              <HelpTip term="continuousCompliance" />
            </h2>
            <button
              type="button"
              className="gm-btn"
              disabled={busy}
              onClick={async () => {
                const res = await onExportOcsf();
                setOcsfPreview(JSON.stringify(res, null, 2).slice(0, 900));
              }}
            >
              Export OCSF v1.3
            </button>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {(compliance?.frameworks ?? []).map((fw) => (
              <div className="gm-item-box" key={fw.framework}>
                <div className="gm-row-between">
                  <strong style={{ fontSize: 12.5 }}>{fw.full_name}</strong>
                  <span className="gm-tag champion">
                    {fw.passing_controls}/{fw.total_controls} ({fw.readiness_pct}%)
                  </span>
                </div>
                <div className="gm-muted" style={{ fontSize: 11, marginTop: 4 }}>
                  {fw.controls.map((c) => `${c.control_id}: ${c.status}`).join(' · ')}
                </div>
              </div>
            ))}
            {ocsfPreview && (
              <pre className="gm-code" style={{ fontSize: 10.5, maxHeight: 160, overflowY: 'auto' }}>
                {ocsfPreview}
              </pre>
            )}
          </div>
        </div>

        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              MITRE Triple-Matrix (Enterprise + ICS + ATLAS) &amp; Sigma
              <HelpTip term="mitreTripleMatrix" />
            </h2>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {compliance && (
              <>
                <div>
                  <strong style={{ fontSize: 11.5 }}>MITRE ATT&amp;CK for ICS (Factory OT)</strong>
                  <div className="gm-region-chips" style={{ marginTop: 4 }}>
                    {compliance.mitre_triple_matrix.ics_attack.map((m) => (
                      <span className="gm-tag champion" key={m.id} title={`${m.name} — ${m.layer}`}>
                        {m.id}: {m.name.split(' ')[0]}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <strong style={{ fontSize: 11.5 }}>MITRE ATLAS (Agentic AI &amp; LLM)</strong>
                  <div className="gm-region-chips" style={{ marginTop: 4 }}>
                    {compliance.mitre_triple_matrix.atlas_ai.map((m) => (
                      <span className="gm-tag rea" key={m.id} title={`${m.name} — ${m.layer}`}>
                        {m.id}: {m.name.split(' ')[0]}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <strong style={{ fontSize: 11.5 }}>MITRE ATT&amp;CK Enterprise</strong>
                  <div className="gm-region-chips" style={{ marginTop: 4 }}>
                    {compliance.mitre_triple_matrix.enterprise_attack.map((m) => (
                      <span className="gm-tag" key={m.id} title={`${m.name} — ${m.layer}`}>
                        {m.id}: {m.name.split(' ')[0]}
                      </span>
                    ))}
                  </div>
                </div>
                <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 8 }}>
                  <strong style={{ fontSize: 11.5 }}>Active Sigma Detection-as-Code Rules</strong>
                  {compliance.sigma_rules.map((r) => (
                    <div className="gm-row-between" style={{ fontSize: 11.5, marginTop: 4 }} key={r.rule_id}>
                      <span>{r.title}</span>
                      <span className="gm-tag">{r.matches_count} matches</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 4. Declarative SOAR Playbooks with Dry-Run & 1-Click Safe Rollback */}
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            Declarative SOAR Playbooks (Dry-Run + 1-Click Safe Rollback)
            <HelpTip term="soarRollback" />
          </h2>
          <span className="gm-tag">{soar?.playbooks.length ?? 0} Turn-Key Playbooks</span>
        </div>
        <div className="gm-panel-body gm-list-stack">
          <div className="gm-grid-2">
            {(soar?.playbooks ?? []).map((pb) => {
              const target =
                pb.playbook_id === 'pb-plant-lockdown'
                  ? 'AustinPlant'
                  : pb.playbook_id === 'pb-rogue-ai-quarantine'
                  ? 'rogue-agent-01'
                  : 'zseg-l3-to-l1-s7';
              return (
                <div className="gm-item-box" key={pb.playbook_id}>
                  <strong style={{ fontSize: 13 }}>{pb.name}</strong>
                  <p className="gm-muted" style={{ fontSize: 11.5, margin: '4px 0 8px' }}>
                    {pb.plain_english_summary}
                  </p>
                  <div className="gm-form-row">
                    <button
                      type="button"
                      className="gm-btn"
                      disabled={busy}
                      onClick={() => onRunPlaybook(pb.playbook_id, target, true)}
                    >
                      Dry-Run Preview
                    </button>
                    <button
                      type="button"
                      className="gm-btn gm-btn-crimson"
                      disabled={busy}
                      onClick={() => onRunPlaybook(pb.playbook_id, target, false)}
                    >
                      Execute Now
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {(soar?.recent_executions ?? []).length > 0 && (
            <div className="gm-list-stack">
              {(soar?.recent_executions ?? []).slice(0, 5).map((ex) => (
                <div className="gm-item-box" key={ex.execution_id}>
                  <div className="gm-row-between">
                    <div>
                      <strong>{ex.playbook_name}</strong>{' '}
                      <span className="gm-muted mono" style={{ fontSize: 11 }}>
                        ({ex.target})
                      </span>
                    </div>
                    <div className="gm-form-row">
                      <span
                        className={`gm-tag ${
                          ex.status === 'executed'
                            ? 'critical'
                            : ex.status === 'rolled_back'
                            ? 'champion'
                            : 'rea'
                        }`}
                      >
                        {ex.status.toUpperCase()}
                      </span>
                      {ex.status === 'executed' && (
                        <button
                          type="button"
                          className="gm-btn gm-btn-emerald"
                          disabled={busy}
                          onClick={() => onRollbackPlaybook(ex.execution_id)}
                        >
                          ↩ 1-Click Rollback
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="gm-muted mono" style={{ fontSize: 11, marginTop: 4 }}>
                    {ex.actions_log.join(' → ')}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
