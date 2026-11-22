import type { MetabolizedDefenseModule, OverviewResponse, ReaEvidenceDossier, RedHatControlData } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  doctor: OverviewResponse['rea_doctor'];
  dossiers: ReaEvidenceDossier[];
  modules: MetabolizedDefenseModule[];
  snares: RedHatControlData['snare_sessions'];
}

export function ReaMetabolismLab({ doctor, dossiers, modules, snares }: Props) {
  return (
    <div className="gm-list-stack">
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            Reverse Engineer Anything (morluto/rea) Bridge Status
            <HelpTip term="reaBridge" />
          </h2>
          <span className={`gm-tag ${doctor.live_rea_available ? 'champion' : 'rea'}`}>
            {doctor.live_rea_available ? 'LIVE REA CLI ATTACHED' : 'REA-CONTRACT LOCAL ENGINE'}
          </span>
        </div>
        <div className="gm-panel-body">
          <div className="gm-row-between">
            <div>
              <div className="gm-muted">Scoped MCP Tool Families (`REA_MCP_TOOL_FAMILIES`)</div>
              <div className="mono" style={{ fontSize: 12.5, marginTop: 4 }}>
                {doctor.configured_tool_families.join(', ')}
              </div>
            </div>
            <div>
              <div className="gm-muted">Attach Live `morluto/rea` Package</div>
              <div className="mono" style={{ fontSize: 12, marginTop: 4 }}>
                {doctor.install_hint}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="gm-grid-equal">
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              REA Dissection Dossiers &amp; Residual Unknowns
              <HelpTip term="reaDossiers" />
            </h2>
            <span className="gm-tag">{dossiers.length} dossiers</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {dossiers.length === 0 ? (
              <p className="gm-muted" style={{ margin: 0 }}>
                No attacker artifacts dissected yet. Trigger an Evolution Generation or Attack Scenario to watch GigaMesh ensnare an attacker, harvest its artifact, and dissect it via REA.
              </p>
            ) : (
              dossiers.map((d) => (
                <div className="gm-item-box" key={d.dossier_id}>
                  <div className="gm-row-between">
                    <strong className="mono" style={{ fontSize: 12.5 }}>{d.attacker_family}</strong>
                    <span className="gm-tag rea tabular">
                      {(d.dissection_completeness * 100).toFixed(0)}% complete · {d.probe_rounds} probe(s)
                    </span>
                  </div>
                  <p style={{ margin: '6px 0', fontSize: 12.5 }}>{d.behavioral_summary}</p>
                  <div className="mono" style={{ fontSize: 11, color: '#4e545e', marginBottom: 8 }}>
                    $ {d.rea_commands_executed.join(' && ')}
                  </div>
                  {d.evidence_items.map((ev) => (
                    <div key={ev.evidence_id} style={{ fontSize: 12, marginBottom: 4 }}>
                      <span className="gm-tag" style={{ marginRight: 6 }}>{ev.category}</span>
                      <span>{ev.summary}</span>{' '}
                      <code style={{ fontSize: 11, color: '#1d4c8a' }}>[{ev.symbol_or_offset}]</code>
                    </div>
                  ))}
                  {d.residual_unknowns.map((u) => (
                    <div key={u.unknown_id} style={{ fontSize: 12, marginTop: 8, paddingTop: 6, borderTop: '1px dashed #dcd7cc' }}>
                      <span className={`gm-tag ${u.resolved ? 'resolved' : 'pending'}`} style={{ marginRight: 6 }}>
                        {u.resolved ? 'UNKNOWN RESOLVED VIA SNARE BAIT' : 'RESIDUAL UNKNOWN'}
                      </span>
                      <span>{u.description}</span>
                      {u.resolution_evidence && (
                        <div className="mono" style={{ fontSize: 11, color: '#16684a', marginTop: 3 }}>
                          Elicited: {u.resolution_evidence}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Metabolized Defensive Modules &amp; Cross-Attacker Immunity
              <HelpTip term="crossAttackerImmunity" />
            </h2>
            <span className="gm-tag champion">{modules.length} metabolized</span>
          </div>
          <div className="gm-panel-body gm-list-stack">
            {modules.length === 0 ? (
              <p className="gm-muted" style={{ margin: 0 }}>
                Metabolized counter-defenses appear here once REA extracts attacker mechanisms. Each module is safety-verified and cross-tested against different attacker families.
              </p>
            ) : (
              modules.map((m) => {
                const crossFamilies = Object.entries(m.cross_attacker_hits).filter(
                  ([fam]) => fam !== m.source_attacker_family
                );
                return (
                  <div className="gm-item-box" key={m.module_id}>
                    <div className="gm-row-between">
                      <strong style={{ fontSize: 13 }}>{m.name}</strong>
                      <span className={`gm-tag ${m.quorum_approved ? 'champion' : 'active'}`}>
                        {m.quorum_approved ? 'QUORUM VERIFIED' : m.capability_kind}
                      </span>
                    </div>
                    <p style={{ margin: '6px 0', fontSize: 12.5, color: '#4e545e' }}>{m.description}</p>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 6 }}>
                      <span className="gm-tag">source: {m.source_attacker_family}</span>
                      <span className="gm-tag champion">
                        +{(m.detection_boost * 100).toFixed(0)}% det · +{(m.containment_boost * 100).toFixed(0)}% contain
                      </span>
                    </div>
                    {crossFamilies.length > 0 && (
                      <div style={{ fontSize: 12, marginTop: 6 }}>
                        <strong>Cross-Attacker Immunity Hits: </strong>
                        {crossFamilies.map(([fam, count]) => (
                          <span key={fam} className="gm-tag rea" style={{ marginRight: 5 }}>
                            {fam} ({count})
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}

            {snares.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <h3 className="gm-heading-tip" style={{ fontSize: 13, marginBottom: 8 }}>
                  Active Adaptive Deception Snares ({snares.length})
                  <HelpTip term="deceptionSnares" />
                </h3>
                {snares.slice(0, 5).map((s) => (
                  <div className="gm-item-box" key={s.session_id} style={{ marginBottom: 6 }}>
                    <div className="gm-row-between">
                      <span className="mono" style={{ fontSize: 12 }}>{s.attacker_id} ({s.attacker_family})</span>
                      <span className="gm-tag ensnared">{s.status}</span>
                    </div>
                    <div className="gm-muted mono" style={{ marginTop: 3 }}>
                      canary={s.canary_token} · dwell={s.dwell_interactions} · probes={s.bait_probes_sent.length}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
