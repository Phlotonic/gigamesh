import { useMemo, useState } from 'react';
import type { OwaspBenchmarkReport } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  report: OwaspBenchmarkReport | null;
  busy: boolean;
  onRunBenchmark: () => Promise<void>;
}

type FwFilter = 'all' | 'OWASP-Agentic-2026' | 'OWASP-LLM-2025' | 'OWASP-Web-2025';

const FW_LABELS: Record<string, string> = {
  'OWASP-Agentic-2026': 'Agentic AI Top 10 (2026)',
  'OWASP-LLM-2025': 'LLM Apps Top 10 (2025)',
  'OWASP-Web-2025': 'Web Apps Top 10 (2025)',
};

export function OwaspBenchmarkPanel({ report, busy, onRunBenchmark }: Props) {
  const [fwFilter, setFwFilter] = useState<FwFilter>('all');

  const rows = useMemo(() => {
    if (!report) return [];
    if (fwFilter === 'all') return report.results;
    return report.results.filter((r) => r.framework === fwFilter);
  }, [report, fwFilter]);

  return (
    <div className="gm-list-stack">
      <div className="gm-panel">
        <div className="gm-panel-body gm-crawler-hero">
          <div>
            <h2 className="gm-heading-tip" style={{ margin: 0, fontFamily: 'var(--font-display)', fontSize: 18 }}>
              OWASP Top 10 Triple-Framework Live Security Benchmark
              <HelpTip term="owaspBenchmark" />
            </h2>
            <p>
              Continuously tests GigaMesh against all 30 canonical OWASP Top 10 risks — <strong>Agentic AI (ASI01–ASI10)</strong>,{' '}
              <strong>LLM Applications (LLM01–LLM10)</strong>, and <strong>Web Applications (A01–A10)</strong> — plus a benign
              control suite to guarantee zero false alarms.
            </p>
          </div>
          <div className="gm-form-row">
            <button
              id="btn-run-owasp-benchmark"
              type="button"
              className="gm-btn gm-btn-primary"
              disabled={busy}
              onClick={onRunBenchmark}
            >
              {busy ? 'Running 30 OWASP Probes…' : 'Run Live OWASP Benchmark Now'}
            </button>
          </div>
        </div>
      </div>

      {report && (
        <>
          <section className="gm-kpi-strip" aria-label="OWASP Benchmark Summary">
            <div className="gm-kpi">
              <div className="gm-kpi-label gm-heading-tip">
                Overall OWASP Score
                <HelpTip term="owaspBenchmark" />
              </div>
              <div
                className="gm-kpi-value tabular"
                style={{ color: report.overall_pass_rate >= 1 ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}
              >
                {report.passed_probes}/{report.total_probes} ({(report.overall_pass_rate * 100).toFixed(0)}%)
              </div>
              <div className="gm-kpi-sub">All 3 OWASP Top 10 frameworks</div>
            </div>
            {report.framework_scores.map((fw) => (
              <div className="gm-kpi" key={fw.framework}>
                <div className="gm-kpi-label">{FW_LABELS[fw.framework] || fw.framework}</div>
                <div
                  className="gm-kpi-value tabular"
                  style={{ color: fw.pass_rate >= 1 ? 'var(--accent-emerald)' : 'var(--accent-crimson)' }}
                >
                  {fw.passed}/{fw.total}
                </div>
                <div className="gm-kpi-sub">{(fw.pass_rate * 100).toFixed(0)}% defended</div>
              </div>
            ))}
            <div className="gm-kpi">
              <div className="gm-kpi-label gm-heading-tip">
                Benign False Alarms
                <HelpTip term="benignFpRate" />
              </div>
              <div
                className="gm-kpi-value tabular"
                style={{ color: report.benign_false_positives === 0 ? 'var(--accent-emerald)' : 'var(--accent-crimson)' }}
              >
                {report.benign_false_positives}/{report.benign_controls_total}
              </div>
              <div className="gm-kpi-sub">{(report.benign_fp_rate * 100).toFixed(1)}% false-positive rate</div>
            </div>
          </section>

          <div className="gm-panel">
            <div className="gm-panel-header">
              <h2 className="gm-heading-tip">
                Detailed Probe Results &amp; Beyond-SOTA Innovations
                <HelpTip term="circuitBreaker" />
              </h2>
              <div className="gm-form-row">
                {(
                  [
                    ['all', 'All (30)'],
                    ['OWASP-Agentic-2026', 'Agentic 2026 (10)'],
                    ['OWASP-LLM-2025', 'LLM 2025 (10)'],
                    ['OWASP-Web-2025', 'Web 2025 (10)'],
                  ] as [FwFilter, string][]
                ).map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    className={`gm-btn ${fwFilter === id ? 'gm-btn-primary' : ''}`}
                    onClick={() => setFwFilter(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <div className="gm-panel-body gm-table-wrap">
              <table className="gm-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>OWASP Category &amp; Probe</th>
                    <th>Result</th>
                    <th>Active Defenses</th>
                    <th>Beyond-Competitor Innovation</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={`${r.framework}-${r.owasp_id}`}>
                      <td className="mono" style={{ fontWeight: 700, whiteSpace: 'nowrap' }}>
                        {r.owasp_id}
                      </td>
                      <td>
                        <strong>{r.category}</strong>
                        <div className="gm-muted" style={{ marginTop: 2 }}>{r.probe_name}</div>
                        {r.gap_summary && (
                          <div className="gm-tag culled" style={{ marginTop: 4 }}>{r.gap_summary}</div>
                        )}
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <span className={`gm-tag ${r.passed ? 'champion' : 'culled'}`}>
                          {r.passed ? 'DEFENDED' : 'GAP'}
                        </span>
                        <div className="gm-muted mono" style={{ marginTop: 3 }}>
                          {(r.confidence * 100).toFixed(0)}% conf
                        </div>
                      </td>
                      <td>
                        <div className="gm-region-chips">
                          {r.defensive_controls.map((c) => (
                            <span key={c} className="gm-tag rea">{c}</span>
                          ))}
                        </div>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--ink-secondary)', maxWidth: 280 }}>
                        {r.innovation_note}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
