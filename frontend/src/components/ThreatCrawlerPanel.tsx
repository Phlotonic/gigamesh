import { useMemo, useState } from 'react';
import type { CrawlFinding, CrawlRunReport, ThreatCrawlerStatus, ThreatSource } from '../types';
import { HelpTip } from './HelpTip';

interface Props {
  status: ThreatCrawlerStatus | null;
  findings: CrawlFinding[];
  runs: CrawlRunReport[];
  busy: boolean;
  onToggle: (enabled: boolean, intervalSec?: number) => Promise<void>;
  onScanNow: (sourceIds?: string[]) => Promise<void>;
  onToggleSource: (sourceId: string, enabled: boolean) => Promise<void>;
  onAddSource: (payload: { source_id: string; name: string; url: string; kind: string; region?: string }) => Promise<void>;
  onDeleteSource: (sourceId: string) => Promise<void>;
}

type FindingFilter = 'all' | 'exploited' | 'critical' | 'revisions' | 'quarantined';

const INTERVAL_OPTIONS: Array<[number, string]> = [
  [60, 'Every minute'],
  [120, 'Every 2 minutes'],
  [300, 'Every 5 minutes'],
  [900, 'Every 15 minutes'],
  [3600, 'Every hour'],
];

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (Number.isNaN(diff)) return '—';
  if (diff < 0) return `in ${Math.round(-diff)}s`;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

function timeUntil(iso: string | null | undefined): string {
  if (!iso) return '—';
  const diff = (new Date(iso).getTime() - Date.now()) / 1000;
  if (Number.isNaN(diff)) return '—';
  if (diff <= 0) return 'any moment';
  if (diff < 60) return `in ${Math.round(diff)}s`;
  return `in ${Math.round(diff / 60)}m`;
}

function statusLabel(s: string): { text: string; cls: string } {
  if (s.startsWith('updated')) return { text: 'NEW UPDATES', cls: 'champion' };
  if (s.startsWith('unchanged_304')) return { text: 'NO CHANGE (304)', cls: 'active' };
  if (s.startsWith('unchanged_hash')) return { text: 'NO CHANGE', cls: 'active' };
  if (s.startsWith('no_new_items')) return { text: 'UP TO DATE', cls: 'active' };
  if (s.startsWith('gated_skipped')) return { text: 'ANTI-BOT GATE · SKIPPED', cls: 'pending' };
  if (s.startsWith('blocked')) return { text: 'BLOCKED BY SSRF GUARD', cls: 'culled' };
  if (s.startsWith('redirect_refused')) return { text: 'REDIRECT REFUSED', cls: 'pending' };
  if (s.startsWith('http_error')) return { text: s.replace('http_error:', 'HTTP '), cls: 'culled' };
  if (s.startsWith('unreachable')) return { text: 'UNREACHABLE', cls: 'culled' };
  return { text: 'NOT YET CHECKED', cls: '' };
}

function SourceRow({
  src,
  busy,
  onToggle,
  onScan,
  onDelete,
}: {
  src: ThreatSource;
  busy: boolean;
  onToggle: (enabled: boolean) => void;
  onScan: () => void;
  onDelete?: () => void;
}) {
  const st = statusLabel(src.last_status);
  return (
    <div className="gm-source-row">
      <label className="gm-switch small" title={src.enabled ? 'Disable this feed' : 'Enable this feed'}>
        <input
          type="checkbox"
          checked={src.enabled}
          disabled={busy}
          onChange={(e) => onToggle(e.target.checked)}
          aria-label={`Toggle ${src.name}`}
        />
        <span className="gm-switch-track" />
      </label>
      <div style={{ minWidth: 0 }}>
        <div className="gm-row-between" style={{ gap: 8 }}>
          <span className="gm-source-name" style={{ opacity: src.enabled ? 1 : 0.55 }}>
            {src.name}
          </span>
          <span className={`gm-tag ${st.cls}`}>{st.text}</span>
        </div>
        <div className="gm-source-meta">
          {src.publisher || 'Custom'} · {src.region} · {src.kind.replace('_', ' ')} · checked {timeAgo(src.last_crawled_at)}
          {src.last_changed_at ? ` · last new intel ${timeAgo(src.last_changed_at)}` : ''}
        </div>
        <div className="gm-source-meta">
          new={src.last_new_items} · ingested={src.total_items_ingested} · checks={src.total_checks} · unchanged=
          {src.unchanged_checks}
          {src.etag ? ' · ETag ✓' : ''}
          {src.last_modified ? ' · Last-Modified ✓' : ''}
        </div>
      </div>
      <div className="gm-form-row">
        <button type="button" className="gm-btn" disabled={busy || !src.enabled} onClick={onScan}>
          Check
        </button>
        {onDelete && (
          <button type="button" className="gm-btn gm-btn-crimson" disabled={busy} onClick={onDelete}>
            Remove
          </button>
        )}
      </div>
    </div>
  );
}

export function ThreatCrawlerPanel({
  status,
  findings,
  runs,
  busy,
  onToggle,
  onScanNow,
  onToggleSource,
  onAddSource,
  onDeleteSource,
}: Props) {
  const [filter, setFilter] = useState<FindingFilter>('all');
  const [newName, setNewName] = useState('');
  const [newUrl, setNewUrl] = useState('');
  const [newKind, setNewKind] = useState('rss_feed');
  const [formError, setFormError] = useState<string | null>(null);

  const enabled = status?.enabled ?? false;
  const interval = status?.crawl_interval_sec ?? 120;
  const sources = status?.sources ?? [];
  const activeSources = sources.filter((s) => s.enabled);
  const latestRun = runs[0];

  const sourcesByRegion = useMemo(() => {
    const groups = new Map<string, ThreatSource[]>();
    for (const s of sources) {
      const list = groups.get(s.region) ?? [];
      list.push(s);
      groups.set(s.region, list);
    }
    return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [sources]);

  const filtered = useMemo(() => {
    switch (filter) {
      case 'exploited':
        return findings.filter((f) => f.actively_exploited);
      case 'critical':
        return findings.filter((f) => f.severity === 'critical');
      case 'revisions':
        return findings.filter((f) => f.is_revision);
      case 'quarantined':
        return findings.filter((f) => f.poison_attempt_blocked);
      default:
        return findings;
    }
  }, [findings, filter]);

  async function handleAdd() {
    setFormError(null);
    if (!newName.trim() || !newUrl.trim()) {
      setFormError('Give the feed a name and an https:// address.');
      return;
    }
    if (!newUrl.trim().startsWith('https://')) {
      setFormError('Only secure https:// feeds are allowed.');
      return;
    }
    const slug = newName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 32);
    try {
      await onAddSource({ source_id: `src-custom-${slug || Date.now()}`, name: newName.trim(), url: newUrl.trim(), kind: newKind });
      setNewName('');
      setNewUrl('');
    } catch (err) {
      setFormError((err as Error).message);
    }
  }

  return (
    <div className="gm-list-stack">
      {/* Master switch */}
      <div className="gm-panel">
        <div className="gm-panel-body gm-crawler-hero">
          <div>
            <h2 className="gm-heading-tip" style={{ margin: 0, fontFamily: 'var(--font-display)', fontSize: 18 }}>
              Global Threat Intelligence Crawler
              <HelpTip term="threatCrawler" />
            </h2>
            <p>
              When switched on, GigaMesh regularly reads the latest security advisories from {sources.length} trusted
              government, vendor and community feeds around the world, learns from anything new, and turns it into
              protections. Only changes are downloaded — feeds that haven't changed are skipped automatically.
            </p>
          </div>
          <div className="gm-form-row" style={{ gap: 14 }}>
            <label className="gm-switch">
              <input
                id="toggle-threat-crawler"
                type="checkbox"
                checked={enabled}
                disabled={busy || !status}
                onChange={(e) => onToggle(e.target.checked, interval)}
              />
              <span className="gm-switch-track" />
              <span>{enabled ? 'Crawler ON' : 'Crawler OFF'}</span>
            </label>
            <select
              className="gm-select"
              value={interval}
              disabled={busy || !status}
              onChange={(e) => onToggle(enabled, Number(e.target.value))}
              aria-label="How often to check for updates"
            >
              {INTERVAL_OPTIONS.map(([sec, label]) => (
                <option key={sec} value={sec}>
                  {label}
                </option>
              ))}
              {!INTERVAL_OPTIONS.some(([sec]) => sec === interval) && <option value={interval}>Every {interval}s</option>}
            </select>
            <button
              id="btn-scan-threat-feeds"
              type="button"
              className="gm-btn gm-btn-primary"
              disabled={busy || activeSources.length === 0}
              onClick={() => onScanNow()}
            >
              {busy ? 'Reading feeds…' : 'Check for updates now'}
            </button>
          </div>
        </div>
      </div>

      {/* Telemetry */}
      <section className="gm-kpi-strip" aria-label="Threat intelligence telemetry">
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Active Feeds
            <HelpTip term="ssrfGuard" />
          </div>
          <div className="gm-kpi-value tabular">
            {activeSources.length}/{sources.length}
          </div>
          <div className="gm-region-chips" style={{ marginTop: 6 }}>
            {(status?.regions_covered ?? []).map((r) => (
              <span key={r} className="gm-tag rea">
                {r}
              </span>
            ))}
          </div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Intel Items Learned
            <HelpTip term="cveBadge" />
          </div>
          <div className="gm-kpi-value tabular">{status?.total_findings ?? 0}</div>
          <div className="gm-kpi-sub">{status?.unique_cves ?? 0} unique CVEs · {status?.total_revisions ?? 0} revisions</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Actively Exploited
            <HelpTip term="activelyExploited" />
          </div>
          <div className="gm-kpi-value tabular" style={{ color: 'var(--accent-crimson)' }}>
            {status?.actively_exploited_count ?? 0}
          </div>
          <div className="gm-kpi-sub">Confirmed in-the-wild exploitation</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Poisoned Content Blocked
            <HelpTip term="poisonedContent" />
          </div>
          <div className="gm-kpi-value tabular" style={{ color: 'var(--accent-amber)' }}>
            {status?.poisoned_pages_blocked ?? 0}
          </div>
          <div className="gm-kpi-sub">Quarantined &amp; REA-dissected</div>
        </div>
        <div className="gm-kpi">
          <div className="gm-kpi-label gm-heading-tip">
            Schedule
            <HelpTip term="deltaUpdates" />
          </div>
          <div className="gm-kpi-value tabular" style={{ fontSize: 18 }}>
            {enabled ? (status?.running ? 'Running' : 'Starting') : 'Paused'}
          </div>
          <div className="gm-kpi-sub">
            last {timeAgo(status?.last_run_at)} · next {enabled ? timeUntil(status?.next_run_at) : '—'}
          </div>
        </div>
      </section>

      <div className="gm-grid-2">
        {/* Feeds */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Trusted Global Feeds
              <HelpTip term="deltaUpdates" />
            </h2>
            <HelpTip term="ssrfGuard">
              <span className="gm-tag">HTTPS · allowlisted · no redirects</span>
            </HelpTip>
          </div>
          <div className="gm-panel-body">
            {sourcesByRegion.map(([region, list]) => (
              <div key={region} style={{ marginBottom: 10 }}>
                <div className="gm-muted" style={{ fontWeight: 600, textTransform: 'uppercase', fontSize: 10.5, letterSpacing: 0.6 }}>
                  {region}
                </div>
                {list.map((src) => (
                  <SourceRow
                    key={src.source_id}
                    src={src}
                    busy={busy}
                    onToggle={(v) => onToggleSource(src.source_id, v)}
                    onScan={() => onScanNow([src.source_id])}
                    onDelete={src.builtin ? undefined : () => onDeleteSource(src.source_id)}
                  />
                ))}
              </div>
            ))}

            <details style={{ marginTop: 8 }}>
              <summary style={{ cursor: 'pointer', fontSize: 12.5, fontWeight: 600 }}>Add your own trusted feed</summary>
              <div className="gm-list-stack" style={{ marginTop: 10 }}>
                <input
                  className="gm-input"
                  placeholder="Feed name (e.g. Vendor PSIRT advisories)"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
                <input
                  className="gm-input"
                  placeholder="https://example.org/security/feed.xml"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                />
                <div className="gm-form-row">
                  <select className="gm-select" value={newKind} onChange={(e) => setNewKind(e.target.value)} aria-label="Feed format">
                    <option value="rss_feed">RSS / Atom feed</option>
                    <option value="json_feed">JSON advisory API</option>
                    <option value="html_page">Web page</option>
                  </select>
                  <button type="button" className="gm-btn gm-btn-emerald" disabled={busy} onClick={handleAdd}>
                    Add feed
                  </button>
                </div>
                {formError && <div className="gm-tag culled">{formError}</div>}
                <div className="gm-muted">
                  Private, local and cloud-metadata addresses are always refused. New feeds are screened for prompt-poisoning like
                  every other source.
                </div>
              </div>
            </details>
          </div>
        </div>

        {/* Latest run */}
        <div className="gm-panel">
          <div className="gm-panel-header">
            <h2 className="gm-heading-tip">
              Latest Update Check
              <HelpTip term="deltaUpdates" />
            </h2>
            {latestRun && <span className="gm-tag">{timeAgo(latestRun.timestamp)}</span>}
          </div>
          <div className="gm-panel-body gm-list-stack">
            {!latestRun ? (
              <p className="gm-muted" style={{ margin: 0 }}>
                No checks yet. Switch the crawler on or press <strong>Check for updates now</strong>.
              </p>
            ) : (
              <>
                <div className="gm-region-chips">
                  <span className="gm-tag champion">{latestRun.sources_updated} feeds with new intel</span>
                  <span className="gm-tag active">{latestRun.sources_unchanged} unchanged</span>
                  <span className="gm-tag">{latestRun.new_findings_count} new items</span>
                  {latestRun.revisions_count > 0 && <span className="gm-tag high">{latestRun.revisions_count} revisions</span>}
                  {latestRun.poisoned_pages_quarantined > 0 && (
                    <span className="gm-tag critical">{latestRun.poisoned_pages_quarantined} quarantined</span>
                  )}
                  {latestRun.sources_blocked_or_gated.length > 0 && (
                    <span className="gm-tag pending">{latestRun.sources_blocked_or_gated.length} skipped</span>
                  )}
                </div>
                <div className="gm-muted mono">
                  trigger={latestRun.trigger} · {latestRun.duration_ms}ms
                  {latestRun.stix_bundle_id ? ` · STIX=${latestRun.stix_bundle_id}` : ''}
                  {latestRun.evolution_generation_id ? ` · evolved Gen #${latestRun.evolution_generation_id}` : ''}
                </div>
                {Object.entries(latestRun.source_outcomes).map(([sid, outcome]) => {
                  const st = statusLabel(outcome);
                  const name = sources.find((s) => s.source_id === sid)?.name ?? sid;
                  return (
                    <div key={sid} className="gm-row-between" style={{ fontSize: 12 }}>
                      <span>{name}</span>
                      <span className={`gm-tag ${st.cls}`}>{st.text}</span>
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="gm-panel">
        <div className="gm-panel-header">
          <h2 className="gm-heading-tip">
            What GigaMesh Learned
            <HelpTip term="advisoryRevisions" />
          </h2>
          <div className="gm-form-row">
            {(
              [
                ['all', 'All'],
                ['exploited', 'Actively exploited'],
                ['critical', 'Critical'],
                ['revisions', 'Revisions'],
                ['quarantined', 'Quarantined'],
              ] as [FindingFilter, string][]
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                className={`gm-btn ${filter === id ? 'gm-btn-primary' : ''}`}
                onClick={() => setFilter(id)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="gm-panel-body gm-list-stack">
          {filtered.length === 0 ? (
            <p className="gm-muted" style={{ margin: 0 }}>
              Nothing here yet.
            </p>
          ) : (
            filtered.slice(0, 40).map((f) => (
              <div className="gm-item-box" key={f.finding_id}>
                <div className="gm-row-between" style={{ alignItems: 'flex-start', gap: 10 }}>
                  <div style={{ minWidth: 0 }}>
                    {f.url.startsWith('https://') && !f.poison_attempt_blocked ? (
                      <a className="gm-finding-link" href={f.url} target="_blank" rel="noopener noreferrer nofollow">
                        <strong style={{ fontSize: 13 }}>{f.title}</strong>
                      </a>
                    ) : (
                      <strong style={{ fontSize: 13 }}>{f.title}</strong>
                    )}
                    <div className="gm-muted mono" style={{ marginTop: 2 }}>
                      {f.source_name} · {f.region} · learned {timeAgo(f.discovered_at)}
                      {f.updated_at ? ` · updated ${f.updated_at.slice(0, 19)}` : ''}
                    </div>
                  </div>
                  <span className={`gm-tag ${f.severity}`}>{f.severity.toUpperCase()}</span>
                </div>
                {f.summary && (
                  <p style={{ margin: '6px 0 0', fontSize: 12.5, color: 'var(--ink-secondary)', lineHeight: 1.45 }}>
                    {f.summary.length > 260 ? `${f.summary.slice(0, 260)}…` : f.summary}
                  </p>
                )}
                <div className="gm-region-chips" style={{ marginTop: 8 }}>
                  {f.actively_exploited && <span className="gm-tag critical">ACTIVELY EXPLOITED</span>}
                  {f.is_revision && <span className="gm-tag high">REVISED ADVISORY</span>}
                  {f.poison_attempt_blocked && <span className="gm-tag critical">PROMPT-POISONING QUARANTINED</span>}
                  {f.cve_ids.slice(0, 4).map((c) => (
                    <span key={c} className="gm-tag">
                      {c}
                    </span>
                  ))}
                  {f.ghsa_ids.slice(0, 2).map((g) => (
                    <span key={g} className="gm-tag">
                      {g}
                    </span>
                  ))}
                  {f.mitre_techniques.slice(0, 3).map((m) => (
                    <span key={m} className="gm-tag rea">
                      {m}
                    </span>
                  ))}
                  {f.metabolized_module_id && <span className="gm-tag champion">Protection compiled: {f.metabolized_module_id}</span>}
                  {f.rea_dossier_id && <span className="gm-tag rea">REA dossier: {f.rea_dossier_id}</span>}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
