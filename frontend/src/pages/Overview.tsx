/**
 * ThreatLens AI — Overview Dashboard
 *
 * Real-time security posture overview with publication trend,
 * severity distribution, common weaknesses, and recent CVE findings.
 */

import { useEffect, useState, useMemo } from 'react';
import {
  Activity,
  ArrowUpRight,
  CalendarDays,
  ChevronRight,
  Database,
  ExternalLink,
  Flame,
  Layers,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { api, MLCoverage, Metrics, PaginatedResponse, SourceStatus, Vulnerability } from '../api';
import {
  Badge,
  Card,
  Loading,
  PageHeading,
  SeverityBadge,
  SkeletonCards,
  showToast,
} from '../components/Shell';

// Palette for severity pie chart
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#f27885',
  HIGH: '#f5aa64',
  MEDIUM: '#e6ce79',
  LOW: '#6cdbb0',
  NONE: '#68758a',
  UNKNOWN: '#4a5568',
};

const FALLBACK_PALETTE = ['#f27885', '#f5aa64', '#e6ce79', '#6cdbb0', '#68758a', '#8b5cf6'];

interface OverviewProps {
  source?: SourceStatus;
  onSelect: (page: string) => void;
}

export default function Overview({ source, onSelect }: OverviewProps) {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [recent, setRecent] = useState<Vulnerability[]>([]);
  const [mlCoverage, setMlCoverage] = useState<MLCoverage | null>(null);
  const [reviewRows, setReviewRows] = useState<Vulnerability[]>([]);
  const [reviewFilter, setReviewFilter] = useState<'needs_review' | 'high_unknown' | 'unscored'>('needs_review');
  const [reviewSearch, setReviewSearch] = useState('');
  const [reviewTotal, setReviewTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadData = () => {
    setLoading(true);
    setError('');

    Promise.all([
      api<{ metrics: Metrics; recent: Vulnerability[] }>('/summary'),
      api<{ coverage: MLCoverage }>('/ml/coverage?per_page=1').catch(() => null),
    ])
      .then(([data, coverage]) => {
        setMetrics(data.metrics);
        setRecent(data.recent ?? []);
        setMlCoverage(coverage?.coverage ?? null);
      })
      .catch((err: Error) => {
        setError(err.message || 'Failed to load overview data');
        showToast('Error loading overview data', 'error');
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    const params = new URLSearchParams({ review: reviewFilter, q: reviewSearch.trim(), page: '1', per_page: '10', sort: 'cvss_score', order: 'desc' });
    api<PaginatedResponse<Vulnerability>>(`/vulnerabilities?${params.toString()}`)
      .then(data => { setReviewRows(data.items ?? []); setReviewTotal(data.total ?? 0); })
      .catch(() => { setReviewRows([]); setReviewTotal(0); });
  }, [reviewFilter, reviewSearch]);

  // Compute percentages safely
  const criticalPct = useMemo(() => {
    if (!metrics || metrics.total === 0) return 0;
    return Math.round((metrics.critical / metrics.total) * 100);
  }, [metrics]);

  const highPct = useMemo(() => {
    if (!metrics || metrics.total === 0) return 0;
    return Math.round((metrics.high / metrics.total) * 100);
  }, [metrics]);

  if (error) {
    return <Loading error={error} onRetry={loadData} />;
  }

  if (loading || !metrics) {
    return (
      <div className="animate-fade-in">
        <PageHeading
          eyebrow="THREAT LANDSCAPE"
          title="Overview"
          description="A current view of records in your active analysis scope."
        />
        <SkeletonCards count={4} />
      </div>
    );
  }

  return (
    <div className="overview-container animate-fade-in">
      {/* ── Page Header ───────────────────────────────────────────── */}
      <PageHeading
        eyebrow="THREAT LANDSCAPE"
        title="Overview"
        description="A current view of records in your active analysis scope."
        action={
          <div className="heading-actions">
            <span className="updated">
              <RefreshCw size={13} className="spin-slow" />{' '}
              {source?.updated_at
                ? `Snapshot · ${new Date(source.updated_at).toLocaleDateString()}`
                : 'Live Snapshot'}
            </span>
            <button
              className="button-secondary"
              onClick={() => onSelect('Data Explorer')}
              aria-label="View source details"
            >
              <Database size={15} /> Source details
            </button>
          </div>
        }
      />

      {/* ── Status Banner ─────────────────────────────────────────── */}
      <div className="banner">
        <div className="banner-icon">
          <ShieldCheck size={18} />
        </div>
        <div>
          <b>
            {source?.mode === 'LIVE'
              ? 'Connected to Snowflake Data Warehouse'
              : 'Demo Mode · Curated NVD Snapshot'}
          </b>
          <span>{source?.note ?? 'Vulnerability telemetry ingested and normalized for analysis.'}</span>
        </div>
        <Badge tone={source?.mode === 'LIVE' ? 'green' : 'violet'}>
          {source?.mode ?? 'ACTIVE'}
        </Badge>
      </div>

      {/* ── Metric Cards Grid ─────────────────────────────────────── */}
      <div className="metric-grid">
        <div className="metric-card animate-scale-in">
          <div className="metric-icon blue">
            <Activity size={20} />
          </div>
          <small>RECORDS IN SCOPE</small>
          <strong>{metrics.total.toLocaleString()}</strong>
          <span>Normalized source vulnerabilities</span>
        </div>

        <div className="metric-card animate-scale-in" style={{ animationDelay: '50ms' }}>
          <div className="metric-icon red">
            <ShieldAlert size={20} />
          </div>
          <small>CRITICAL SEVERITY</small>
          <strong>{metrics.critical.toLocaleString()}</strong>
          <span>
            {criticalPct}% of total scope (CVSS ≥ 9.0)
          </span>
        </div>

        <div className="metric-card animate-scale-in" style={{ animationDelay: '100ms' }}>
          <div className="metric-icon amber">
            <Flame size={20} />
          </div>
          <small>HIGH SEVERITY</small>
          <strong>{metrics.high.toLocaleString()}</strong>
          <span>
            {highPct}% of total scope (CVSS 7.0–8.9)
          </span>
        </div>

        <div className="metric-card animate-scale-in" style={{ animationDelay: '150ms' }}>
          <div className="metric-icon violet">
            <CalendarDays size={20} />
          </div>
          <small>PUBLISHED · 30 DAYS</small>
          <strong>{metrics.new_30d.toLocaleString()}</strong>
          <span>Rolling UTC publication window</span>
        </div>
      </div>

      <Card
        title="Risk & Coverage Review"
        subtitle="Live source counts and current ML run. CVSS-indicated bands are review hints and never replace source severity."
        action={<button className="text-action" onClick={() => { sessionStorage.setItem('threatlens-review-filter', 'needs_review'); onSelect('Vulnerability Explorer'); }}>Open review queue <ArrowUpRight size={14} /></button>}
      >
        <div className="metric-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))' }}>
          <div className="metric-card"><small>TOTAL ACTIVE RECORDS</small><strong>{mlCoverage?.total_active_records.toLocaleString() ?? metrics.total.toLocaleString()}</strong><span>Loaded, non-rejected source records</span></div>
          <div className="metric-card"><small>ML-ELIGIBLE · NONEMPTY TEXT</small><strong>{mlCoverage?.eligible_records.toLocaleString() ?? 'Unavailable'}</strong><span>Eligible for TF-IDF models</span></div>
          <div className="metric-card"><small>DETERMINISTIC ML SAMPLE</small><strong>{mlCoverage?.records_in_deterministic_sample.toLocaleString() ?? 'Unavailable'}</strong><span>Candidate sample in this run</span></div>
          <div className="metric-card"><small>ML COVERAGE · ALL ACTIVE</small><strong>{mlCoverage ? `${mlCoverage.coverage_percent_of_active_records}%` : 'Unavailable'}</strong><span>Modeled records / all active records</span></div>
          <div className="metric-card"><small>NOT ANALYZED BY ML</small><strong>{mlCoverage?.records_not_analyzed.toLocaleString() ?? 'Unavailable'}</strong><span>Not modeled; no safety inference</span></div>
          <div className="metric-card"><small>UNKNOWN / MISSING SEVERITY</small><strong>{metrics.review?.unknown_source_severity?.toLocaleString() ?? '0'}</strong><span>Source label needs context</span></div>
          <div className="metric-card"><small>EXPLICIT NONE SEVERITY</small><strong>{metrics.review?.explicit_none_severity?.toLocaleString() ?? '0'}</strong><span>Distinct from UNKNOWN</span></div>
          <div className="metric-card"><small>UNKNOWN + CVSS ≥ 7</small><strong style={{ color: 'var(--red, #f27885)' }}>{metrics.review?.unknown_with_high_or_critical_cvss?.toLocaleString() ?? '0'}</strong><span>High/critical score-indicated band</span></div>
          <div className="metric-card"><small>MISSING CVSS</small><strong>{metrics.review?.missing_cvss?.toLocaleString() ?? '0'}</strong><span>Unscored; needs evidence review</span></div>
          <div className="metric-card"><small>SEVERITY + CVSS BOTH MISSING</small><strong>{metrics.review?.missing_severity_and_cvss?.toLocaleString() ?? '0'}</strong><span>Manual review; never assumed safe</span></div>
          <div className="metric-card"><small>SEVERITY / CVSS CONFLICTS</small><strong>{metrics.review?.severity_score_mismatch?.toLocaleString() ?? '0'}</strong><span>Verify against source record</span></div>
          <div className="metric-card"><small>INVALID CVSS RANGE</small><strong>{metrics.review?.invalid_cvss?.toLocaleString() ?? '0'}</strong><span>Source value needs verification</span></div>
          <div className="metric-card"><small>RECORDS REQUIRING REVIEW</small><strong>{metrics.review?.needs_review?.toLocaleString() ?? '0'}</strong><span>Rule-based; no exploit probability</span></div>
        </div>
        {mlCoverage && <p className="limitation-footer">Coverage denominator: {mlCoverage.coverage_denominator}. {mlCoverage.partition_note}</p>}
      </Card>

      <Card title="Unknown-severity and data-quality queue" subtitle="Source values and derived CVSS bands stay separate. If advisory or affected-version evidence is unavailable, the record requires manual verification.">
        <div className="filter-toolbar" style={{ marginBottom: 14 }}>
          <input aria-label="Search review queue" className="search-input" placeholder="Search CVE, product, description…" value={reviewSearch} onChange={e => setReviewSearch(e.target.value)} />
          <select aria-label="Review queue filter" value={reviewFilter} onChange={e => setReviewFilter(e.target.value as typeof reviewFilter)}>
            <option value="needs_review">All records requiring review</option>
            <option value="high_unknown">UNKNOWN severity + CVSS ≥ 7</option>
            <option value="unscored">Missing CVSS</option>
          </select>
          <span>{reviewTotal.toLocaleString()} records</span>
        </div>
        <div className="table-wrap"><table>
          <thead><tr><th>CVE</th><th>SOURCE SEVERITY</th><th>SOURCE CVSS</th><th>CVSS-INDICATED BAND</th><th>PUBLISHED</th><th>ML STATUS</th><th>REVIEW PRIORITY / REASON</th><th>AFFECTED-PRODUCT EVIDENCE</th><th>SOURCE</th></tr></thead>
          <tbody>
            {reviewRows.map(v => <tr key={v.record_id ?? v.cve_id}>
              <td><a className="cve-link" href={v.source_url || `https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noreferrer">{v.cve_id}<ArrowUpRight size={12} /></a></td>
              <td><SeverityBadge severity={v.severity} /></td>
              <td>{v.cvss_score == null ? 'Unscored' : v.cvss_score.toFixed(1)}</td>
              <td>{v.cvss_indicated_severity ?? 'No score-derived band'}</td>
              <td>{v.published ? new Date(v.published).toLocaleDateString() : 'Not recorded'}</td>
              <td>{v.ml_analysis_status ?? 'Not run / unavailable'}</td>
              <td><b>{v.review_priority ?? 'Manual review'}</b><small className="row-desc">{v.review_reasons?.join('; ') || 'Verify source evidence'}</small></td>
              <td><b>{v.affected_product_evidence || 'Product not listed'}</b><small className="row-desc">{v.affected_version_evidence || 'Version ranges unavailable in active schema; verify manually'}</small></td>
              <td><a href={v.review_evidence_url || v.source_url || `https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noreferrer">NVD source <ExternalLink size={12} /></a><small className="row-desc">{v.advisory_evidence_status === 'NOT_QUERIED' ? 'Vendor advisory not queried' : 'Manual verification'}</small></td>
            </tr>)}
            {reviewRows.length === 0 && <tr><td colSpan={9}><div className="empty-row">No matching records, or the review queue is unavailable.</div></td></tr>}
          </tbody>
        </table></div>
      </Card>

      {/* ── Primary Charts Grid ───────────────────────────────────── */}
      <div className="chart-grid">
        {/* Publication Activity Trend */}
        <Card
          title="Publication activity"
          subtitle="Monthly CVE publication dates over the active analysis timeline"
          action={
            <button
              className="text-action"
              onClick={() => onSelect('Threat Trends')}
              aria-label="Deep dive into trends"
            >
              Analyze trends <ArrowUpRight size={14} />
            </button>
          }
        >
          <div className="chart-wrap" style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={metrics.publication_trend}
                margin={{ top: 12, right: 10, left: -20, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="pubGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6487ff" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#6487ff" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#212b39" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="month"
                  tick={{ fill: '#778397', fontSize: 11 }}
                  axisLine={{ stroke: '#212b39' }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#778397', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: '#151c28',
                    border: '1px solid #2a3545',
                    borderRadius: 8,
                    boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4)',
                    color: '#e7ebf3',
                    fontSize: 12,
                  }}
                  formatter={(value: any) => [`${Number(value).toLocaleString()} CVEs`, 'Published']}
                  labelStyle={{ color: '#93a2b8', fontWeight: 600, marginBottom: 4 }}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#7794ff"
                  strokeWidth={2.5}
                  fill="url(#pubGradient)"
                  dot={{ fill: '#7794ff', r: 3, strokeWidth: 0 }}
                  activeDot={{ r: 5, fill: '#ffffff', stroke: '#7794ff', strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Severity Distribution Donut */}
        <Card
          title="Severity distribution"
          subtitle="Breakdown of source-reported CVSS severity tiers"
        >
          <div className="severity-layout">
            <div className="donut" style={{ position: 'relative', width: 180, height: 180 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={metrics.severity}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={58}
                    outerRadius={80}
                    paddingAngle={3}
                    stroke="none"
                  >
                    {metrics.severity.map((entry, index) => {
                      const color =
                        SEVERITY_COLORS[entry.name.toUpperCase()] ??
                        FALLBACK_PALETTE[index % FALLBACK_PALETTE.length];
                      return <Cell key={`cell-${index}`} fill={color} />;
                    })}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#151c28',
                      border: '1px solid #2a3545',
                      borderRadius: 8,
                      color: '#e7ebf3',
                      fontSize: 12,
                      padding: '8px 10px',
                    }}
                    itemStyle={{ color: '#e7ebf3', fontWeight: 600 }}
                    labelStyle={{ color: '#aebbd0' }}
                    formatter={(val: any) => [Number(val).toLocaleString(), 'Count']}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-label">
                <b>{metrics.total.toLocaleString()}</b>
                <small>records</small>
              </div>
            </div>

            <div className="legend-list">
              {metrics.severity.map((item, i) => {
                const color =
                  SEVERITY_COLORS[item.name.toUpperCase()] ??
                  FALLBACK_PALETTE[i % FALLBACK_PALETTE.length];
                const pct = metrics.total > 0 ? Math.round((item.value / metrics.total) * 100) : 0;
                return (
                  <div key={item.name} className="legend-item">
                    <span className="legend-name">
                      <i style={{ background: color }} />
                      {item.name}
                    </span>
                    <div className="legend-values">
                      <b>{item.value.toLocaleString()}</b>
                      <span className="pct-tag">{pct}%</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </Card>
      </div>

      {/* ── Lower Section Grid: Recent CVEs & Weaknesses ──────────── */}
      <div className="lower-grid">
        {/* Recent Vulnerabilities Table */}
        <Card
          title="Highest severity vulnerabilities"
          subtitle="Ranked by source CVSS Base Score; unscored records follow"
          action={
            <button
              className="text-action"
              onClick={() => onSelect('Vulnerability Explorer')}
            >
              Open explorer <ArrowUpRight size={14} />
            </button>
          }
        >
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IDENTIFIER</th>
                  <th>SEVERITY</th>
                  <th>CVSS</th>
                  <th>PUBLISHED</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {recent.map(v => (
                  <tr key={v.cve_id} className="table-row-hover">
                    <td>
                      <a
                        className="cve-link"
                        href={v.source_url || `https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {v.cve_id}
                        <ArrowUpRight size={12} />
                      </a>
                      <small className="row-desc">
                        {v.description
                          ? v.description.slice(0, 80) + (v.description.length > 80 ? '…' : '')
                          : 'No description provided'}
                      </small>
                    </td>
                    <td>
                      <SeverityBadge severity={v.severity} />
                    </td>
                    <td>
                      <span className="mono-score" title={v.cvss_score != null ? 'Source-provided CVSS Base Score' : 'No CVSS score is present in the source record'}>
                        {v.cvss_score?.toFixed(1) ?? 'Unscored'}
                      </span>
                    </td>
                    <td title={v.published ? `Full UTC Timestamp: ${v.published}` : undefined}>
                      {v.published ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                          <span style={{ fontSize: '0.82rem', fontWeight: 500 }}>
                            {new Date(v.published).toLocaleDateString(undefined, {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric',
                              timeZone: 'UTC',
                            })}
                          </span>
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)' }}>
                            {new Date(v.published).toLocaleTimeString(undefined, {
                              hour: '2-digit',
                              minute: '2-digit',
                              timeZone: 'UTC',
                            })}{' '}
                            UTC
                          </span>
                        </div>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>
                      <ChevronRight size={15} className="muted-icon" />
                    </td>
                  </tr>
                ))}
                {recent.length === 0 && (
                  <tr>
                    <td colSpan={5}>
                      <div className="empty-row">No source records are available in this scope.</div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Top Weaknesses (CWE) & Affected Products */}
        <Card
          title="Weakness & product distribution"
          subtitle="Most prevalent Common Weakness Enumeration patterns"
        >
          <div className="rank-list">
            <div className="rank-header">
              <span>Top CWE Categories</span>
              <span>Count</span>
            </div>
            {metrics.top_cwe.slice(0, 5).map((x, i) => {
              const maxCount = metrics.top_cwe[0]?.count || 1;
              const widthPct = Math.max(8, (x.count / maxCount) * 100);
              return (
                <div className="rank-row" key={x.name}>
                  <span className="rank-number">0{i + 1}</span>
                  <span className="rank-title" title={x.name}>
                    {x.name}
                  </span>
                  <div className="rank-track">
                    <i
                      className="rank-bar-fill"
                      style={{
                        width: `${widthPct}%`,
                      }}
                    />
                  </div>
                  <b>{x.count.toLocaleString()}</b>
                </div>
              );
            })}
            {metrics.top_cwe.length === 0 && (
              <div className="empty-row">No CWE values reported by the source.</div>
            )}
          </div>

          <div className="product-list">
            <div className="product-list-heading">
              <Layers size={13} style={{ display: 'inline', marginRight: 6 }} />
              High-Frequency Target Products
            </div>
            {metrics.top_products.slice(0, 4).map(x => (
              <div className="product-row" key={x.name} title={x.name}>
                <span className="product-name">{x.name}</span>
                <Badge tone="gray">{x.count} CVEs</Badge>
              </div>
            ))}
            {metrics.top_products.length === 0 && (
              <div className="product-empty">No product vendor data extracted.</div>
            )}
          </div>
        </Card>
      </div>

      {/* ── Scope & Provenance Footer ─────────────────────────────── */}
      <div className="scope-note">
        <span>
          <Activity size={14} />
          {metrics.analysis_scope}
        </span>
        <button
          className="link-button"
          onClick={() => onSelect('Data Explorer')}
        >
          Inspect source quality <ArrowUpRight size={13} />
        </button>
      </div>
    </div>
  );
}
