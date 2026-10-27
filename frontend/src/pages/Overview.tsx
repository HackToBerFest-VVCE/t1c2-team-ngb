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

import { api, Metrics, SourceStatus, Vulnerability } from '../api';
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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadData = () => {
    setLoading(true);
    setError('');

    api<{ metrics: Metrics; recent: Vulnerability[] }>('/summary')
      .then((data) => {
        setMetrics(data.metrics);
        setRecent(data.recent ?? []);
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
          <small>RECORDS ANALYZED</small>
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
                      background: '#151c28',
                      border: '1px solid #2a3545',
                      borderRadius: 8,
                      color: '#e7ebf3',
                      fontSize: 12,
                    }}
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
