/**
 * ThreatLens AI — Analysis, Intelligence & Configuration Views
 *
 * Contains:
 * - Trends: Time series publication volume & severity distribution via Recharts
 * - Risk: Transparent triage priority scoring & interactive simulator
 * - ML: Unsupervised TF-IDF clustering & Isolation Forest anomaly detection
 * - DataExplorer: Data provenance, completeness meters & schema audit
 * - Reports: Executive report generation & evidence-ready exports
 * - Settings: Platform configuration & backend health monitoring
 */

import { useEffect, useState, useMemo, useRef } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BarChart2,
  Calendar,
  Check,
  CheckCircle2,
  Copy,
  Cpu,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileCheck,
  FileCode,
  FileDown,
  FileText,
  Filter,
  Info,
  Layers,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import {
  api,
  downloadExport,
  AIInsights,
  AIStatus,
  ClustersResponse,
  HealthResponse,
  RiskResponse,
  SourceStatus,
  TrendsResponse,
  Vulnerability,
} from '../api';
import {
  Badge,
  Card,
  Loading,
  PageHeading,
  SeverityBadge,
  showToast,
} from '../components/Shell';

// ═══════════════════════════════════════════════════════════════════════
// 1. THREAT TRENDS (RECHARTS STACKED BAR CHART)
// ═══════════════════════════════════════════════════════════════════════

export function Trends() {
  const [data, setData] = useState<TrendsResponse | null>(null);
  const [days, setDays] = useState(365);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const requestId = useRef(0);

  const loadTrends = () => {
    const currentRequest = ++requestId.current;
    setLoading(true);
    setError('');
    setData(null);

    api<TrendsResponse>(`/trends?days=${days}`)
      .then(res => { if (currentRequest === requestId.current) setData(res); })
      .catch((err: Error) => {
        if (currentRequest !== requestId.current) return;
        setError(err.message || 'Failed to load threat trends');
        showToast('Error loading trend analytics', 'error');
      })
      .finally(() => { if (currentRequest === requestId.current) setLoading(false); });
  };

  useEffect(() => {
    loadTrends();
    return () => { requestId.current += 1; };
  }, [days]);

  // Derive peak month and stats
  const stats = useMemo(() => {
    if (!data || !data.items || data.items.length === 0) return null;
    let peakMonth = '';
    let peakCount = 0;
    let criticalTotal = 0;

    data.items.forEach(item => {
      const monthSum = Object.entries(item)
        .filter(([k]) => k !== 'month')
        .reduce((acc, [, val]) => acc + (typeof val === 'number' ? val : 0), 0);
      if (monthSum > peakCount) {
        peakCount = monthSum;
        peakMonth = item.month;
      }
      criticalTotal += Number(item.CRITICAL ?? 0);
    });

    return { peakMonth, peakCount, criticalTotal };
  }, [data]);

  return (
    <div className="trends-page animate-fade-in">
      <PageHeading
        eyebrow="TIME SERIES ANALYTICS"
        title="Threat Trends"
        description="Explore publication frequency and severity trajectory over customizable observation windows."
        action={
          <div className="filter-actions">
            <span className="pills-label">
              <Calendar size={13} /> Time Horizon:
            </span>
            <select
              className="button-secondary"
              value={days}
              onChange={e => setDays(Number(e.target.value))}
            >
              <option value={90}>Last 90 days (Quarter)</option>
              <option value={180}>Last 180 days (6 Months)</option>
              <option value={365}>Last 365 days (1 Year)</option>
              <option value={730}>Last 2 Years</option>
            </select>
          </div>
        }
      />

      {error ? (
        <Loading error={error} onRetry={loadTrends} />
      ) : loading && !data ? (
        <Loading />
      ) : !data ? null : (
        <>
          <div className="notice blue-notice">
            <Info size={17} />
            <div>
              <b>Data Provenance & Time Series Boundary</b>
              <span>{data.limitations}</span>
            </div>
          </div>
          {data.coverage?.limited_for_window && (
            <div className="notice" role="status">
              <Info size={17} />
              <div>
                <b>Available CVE history is shorter than this horizon</b>
                <span>
                  This source has {data.coverage.dated_records.toLocaleString()} dated records from {data.coverage.from ? new Date(data.coverage.from).toLocaleDateString() : 'an unknown start date'} to {data.coverage.to ? new Date(data.coverage.to).toLocaleDateString() : 'an unknown end date'}. Earlier empty months are missing source coverage, not proof of zero disclosures. Import more NVD history to compare longer horizons.
                </span>
              </div>
            </div>
          )}

          {/* Trend KPI Cards */}
          <div className="metric-grid">
            <div className="metric-card">
              <small>TOTAL DISCLOSURES</small>
              <strong>{data.count.toLocaleString()}</strong>
              <span>Observed in {data.days}-day window</span>
            </div>
            <div className="metric-card">
              <small>PEAK VOLUME MONTH</small>
              <strong className="date-stat">{stats?.peakMonth || '—'}</strong>
              <span>{stats?.peakCount.toLocaleString() ?? 0} published CVEs</span>
            </div>
            <div className="metric-card">
              <small>CRITICAL VOLUMES</small>
              <strong style={{ color: 'var(--red)' }}>
                {stats?.criticalTotal.toLocaleString() ?? 0}
              </strong>
              <span>
                {data.count > 0 && stats
                  ? `${Math.round((stats.criticalTotal / data.count) * 100)}% of period`
                  : '—'}
              </span>
            </div>
            <div className="metric-card">
              <small>VS PREVIOUS {days}-DAY WINDOW</small>
              <strong className="date-stat">
                {data.comparison?.percent == null
                  ? '—'
                  : `${data.comparison.percent > 0 ? '+' : ''}${data.comparison.percent}%`}
              </strong>
              <span>
                {data.comparison?.previous_count
                  ? `${data.comparison.delta > 0 ? '+' : ''}${data.comparison.delta.toLocaleString()} records · prior ${data.comparison.previous_count.toLocaleString()}`
                  : 'No prior-window records available'}
              </span>
            </div>
          </div>

          {/* Interactive Recharts Stacked Chart */}
          <Card
            title={`Monthly publication cadence (${days}-day view)`}
            subtitle={`Rolling ${days}-day window · ${new Date(data.from).toLocaleDateString()} to ${new Date(data.to).toLocaleDateString()} · empty months are included; see source-coverage note`}
          >
            <div className="chart-wrap" style={{ height: 350, marginTop: 12 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={data.items}
                  margin={{ top: 20, right: 15, left: -10, bottom: 20 }}
                >
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
                    cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }}
                  />
                  <Legend
                    verticalAlign="top"
                    wrapperStyle={{ paddingBottom: 16, fontSize: 12 }}
                  />
                  <Bar dataKey="CRITICAL" name="Critical" stackId="sev" fill="#f27885" />
                  <Bar dataKey="HIGH" name="High" stackId="sev" fill="#f5aa64" />
                  <Bar dataKey="MEDIUM" name="Medium" stackId="sev" fill="#e6ce79" />
                  <Bar dataKey="LOW" name="Low" stackId="sev" fill="#6cdbb0" />
                  <Bar dataKey="UNKNOWN" name="Unknown / None" stackId="sev" fill="#68758a" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
          <Card title="Frequent patterns in this window" subtitle="Observed source categories; empty fields are not inferred">
            <div className="report-includes-grid">
              <div>
                <b>Common CWE values</b>
                <div className="term-cloud">
                  {(data.top_cwe ?? []).map(item => <Badge key={item.name} tone="violet">{item.name} · {item.count}</Badge>)}
                  {(data.top_cwe ?? []).length === 0 && <span className="limitation-footer">No CWE values in the selected window.</span>}
                </div>
              </div>
              <div>
                <b>Common affected products</b>
                <div className="term-cloud">
                  {(data.top_products ?? []).map(item => <Badge key={item.name} tone="blue">{item.name} · {item.count}</Badge>)}
                  {(data.top_products ?? []).length === 0 && <span className="limitation-footer">No product mappings in the selected window.</span>}
                </div>
              </div>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. RISK ANALYSIS & INTERACTIVE TRIAGE SIMULATOR
// ═══════════════════════════════════════════════════════════════════════

export function Risk() {
  const [data, setData] = useState<RiskResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Simulator state
  const [simCvss, setSimCvss] = useState<number>(8.5);
  const [simDays, setSimDays] = useState<number>(14);

  const loadRisk = () => {
    setLoading(true);
    setError('');

    api<RiskResponse>('/risk-analysis')
      .then(res => setData(res))
      .catch((err: Error) => {
        setError(err.message || 'Failed to load risk analysis');
        showToast('Error loading risk metrics', 'error');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadRisk();
  }, []);

  // Compute simulated priority score
  const simScore = useMemo(() => {
    const cvssNorm = Math.min(1.0, Math.max(0.0, simCvss / 10.0));
    const recency = Math.max(0.0, 1.0 - simDays / 730.0);
    const raw = 0.8 * cvssNorm + 0.2 * recency;
    return Math.round(raw * 1000) / 10;
  }, [simCvss, simDays]);

  return (
    <div className="risk-page animate-fade-in">
      <PageHeading
        eyebrow="TRANSPARENT TRIAGE HEURISTIC"
        title="Risk Analysis"
        description="Explainable prioritization algorithm separating verified source facts from local heuristics."
      />

      {error ? (
        <Loading error={error} onRetry={loadRisk} />
      ) : loading && !data ? (
        <Loading />
      ) : !data ? null : (
        <>
          <div className="notice">
            <Info size={17} />
            <div>
              <b>Local Triage Heuristic Notice</b>
              <span>{data.method.warning}</span>
            </div>
          </div>

          {/* Methodology & Simulator Grid */}
          <div className="method-grid">
            <Card
              title="Prioritization formula"
              subtitle="Explicit, reproducible weighting model"
            >
              <div className="formula-box">
                <code>{data.method.formula}</code>
              </div>
              <div className="method-rows">
                <p>
                  <b>Recency factor:</b> {data.method.recency}
                </p>
                <p>
                  <b>Missing data handling:</b> {data.method.missing}
                </p>
              </div>
            </Card>

            <Card
              title="Interactive priority simulator"
              subtitle="Test how CVSS and publication age influence local triage"
            >
              <div className="simulator-controls">
                <div className="slider-control">
                  <div className="slider-label">
                    <span>CVSS Score:</span>
                    <b>{simCvss.toFixed(1)} / 10.0</b>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="10"
                    step="0.1"
                    value={simCvss}
                    onChange={e => setSimCvss(parseFloat(e.target.value))}
                  />
                </div>

                <div className="slider-control">
                  <div className="slider-label">
                    <span>Age (Days since publication):</span>
                    <b>{simDays} days</b>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="730"
                    step="5"
                    value={simDays}
                    onChange={e => setSimDays(parseInt(e.target.value, 10))}
                  />
                </div>

                <div className="sim-result-card">
                  <div>
                    <small>CALCULATED PRIORITY INDEX</small>
                    <div className="sim-score-val">{simScore.toFixed(1)} / 100</div>
                  </div>
                  <Badge
                    tone={
                      simScore >= 80 ? 'red' : simScore >= 60 ? 'amber' : simScore >= 40 ? 'yellow' : 'green'
                    }
                  >
                    {simScore >= 80 ? 'CRITICAL TIER' : simScore >= 60 ? 'ELEVATED' : 'MODERATE'}
                  </Badge>
                </div>
              </div>
            </Card>
          </div>

          {/* Evidence Types Distinction */}
          <div className="banner" style={{ marginTop: 20 }}>
            <div className="banner-icon">
              <ShieldCheck size={18} />
            </div>
            <div>
              <b>Evidence Category Taxonomy</b>
              <span>Always distinguish ground-truth supplier telemetry from derived heuristics.</span>
            </div>
            <div className="evidence-tags-row">
              <Badge tone="blue">SOURCE FACT (NVD CVSS)</Badge>
              <Badge tone="violet">LOCAL SCORE (ThreatLens)</Badge>
              <Badge tone="amber">MODEL SIGNAL (Unsupervised ML)</Badge>
            </div>
          </div>

          {/* Prioritized Vulnerabilities Table */}
          <Card
            title="Highest priority records"
            subtitle="Sorted by local priority score (80% CVSS + 20% Recency) with deterministic tie-breaking by newest publication timestamp"
          >
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>CVE IDENTIFIER</th>
                    <th>SEVERITY</th>
                    <th>SOURCE CVSS</th>
                    <th>LOCAL PRIORITY</th>
                    <th>PUBLISHED</th>
                    <th style={{ textAlign: 'right' }}>EVIDENCE</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.slice(0, 15).map(v => (
                    <tr key={v.cve_id} className="table-row-hover">
                      <td>
                        <b className="mono">{v.cve_id}</b>
                        <small className="row-desc">
                          {v.description?.slice(0, 75)}
                          {v.description && v.description.length > 75 ? '…' : ''}
                        </small>
                      </td>
                      <td>
                        <SeverityBadge severity={v.severity} />
                      </td>
                      <td>
                        <span className="mono-score">{v.cvss_score?.toFixed(1) ?? '—'}</span>
                      </td>
                      <td>
                        <div
                          className="priority-bar-cell"
                          title={
                            v.priority_score != null
                              ? `Score: ${v.priority_score.toFixed(1)} / 100 (CVSS: ${v.cvss_score?.toFixed(1) ?? '—'} · Published: ${v.published ? new Date(v.published).toUTCString() : '—'})`
                              : undefined
                          }
                        >
                          <strong className="priority">
                            {v.priority_score != null ? v.priority_score.toFixed(1) : '—'}
                          </strong>
                          {v.priority_score != null && (
                            <div className="priority-mini-bar">
                              <span style={{ width: `${Math.min(100, v.priority_score)}%` }} />
                            </div>
                          )}
                        </div>
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
                      <td style={{ textAlign: 'right' }}>
                        <a
                          className="icon-button"
                          href={v.source_url || `https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                          target="_blank"
                          rel="noreferrer"
                          aria-label={`View ${v.cve_id}`}
                        >
                          <ExternalLink size={14} />
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 3. UNSUPERVISED ML INSIGHTS (CLUSTERING & ANOMALIES)
// ═══════════════════════════════════════════════════════════════════════

export function ML() {
  const [clusters, setClusters] = useState<ClustersResponse | null>(null);
  const [anomalies, setAnomalies] = useState<any>(null);
  const [training, setTraining] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadML = () => {
    setLoading(true);
    setError('');

    Promise.all([
      api<ClustersResponse>('/ml/clusters'),
      api<any>('/ml/anomalies'),
      api<any>('/ml/training'),
    ])
      .then(([cls, anm, report]) => {
        setClusters(cls);
        setAnomalies(anm);
        setTraining(report);
      })
      .catch((err: Error) => {
        setError(err.message || 'Failed to load ML analysis');
        showToast('Error loading ML analytics', 'error');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadML();
  }, []);

  // Safe extraction of anomaly list whether backend returns { items: [] } or array directly
  const anomalyList: Vulnerability[] = useMemo(() => {
    if (!anomalies) return [];
    if (Array.isArray(anomalies)) return anomalies;
    if (Array.isArray(anomalies.items)) return anomalies.items;
    return [];
  }, [anomalies]);

  return (
    <div className="ml-page animate-fade-in">
      <PageHeading
        eyebrow="SUPERVISED + UNSUPERVISED MACHINE LEARNING"
        title="ML Insights"
        description="Text-derived semantic clusters and anomaly scoring generated via reproducible pipelines."
        action={
          <Badge tone="violet">
            <Sparkles size={13} /> ML Models
          </Badge>
        }
      />

      {training?.available && (
        <>
          <div className="section-title-wrap">
            <h2>Supervised Models Trained from Hugging Face Data</h2>
            <p>Each model uses a separate dataset and task-specific labels; scores are measured on held-out rows.</p>
          </div>
          <div className="cluster-grid">
            {Object.entries(training.sources || {}).flatMap(([source, details]: [string, any]) =>
              Object.entries(details || {})
                .filter(([, value]: [string, any]) => value && typeof value === 'object' && 'status' in value)
                .map(([task, value]: [string, any]) => (
                  <Card
                    key={`${source}-${task}`}
                    title={task.replace(/_/g, ' ')}
                    subtitle={`${source.replace(/_/g, ' ')} · ${value.status}`}
                  >
                    {value.status === 'trained' ? (
                      <div className="evaluation-grid">
                        <div className="eval-metric"><small>Held-out macro F1</small><p>{value.metrics?.macro_f1 ?? '—'}</p></div>
                        <div className="eval-metric"><small>Held-out accuracy</small><p>{value.metrics?.accuracy ?? '—'}</p></div>
                        <div className="eval-metric"><small>Training / test rows</small><p>{value.train_rows ?? '—'} / {value.test_rows ?? '—'}</p></div>
                      </div>
                    ) : (
                      <p>{value.reason || 'Model not trained for this dataset.'}</p>
                    )}
                    {value.limitations && <p className="limitation-footer">{value.limitations}</p>}
                  </Card>
                ))
            )}
          </div>
          <div className="notice blue-notice">
            <Info size={17} />
            <div><b>Training scope</b><span>{training.notice} Models are local artifacts and are not committed to the repository.</span></div>
          </div>
        </>
      )}

      {error ? (
        <Loading error={error} onRetry={loadML} />
      ) : loading && !clusters ? (
        <Loading />
      ) : !clusters ? null : !clusters.available ? (
        <div className="notice">
          <Info size={17} />
          <div>
            <b>Model Pipeline Unavailable</b>
            <span>{clusters.reason || 'Sufficient text records not available for clustering.'}</span>
          </div>
        </div>
      ) : (
        <>
          <div className="notice blue-notice">
            <Info size={17} />
            <div>
              <b>Unsupervised Signal Notice (No Ground Truth)</b>
              <span>
                These clusters and anomaly scores model statistical similarity and distribution deviation.
                They do not prove active zero-day exploitation or adversarial intent.
              </span>
            </div>
          </div>

          {/* Semantic Clusters Section */}
          <div className="section-title-wrap">
            <h2>Semantic Topic Clusters (TF-IDF + K-Means)</h2>
            <p>Discovered vulnerability pattern groupings based on lexical description tokens</p>
          </div>

          <div className="cluster-grid">
            {clusters.clusters.map(c => (
              <Card
                key={c.id}
                title={`Topic Pattern ${String(c.id + 1).padStart(2, '0')}`}
                subtitle={`${c.count.toLocaleString()} associated records`}
              >
                <div className="term-cloud">
                  {c.terms.map(t => (
                    <Badge key={t} tone="blue">
                      {t}
                    </Badge>
                  ))}
                </div>

                <div className="rep-list">
                  <small className="rep-list-label">Exemplar Records:</small>
                  {c.representatives.map(v => (
                    <a
                      key={v.cve_id}
                      href={v.source_url || `https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="rep-link"
                    >
                      <b>{v.cve_id}</b>
                      <span>{v.description?.slice(0, 85)}…</span>
                      <ArrowUpRight size={13} />
                    </a>
                  ))}
                </div>
              </Card>
            ))}
          </div>

          {/* Anomaly Detection Table */}
          <Card
            title="Statistical Outliers (Isolation Forest)"
            subtitle="Records exhibiting extreme deviation across text embeddings and CVSS severity metrics"
          >
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>CVE IDENTIFIER</th>
                    <th>SEVERITY</th>
                    <th>CVSS</th>
                    <th>ANOMALY DECISION SCORE</th>
                    <th>ASSIGNED CLUSTER</th>
                    <th style={{ textAlign: 'right' }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalyList.slice(0, 10).map((v: any) => (
                    <tr key={v.cve_id} className="table-row-hover">
                      <td>
                        <b className="mono">{v.cve_id}</b>
                        <small className="row-desc">
                          {v.description?.slice(0, 95)}
                          {v.description && v.description.length > 95 ? '…' : ''}
                        </small>
                      </td>
                      <td>
                        <SeverityBadge severity={v.severity} />
                      </td>
                      <td>
                        <span className="mono-score">{v.cvss_score?.toFixed(1) ?? '—'}</span>
                      </td>
                      <td>
                        <span className="mono bold" style={{ color: 'var(--amber)' }}>
                          {v.anomaly_score != null ? Number(v.anomaly_score).toFixed(4) : '—'}
                        </span>
                      </td>
                      <td>Pattern {v.cluster != null ? Number(v.cluster) + 1 : '—'}</td>
                      <td style={{ textAlign: 'right' }}>
                        <a
                          className="icon-button"
                          href={v.source_url || `https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                          target="_blank"
                          rel="noreferrer"
                          aria-label={`View ${v.cve_id}`}
                        >
                          <ExternalLink size={14} />
                        </a>
                      </td>
                    </tr>
                  ))}
                  {anomalyList.length === 0 && (
                    <tr>
                      <td colSpan={6}>
                        <div className="empty-row">No anomalies detected in the current partition.</div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>

          {/* Model Evaluation & Limitations */}
          <Card
            title="Model Evaluation & Rigor"
            subtitle="Fixed seeds (random_state=42) guarantee identical execution across runs"
          >
            <div className="evaluation-grid">
              <div className="eval-metric">
                <small>Clustering Model</small>
                <p>{clusters.evaluation.method}</p>
              </div>
              <div className="eval-metric">
                <small>Silhouette Score</small>
                <p>
                  {clusters.evaluation.silhouette != null
                    ? clusters.evaluation.silhouette.toFixed(4)
                    : 'Undefined for sample size'}
                </p>
                <span>{clusters.evaluation.silhouette_note}</span>
              </div>
              <div className="eval-metric">
                <small>Baseline Model</small>
                <p>
                  {clusters.evaluation.baseline} (Score:{' '}
                  {clusters.evaluation.baseline_score ?? '—'})
                </p>
              </div>
              <div className="eval-metric">
                <small>Outlier Method</small>
                <p>{clusters.evaluation.anomaly_method}</p>
              </div>
            </div>
            <p className="limitation-footer">{clusters.evaluation.limitations}</p>
          </Card>
        </>
      )}
      <AIInsightPanel />
    </div>
  );
}

function AIInsightPanel() {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [result, setResult] = useState<AIInsights | null>(null);
  const [days, setDays] = useState(90);
  const [provider, setProvider] = useState('nvidia');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api<AIStatus>('/ai/status').then(value => { setStatus(value); setProvider(value.provider || 'nvidia'); }).catch(() => setStatus(null));
  }, []);

  const selectedModel = status?.providers?.find(option => option.provider === provider);

  const runAnalysis = async () => {
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await api<AIInsights>('/ai/insights', {
        method: 'POST',
        body: JSON.stringify({ days, provider }),
      });
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI analysis could not be completed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card
      title="AI Pattern Analysis"
      subtitle="Evidence-grounded interpretation of dataset aggregates, recent CVEs, and ML outliers"
    >
      <div className="filter-actions" style={{ marginBottom: 14 }}>
        <label className="pills-label" htmlFor="ai-window">Analysis window</label>
        <select id="ai-window" className="button-secondary" value={days} onChange={e => setDays(Number(e.target.value))}>
          <option value={90}>90 days</option>
          <option value={180}>180 days</option>
          <option value={365}>1 year</option>
          <option value={730}>2 years</option>
        </select>
        <label className="pills-label" htmlFor="ai-provider">Model provider</label>
        <select id="ai-provider" className="button-secondary" value={provider} onChange={e => setProvider(e.target.value)}>
          {(status?.providers ?? [
            { provider: 'nvidia', model: 'Nemotron', configured: false },
            { provider: 'kimi', model: 'Kimi', configured: false },
            { provider: 'deepseek', model: 'DeepSeek', configured: false },
          ]).map(option => <option key={option.provider} value={option.provider}>{option.provider.toUpperCase()} · {option.model}{option.configured ? '' : ' (key missing)'}</option>)}
        </select>
        <button className="button-primary" onClick={runAnalysis} disabled={loading || !status}>
          <Sparkles size={15} /> {loading ? 'Analyzing…' : selectedModel?.configured ? 'Analyze patterns' : 'Analyze locally'}
        </button>
        <Badge tone={selectedModel?.configured ? 'green' : 'gray'}>
          {selectedModel?.configured ? `${provider.toUpperCase()} · ${selectedModel.model}` : 'LOCAL · no API key needed'}
        </Badge>
      </div>
      <p className="limitation-footer">
        {selectedModel?.configured
          ? 'This action sends full-window summary statistics, up to 80 Critical/High CVEs (severity or CVSS ≥ 7), up to 20 comparison CVEs, and ML outlier IDs to the selected provider. The API key stays on the backend.'
          : 'Local mode analyzes full-window summary statistics, prioritized Critical/High CVEs, and ML outliers on the server. No third-party AI request is made.'}
      </p>
      {!selectedModel?.configured && (
        <div className="notice">
          <Info size={16} />
          <div><b>Local analysis is available</b><span>Analyze patterns runs a deterministic evidence summary from your dataset and ML results without sending data to an AI provider. To enable generated AI commentary, configure the selected provider’s API key in the backend environment.</span></div>
        </div>
      )}
      {error && <div className="notice" role="alert"><AlertTriangle size={16} /><div><b>Analysis unavailable</b><span>{error}</span></div></div>}
      {result && (
        <div className="ai-result">
          <div className="banner" style={{ marginBottom: 16 }}>
            <div className="banner-icon"><Sparkles size={17} /></div>
            <div><b>{result.source.dataset} · {result.source.mode} · {result.record_count.toLocaleString()} records</b><span>{result.window_days}-day window · {result.model} · generated {new Date(result.generated_at).toLocaleString()}</span></div>
          </div>
          {result.cve_selection && <p className="limitation-footer" style={{ marginTop: 0 }}>AI input: {result.cve_selection.included_high_critical} of {result.cve_selection.window_high_critical} Critical/High CVEs in the window, plus {result.cve_selection.included_context} comparison CVEs. Summary statistics cover all {result.cve_selection.window_records.toLocaleString()} distinct CVEs in the window.</p>}
          <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.7 }}>{result.analysis}</div>
          <p className="limitation-footer" style={{ marginTop: 16 }}>{result.notice}</p>
          {result.cited_cves.length > 0 && <div className="term-cloud">{result.cited_cves.map(id => <a key={id} className="text-action" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`} target="_blank" rel="noreferrer">{id} <ExternalLink size={12} /></a>)}</div>}
        </div>
      )}
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 4. DATA EXPLORER & SCHEMA AUDIT
// ═══════════════════════════════════════════════════════════════════════

export function DataExplorer({ source }: { source?: SourceStatus }) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copiedSql, setCopiedSql] = useState(false);

  const loadDataQuality = () => {
    setLoading(true);
    setError('');

    api<any>('/data-quality')
      .then(res => setData(res))
      .catch((err: Error) => {
        setError(err.message || 'Failed to load data provenance');
        showToast('Error loading data quality', 'error');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadDataQuality();
  }, []);

  const sampleSql = `SELECT CVE_ID, DESCRIPTION, PUBLISHED, LAST_MODIFIED, CVSS_SCORE, SEVERITY, CWE, AFFECTED_PRODUCTS, SOURCE_URL\nFROM \${SNOWFLAKE_DATABASE}.\${SNOWFLAKE_SCHEMA}.\${SNOWFLAKE_TABLE}\nORDER BY PUBLISHED DESC LIMIT 500000; -- default SNOWFLAKE_MAX_ROWS`;

  const copySql = () => {
    navigator.clipboard.writeText(sampleSql);
    setCopiedSql(true);
    showToast('Snowflake bounded query copied to clipboard', 'success');
    setTimeout(() => setCopiedSql(false), 2000);
  };

  return (
    <div className="data-explorer-page animate-fade-in">
      <PageHeading
        eyebrow="PROVENANCE & DATA INTEGRITY"
        title="Data Explorer"
        description="Inspect data source connectivity, normalized schema definitions, completeness metrics, and bounded SQL."
      />

      {error ? (
        <Loading error={error} onRetry={loadDataQuality} />
      ) : loading && !data ? (
        <Loading />
      ) : !data ? null : (
        <>
          {/* Active Data Provider Card */}
          <div className="data-source-card">
            <div className="data-source-icon">
              <Database size={24} />
            </div>
            <div className="data-source-copy">
              <small>ACTIVE PROVIDER · {source?.mode ?? data.source.mode}</small>
              <h2>{data.source.dataset}</h2>
              <p>
                {data.source.provider} — {data.source.note}{' '}
                {data.source.updated_at
                  ? `Snapshot retrieved ${new Date(data.source.updated_at).toLocaleString()}.`
                  : 'Refresh timestamp unavailable.'}
              </p>
            </div>
            <Badge tone={data.source.connected ? 'green' : 'violet'}>
              {data.source.connected ? 'CONNECTED' : 'SNAPSHOT DEMO'}
            </Badge>
          </div>

          {/* Completeness & Metrics Overview */}
          <div className="metric-grid three">
            <div className="metric-card">
              <small>RECORDS INDEXED</small>
              <strong>{data.record_count.toLocaleString()}</strong>
              <span>Normalized source rows</span>
            </div>
            <div className="metric-card">
              <small>CANONICAL SCHEMA FIELDS</small>
              <strong>{data.fields.length}</strong>
              <span>Typed & validated columns</span>
            </div>
            <div className="metric-card">
              <small>LATEST SOURCE PUBLICATION</small>
              <strong className="date-stat">
                {data.last_publication
                  ? new Date(data.last_publication).toLocaleDateString()
                  : 'Unknown'}
              </strong>
              <span>Most recent timestamp</span>
            </div>
          </div>

          {/* Schema & Missing Value Audit */}
          <Card
            title="Schema structure and completeness audit"
            subtitle="Calculated over the active normalized vulnerability corpus"
          >
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>FIELD IDENTIFIER</th>
                    <th>DATA TYPE</th>
                    <th>MISSING VALUES</th>
                    <th>DATA COMPLETENESS</th>
                  </tr>
                </thead>
                <tbody>
                  {data.fields.map((f: any) => {
                    const completeness = Math.max(0, 100 - f.missing_percent);
                    return (
                      <tr key={f.name}>
                        <td>
                          <b className="mono">{f.name}</b>
                        </td>
                        <td>
                          <span className="type-tag">{f.type}</span>
                        </td>
                        <td>
                          {f.missing.toLocaleString()}{' '}
                          <small className="muted-pct">({f.missing_percent}%)</small>
                        </td>
                        <td>
                          <div className="completeness-bar-wrap">
                            <div className="completeness-bar">
                              <span
                                style={{
                                  width: `${completeness}%`,
                                  background:
                                    completeness > 90
                                      ? 'var(--green)'
                                      : completeness > 60
                                      ? 'var(--amber)'
                                      : 'var(--red)',
                                }}
                              />
                            </div>
                            <span className="completeness-pct">{completeness}%</span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="pipeline-note">
              <b>Normalization Pipeline Specification</b>
              <p>{data.ingestion}</p>
            </div>
          </Card>

          {/* Bounded Snowflake Query */}
          <Card
            title="Snowflake Ingestion Query"
            subtitle="Fixed-column projection; reads are bounded by SNOWFLAKE_MAX_ROWS (500,000 default, 1,000,000 maximum). No user SQL is executed."
            action={
              <button className="button-secondary" onClick={copySql}>
                {copiedSql ? <Check size={14} className="green-icon" /> : <Copy size={14} />}
                {copiedSql ? 'Copied' : 'Copy Query'}
              </button>
            }
          >
            <pre className="sql-block">{sampleSql}</pre>
          </Card>
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 5. EXECUTIVE REPORTS & EVIDENCE-READY EXPORTS
// ═══════════════════════════════════════════════════════════════════════

export function Reports() {
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadSummary = () => {
    setLoading(true);
    setError('');

    api<any>('/reports/summary')
      .then(res => setSummary(res))
      .catch((err: Error) => {
        setError(err.message || 'Failed to load report summary');
        showToast('Error loading report data', 'error');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadSummary();
  }, []);

  // Generate and download executive HTML report
  const downloadHtmlReport = () => {
    if (!summary) return;

    showToast('Compiling executive report...', 'info');

    const esc = (v: any) =>
      String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    const htmlContent = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ThreatLens AI — Vulnerability Intelligence Executive Report</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card: #131a29;
      --border: #222e42;
      --text: #e2e8f0;
      --muted: #8492a6;
      --primary: #6366f1;
      --red: #ef4444;
      --amber: #f59e0b;
      --green: #10b981;
    }
    @media print {
      body { background: #fff !important; color: #111 !important; }
      .card, table { border: 1px solid #ccc !important; box-shadow: none !important; }
      th, td { border: 1px solid #ddd !important; }
      .no-print { display: none !important; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      max-width: 960px;
      margin: 40px auto;
      padding: 0 24px;
    }
    .header {
      border-bottom: 2px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
    }
    h1 { font-size: 28px; margin: 0 0 8px 0; color: #fff; }
    .meta { color: var(--muted); font-size: 14px; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 24px;
    }
    h2 { font-size: 20px; margin-top: 0; color: #cbd5e1; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }
    th { text-align: left; padding: 10px; border-bottom: 2px solid var(--border); color: var(--muted); text-transform: uppercase; font-size: 12px; }
    td { padding: 10px; border-bottom: 1px solid var(--border); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 600; }
    .badge-crit { color: var(--red); font-weight: bold; }
    .badge-high { color: var(--amber); font-weight: bold; }
    .footer { text-align: center; color: var(--muted); font-size: 13px; margin-top: 48px; border-top: 1px solid var(--border); padding-top: 24px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>ThreatLens AI — Vulnerability Intelligence Report</h1>
    <div class="meta">
      Generated: ${new Date(summary.generated_at).toLocaleString()} |
      Source: ${esc(summary.source.dataset)} (${esc(summary.source.mode)}) |
      Scope: ${esc(summary.metrics.analysis_scope)}
    </div>
  </div>

  <div class="card">
    <h2>Executive Summary & High-Water Observations</h2>
    <p>
      An analysis of <b>${summary.metrics.total.toLocaleString()}</b> verified vulnerability records identified
      <b>${summary.metrics.critical.toLocaleString()}</b> Critical severity and <b>${summary.metrics.high.toLocaleString()}</b>
      High severity items. A total of <b>${summary.metrics.new_30d.toLocaleString()}</b> CVEs were published within the recent
      30-day observation window.
    </p>
  </div>

  <div class="card">
    <h2>Prioritized Investigative Candidates</h2>
    <table>
      <thead>
        <tr>
          <th>CVE IDENTIFIER</th>
          <th>SEVERITY</th>
          <th>SOURCE CVSS</th>
          <th>PRIORITY INDEX</th>
          <th>SOURCE EVIDENCE</th>
        </tr>
      </thead>
      <tbody>
        ${summary.prioritized
          .map(
            (v: any) => `<tr>
          <td class="mono">${esc(v.cve_id)}</td>
          <td class="${v.severity === 'CRITICAL' ? 'badge-crit' : v.severity === 'HIGH' ? 'badge-high' : ''}">${esc(
              v.severity
            )}</td>
          <td class="mono">${v.cvss_score != null ? Number(v.cvss_score).toFixed(1) : '—'}</td>
          <td class="mono"><b>${v.priority_score != null ? Number(v.priority_score).toFixed(1) : '—'} / 100</b></td>
          <td><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve_id)}" target="_blank" style="color:#818cf8;">NIST NVD Advisory</a></td>
        </tr>`
          )
          .join('')}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Methodology & Rigor Statement</h2>
    <p><b>Prioritization Model:</b> ${esc(summary.method)}</p>
    <p><b>Boundary & Limitations:</b> ${esc(summary.limitations)}</p>
  </div>

  <div class="footer">
    ThreatLens AI — Open Cybersecurity Intelligence Platform.
    <br>
    Notice: Prioritization scores reflect analytical triage and do not constitute proof of active adversary exploitation.
  </div>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threatlens-executive-report-${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast('Executive report downloaded successfully', 'success');
  };

  return (
    <div className="reports-page animate-fade-in">
      <PageHeading
        eyebrow="EVIDENCE-READY OUTPUTS"
        title="Reports & Briefings"
        description="Generate formatted intelligence briefings and download reproducible data snapshots."
        action={
          <div className="button-group">
            <button
              className="button-secondary"
              onClick={() => {
                showToast('Exporting CSV records...', 'info');
                downloadExport('csv');
              }}
            >
              <Download size={15} /> Export CSV
            </button>
            <button
              className="button-primary"
              onClick={downloadHtmlReport}
              disabled={!summary}
            >
              <FileDown size={15} /> Download Executive Report (HTML)
            </button>
          </div>
        }
      />

      {error ? (
        <Loading error={error} onRetry={loadSummary} />
      ) : loading && !summary ? (
        <Loading />
      ) : !summary ? null : (
        <>
          {/* Executive Overview Banner */}
          <div className="banner">
            <div className="banner-icon">
              <FileText size={18} />
            </div>
            <div>
              <b>
                {summary.source.dataset} · {summary.source.mode}
              </b>
              <span>
                Generated at {new Date(summary.generated_at).toLocaleString()} across{' '}
                {summary.metrics.total.toLocaleString()} ingested records.
              </span>
            </div>
          </div>

          {/* Summary Metric Counters */}
          <div className="metric-grid">
            <div className="metric-card">
              <small>CRITICAL & HIGH SEVERITY</small>
              <strong>{(summary.metrics.critical + summary.metrics.high).toLocaleString()}</strong>
              <span>Requiring urgent remediation review</span>
            </div>
            <div className="metric-card">
              <small>RECENT 30-DAY WINDOW</small>
              <strong>{summary.metrics.new_30d.toLocaleString()}</strong>
              <span>Newly disclosed vulnerabilities</span>
            </div>
            <div className="metric-card">
              <small>PRIORITIZED CANDIDATES</small>
              <strong>
                {summary.prioritized.filter((v: any) => v.priority_score != null).length}
              </strong>
              <span>Scored above investigative threshold</span>
            </div>
            <div className="metric-card">
              <small>ANALYTICAL PARADIGM</small>
              <strong className="date-stat">Unsupervised</strong>
              <span>No proprietary labeled bias</span>
            </div>
          </div>

          {/* Report Sections Breakdown Card */}
          <Card
            title="Executive Briefing Contents"
            subtitle="The generated report packages full telemetry context for security decision-makers"
          >
            <div className="report-includes-grid">
              {[
                {
                  title: 'Data Provenance & Source Metadata',
                  desc: 'Snowflake / NVD data snapshot attribution with synchronization timestamp.',
                },
                {
                  title: 'Severity & Vulnerability Volume Trajectory',
                  desc: 'Comprehensive counts across all standardized CVSS severity bands.',
                },
                {
                  title: 'Explainable Prioritization Ranking',
                  desc: 'Ranked list of highest-risk CVEs with clear formula transparency.',
                },
                {
                  title: 'Direct NIST NVD Evidence Links',
                  desc: 'Verified hyperlinks to official NIST National Vulnerability Database advisories.',
                },
                {
                  title: 'Defensive Action Checklist',
                  desc: 'Clear triage workflow guidance for SecOps, vulnerability engineers, and CISOs.',
                },
              ].map((item, idx) => (
                <div key={idx} className="report-include-item">
                  <div className="include-icon">
                    <CheckCircle2 size={16} />
                  </div>
                  <div>
                    <b>{item.title}</b>
                    <p>{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 6. SYSTEM SETTINGS & PLATFORM HEALTH MONITOR
// ═══════════════════════════════════════════════════════════════════════

export function Settings({ source }: { source?: SourceStatus }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<HealthResponse>('/health')
      .then(res => setHealth(res))
      .catch(() => null)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="settings-page animate-fade-in">
      <PageHeading
        eyebrow="CONFIGURATION & HEALTH"
        title="Settings"
        description="Inspect data source settings, analytical tuning parameters, and runtime environment security."
      />

      <div className="settings-grid">
        {/* Source Provider Config */}
        <Card
          title="Data Provider Configuration"
          subtitle="Governed by the DATA_SOURCE backend environment flag"
        >
          <div className="setting-row">
            <div>
              <b>Operational Mode</b>
              <p>
                {source?.mode === 'LIVE'
                  ? 'Snowflake Data Warehouse Live Connection'
                  : 'Curated NIST NVD Demo Snapshot'}
              </p>
            </div>
            <Badge tone={source?.mode === 'LIVE' ? 'green' : 'violet'}>
              {source?.mode ?? 'UNKNOWN'}
            </Badge>
          </div>

          <div className="setting-row">
            <div>
              <b>Connection Status</b>
              <p>
                {source?.connected
                  ? 'Active data warehouse connection verified.'
                  : 'Operating in standalone demo mode.'}
              </p>
            </div>
            <Badge tone={source?.connected ? 'green' : 'gray'}>
              {source?.connected ? 'CONNECTED' : 'STANDALONE'}
            </Badge>
          </div>

          <div className="setting-row">
            <div>
              <b>Data Attribution</b>
              <p>
                NIST National Vulnerability Database (NVD API 2.0). All CVE identifiers and CVSS
                metrics are curated by NIST.
              </p>
            </div>
            <a
              className="text-action"
              href="https://nvd.nist.gov/"
              target="_blank"
              rel="noreferrer"
            >
              NVD Portal <ExternalLink size={13} />
            </a>
          </div>
        </Card>

        {/* Analysis Parameters */}
        <Card
          title="Analytical Tuning Parameters"
          subtitle="Fixed coefficients ensuring deterministic reproducible results"
        >
          <div className="setting-row">
            <div>
              <b>Priority Heuristic Weights</b>
              <p>80% normalized CVSS score + 20% publication recency decay (730-day window).</p>
            </div>
            <Badge tone="blue">0.8 / 0.2 WEIGHT</Badge>
          </div>

          <div className="setting-row">
            <div>
              <b>Unsupervised ML Random Seed</b>
              <p>Deterministic random seed (random_state=42) for KMeans and Isolation Forest.</p>
            </div>
            <Badge tone="violet">SEED 42</Badge>
          </div>

          <div className="setting-row">
            <div>
              <b>Record Limits & Bounding</b>
              <p>Snowflake reads bounded to 500,000 by default (1,000,000 maximum). REST API endpoints paginate up to 100 rows.</p>
            </div>
            <Badge tone="gray">BOUNDED</Badge>
          </div>
        </Card>

        {/* Security & Credentials */}
        <Card
          title="Security & Confidentiality Safeguards"
          subtitle="Enterprise-grade boundary separation between frontend and backend"
        >
          <div className="setting-row">
            <div>
              <b>Credential Isolation</b>
              <p>
                Snowflake credentials and secrets are managed strictly in server environment variables.
                No credentials or tokens are ever sent to client browsers.
              </p>
            </div>
            <Badge tone="green">ISOLATED</Badge>
          </div>

          <div className="setting-row">
            <div>
              <b>Zero Arbitrary SQL Injection Surface</b>
              <p>
                Only parameterized, bounded SQL projections are executed. No user-supplied SQL or query
                fragments are evaluated.
              </p>
            </div>
            <Badge tone="green">PROTECTED</Badge>
          </div>

          <div className="setting-row">
            <div>
              <b>Platform Version</b>
              <p>ThreatLens AI Engine v{health?.version ?? '0.1.0'}</p>
            </div>
            <Badge tone="blue">v{health?.version ?? '0.1.0'}</Badge>
          </div>
        </Card>
      </div>
    </div>
  );
}
