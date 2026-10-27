/**
 * ThreatLens AI — Vulnerability Explorer
 *
 * Search, filter, inspect, and export normalized CVE records with
 * CVSS-first ranking, source severity labels, detailed inspection, and NVD links.
 */

import { useEffect, useRef, useState, useTransition } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Calendar,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  ExternalLink,
  FileJson,
  Filter,
  Info,
  Layers,
  Search,
  Shield,
  SlidersHorizontal,
  X,
} from 'lucide-react';

import { api, downloadExport, PaginatedResponse, Vulnerability, VulnerabilityFilters } from '../api';
import {
  Badge,
  Card,
  Loading,
  PageHeading,
  SeverityBadge,
  showToast,
} from '../components/Shell';

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'];

function formatUtcDate(value: string | null): string {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Not recorded';
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC',
  }).format(date);
}

function formatUtcTime(value: string | null): string {
  if (!value) return 'Time not recorded';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Time not recorded';
  const time = new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone: 'UTC',
  }).format(date);
  return `${time} UTC`;
}

export default function Explorer() {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [review, setReview] = useState<VulnerabilityFilters['review']>(() => {
    const initial = sessionStorage.getItem('threatlens-review-filter') as VulnerabilityFilters['review'];
    sessionStorage.removeItem('threatlens-review-filter');
    return initial;
  });
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(15);
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [minScore, setMinScore] = useState('');
  const [maxScore, setMaxScore] = useState('');
  const [cwe, setCwe] = useState('');
  const [sort, setSort] = useState<VulnerabilityFilters['sort']>('severity');
  const [order, setOrder] = useState<VulnerabilityFilters['order']>('desc');
  const [data, setData] = useState<PaginatedResponse<Vulnerability> | null>(null);
  const [selectedCve, setSelectedCve] = useState<Vulnerability | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [, startTransition] = useTransition();
  const requestId = useRef(0);
  const tableRef = useRef<HTMLDivElement>(null);

  const currentFilters = (): VulnerabilityFilters => ({
    q: query.trim(),
    severity: severity && severity !== 'ALL' ? [severity] : [],
    from: fromDate || undefined,
    to: toDate || undefined,
    min_score: minScore || undefined,
    max_score: maxScore || undefined,
    cwe: cwe.trim() || undefined,
    review,
    sort,
    order,
  });

  const loadVulnerabilities = () => {
    const currentRequest = ++requestId.current;
    setLoading(true);
    setError('');

    const params = new URLSearchParams({
      page: String(page),
      per_page: String(perPage),
    });

    const filters = currentFilters();
    if (filters.q) params.append('q', filters.q);
    if (filters.severity?.length) params.append('severity', filters.severity.join(','));
    if (filters.from) params.append('from', filters.from);
    if (filters.to) params.append('to', filters.to);
    if (filters.min_score) params.append('min_score', filters.min_score);
    if (filters.max_score) params.append('max_score', filters.max_score);
    if (filters.cwe) params.append('cwe', filters.cwe);
    if (filters.review) params.append('review', filters.review);
    if (filters.sort) params.append('sort', filters.sort);
    if (filters.order) params.append('order', filters.order);

    api<PaginatedResponse<Vulnerability>>(`/vulnerabilities?${params.toString()}`)
      .then(res => {
        if (currentRequest === requestId.current) setData(res);
      })
      .catch((err: Error) => {
        if (currentRequest !== requestId.current) return;
        setError(err.message || 'Failed to fetch vulnerabilities');
        showToast('Error loading vulnerabilities', 'error');
      })
      .finally(() => {
        if (currentRequest === requestId.current) setLoading(false);
      });
  };

  useEffect(() => {
    loadVulnerabilities();
  }, [query, severity, review, page, perPage, fromDate, toDate, minScore, maxScore, cwe, sort, order]);

  useEffect(() => {
    if (review) {
      setSort('cvss_score');
      setOrder('desc');
      setPage(1);
    }
  }, [review]);

  // Handle Search Input Change
  const handleSearchChange = (val: string) => {
    startTransition(() => {
      setPage(1);
      setQuery(val);
    });
  };

  // Copy CVE to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    showToast(`Copied ${text} to clipboard`, 'success');
    setTimeout(() => setCopied(false), 2000);
  };

  // Export handlers with notifications
  const handleExport = (format: 'csv' | 'json') => {
    showToast(`Generating ${format.toUpperCase()} export...`, 'info');
    downloadExport(format, currentFilters()).catch((err: Error) => {
      showToast(err.message || 'Export failed', 'error');
    });
  };

  const handleSortClick = (column: VulnerabilityFilters['sort']) => {
    setPage(1);
    if (sort === column) {
      setOrder(o => (o === 'desc' ? 'asc' : 'desc'));
    } else {
      setSort(column);
      setOrder(column === 'cve_id' ? 'asc' : 'desc');
    }
  };

  const renderSortIcon = (column: VulnerabilityFilters['sort']) => {
    if (sort !== column) return <ArrowUpDown size={13} className="th-sort-icon inactive" />;
    return order === 'asc' ? (
      <ArrowUp size={13} className="th-sort-icon active" />
    ) : (
      <ArrowDown size={13} className="th-sort-icon active" />
    );
  };

  const resetFilters = () => {
    setQuery(''); setSeverity(''); setReview(undefined); setFromDate(''); setToDate('');
    setMinScore(''); setMaxScore(''); setCwe(''); setSort('severity'); setOrder('desc'); setPage(1);
  };

  useEffect(() => {
    if (!loading && data?.page === page && page > 1) {
      tableRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
    }
  }, [data?.page, loading, page]);

  return (
    <div className="explorer-container animate-fade-in">
      {/* ── Page Header ───────────────────────────────────────────── */}
      <PageHeading
        eyebrow="SOURCE RECORDS"
        title="Vulnerability Explorer"
        description="Rank vulnerabilities from Critical to Low by NVD CVSS severity, with unscored records clearly identified."
        action={
          <div className="button-group">
            <button
              className="button-secondary"
              onClick={() => handleExport('csv')}
              aria-label="Export as CSV"
            >
              <Download size={15} /> Export CSV
            </button>
            <button
              className="button-secondary"
              onClick={() => handleExport('json')}
              aria-label="Export as JSON"
            >
              <FileJson size={15} /> Export JSON
            </button>
          </div>
        }
      />

      {/* ── Main Explorer Card ────────────────────────────────────── */}
      <Card
        title="Record catalog"
        subtitle="Source severity is preserved. CVSS-indicated severity is a review hint only; unscored records remain unscored."
      >
        {/* Search & Filter Toolbar */}
        <div className="filter-toolbar">
          <div className="search-field-wrap">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Search CVE ID, product name, vulnerability description…"
              value={query}
              onChange={e => handleSearchChange(e.target.value)}
            />
            {query && (
              <button
                className="clear-search"
                onClick={() => handleSearchChange('')}
                aria-label="Clear search"
              >
                <X size={14} />
              </button>
            )}
            <kbd className="search-kbd">Ctrl K</kbd>
          </div>

          <div className="filter-actions">
            <div className="select-wrap">
              <ArrowUpDown size={14} />
              <select
                value={`${sort}-${order}`}
                onChange={e => {
                  setPage(1);
                  const [s, o] = e.target.value.split('-');
                  setSort(s as VulnerabilityFilters['sort']);
                  setOrder(o as VulnerabilityFilters['order']);
                }}
                aria-label="Sort order"
              >
                <option value="published-desc">Newest Published</option>
                <option value="published-asc">Oldest Published</option>
                <option value="severity-desc">Highest severity (Critical first)</option>
                <option value="cvss_score-desc">Highest CVSS (10.0 first)</option>
                <option value="cvss_score-asc">Lowest CVSS (0.0 first)</option>
                <option value="priority_score-desc">Highest Priority Risk</option>
                <option value="cve_id-asc">CVE ID (A → Z)</option>
              </select>
            </div>

            <div className="select-wrap">
              <SlidersHorizontal size={14} />
              <select
                value={severity}
                onChange={e => {
                  setPage(1);
                  setSeverity(e.target.value);
                }}
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="NONE">None</option>
              </select>
            </div>

            <div className="select-wrap">
              <select aria-label="Review queue" value={review ?? ''} onChange={e => { setPage(1); setReview((e.target.value || undefined) as VulnerabilityFilters['review']); }}>
                <option value="">All review states</option>
                <option value="needs_review">Needs review (missing or inconsistent data)</option>
                <option value="high_unknown">Unknown severity + CVSS ≥ 7</option>
                <option value="unscored">Missing CVSS score</option>
              </select>
            </div>

            <div className="select-wrap">
              <select
                value={perPage}
                onChange={e => {
                  setPage(1);
                  setPerPage(Number(e.target.value));
                }}
              >
                <option value={15}>15 per page</option>
                <option value={25}>25 per page</option>
                <option value={50}>50 per page</option>
              </select>
            </div>
          </div>
        </div>

        <div className="explorer-advanced-filters" aria-label="Advanced vulnerability filters">
          <label>Published from<input type="date" value={fromDate} onChange={e => { setPage(1); setFromDate(e.target.value); }} /></label>
          <label>Published to<input type="date" value={toDate} onChange={e => { setPage(1); setToDate(e.target.value); }} /></label>
          <label>CVSS minimum<input type="number" min="0" max="10" step="0.1" placeholder="0.0" value={minScore} onChange={e => { setPage(1); setMinScore(e.target.value); }} /></label>
          <label>CVSS maximum<input type="number" min="0" max="10" step="0.1" placeholder="10.0" value={maxScore} onChange={e => { setPage(1); setMaxScore(e.target.value); }} /></label>
          <label>CWE<input type="search" maxLength={100} placeholder="e.g. CWE-79" value={cwe} onChange={e => { setPage(1); setCwe(e.target.value); }} /></label>
          <label>Sort by<select value={sort} onChange={e => { setPage(1); setSort(e.target.value as VulnerabilityFilters['sort']); }}><option value="severity">Severity (Critical first)</option><option value="published">Published date</option><option value="cvss_score">Source CVSS score</option><option value="priority_score">Priority score</option><option value="cve_id">CVE ID</option></select></label>
          <label>Order<select value={order} onChange={e => { setPage(1); setOrder(e.target.value as VulnerabilityFilters['order']); }}><option value="desc">Descending</option><option value="asc">Ascending</option></select></label>
          <button className="button-secondary explorer-reset" onClick={resetFilters}>Reset filters</button>
        </div>

        {/* Severity Quick Pills */}
        <div className="severity-pills">
          <span className="pills-label">
            <Filter size={12} /> Severity:
          </span>
          {SEVERITIES.map(s => {
            const isSelected = (s === 'ALL' && !severity) || severity === s;
            return (
              <button
                key={s}
                className={`pill-btn ${isSelected ? 'active' : ''}`}
                onClick={() => {
                  setPage(1);
                  setSeverity(s === 'ALL' ? '' : s);
                }}
              >
                {s === 'UNKNOWN' ? 'UNSCORED' : s}
              </button>
            );
          })}
          <div className="result-counter">
            {data ? `${data.total.toLocaleString()} records found` : 'Searching…'}
          </div>
        </div>

        {/* Informative notice when sorting by CVSS desc with all severities */}
        {sort === 'severity' && order === 'desc' && !severity && (
          <div className="notice blue-notice" style={{ margin: '8px 0 16px', padding: '10px 14px' }}>
            <Info size={15} />
            <div>
              <span>
                Sorted by <b>severity level</b>: Critical, High, Medium, Low, None, then unscored. Records within each severity are ordered by publication date, so the list doesn’t spend hundreds of pages on tied 10.0 scores.
              </span>
            </div>
          </div>
        )}

        {/* Data Table */}
        {error ? (
          <Loading error={error} onRetry={loadVulnerabilities} />
        ) : loading && !data ? (
          <Loading />
        ) : (
          <>
            <div className="table-wrap" ref={tableRef}>
              <table className="explorer-table" aria-busy={loading}>
                <thead>
                  <tr>
                    <th
                      className="sortable-th"
                      onClick={() => handleSortClick('cve_id')}
                      title="Click to sort by CVE ID"
                    >
                      <div className="th-content">
                        <span>CVE RECORD</span>
                        {renderSortIcon('cve_id')}
                      </div>
                    </th>
                    <th
                      className="sortable-th"
                      onClick={() => handleSortClick('severity')}
                      title="Click to rank by severity level"
                    >
                      <div className="th-content">
                        <span>SOURCE SEVERITY</span>
                        {renderSortIcon('severity')}
                      </div>
                    </th>
                    <th
                      className="sortable-th"
                      onClick={() => handleSortClick('cvss_score')}
                      title="Click to sort by CVSS Base Score"
                    >
                      <div className="th-content">
                        <span>CVSS BASE SCORE</span>
                        {renderSortIcon('cvss_score')}
                      </div>
                    </th>
                    <th
                      className="sortable-th"
                      onClick={() => handleSortClick('published')}
                      title="Click to sort by Published Date"
                    >
                      <div className="th-content">
                        <span>PUBLISHED (UTC)</span>
                        {renderSortIcon('published')}
                      </div>
                    </th>
                    <th style={{ textAlign: 'right' }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.items.map(v => (
                    <tr
                      key={v.cve_id}
                      className="table-row-hover"
                      onClick={() => setSelectedCve(v)}
                    >
                      <td>
                        <div className="cve-cell">
                          <span className="mono bold">{v.cve_id}</span>
                          {v.cwe && <span className="cwe-pill">{v.cwe}</span>}
                        </div>
                        <small className="row-desc">
                          {v.description || 'No description provided by source.'}
                        </small>
                      </td>
                      <td>
                        <div style={{ display: 'grid', gap: 4 }}>
                          {v.severity === 'UNKNOWN' && v.cvss_score == null ? (
                            <Badge tone="gray" title="No CVSS score is present in the source record.">UNKNOWN · UNSCORED</Badge>
                          ) : <SeverityBadge severity={v.severity} />}
                          {v.cvss_indicated_severity && v.severity === 'UNKNOWN' && <Badge tone={['HIGH', 'CRITICAL'].includes(v.cvss_indicated_severity) ? 'red' : 'blue'} title="Derived from the source CVSS score; it is not a source-reported severity.">CVSS INDICATES {v.cvss_indicated_severity}</Badge>}
                          {!!v.review_reasons?.length && <small title={v.review_reasons.join('; ')} style={{ color: 'var(--text-muted)' }}>Review: {v.review_reasons.join('; ')}</small>}
                        </div>
                      </td>
                      <td>
                        {v.cvss_score != null ? (
                          <div className="score-cell">
                            <span className="cvss-score-value" title="Source-provided CVSS Base Score">
                              {v.cvss_score.toFixed(1)}<small> / 10.0</small>
                            </span>
                            {v.priority_score != null && (
                              <span className="priority-pill" title="Operational triage priority score (0-100)">
                                P{Math.round(v.priority_score)}
                              </span>
                            )}
                          </div>
                        ) : (
                          <div className="score-cell">
                            <span className="unscored-value">Not scored by NVD</span>
                            {v.priority_score != null && (
                              <span className="priority-pill" title="Local triage priority (0–100), based on publication recency because the source has no CVSS score.">
                                P{Math.round(v.priority_score)}
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="date-cell" title={v.published ? `Full source timestamp: ${v.published}` : undefined}>
                        {v.published ? (
                          <span className="published-date">{formatUtcDate(v.published)}</span>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="icon-button"
                          onClick={e => {
                            e.stopPropagation();
                            setSelectedCve(v);
                          }}
                          aria-label={`Inspect ${v.cve_id}`}
                        >
                          <ExternalLink size={15} />
                        </button>
                      </td>
                    </tr>
                  ))}
                  {data?.items.length === 0 && (
                    <tr>
                      <td colSpan={5}>
                        <div className="empty-state">
                          <Shield size={32} className="muted-icon" />
                          <b>No matching vulnerabilities</b>
                          <p>Try adjusting your search keywords or clearing severity filters.</p>
                          <button
                            className="button-secondary"
                            onClick={() => {
                              resetFilters();
                            }}
                          >
                            Reset filters
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {data && data.pages > 1 && (
              <div className="pagination">
                <span className="page-info" aria-live="polite">
                  {loading || data.page !== page
                    ? <>Loading page <b>{page}</b> of <b>{data.pages}</b>…</>
                    : <>Showing page <b>{data.page}</b> of <b>{data.pages}</b> ({data.total.toLocaleString()} total entries)</>}
                </span>
                <div className="pagination-buttons">
                  <button
                    className="button-secondary"
                    disabled={loading || page !== data.page || page <= 1}
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                  >
                    <ChevronLeft size={16} /> Previous
                  </button>
                  <span className="page-indicator">
                    {data.page} / {data.pages}
                  </span>
                  <button
                    className="button-secondary"
                    disabled={loading || page !== data.page || page >= data.pages}
                    onClick={() => setPage(p => Math.min(data.pages, p + 1))}
                  >
                    Next <ChevronRight size={16} />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>

      {/* ── CVE Detail Modal ──────────────────────────────────────── */}
      {selectedCve && (
        <div className="modal-backdrop animate-fade-in" onClick={() => setSelectedCve(null)}>
          <div
            className="detail-modal animate-scale-in"
            onClick={e => e.stopPropagation()}
          >
            <div className="modal-top">
              <div>
                <div className="eyebrow">SOURCE RECORD INSPECTION</div>
                <div className="modal-title-row">
                  <h2>{selectedCve.cve_id}</h2>
                  <button
                    className="copy-button"
                    onClick={() => copyToClipboard(selectedCve.cve_id)}
                    title="Copy CVE ID"
                  >
                    {copied ? <Check size={14} className="green-icon" /> : <Copy size={14} />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
              <button
                className="icon-button close-btn"
                onClick={() => setSelectedCve(null)}
                aria-label="Close modal"
              >
                <X size={18} />
              </button>
            </div>

            <div className="modal-badges">
              {selectedCve.severity === 'UNKNOWN' && selectedCve.cvss_score == null ? (
                <Badge tone="gray" title="No CVSS score is present in the source record.">UNSCORED</Badge>
              ) : <SeverityBadge severity={selectedCve.severity} />}
              {selectedCve.cwe && <Badge tone="blue">{selectedCve.cwe}</Badge>}
              {selectedCve.cvss_score != null && (
                <Badge tone="gray">
                  CVSS Base: <b>{selectedCve.cvss_score.toFixed(1)}</b>
                </Badge>
              )}
              {selectedCve.priority_score != null && (
                <Badge tone="gray" title="Local triage priority score (0–100), not an NVD CVSS score.">
                  Priority: <b>{Math.round(selectedCve.priority_score)} / 100</b>
                </Badge>
              )}
            </div>

            <div className="modal-section">
              <small className="section-label">DESCRIPTION</small>
              <p className="detail-description">
                {selectedCve.description || 'No detailed description supplied by source provider.'}
              </p>
            </div>

            <div className="detail-fields-grid">
              <div className="field-item">
                <small>Published Date</small>
                <span>
                  <Calendar size={13} />{' '}
                  {formatUtcDate(selectedCve.published)} · {formatUtcTime(selectedCve.published)}
                </span>
              </div>

              <div className="field-item">
                <small>Last Modified</small>
                <span>
                  <Calendar size={13} />{' '}
                  {formatUtcDate(selectedCve.last_modified)} · {formatUtcTime(selectedCve.last_modified)}
                </span>
              </div>

              <div className="field-item">
                <small>CVSS Score (NVD)</small>
                <span className="mono bold">
                  {selectedCve.cvss_score != null ? `${selectedCve.cvss_score.toFixed(1)} / 10.0` : 'Not scored in source'}
                </span>
              </div>
            </div>

            {selectedCve.affected_products && (
              <div className="modal-section">
                <small className="section-label">
                  <Layers size={13} /> AFFECTED PRODUCTS & VENDORS
                </small>
                <div className="products-tags">
                  {selectedCve.affected_products
                    .split(',')
                    .map(p => p.trim())
                    .filter(Boolean)
                    .map((product, i) => (
                      <span key={i} className="product-tag">
                        {product}
                      </span>
                    ))}
                </div>
              </div>
            )}

            <div className="modal-actions">
              <a
                className="button-primary full"
                href={
                  selectedCve.source_url ||
                  `https://nvd.nist.gov/vuln/detail/${selectedCve.cve_id}`
                }
                target="_blank"
                rel="noreferrer"
              >
                Verify on NIST NVD Official Advisory <ExternalLink size={15} />
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
