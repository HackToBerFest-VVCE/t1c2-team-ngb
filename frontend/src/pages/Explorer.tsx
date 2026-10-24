/**
 * ThreatLens AI — Vulnerability Explorer
 *
 * Search, filter, inspect, and export normalized CVE records with
 * detailed modal inspection and provenance links to NIST NVD.
 */

import { useEffect, useState, useTransition } from 'react';
import {
  Calendar,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  ExternalLink,
  FileJson,
  Filter,
  Layers,
  Search,
  Shield,
  SlidersHorizontal,
  X,
} from 'lucide-react';

import { api, downloadExport, PaginatedResponse, Vulnerability } from '../api';
import {
  Badge,
  Card,
  Loading,
  PageHeading,
  SeverityBadge,
  showToast,
} from '../components/Shell';

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];

export default function Explorer() {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(15);
  const [data, setData] = useState<PaginatedResponse<Vulnerability> | null>(null);
  const [selectedCve, setSelectedCve] = useState<Vulnerability | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [, startTransition] = useTransition();

  const loadVulnerabilities = () => {
    setLoading(true);
    setError('');

    const params = new URLSearchParams({
      page: String(page),
      per_page: String(perPage),
    });

    if (query.trim()) params.append('q', query.trim());
    if (severity && severity !== 'ALL') params.append('severity', severity);

    api<PaginatedResponse<Vulnerability>>(`/vulnerabilities?${params.toString()}`)
      .then(res => {
        setData(res);
      })
      .catch((err: Error) => {
        setError(err.message || 'Failed to fetch vulnerabilities');
        showToast('Error loading vulnerabilities', 'error');
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    loadVulnerabilities();
  }, [query, severity, page, perPage]);

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
    downloadExport(format, query, severity && severity !== 'ALL' ? [severity] : []);
  };

  return (
    <div className="explorer-container animate-fade-in">
      {/* ── Page Header ───────────────────────────────────────────── */}
      <PageHeading
        eyebrow="SOURCE RECORDS"
        title="Vulnerability Explorer"
        description="Search, filter, and drill into CVE records with verified source evidence."
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
        subtitle="Filter by CVE identifier, keyword, CVSS severity, or weakness class"
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
                {s}
              </button>
            );
          })}
          <div className="result-counter">
            {data ? `${data.total.toLocaleString()} records found` : 'Searching…'}
          </div>
        </div>

        {/* Data Table */}
        {error ? (
          <Loading error={error} onRetry={loadVulnerabilities} />
        ) : loading && !data ? (
          <Loading />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>CVE RECORD</th>
                    <th>SEVERITY</th>
                    <th>CVSS</th>
                    <th>PRIORITY</th>
                    <th>PUBLISHED</th>
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
                        <SeverityBadge severity={v.severity} />
                      </td>
                      <td>
                        <span className="mono-score">
                          {v.cvss_score != null ? v.cvss_score.toFixed(1) : '—'}
                        </span>
                      </td>
                      <td>
                        <span className="priority-badge">
                          {v.priority_score != null ? v.priority_score.toFixed(1) : '—'}
                        </span>
                      </td>
                      <td className="date-cell" title={v.published ? `Full UTC Timestamp: ${v.published}` : undefined}>
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
                      <td colSpan={6}>
                        <div className="empty-state">
                          <Shield size={32} className="muted-icon" />
                          <b>No matching vulnerabilities</b>
                          <p>Try adjusting your search keywords or clearing severity filters.</p>
                          <button
                            className="button-secondary"
                            onClick={() => {
                              setQuery('');
                              setSeverity('');
                              setPage(1);
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
                <span className="page-info">
                  Showing page <b>{data.page}</b> of <b>{data.pages}</b> ({data.total.toLocaleString()} total entries)
                </span>
                <div className="pagination-buttons">
                  <button
                    className="button-secondary"
                    disabled={page <= 1}
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                  >
                    <ChevronLeft size={16} /> Previous
                  </button>
                  <span className="page-indicator">
                    {page} / {data.pages}
                  </span>
                  <button
                    className="button-secondary"
                    disabled={page >= data.pages}
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
              <SeverityBadge severity={selectedCve.severity} />
              {selectedCve.cwe && <Badge tone="blue">{selectedCve.cwe}</Badge>}
              {selectedCve.cvss_score != null && (
                <Badge tone="gray">
                  CVSS Base: <b>{selectedCve.cvss_score.toFixed(1)}</b>
                </Badge>
              )}
              {selectedCve.priority_score != null && (
                <Badge tone="violet">
                  Priority Index: <b>{selectedCve.priority_score.toFixed(1)}/100</b>
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
                  {selectedCve.published
                    ? new Date(selectedCve.published).toLocaleDateString(undefined, {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                      })
                    : 'Not recorded'}
                </span>
              </div>

              <div className="field-item">
                <small>Last Modified</small>
                <span>
                  <Calendar size={13} />{' '}
                  {selectedCve.last_modified
                    ? new Date(selectedCve.last_modified).toLocaleDateString(undefined, {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                      })
                    : 'Not recorded'}
                </span>
              </div>

              <div className="field-item">
                <small>CVSS Score (NVD)</small>
                <span className="mono bold">
                  {selectedCve.cvss_score != null ? selectedCve.cvss_score.toFixed(1) : 'N/A'}
                </span>
              </div>

              <div className="field-item">
                <small>ThreatLens Priority Score</small>
                <span className="mono bold" style={{ color: 'var(--violet)' }}>
                  {selectedCve.priority_score != null
                    ? `${selectedCve.priority_score.toFixed(1)} / 100`
                    : 'N/A'}
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
