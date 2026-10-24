/**
 * ThreatLens AI — API Client
 *
 * Type-safe API client with error handling and download support.
 */

const BASE = import.meta.env.VITE_API_URL ?? '/api';

// ─── Types ───────────────────────────────────────────────────────────

export interface Vulnerability {
  cve_id: string;
  description: string | null;
  published: string | null;
  last_modified: string | null;
  cvss_score: number | null;
  severity: string;
  cwe: string | null;
  affected_products: string | null;
  source_url: string | null;
  priority_score: number | null;
  anomaly_score?: number;
  cluster?: number;
}

export interface Metrics {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  new_30d: number;
  avg_cvss: number | null;
  severity: { name: string; value: number }[];
  publication_trend: { month: string; count: number }[];
  top_cwe: { name: string; count: number }[];
  top_products: { name: string; count: number }[];
  analysis_scope: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  page: number;
  per_page: number;
  total: number;
  pages: number;
}

export interface SourceStatus {
  mode: string;
  connected: boolean;
  dataset: string;
  provider: string;
  updated_at: string | null;
  record_count: number;
  note: string;
}

export interface HealthResponse {
  status: string;
  source: SourceStatus;
  version: string;
}

export interface TrendItem {
  month: string;
  [severity: string]: string | number;
}

export interface TrendsResponse {
  days: number;
  items: TrendItem[];
  count: number;
  from: string;
  to: string;
  bucket: string;
  comparison: { previous_count: number; delta: number; percent: number | null };
  top_cwe: { name: string; count: number }[];
  top_products: { name: string; count: number }[];
  coverage: { from: string | null; to: string | null; dated_records: number; limited_for_window: boolean };
  limitations: string;
}

export interface AIStatus {
  configured: boolean;
  provider: string;
  model: string;
  endpoint: string;
  providers: { provider: string; model: string; configured: boolean }[];
  note: string;
}

export interface AIInsights {
  provider: string;
  model: string;
  analysis: string;
  source: { mode: string; dataset: string; record_count: number };
  window_days: number;
  record_count: number;
  generated_at: string;
  cited_cves: string[];
  notice: string;
}

export interface RiskMethod {
  name: string;
  formula: string;
  recency: string;
  missing: string;
  warning: string;
}

export interface RiskResponse {
  method: RiskMethod;
  items: Vulnerability[];
}

export interface ClusterInfo {
  id: number;
  count: number;
  terms: string[];
  representatives: Vulnerability[];
}

export interface MLEvaluation {
  method: string;
  silhouette: number | null;
  silhouette_note: string;
  baseline: string;
  baseline_score: number | null;
  anomaly_method: string;
  limitations: string;
}

export interface ClustersResponse {
  available: boolean;
  reason?: string;
  clusters: ClusterInfo[];
  evaluation: MLEvaluation;
}

export interface AnomaliesResponse {
  available: boolean;
  reason?: string;
  items: Vulnerability[];
  evaluation: MLEvaluation;
}

export interface FieldInfo {
  name: string;
  type: string;
  missing: number;
  missing_percent: number;
}

export interface DataQualityResponse {
  source: SourceStatus;
  record_count: number;
  fields: FieldInfo[];
  last_publication: string | null;
  ingestion: string;
}

export interface ReportSummary {
  generated_at: string;
  source: SourceStatus;
  metrics: Metrics;
  prioritized: Vulnerability[];
  method: string;
  limitations: string;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
  };
}

// ─── API Client ──────────────────────────────────────────────────────

/**
 * Generic API request with error handling.
 */
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(
      body?.error?.message ?? `API request failed (${response.status})`
    );
  }

  return response.json();
}

/**
 * Download filtered records as CSV or JSON.
 */
export async function downloadExport(
  format: 'csv' | 'json',
  q = '',
  severity: string[] = []
): Promise<void> {
  const response = await fetch(`${BASE}/reports/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ format, q, severity }),
  });

  if (!response.ok) {
    throw new Error('Export failed');
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `threatlens-vulnerabilities.${format}`;
  anchor.click();
  URL.revokeObjectURL(url);
}
