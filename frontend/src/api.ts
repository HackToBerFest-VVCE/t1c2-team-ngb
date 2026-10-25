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

export interface VulnerabilityFilters {
  q?: string;
  severity?: string[];
  from?: string;
  to?: string;
  min_score?: string;
  max_score?: string;
  cwe?: string;
  sort?: 'published' | 'cvss_score' | 'priority_score' | 'cve_id';
  order?: 'asc' | 'desc';
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
  cve_selection?: {
    window_records: number;
    window_high_critical: number;
    included_high_critical: number;
    included_context: number;
    policy: string;
  };
  generated_at: string;
  cited_cves: string[];
  notice: string;
}

export interface RiskMethod {
  name: string;
  source: string;
  scale: string;
  ranking: string;
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
  dataset_size?: number;
  model_sample_size?: number;
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
  reporting_period: { start: string; end: string; label: string };
  source_coverage: { from: string | null; to: string | null; dated_records: number };
  source: SourceStatus;
  metrics: Metrics;
  prioritized: Vulnerability[];
  ml: { available: boolean; reason?: string; evaluation: MLEvaluation };
  supervised_models?: {
    trained_at?: string;
    random_state?: number;
    notice?: string;
    tasks: Array<{
      source: string;
      task: string;
      status: string;
      test_rows?: number;
      accuracy?: number;
      macro_f1?: number;
      limitations?: string;
    }>;
  } | null;
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
  filters: VulnerabilityFilters = {}
): Promise<void> {
  const response = await fetch(`${BASE}/reports/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ format, ...filters }),
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
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
