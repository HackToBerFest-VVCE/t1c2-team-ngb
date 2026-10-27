/**
 * ThreatLens AI — API Client
 *
 * Type-safe API client with error handling and download support.
 */

const BASE = import.meta.env.VITE_API_URL ?? '/api';

// ─── Types ───────────────────────────────────────────────────────────

export interface Vulnerability {
  record_id?: string;
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
  cvss_indicated_severity?: string | null;
  review_reasons?: string[];
  review_priority?: 'URGENT_REVIEW' | 'HIGH_REVIEW' | 'VERIFY_SOURCE' | 'MANUAL_REVIEW' | 'REVIEW' | 'VERIFY_SCORE' | 'NO_REVIEW_FLAG';
  review_evidence_url?: string;
  affected_product_evidence?: string;
  affected_version_evidence?: string;
  affected_version_evidence_status?: string;
  advisory_evidence_status?: string;
  advisory_references?: string[];
  manual_verification_required?: boolean;
  ml_analysis_status?: string;
  ml_sample_membership?: string;
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
  review?: {
    unknown_source_severity: number;
    unknown_with_critical_cvss: number;
    unknown_with_high_or_critical_cvss: number;
    explicit_none_severity: number;
    missing_cvss: number;
    missing_severity_and_cvss: number;
    severity_score_mismatch: number;
    invalid_cvss: number;
    needs_review: number;
  };
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
  review?: 'needs_review' | 'high_unknown' | 'unscored';
  sort?: 'published' | 'cvss_score' | 'priority_score' | 'severity' | 'cve_id';
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
  fallback_from?: string;
  fallback_reason?: string;
}

export interface RiskMethod {
  name: string;
  source: string;
  scale: string;
  ranking: string;
  missing: string;
  warning: string;
}

export interface RiskDistribution {
  total: number;
  scored: number;
  unscored: number;
  exact_10: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  mean_cvss: number;
}

export interface RiskResponse {
  method: RiskMethod;
  distribution?: RiskDistribution;
  tier?: string;
  sort?: string;
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
  total_records?: number;
  eligible_description_count?: number;
  not_analyzed_count?: number;
}

export interface MLCoverage {
  total_active_records: number;
  records_with_nonempty_descriptions: number;
  eligible_records: number;
  records_in_deterministic_sample: number;
  records_assigned_to_kmeans: number;
  records_scored_by_isolation_forest: number;
  excluded_missing_or_empty_description: number;
  eligible_records_outside_sample: number;
  sample_records_below_minimum: number;
  records_not_analyzed: number;
  coverage_percent_of_active_records: number;
  coverage_denominator: string;
  partition_note: string;
}

export interface MLCoverageResponse {
  coverage: MLCoverage;
  evaluation: MLEvaluation;
  assignments: Array<{ record_id: string; cve_id: string; cluster: number; anomaly_score: number }>;
  assignment_count: number;
  page: number;
  per_page: number;
  pages: number;
  output_meaning: string;
}

export interface ClustersResponse {
  available: boolean;
  reason?: string;
  clusters: ClusterInfo[];
  evaluation: MLEvaluation;
  coverage?: MLCoverage;
}

export interface AnomaliesResponse {
  available: boolean;
  reason?: string;
  items: Vulnerability[];
  evaluation: MLEvaluation;
  coverage?: MLCoverage;
}

export interface AttackForecastFamily {
  name: string;
  count: number;
  critical: number;
  high: number;
  latest_30d: number;
  historical_per_30d: number;
  direction: string;
  mean_cvss: number | null;
  cve_examples: string[];
  remedy: string;
  expected_outcome: string;
}

export interface AttackForecastResponse {
  window_days: number;
  from: string;
  to: string;
  generated_at: string;
  source: { mode: string; dataset: string; provider: string; record_count: number };
  window_records: number;
  high_critical_records: number;
  latest_30d_high_critical: number;
  historical_high_critical_per_30d: number;
  coverage: {
    from: string | null;
    to: string | null;
    dated_records_loaded: number;
    window_limited_by_source_history: boolean;
  };
  confidence: string;
  families: AttackForecastFamily[];
  near_term_watchlist: Array<{
    name: string;
    observed_latest_30d: number;
    direction: string;
    reason: string;
    defensive_action: string;
    expected_outcome: string;
    cve_examples: string[];
  }>;
  recent_high_critical: Array<{
    cve_id: string;
    published: string | null;
    severity: string;
    cvss_score: number | null;
    attack_family: string;
    source_url: string;
  }>;
  method: string;
  limitations: string;
  analysis_provider: 'local' | 'snowflake_cortex';
  cortex_status: 'complete' | 'unavailable' | 'fallback';
  cortex_model?: string;
  cortex_interpretation?: string;
  cortex_notice?: string;
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

// ─── Software Safety Advisor Types & Client ───────────────────────────

export interface SoftwareFinding {
  id: string;
  source: string;
  summary: string;
  details: string;
  severity: string;
  cvss_score: number | null;
  match_type: 'EXACT' | 'RANGE_MATCH' | 'POTENTIAL' | 'NOT_AFFECTED';
  range_description: string;
  verified_fixed_version: string | null;
  cwe: string;
  published: string;
  modified: string;
  source_url: string;
  advisories: string[];
}

export interface SoftwareIdentity {
  product_name: string;
  vendor: string;
  version: string;
  ecosystem: string;
  package_name?: string | null;
  source_url?: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface AssessmentRecommendation {
  action: string;
  explanation: string;
}

export interface FileMetadata {
  filename: string;
  size_bytes: number;
  sha256: string;
  sha1: string;
  md5: string;
  detected_type: string;
  suggested_ecosystem: string;
  extracted_name?: string | null;
  extracted_version?: string | null;
  suspicious_flags: string[];
  is_executable_binary: boolean;
  analysis_mode: string;
  notice: string;
}

export interface SoftwareAssessmentResponse {
  assessment_id: string;
  verdict:
    | 'KNOWN_VULNERABILITIES_FOUND'
    | 'POTENTIAL_MATCH_REQUIRES_VERIFICATION'
    | 'NO_MATCHING_VULNERABILITIES_FOUND'
    | 'INSUFFICIENT_IDENTIFICATION'
    | 'FILE_ANALYSIS_INCONCLUSIVE'
    | 'SUSPICIOUS_INDICATORS_FOUND';
  verdict_title: string;
  software: SoftwareIdentity;
  file_metadata?: FileMetadata | null;
  findings: SoftwareFinding[];
  total_findings: number;
  exact_matches_count: number;
  potential_matches_count: number;
  potential_impacts: string[];
  verified_fixed_version: string | null;
  recommendation: AssessmentRecommendation;
  sources_checked: string[];
  suspicious_indicators?: string[];
  limitations: string[];
  deterministic_summary?: string;
  generated_at: string;
  duration_ms?: number;
  ai?: {
    used: boolean;
    provider: string;
    model: string;
    executive_summary?: string;
    plain_english_impact?: string;
    recommended_action?: string;
    verification_steps?: string[];
    technical_notes?: string;
  };
}

export interface SoftwareAssessmentRequest {
  product_name?: string;
  package_name?: string;
  vendor?: string;
  version?: string;
  ecosystem?: string;
  source_url?: string;
  provider?: string;
}

export interface AssessmentChatResponse {
  answer: string;
  provider?: string;
  model?: string;
  citations?: string[];
}

export async function runSoftwareAssessment(
  params: SoftwareAssessmentRequest,
  file?: File
): Promise<SoftwareAssessmentResponse> {
  if (file) {
    const formData = new FormData();
    if (params.product_name) formData.append('product_name', params.product_name);
    if (params.vendor) formData.append('vendor', params.vendor);
    if (params.version) formData.append('version', params.version);
    if (params.ecosystem) formData.append('ecosystem', params.ecosystem);
    if (params.source_url) formData.append('source_url', params.source_url);
    if (params.provider) formData.append('provider', params.provider);
    formData.append('file', file);

    const resp = await fetch(`${BASE}/software-assessment`, {
      method: 'POST',
      body: formData,
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => null);
      throw new Error(err?.error?.message ?? 'Assessment request failed');
    }
    return resp.json();
  }

  return api<SoftwareAssessmentResponse>('/software-assessment', {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

export async function askAdvisorQuestion(
  assessmentId: string,
  question: string,
  evidence?: SoftwareAssessmentResponse,
  provider?: string
): Promise<AssessmentChatResponse> {
  return api<AssessmentChatResponse>('/software-assessment/chat', {
    method: 'POST',
    body: JSON.stringify({
      assessment_id: assessmentId,
      question,
      evidence,
      provider,
    }),
  });
}

export async function downloadAssessmentReport(
  assessment: SoftwareAssessmentResponse,
  format: 'json' | 'markdown' | 'html'
): Promise<void> {
  const resp = await fetch(`${BASE}/software-assessment/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      assessment_id: assessment.assessment_id,
      assessment,
      format,
    }),
  });

  if (!resp.ok) {
    throw new Error('Export download failed');
  }

  const blob = await resp.blob();
  const ext = format === 'markdown' ? 'md' : format;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const safeName = (assessment.software.product_name || 'software').replace(/[^a-zA-Z0-9-_]/g, '_');
  a.download = `threatlens-assessment-${safeName}.${ext}`;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

