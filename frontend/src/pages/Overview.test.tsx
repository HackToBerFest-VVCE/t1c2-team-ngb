/**
 * ThreatLens AI — Frontend Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Overview from './Overview';
import { SourceStatus } from '../api';

// Mock Recharts components for jsdom compatibility
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: any) => <div className="recharts-mock">{children}</div>,
  AreaChart: ({ children }: any) => <svg>{children}</svg>,
  Area: () => null,
  CartesianGrid: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  PieChart: ({ children }: any) => <div>{children}</div>,
  Pie: () => null,
  Cell: () => null,
  BarChart: ({ children }: any) => <div>{children}</div>,
  Bar: () => null,
  Legend: () => null,
}));

// Mock API client
vi.mock('../api', () => ({
  api: vi.fn((path: string) => {
    if (path === '/summary') {
      return Promise.resolve({
        metrics: {
          total: 12,
          critical: 2,
          high: 3,
          medium: 5,
          low: 2,
          new_30d: 1,
          avg_cvss: 7.2,
          severity: [
            { name: 'CRITICAL', value: 2 },
            { name: 'HIGH', value: 3 },
            { name: 'MEDIUM', value: 5 },
            { name: 'LOW', value: 2 },
          ],
          publication_trend: [
            { month: '2026-01', count: 4 },
            { month: '2026-02', count: 8 },
          ],
          top_cwe: [{ name: 'CWE-79', count: 4 }],
          top_products: [{ name: 'Apache HTTP Server', count: 3 }],
          analysis_scope: 'All sample records',
          review: {
            unknown_source_severity: 2,
            unknown_with_critical_cvss: 1,
            unknown_with_high_or_critical_cvss: 1,
            explicit_none_severity: 1,
            missing_cvss: 1,
            missing_severity_and_cvss: 1,
            severity_score_mismatch: 0,
            invalid_cvss: 0,
            needs_review: 2,
          },
        },
        recent: [{
          cve_id: 'CVE-2026-1001',
          description: 'Critical buffer overflow in network service.',
          published: '2026-02-15T00:00:00Z',
          cvss_score: 9.8,
          severity: 'CRITICAL',
          source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1001',
        }],
      });
    }
    if (path.startsWith('/ml/coverage')) {
      return Promise.resolve({ coverage: {
        total_active_records: 12,
        records_with_nonempty_descriptions: 10,
        eligible_records: 10,
        records_in_deterministic_sample: 10,
        records_assigned_to_kmeans: 10,
        records_scored_by_isolation_forest: 10,
        excluded_missing_or_empty_description: 2,
        eligible_records_outside_sample: 0,
        sample_records_below_minimum: 0,
        records_not_analyzed: 2,
        coverage_percent_of_active_records: 83.33,
        coverage_denominator: 'all active records',
        partition_note: 'coverage partition',
      } });
    }
    if (path.startsWith('/vulnerabilities')) {
      return Promise.resolve({
        total: 1,
        items: [
          {
            cve_id: 'CVE-2026-1002',
            record_id: 'record-1002',
            description: 'Unresolved source severity; critical score.',
            published: '2026-02-15T00:00:00Z',
            cvss_score: 9.8,
            severity: 'UNKNOWN',
            cvss_indicated_severity: 'CRITICAL',
            ml_analysis_status: 'NOT_ANALYZED_OUTSIDE_SAMPLE',
            review_priority: 'URGENT_REVIEW',
            review_reasons: ['Source severity is UNKNOWN or missing'],
            source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1002',
          },
        ],
      });
    }
    return Promise.resolve({});
  }),
}));

const mockSource: SourceStatus = {
  mode: 'DEMO',
  connected: false,
  dataset: 'NVD Sample Snapshot',
  provider: 'NVD API 2.0',
  updated_at: '2026-03-01T00:00:00Z',
  record_count: 12,
  note: 'Bundled NVD sample snapshot',
};

describe('Overview Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders overview header and source status banner', async () => {
    render(<Overview source={mockSource} onSelect={vi.fn()} />);

    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('THREAT LANDSCAPE')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('Demo Mode · Curated NVD Snapshot')).toBeInTheDocument();
    });
  });

  it('displays calculated metrics and counts accurately', async () => {
    render(<Overview source={mockSource} onSelect={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getAllByText('12')[0]).toBeInTheDocument(); // Total records
      expect(screen.getByText('Apache HTTP Server')).toBeInTheDocument(); // Top products
      expect(screen.getByText('All sample records')).toBeInTheDocument(); // Analysis scope
    }, { timeout: 3000 });
  });

  it('renders top CWE weaknesses', async () => {
    render(<Overview source={mockSource} onSelect={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText('CWE-79')).toBeInTheDocument();
    });
  });

  it('shows live risk coverage and unknown severity review evidence', async () => {
    render(<Overview source={mockSource} onSelect={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('Risk & Coverage Review')).toBeInTheDocument();
      expect(screen.getByText('83.33%')).toBeInTheDocument();
      expect(screen.getByText('CVE-2026-1002')).toBeInTheDocument();
      expect(screen.getByText('NOT_ANALYZED_OUTSIDE_SAMPLE')).toBeInTheDocument();
      expect(screen.getByText('CVSS-INDICATED BAND')).toBeInTheDocument();
    });
  });
});
