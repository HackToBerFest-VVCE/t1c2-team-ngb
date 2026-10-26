/**
 * ThreatLens AI — Analysis Pages Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { api } from '../api';
import { Trends, Risk, ML, DataExplorer, Reports, Settings } from './Analysis';

// Mock Recharts
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: any) => <div>{children}</div>,
  BarChart: ({ children }: any) => <div>{children}</div>,
  Bar: () => null,
  CartesianGrid: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  Legend: () => null,
}));

// Mock API client
vi.mock('../api', () => ({
  api: vi.fn((path: string) => {
    if (path.startsWith('/trends')) {
      return Promise.resolve({
        days: Number(new URLSearchParams(path.split('?')[1]).get('days')),
        count: 50,
        from: '2026-01-01T00:00:00Z',
        to: '2026-10-23T00:00:00Z',
        bucket: 'month',
        limitations: 'Limited to sample data',
        items: [{ month: '2026-01', CRITICAL: 10, HIGH: 20, MEDIUM: 15, LOW: 5, UNKNOWN: 0 }],
      });
    }
    if (path.startsWith('/risk-analysis')) {
      return Promise.resolve({
        method: {
          name: 'NVD CVSS Base Score',
          source: 'NVD record',
          scale: '0.0–10.0',
          ranking: 'Highest score first',
          missing: 'No score is inferred',
          warning: 'CVSS describes severity, not risk',
        },
        items: [
          {
            cve_id: 'CVE-2026-7777',
            severity: 'CRITICAL',
            cvss_score: 9.9,
            priority_score: 95.2,
            published: '2026-02-01T00:00:00Z',
            description: 'Critical memory corruption',
          },
        ],
      });
    }
    if (path === '/ml/clusters') {
      return Promise.resolve({
        available: true,
        clusters: [
          {
            id: 0,
            count: 25,
            terms: ['buffer', 'overflow', 'execution'],
            representatives: [{ cve_id: 'CVE-2026-1111', description: 'Sample' }],
          },
        ],
        evaluation: {
          method: 'K-Means (k=4)',
          silhouette: 0.42,
          silhouette_note: 'Fair semantic separation',
          baseline: 'Random',
          baseline_score: 0.05,
          anomaly_method: 'Isolation Forest',
          limitations: 'Unsupervised signal only',
        },
      });
    }
    if (path === '/ml/anomalies') {
      return Promise.resolve({
        available: true,
        items: [
          {
            cve_id: 'CVE-2026-8888',
            severity: 'HIGH',
            cvss_score: 8.8,
            anomaly_score: -0.215,
            cluster: 0,
            description: 'Rare weakness combination',
          },
        ],
        evaluation: {
          method: 'Isolation Forest',
          anomaly_method: 'Isolation Forest',
          limitations: 'Statistical outlier only',
        },
      });
    }
    if (path === '/data-quality') {
      return Promise.resolve({
        source: {
          mode: 'DEMO',
          connected: true,
          dataset: 'Curated NVD Corpus',
          provider: 'NVD API 2.0',
          updated_at: '2026-03-01T00:00:00Z',
          note: 'Sample snapshot',
        },
        record_count: 100,
        fields: [
          { name: 'CVE_ID', type: 'VARCHAR', missing: 0, missing_percent: 0 },
          { name: 'DESCRIPTION', type: 'TEXT', missing: 2, missing_percent: 2 },
        ],
        last_publication: '2026-03-01T00:00:00Z',
        ingestion: 'Standard ingestion pipeline',
      });
    }
    if (path === '/reports/summary') {
      return Promise.resolve({
        generated_at: '2026-03-01T12:00:00Z',
        source: { dataset: 'Curated NVD Corpus', mode: 'DEMO' },
        metrics: {
          total: 100,
          critical: 20,
          high: 40,
          new_30d: 15,
          analysis_scope: 'All records',
        },
        prioritized: [
          { cve_id: 'CVE-2026-7777', severity: 'CRITICAL', cvss_score: 9.9, priority_score: 95.2 },
        ],
        method: '0.8 * CVSS + 0.2 * Recency',
        limitations: 'Unsupervised and heuristic',
      });
    }
    if (path === '/health') {
      return Promise.resolve({
        status: 'ok',
        version: '0.1.0',
        source: { mode: 'DEMO', connected: true },
      });
    }
    return Promise.resolve({});
  }),
  downloadExport: vi.fn(),
}));

describe('Analysis Pages', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders Trends with Recharts bar chart data', async () => {
    render(<Trends />);
    expect(screen.getByText('Threat Trends')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('TOTAL DISCLOSURES')).toBeInTheDocument();
      expect(screen.getByText('50')).toBeInTheDocument();
    });
  });

  it('reloads and labels the selected trend horizon', async () => {
    render(<Trends />);
    const horizon = screen.getByRole('combobox');
    fireEvent.change(horizon, { target: { value: '90' } });
    await waitFor(() => {
      expect(screen.getByText('Monthly publication cadence (90-day view)')).toBeInTheDocument();
      expect(api).toHaveBeenCalledWith('/trends?days=90');
    });
  });

  it('renders CVSS analysis with the source severity and score', async () => {
    render(<Risk />);
    expect(screen.getByText('CVSS Analysis')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('CVE-2026-7777')).toBeInTheDocument();
      expect(screen.getByText('CRITICAL')).toBeInTheDocument();
      expect(screen.getAllByText('9.9', { exact: false }).length).toBeGreaterThan(0);
    });
  });

  it('renders ML Insights clusters and anomalies', async () => {
    render(<ML />);
    expect(screen.getByText('ML Insights')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('Topic Pattern 01')).toBeInTheDocument();
      expect(screen.getByText('CVE-2026-8888')).toBeInTheDocument();
    });
  });

  it('renders DataExplorer schema completeness', async () => {
    render(<DataExplorer source={{ mode: 'DEMO', connected: true, dataset: 'NVD', provider: 'NIST', updated_at: null, record_count: 100, note: '' }} />);
    expect(screen.getByText('Data Explorer')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('CANONICAL SCHEMA FIELDS')).toBeInTheDocument();
      expect(screen.getByText('CVE_ID')).toBeInTheDocument();
    });
    const completenessMarker = await screen.findByRole('progressbar', {
      name: 'CVE_ID data completeness',
    });
    expect(completenessMarker).toHaveAttribute('aria-valuenow', '100');
    expect(completenessMarker).toHaveStyle({ width: '100%' });
  });

  it('renders Reports briefing and download buttons', async () => {
    render(<Reports />);
    expect(screen.getByText('Reports & Briefings')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('Executive Briefing Contents')).toBeInTheDocument();
      expect(screen.getByText(/Download Executive Report/i)).toBeInTheDocument();
    });
  });

  it('renders Settings configuration view', async () => {
    render(<Settings source={{ mode: 'DEMO', connected: true, dataset: 'NVD', provider: 'NIST', updated_at: null, record_count: 100, note: '' }} />);
    expect(screen.getByText('Settings')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('Operational Mode')).toBeInTheDocument();
    });
  });
});
