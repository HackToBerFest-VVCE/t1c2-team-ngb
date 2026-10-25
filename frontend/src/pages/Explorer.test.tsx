/**
 * ThreatLens AI — Explorer Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import Explorer from './Explorer';
import { api, downloadExport } from '../api';

vi.mock('../api', () => ({
  api: vi.fn((url: string) => {
    return Promise.resolve({
      items: [
        {
          cve_id: 'CVE-2026-9999',
          description: 'Remote code execution in core service daemon.',
          published: '2026-03-01T00:00:00Z',
          last_modified: '2026-03-02T00:00:00Z',
          cvss_score: 9.8,
          severity: 'CRITICAL',
          cwe: 'CWE-78',
          affected_products: 'Enterprise Server 2026',
          source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-9999',
          priority_score: 94.5,
        },
      ],
      page: 1,
      per_page: 15,
      total: 1,
      pages: 1,
    });
  }),
  downloadExport: vi.fn().mockResolvedValue(undefined),
}));

describe('Vulnerability Explorer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders search bar and table records', async () => {
    render(<Explorer />);

    expect(screen.getByText('Vulnerability Explorer')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Search CVE ID/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('CVE-2026-9999')).toBeInTheDocument();
      expect(screen.getByText('CWE-78')).toBeInTheDocument();
    });
  });

  it('opens detail modal when row is clicked', async () => {
    render(<Explorer />);

    await waitFor(() => {
      expect(screen.getByText('CVE-2026-9999')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('CVE-2026-9999'));

    await waitFor(() => {
      expect(screen.getByText('SOURCE RECORD INSPECTION')).toBeInTheDocument();
      expect(screen.getByText('Enterprise Server 2026')).toBeInTheDocument();
    });
  });

  it('sends date, score, and CWE filters to the API and preserves them in exports', async () => {
    render(<Explorer />);
    await screen.findByText('CVE-2026-9999');

    fireEvent.change(screen.getByLabelText('Published from'), { target: { value: '2026-01-01' } });
    fireEvent.change(screen.getByLabelText('CVSS minimum'), { target: { value: '7.5' } });
    fireEvent.change(screen.getByLabelText('CWE'), { target: { value: 'CWE-78' } });

    await waitFor(() => {
      expect(api).toHaveBeenCalledWith(expect.stringContaining('from=2026-01-01'));
      expect(api).toHaveBeenCalledWith(expect.stringContaining('min_score=7.5'));
      expect(api).toHaveBeenCalledWith(expect.stringContaining('cwe=CWE-78'));
    });

    fireEvent.click(screen.getByRole('button', { name: 'Export as CSV' }));
    await waitFor(() => {
      expect(downloadExport).toHaveBeenCalledWith('csv', expect.objectContaining({
        from: '2026-01-01', min_score: '7.5', cwe: 'CWE-78',
      }));
    });
  });
});
