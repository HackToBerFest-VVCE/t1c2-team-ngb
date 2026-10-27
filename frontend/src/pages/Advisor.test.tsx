/**
 * ThreatLens AI — Software Safety Advisor Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import Advisor from './Advisor';
import { runSoftwareAssessment, askAdvisorQuestion, downloadAssessmentReport } from '../api';

vi.mock('../api', () => ({
  runSoftwareAssessment: vi.fn(),
  askAdvisorQuestion: vi.fn(),
  downloadAssessmentReport: vi.fn(),
  api: vi.fn(),
}));

const mockAssessmentResult = {
  assessment_id: 'TL-SA-123456',
  verdict: 'KNOWN_VULNERABILITIES_FOUND' as const,
  verdict_title: '2 Known Vulnerabilities Confirmed',
  software: {
    product_name: 'cryptography',
    vendor: 'PyCA',
    version: '41.0.0',
    ecosystem: 'pypi',
    confidence: 'HIGH' as const,
  },
  findings: [
    {
      id: 'GHSA-jm77-qphf-c4w8',
      source: 'OSV.dev',
      summary: 'Vulnerable OpenSSL bundled in cryptography wheels',
      details: 'Contains vulnerable bundled OpenSSL library allowing denial of service.',
      severity: 'HIGH',
      cvss_score: 7.5,
      match_type: 'RANGE_MATCH' as const,
      range_description: '>= 41.0.0, < 41.0.2',
      verified_fixed_version: '41.0.2',
      cwe: 'CWE-400',
      published: '2023-07-15T00:00:00Z',
      modified: '2023-07-20T00:00:00Z',
      source_url: 'https://osv.dev/vulnerability/GHSA-jm77-qphf-c4w8',
      advisories: ['https://example.com/advisory'],
    },
  ],
  total_findings: 1,
  exact_matches_count: 1,
  potential_matches_count: 0,
  potential_impacts: ['Denial of Service (DoS)', 'Remote Code Execution (RCE)'],
  verified_fixed_version: '41.0.2',
  recommendation: {
    action: 'UPGRADE_TO_VERSION_41.0.2',
    explanation: 'Version 41.0.0 is affected by known vulnerabilities. Upgrade to verified release 41.0.2.',
  },
  sources_checked: ['OSV.dev (PyPI)', 'ThreatLens Database'],
  limitations: ['Static inspection only'],
  ai: {
    used: true,
    provider: 'nvidia',
    model: 'nemotron-3.5',
    executive_summary: 'Upgrade cryptography to 41.0.2 immediately to remediate bundled vulnerability.',
    plain_english_impact: 'Attackers can cause denial of service or application crashes.',
    verification_steps: ['Check requirements.txt', 'Run pip install cryptography>=41.0.2'],
  },
  generated_at: '2026-10-27T12:00:00Z',
};

describe('Software Safety Advisor Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders mode tabs and assessment form', () => {
    render(<Advisor />);
    expect(screen.getByText('Software Safety Advisor')).toBeInTheDocument();
    expect(screen.getByText(/Software & Version \(Mode A\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Package Ecosystem \(Mode B\)/i)).toBeInTheDocument();
    expect(screen.getByText(/URL & Safe File \(Mode C\)/i)).toBeInTheDocument();
    expect(screen.getByText('Assess Software Safety')).toBeInTheDocument();
  });

  it('switches tabs and displays mode-specific inputs', () => {
    render(<Advisor />);

    // Switch to Package Ecosystem
    fireEvent.click(screen.getByText(/Package Ecosystem \(Mode B\)/i));
    expect(screen.getByText(/Package Ecosystem \*/i)).toBeInTheDocument();

    // Switch to URL & File
    fireEvent.click(screen.getByText(/URL & Safe File \(Mode C\)/i));
    expect(screen.getByText(/Software Download URL/i)).toBeInTheDocument();
    expect(screen.getByText(/Upload Package \/ Binary/i)).toBeInTheDocument();
  });

  it('populates fields using quick presets', () => {
    render(<Advisor />);

    const presetBtn = screen.getByText('cryptography 41.0.0 (PyPI)');
    fireEvent.click(presetBtn);

    const input = screen.getByDisplayValue('cryptography');
    expect(input).toBeInTheDocument();
    expect(screen.getByDisplayValue('41.0.0')).toBeInTheDocument();
  });

  it('executes assessment and renders results dashboard', async () => {
    vi.mocked(runSoftwareAssessment).mockResolvedValue(mockAssessmentResult);

    render(<Advisor />);
    const presetBtn = screen.getByText('cryptography 41.0.0 (PyPI)');
    fireEvent.click(presetBtn);

    const submitBtn = screen.getByText('Assess Software Safety');
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText('2 Known Vulnerabilities Confirmed')).toBeInTheDocument();
      expect(screen.getByText('UPGRADE_TO_VERSION_41.0.2')).toBeInTheDocument();
      expect(screen.getByText('v41.0.2')).toBeInTheDocument();
      expect(screen.getByText('GHSA-jm77-qphf-c4w8')).toBeInTheDocument();
      expect(screen.getByText(/Upgrade cryptography to 41.0.2 immediately/i)).toBeInTheDocument();
    });
  });

  it('supports interactive context-grounded AI follow-up chat', async () => {
    vi.mocked(runSoftwareAssessment).mockResolvedValue(mockAssessmentResult);
    vi.mocked(askAdvisorQuestion).mockResolvedValue({
      answer: 'Version 41.0.0 is affected because it bundles an unpatched OpenSSL version.',
      citations: ['GHSA-jm77-qphf-c4w8'],
    });

    render(<Advisor />);
    fireEvent.click(screen.getByText('cryptography 41.0.0 (PyPI)'));
    fireEvent.click(screen.getByText('Assess Software Safety'));

    await waitFor(() => {
      expect(screen.getByText('Ask AI About This Assessment')).toBeInTheDocument();
    });

    const questionBtn = screen.getByText('Why is this specific version affected?');
    fireEvent.click(questionBtn);

    await waitFor(() => {
      expect(screen.getByText(/bundles an unpatched OpenSSL version/i)).toBeInTheDocument();
      expect(screen.getAllByText('GHSA-jm77-qphf-c4w8').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('triggers report download on export button click', async () => {
    vi.mocked(runSoftwareAssessment).mockResolvedValue(mockAssessmentResult);
    vi.mocked(downloadAssessmentReport).mockResolvedValue(undefined);

    render(<Advisor />);
    fireEvent.click(screen.getByText('cryptography 41.0.0 (PyPI)'));
    fireEvent.click(screen.getByText('Assess Software Safety'));

    await waitFor(() => {
      expect(screen.getByText('JSON')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('JSON'));
    expect(downloadAssessmentReport).toHaveBeenCalledWith(mockAssessmentResult, 'json');
  });
});
