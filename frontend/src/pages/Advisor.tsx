/**
 * ThreatLens AI — Software Safety Advisor Page
 *
 * Evidence-based software vulnerability risk assessment supporting:
 * - Mode A: Software Name & Version
 * - Mode B: Open Source Package Ecosystem (PyPI, npm, Maven, Go, Crates.io, NuGet)
 * - Mode C: URL & Safe Static File Inspection (Anti-SSRF & SHA-256)
 * - AI Provider Selection: NVIDIA NIM, DeepSeek (NVIDIA NIM), Cortex, Deterministic
 * - Interactive context-grounded follow-up chat
 * - Report export (JSON, Markdown, HTML)
 */

import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  ExternalLink,
  Download,
  Copy,
  Send,
  Sparkles,
  FileText,
  Search,
  Upload,
  Layers,
  Cpu,
  RefreshCw,
  Terminal,
  Globe,
  FileCheck,
  AlertCircle,
  Package,
  ArrowRight,
  Bot,
  User,
  Zap,
} from 'lucide-react';
import {
  Card,
  SeverityBadge,
  PageHeading,
  Loading,
  showToast,
} from '../components/Shell';
import {
  runSoftwareAssessment,
  askAdvisorQuestion,
  downloadAssessmentReport,
  SoftwareAssessmentResponse,
  SoftwareAssessmentRequest,
} from '../api';

const ECOSYSTEMS = [
  { id: 'generic', label: 'Generic Software / OS Binary' },
  { id: 'pypi', label: 'PyPI (Python Ecosystem)' },
  { id: 'npm', label: 'npm (JavaScript / Node.js)' },
  { id: 'maven', label: 'Maven (Java / JVM Ecosystem)' },
  { id: 'go', label: 'Go Modules (Golang)' },
  { id: 'crates.io', label: 'Crates.io (Rust Ecosystem)' },
  { id: 'nuget', label: 'NuGet (.NET Ecosystem)' },
  { id: 'packagist', label: 'Packagist (PHP Ecosystem)' },
  { id: 'rubygems', label: 'RubyGems (Ruby Ecosystem)' },
];

const PRESET_EXAMPLES = [
  {
    label: 'OpenSSL 3.0.0',
    mode: 'software',
    name: 'OpenSSL',
    vendor: 'OpenSSL Project',
    version: '3.0.0',
    ecosystem: 'generic',
    tag: 'C/C++',
  },
  {
    label: 'cryptography 41.0.0 (PyPI)',
    mode: 'package',
    name: 'cryptography',
    vendor: 'PyCA',
    version: '41.0.0',
    ecosystem: 'pypi',
    tag: 'Python',
  },
  {
    label: 'log4j-core 2.14.1 (Maven)',
    mode: 'package',
    name: 'org.apache.logging.log4j:log4j-core',
    vendor: 'Apache',
    version: '2.14.1',
    ecosystem: 'maven',
    tag: 'Java',
  },
  {
    label: 'express 4.17.1 (npm)',
    mode: 'package',
    name: 'express',
    vendor: 'OpenJS Foundation',
    version: '4.17.1',
    ecosystem: 'npm',
    tag: 'Node.js',
  },
];

function renderMarkdown(text: string) {
  const lines = text.split('\n');
  const elements: React.ReactNode[] = [];
  let inList = false;
  let listItems: React.ReactNode[] = [];
  let listKey = 0;

  const flushList = () => {
    if (inList && listItems.length > 0) {
      elements.push(<ul key={`ul-${listKey++}`} style={{ margin: '6px 0 8px 18px', padding: 0 }}>{listItems}</ul>);
      listItems = [];
      inList = false;
    }
  };

  const parseInline = (line: string): React.ReactNode[] => {
    const parts = line.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
    return parts.map((part, idx) => {
      if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
        return <code key={idx} style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 5px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#92abff' }}>{part.slice(1, -1)}</code>;
      }
      if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
        return <strong key={idx} style={{ color: '#fff' }}>{part.slice(2, -2)}</strong>;
      }
      return part;
    });
  };

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed) {
      flushList();
      return;
    }

    if (trimmed.startsWith('### ') || trimmed.startsWith('#### ') || trimmed.startsWith('## ')) {
      flushList();
      const title = trimmed.replace(/^#+\s*/, '');
      elements.push(<h4 key={`h-${idx}`} style={{ margin: '12px 0 6px 0', fontSize: '13px', fontWeight: 700, color: '#f8fafc' }}>{parseInline(title)}</h4>);
      return;
    }

    if (trimmed.startsWith('• ') || trimmed.startsWith('- ') || trimmed.startsWith('* ') || /^\d+\.\s/.test(trimmed)) {
      inList = true;
      const content = trimmed.replace(/^[•\-*]\s+|\d+\.\s+/, '');
      listItems.push(<li key={`li-${idx}`} style={{ margin: '4px 0', lineHeight: 1.5 }}>{parseInline(content)}</li>);
      return;
    }

    flushList();
    elements.push(<p key={`p-${idx}`} style={{ margin: '6px 0', lineHeight: 1.6 }}>{parseInline(trimmed)}</p>);
  });

  flushList();
  return elements;
}

export default function Advisor() {
  // Input state
  const [activeTab, setActiveTab] = useState<'software' | 'package' | 'file'>('package');
  const [productName, setProductName] = useState('cryptography');
  const [vendor, setVendor] = useState('PyCA');
  const [version, setVersion] = useState('41.0.0');
  const [ecosystem, setEcosystem] = useState('pypi');
  const [sourceUrl, setSourceUrl] = useState('https://pypi.org/project/cryptography/');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [provider, setProvider] = useState('nvidia');

  // Execution state
  const [loading, setLoading] = useState(false);
  const [assessment, setAssessment] = useState<SoftwareAssessmentResponse | null>(null);
  const [findingsFilter, setFindingsFilter] = useState('');

  // Follow-up chat state
  const [chatQuestion, setChatQuestion] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [chatMessages, setChatMessages] = useState<Array<{ sender: 'user' | 'ai'; text: string; citations?: string[] }>>([]);

  const handleQuickPreset = (preset: typeof PRESET_EXAMPLES[0]) => {
    setProductName(preset.name);
    setVendor(preset.vendor);
    setVersion(preset.version);
    setEcosystem(preset.ecosystem);
    if (preset.mode === 'package') {
      setActiveTab('package');
    } else {
      setActiveTab('software');
    }
  };

  const handleRunAssessment = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!productName.trim() && !selectedFile && !sourceUrl.trim()) {
      showToast('Please enter a software name, package identifier, URL, or upload a file.', 'error');
      return;
    }

    setLoading(true);
    setAssessment(null);
    setChatMessages([]);

    try {
      const payload: SoftwareAssessmentRequest = {
        product_name: productName.trim(),
        vendor: vendor.trim(),
        version: version.trim(),
        ecosystem: activeTab === 'package' ? ecosystem : 'generic',
        source_url: sourceUrl.trim(),
        provider,
      };

      const result = await runSoftwareAssessment(payload, selectedFile || undefined);
      setAssessment(result);
      showToast(`Assessment complete for ${result.software.product_name}`, 'success');
    } catch (err: any) {
      showToast(err.message || 'Failed to complete vulnerability assessment', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleAskQuestion = async (questionText?: string) => {
    const q = (questionText || chatQuestion).trim();
    if (!q) return;

    setChatMessages(prev => [...prev, { sender: 'user', text: q }]);
    setChatQuestion('');
    setChatLoading(true);

    try {
      const resp = await askAdvisorQuestion(
        assessment ? assessment.assessment_id : '',
        q,
        assessment || undefined,
        provider
      );
      setChatMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: resp.answer,
          citations: resp.citations,
        },
      ]);
    } catch (err: any) {
      setChatMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: `⚠️ **Security Assistant Notice:** ${err.message || 'Unable to complete request'}. Please try asking your question again or specify a software name.`,
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleExport = async (format: 'json' | 'markdown' | 'html') => {
    if (!assessment) return;
    try {
      await downloadAssessmentReport(assessment, format);
      showToast(`Exported ${format.toUpperCase()} report successfully`, 'success');
    } catch (err: any) {
      showToast(`Failed to export report: ${err.message}`, 'error');
    }
  };

  const handleCopySummary = () => {
    if (!assessment) return;
    const text = `ThreatLens AI Software Safety Assessment
Product: ${assessment.software.product_name} v${assessment.software.version || 'unspecified'}
Verdict: ${assessment.verdict} (${assessment.verdict_title})
Total Findings: ${assessment.total_findings} (Exact: ${assessment.exact_matches_count})
Recommended Action: ${assessment.recommendation.action}
Recommendation: ${assessment.recommendation.explanation}
Verified Fixed Version: ${assessment.verified_fixed_version || 'None specified'}`;
    navigator.clipboard.writeText(text);
    showToast('Assessment summary copied to clipboard', 'success');
  };

  // Verdict style mapper
  const getVerdictStyleClass = (verdict: string) => {
    switch (verdict) {
      case 'KNOWN_VULNERABILITIES_FOUND':
        return 'known-vulns';
      case 'POTENTIAL_MATCH_REQUIRES_VERIFICATION':
        return 'potential';
      case 'NO_MATCHING_VULNERABILITIES_FOUND':
        return 'no-match';
      case 'SUSPICIOUS_INDICATORS_FOUND':
        return 'suspicious';
      default:
        return 'potential';
    }
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict) {
      case 'KNOWN_VULNERABILITIES_FOUND':
        return <ShieldAlert size={28} color="#f27885" />;
      case 'POTENTIAL_MATCH_REQUIRES_VERIFICATION':
        return <AlertTriangle size={28} color="#f5aa64" />;
      case 'NO_MATCHING_VULNERABILITIES_FOUND':
        return <ShieldCheck size={28} color="#5cc8e4" />;
      case 'SUSPICIOUS_INDICATORS_FOUND':
        return <AlertCircle size={28} color="#a18aff" />;
      default:
        return <Info size={28} color="#8491a5" />;
    }
  };

  const filteredFindings = (assessment?.findings || []).filter(f => {
    if (!findingsFilter.trim()) return true;
    const term = findingsFilter.toLowerCase();
    return (
      f.id.toLowerCase().includes(term) ||
      f.summary.toLowerCase().includes(term) ||
      f.severity.toLowerCase().includes(term) ||
      (f.cwe && f.cwe.toLowerCase().includes(term))
    );
  });

  return (
    <div className="advisor-container">
      {/* ── Page Header ── */}
      <PageHeading
        title="Software Safety Advisor"
        description="Evidence-based software vulnerability and risk assessment powered by Snowflake CVE dataset, OSV.dev, and DeepSeek/NVIDIA AI."
        eyebrow="EVIDENCE-LINKED SECURITY"
      />

      {/* ── Main Assessment Form Card ── */}
      <div className="advisor-card">
        {/* Mode Switcher Tabs */}
        <div className="advisor-tabs-bar">
          <div className="advisor-tab-group">
            <button
              type="button"
              onClick={() => {
                setActiveTab('software');
                setEcosystem('generic');
              }}
              className={`advisor-tab-btn ${activeTab === 'software' ? 'active' : ''}`}
            >
              <Cpu size={16} />
              Software & Version (Mode A)
            </button>

            <button
              type="button"
              onClick={() => {
                setActiveTab('package');
                if (ecosystem === 'generic') setEcosystem('pypi');
              }}
              className={`advisor-tab-btn ${activeTab === 'package' ? 'active' : ''}`}
            >
              <Layers size={16} />
              Package Ecosystem (Mode B)
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('file')}
              className={`advisor-tab-btn ${activeTab === 'file' ? 'active' : ''}`}
            >
              <Upload size={16} />
              URL & Safe File (Mode C)
            </button>
          </div>

          <div className="advisor-pill-note">
            <Zap size={14} color="#f5aa64" />
            <span>Deterministic SemVer matching + Real-time CVE intelligence</span>
          </div>
        </div>

        {/* Quick Presets Bar */}
        <div className="advisor-presets-bar">
          <div className="advisor-preset-label">
            <Sparkles size={14} color="#6b8cff" />
            Quick Presets:
          </div>
          {PRESET_EXAMPLES.map((ex, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleQuickPreset(ex)}
              className="advisor-preset-chip"
            >
              <span>{ex.label}</span>
              <span className="advisor-preset-tag">{ex.tag}</span>
            </button>
          ))}
        </div>

        {/* Assessment Input Form */}
        <form onSubmit={handleRunAssessment}>
          <div className="advisor-form-grid">
            {/* Field 1: Software/Package Name */}
            <div className="advisor-field-group">
              <label className="advisor-label">
                {activeTab === 'package' ? 'Package Identifier *' : 'Software / Application Name *'}
              </label>
              <input
                type="text"
                value={productName}
                onChange={e => setProductName(e.target.value)}
                placeholder={activeTab === 'package' ? 'e.g. cryptography, express, log4j-core' : 'e.g. OpenSSL, Apache HTTP Server'}
                className="advisor-input"
              />
              <span className="advisor-hint">
                {activeTab === 'package' ? 'Official package registry name' : 'Application or library identifier'}
              </span>
            </div>

            {/* Field 2: Version */}
            <div className="advisor-field-group">
              <label className="advisor-label">
                <span>Exact Version</span>
                <small>(recommended)</small>
              </label>
              <input
                type="text"
                value={version}
                onChange={e => setVersion(e.target.value)}
                placeholder="e.g. 3.0.0, 41.0.0, 2.14.1"
                className="advisor-input"
              />
              <span className="advisor-hint">
                Required for accurate version range correlation
              </span>
            </div>

            {/* Field 3: Vendor / Publisher */}
            <div className="advisor-field-group">
              <label className="advisor-label">
                <span>Vendor / Publisher</span>
                <small>(optional)</small>
              </label>
              <input
                type="text"
                value={vendor}
                onChange={e => setVendor(e.target.value)}
                placeholder="e.g. Apache, Microsoft, PyCA"
                className="advisor-input"
              />
              <span className="advisor-hint">
                Filters vendor-specific advisories
              </span>
            </div>
          </div>

          {/* Mode-Specific Sub-Rows */}
          {activeTab === 'package' && (
            <div className="advisor-form-grid two-col">
              <div className="advisor-field-group">
                <label className="advisor-label">
                  Package Ecosystem *
                </label>
                <select
                  value={ecosystem}
                  onChange={e => setEcosystem(e.target.value)}
                  className="advisor-select"
                >
                  {ECOSYSTEMS.filter(e => e.id !== 'generic').map(eco => (
                    <option key={eco.id} value={eco.id}>
                      {eco.label}
                    </option>
                  ))}
                </select>
                <span className="advisor-hint">
                  Authoritative OSV.dev repository lookup target
                </span>
              </div>
              <div className="advisor-field-group">
                <label className="advisor-label">
                  <span>Package Source URL</span>
                  <small>(optional registry link)</small>
                </label>
                <input
                  type="url"
                  value={sourceUrl}
                  onChange={e => setSourceUrl(e.target.value)}
                  placeholder="https://pypi.org/project/cryptography/"
                  className="advisor-input"
                />
                <span className="advisor-hint">
                  Optional vendor verification reference
                </span>
              </div>
            </div>
          )}

          {activeTab === 'file' && (
            <div className="advisor-form-grid two-col">
              <div className="advisor-field-group">
                <label className="advisor-label">
                  <span>Software Download URL</span>
                  <small>(anti-ssrf protected)</small>
                </label>
                <input
                  type="url"
                  value={sourceUrl}
                  onChange={e => setSourceUrl(e.target.value)}
                  placeholder="https://vendor.example/downloads/app.zip"
                  className="advisor-input"
                />
                <span className="advisor-hint">
                  Private networks, loopbacks (127.0.0.1), and cloud metadata endpoints are strictly blocked.
                </span>
              </div>

              <div className="advisor-field-group">
                <label className="advisor-label">
                  <span>Upload Package / Binary</span>
                  <small>(max 15mb, static inspection only)</small>
                </label>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <input
                    type="file"
                    onChange={e => setSelectedFile(e.target.files?.[0] || null)}
                    className="advisor-input"
                    style={{ paddingTop: '8px' }}
                  />
                  {selectedFile && (
                    <button
                      type="button"
                      onClick={() => setSelectedFile(null)}
                      className="button-secondary"
                      style={{ color: '#f27885' }}
                    >
                      Clear
                    </button>
                  )}
                </div>
                <span className="advisor-hint">
                  Binaries are never executed. SHA-256 and package structures are inspected in an isolated process.
                </span>
              </div>
            </div>
          )}

          {/* Action & Engine Bar */}
          <div className="advisor-action-bar">
            <div className="advisor-engine-select-wrap">
              <span className="advisor-label" style={{ margin: 0, textTransform: 'none', fontSize: '12px' }}>
                <Sparkles size={15} color="#6b8cff" style={{ marginRight: '6px' }} />
                AI Analysis Engine:
              </span>
              <select
                value={provider}
                onChange={e => setProvider(e.target.value)}
                className="advisor-select"
                style={{ height: '42px', minWidth: '240px' }}
              >
                <option value="nvidia">NVIDIA NIM (Nemotron 3.5)</option>
                <option value="deepseek">DeepSeek R1 (via NVIDIA NIM)</option>
                <option value="cortex">Snowflake Cortex (Llama 3.1)</option>
                <option value="deterministic">Deterministic (No AI / Offline)</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="advisor-assess-btn"
            >
              {loading ? (
                <>
                  <RefreshCw size={17} className="animate-spin" />
                  Assessing Risk...
                </>
              ) : (
                <>
                  <Shield size={17} />
                  Assess Software Safety
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* ── Loading State ── */}
      {loading && (
        <div className="advisor-card" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <Loading />
          <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#e6eaf2', marginTop: '16px' }}>
            Querying Snowflake vulnerability dataset and authoritative registries...
          </h3>
          <p style={{ fontSize: '12px', color: '#8491a5', maxWidth: '540px', margin: '8px auto 0' }}>
            Cross-referencing package ranges, verifying fixed releases, inspecting static indicators, and grounding assessment evidence.
          </p>
        </div>
      )}

      {/* ── Assessment Results Dashboard ── */}
      {assessment && !loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Executive Verdict Banner */}
          <div className={`advisor-verdict-box ${getVerdictStyleClass(assessment.verdict)}`}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '16px' }}>
              <div style={{ padding: '8px', background: 'rgba(8, 11, 18, 0.6)', borderRadius: '12px' }}>
                {getVerdictIcon(assessment.verdict)}
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.6px', textTransform: 'uppercase' }}>
                    {assessment.verdict}
                  </span>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', opacity: 0.8 }}>
                    {assessment.assessment_id}
                  </span>
                </div>
                <h3 style={{ fontSize: '20px', fontWeight: 700, color: '#ffffff', margin: '8px 0 6px' }}>
                  {assessment.verdict_title}
                </h3>
                <p style={{ fontSize: '13px', color: '#e6eaf2', maxWidth: '800px', lineHeight: 1.6 }}>
                  {assessment.recommendation.explanation}
                </p>
              </div>
            </div>

            {/* Export & Copy Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={handleCopySummary}
                className="button-secondary"
                title="Copy Summary"
              >
                <Copy size={14} /> Copy
              </button>
              <button
                type="button"
                onClick={() => handleExport('json')}
                className="button-secondary"
              >
                <Download size={14} /> JSON
              </button>
              <button
                type="button"
                onClick={() => handleExport('markdown')}
                className="button-secondary"
              >
                <FileText size={14} /> Markdown
              </button>
              <button
                type="button"
                onClick={() => handleExport('html')}
                className="button-secondary"
              >
                <Globe size={14} /> HTML
              </button>
            </div>
          </div>

          {/* Metric Stats Row */}
          <div className="advisor-metrics-row">
            <div className="advisor-metric-card">
              <span className="advisor-metric-title">Total Vulnerabilities</span>
              <span className="advisor-metric-num">{assessment.total_findings}</span>
              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                {assessment.exact_matches_count} confirmed exact matches
              </span>
            </div>

            <div className="advisor-metric-card">
              <span className="advisor-metric-title">Evaluated Version</span>
              <span className="advisor-metric-num" style={{ fontSize: '22px' }}>
                {assessment.software.version || 'Unspecified'}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                {assessment.software.product_name} ({assessment.software.ecosystem})
              </span>
            </div>

            <div className="advisor-metric-card">
              <span className="advisor-metric-title">Verified Fixed Release</span>
              <span className="advisor-metric-num" style={{ fontSize: '22px', color: '#58cf9b' }}>
                {assessment.verified_fixed_version ? `v${assessment.verified_fixed_version}` : 'No known fix'}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                {assessment.verified_fixed_version ? 'Upgrade path verified by advisory' : 'Check vendor for mitigations'}
              </span>
            </div>

            <div className="advisor-metric-card">
              <span className="advisor-metric-title">Recommended Action</span>
              <span style={{ fontSize: '14px', fontWeight: 700, color: '#6b8cff' }}>
                {assessment.recommendation.action}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                Confidence: <b>{assessment.software.confidence}</b>
              </span>
            </div>
          </div>

          {/* Potential Impacts Section */}
          {assessment.potential_impacts.length > 0 && (
            <div className="advisor-card" style={{ padding: '22px 26px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                <AlertTriangle size={17} color="#f5aa64" />
                <h4 style={{ fontSize: '13px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.6px', color: '#e6eaf2' }}>
                  Documented Potential Impacts
                </h4>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {assessment.potential_impacts.map((impact, i) => (
                  <span
                    key={i}
                    style={{
                      padding: '6px 14px',
                      borderRadius: '20px',
                      fontSize: '12px',
                      fontWeight: 600,
                      background: 'rgba(245, 170, 100, 0.12)',
                      color: '#f5aa64',
                      border: '1px solid rgba(245, 170, 100, 0.28)',
                    }}
                  >
                    {impact}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* AI Grounded Summary Card */}
          {assessment.ai && (
            <div className="advisor-card">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '16px', borderBottom: '1px solid var(--border-subtle)', flexWrap: 'wrap', gap: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Sparkles size={18} color="#6b8cff" />
                  <h4 style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff' }}>
                    Evidence-Grounded AI Assessment
                  </h4>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ padding: '3px 10px', borderRadius: '6px', background: 'rgba(13, 18, 27, 0.9)', border: '1px solid var(--border-default)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                    {assessment.ai.provider}
                  </span>
                  <span style={{ padding: '3px 10px', borderRadius: '6px', background: 'rgba(13, 18, 27, 0.9)', border: '1px solid var(--border-default)', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)' }}>
                    {assessment.ai.model}
                  </span>
                </div>
              </div>

              <div style={{ marginTop: '20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {assessment.ai.executive_summary && (
                  <div>
                    <h5 className="advisor-label" style={{ marginBottom: '8px' }}>Executive Summary</h5>
                    <div style={{ background: 'rgba(10, 14, 22, 0.7)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)', lineHeight: 1.6, fontSize: '13px' }}>
                      {assessment.ai.executive_summary}
                    </div>
                  </div>
                )}

                {assessment.ai.plain_english_impact && (
                  <div>
                    <h5 className="advisor-label" style={{ marginBottom: '8px' }}>Plain-English Impact Analysis</h5>
                    <div style={{ background: 'rgba(10, 14, 22, 0.7)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)', lineHeight: 1.6, fontSize: '13px' }}>
                      {assessment.ai.plain_english_impact}
                    </div>
                  </div>
                )}

                {assessment.ai.verification_steps && assessment.ai.verification_steps.length > 0 && (
                  <div>
                    <h5 className="advisor-label" style={{ marginBottom: '8px' }}>Recommended Verification Steps</h5>
                    <ul style={{ background: 'rgba(10, 14, 22, 0.7)', padding: '16px 20px', borderRadius: '10px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px', listStyleType: 'disc', paddingLeft: '32px' }}>
                      {assessment.ai.verification_steps.map((step, idx) => (
                        <li key={idx} style={{ color: 'var(--text-primary)' }}>
                          {step}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Static File Inspection Metadata */}
          {assessment.file_metadata && (
            <div className="advisor-card" style={{ padding: '22px 26px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                <FileCheck size={18} color="#6b8cff" />
                <h4 style={{ fontSize: '13px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.6px', color: '#e6eaf2' }}>
                  Static File Inspection Metadata
                </h4>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', background: 'rgba(9, 13, 20, 0.8)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                <div><span style={{ color: 'var(--text-tertiary)' }}>Filename:</span> {assessment.file_metadata.filename}</div>
                <div><span style={{ color: 'var(--text-tertiary)' }}>Size:</span> {(assessment.file_metadata.size_bytes / 1024).toFixed(1)} KB</div>
                <div style={{ gridColumn: '1 / -1', overflow: 'hidden', textOverflow: 'ellipsis' }}><span style={{ color: 'var(--text-tertiary)' }}>SHA-256:</span> {assessment.file_metadata.sha256}</div>
                <div><span style={{ color: 'var(--text-tertiary)' }}>Format:</span> {assessment.file_metadata.detected_type}</div>
                <div><span style={{ color: 'var(--text-tertiary)' }}>Execution:</span> Non-executed (Safe Static Only)</div>
              </div>
              {assessment.file_metadata.suspicious_flags.length > 0 && (
                <div style={{ marginTop: '14px', padding: '12px 16px', background: 'rgba(242, 120, 133, 0.1)', border: '1px solid rgba(242, 120, 133, 0.3)', borderRadius: '10px', fontSize: '12px', color: '#f27885' }}>
                  <b>Static Warning Flags:</b> {assessment.file_metadata.suspicious_flags.join('; ')}
                </div>
              )}
            </div>
          )}

          {/* Vulnerability Findings Table */}
          <div className="advisor-card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Search size={17} color="var(--text-secondary)" />
                <h4 style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff' }}>
                  Vulnerability Findings ({assessment.total_findings})
                </h4>
              </div>
              <input
                type="text"
                value={findingsFilter}
                onChange={e => setFindingsFilter(e.target.value)}
                placeholder="Filter findings by CVE, severity, or description..."
                className="advisor-input"
                style={{ height: '38px', maxWidth: '320px', fontSize: '12px' }}
              />
            </div>

            {filteredFindings.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '36px', color: 'var(--text-tertiary)', fontSize: '13px' }}>
                {assessment.total_findings === 0
                  ? 'No matching vulnerability records found in checked sources.'
                  : 'No findings match the current filter term.'}
              </div>
            ) : (
              <div style={{ overflowX: 'auto', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '12px' }}>
                  <thead style={{ background: 'rgba(8, 12, 18, 0.9)', color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-default)' }}>
                    <tr>
                      <th style={{ padding: '12px 16px', fontWeight: 600 }}>Identifier</th>
                      <th style={{ padding: '12px 16px', fontWeight: 600 }}>Severity</th>
                      <th style={{ padding: '12px 16px', fontWeight: 600 }}>CVSS</th>
                      <th style={{ padding: '12px 16px', fontWeight: 600 }}>Match Type</th>
                      <th style={{ padding: '12px 16px', fontWeight: 600 }}>Affected Range / Fix</th>
                      <th style={{ padding: '12px 16px', fontWeight: 600 }}>Summary</th>
                      <th style={{ padding: '12px 16px', fontWeight: 600 }}>Advisory</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map((f, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)', background: i % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.015)' }}>
                        <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>
                          {f.id}
                        </td>
                        <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                          {f.cvss_score !== null ? f.cvss_score.toFixed(1) : '—'}
                        </td>
                        <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                          <span
                            style={{
                              padding: '3px 8px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 600,
                              background: f.match_type === 'EXACT' ? 'rgba(242, 120, 133, 0.15)' : f.match_type === 'RANGE_MATCH' ? 'rgba(245, 170, 100, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                              color: f.match_type === 'EXACT' ? '#f27885' : f.match_type === 'RANGE_MATCH' ? '#f5aa64' : 'var(--text-secondary)',
                              border: f.match_type === 'EXACT' ? '1px solid rgba(242, 120, 133, 0.3)' : f.match_type === 'RANGE_MATCH' ? '1px solid rgba(245, 170, 100, 0.3)' : '1px solid var(--border-subtle)',
                            }}
                          >
                            {f.match_type}
                          </span>
                        </td>
                        <td style={{ padding: '12px 16px', color: 'var(--text-primary)', fontSize: '11px' }}>
                          <div>{f.range_description}</div>
                          {f.verified_fixed_version && (
                            <div style={{ color: '#58cf9b', fontWeight: 600, marginTop: '2px' }}>
                              Fix: v{f.verified_fixed_version}
                            </div>
                          )}
                        </td>
                        <td style={{ padding: '12px 16px', color: 'var(--text-secondary)', maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={f.details}>
                          {f.summary}
                        </td>
                        <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                          <a
                            href={f.source_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ color: 'var(--accent-blue)', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}
                          >
                            Source
                            <ExternalLink size={12} />
                          </a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Sources Checked & Limitations Disclaimer */}
          <div className="advisor-card" style={{ padding: '20px 24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '10px' }}>
              <Info size={15} color="var(--text-secondary)" />
              <h4 style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.6px', color: 'var(--text-secondary)' }}>
                Coverage, Sources & Assessment Limitations
              </h4>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', fontSize: '12px', color: 'var(--text-secondary)' }}>
              <div>
                <b style={{ color: 'var(--text-primary)' }}>Sources Checked:</b>
                <ul style={{ listStyleType: 'disc', paddingLeft: '20px', marginTop: '6px' }}>
                  {assessment.sources_checked.map((src, i) => (
                    <li key={i}>{src}</li>
                  ))}
                </ul>
              </div>
              <div>
                <b style={{ color: 'var(--text-primary)' }}>Important Disclaimers:</b>
                <ul style={{ listStyleType: 'disc', paddingLeft: '20px', marginTop: '6px' }}>
                  {assessment.limitations.map((lim, i) => (
                    <li key={i}>{lim}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Interactive AI Grounded Software Security Chat (Always Visible & Sleek) ── */}
      <div className="advisor-chat-card">
        <div className="advisor-chat-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', background: 'rgba(107, 140, 255, 0.1)', borderRadius: '10px' }}>
              <Terminal size={18} color="#6b8cff" />
            </div>
            <div>
              <h4 style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff' }}>
                {assessment ? 'Ask AI About This Assessment' : 'AI Software Security Assistant & Chat'}
              </h4>
              <p style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                {assessment
                  ? `Context-grounded analysis for ${assessment.software.product_name} v${assessment.software.version}`
                  : `Ask any software safety or CVE question powered by ${provider.toUpperCase()}`}
              </p>
            </div>
          </div>

          <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', background: 'rgba(8, 11, 18, 0.7)', padding: '4px 12px', borderRadius: '8px', border: '1px solid var(--border-default)' }}>
            {assessment
              ? `Evidence: ${assessment.total_findings} findings loaded`
              : `Engine: ${provider.toUpperCase()}`}
          </span>
        </div>

        {/* Quick Suggested Questions */}
        <div className="advisor-chat-prompts">
          {(assessment
            ? [
                'Explain the highest severity vulnerability in simple English.',
                'Why is this specific version affected?',
                'Which fixed version is supported by the vendor advisory?',
                'What should our administrator verify before installation?',
              ]
            : [
                'What are the security risks of OpenSSL 3.0.0?',
                'How do I check if my package has known CVEs?',
                'What does CVSS score 9.8 mean?',
                'What should our team verify before installing a third-party package?',
              ]
          ).map((q, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleAskQuestion(q)}
              className="advisor-chat-prompt-pill"
            >
              <span>{q}</span>
              <ArrowRight size={12} color="var(--text-tertiary)" />
            </button>
          ))}
        </div>

        {/* Chat Messages Thread */}
        <div className="advisor-chat-thread">
          {chatMessages.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '36px 16px', color: 'var(--text-tertiary)', fontSize: '13px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
              <Bot size={28} color="var(--border-strong)" />
              <span>
                {assessment
                  ? 'Have questions about these vulnerabilities? Type below or pick a suggested question above.'
                  : 'Ask questions about any software package, CVE, or security practice, or run an assessment above to ground the analysis.'}
              </span>
            </div>
          ) : (
            chatMessages.map((msg, i) => (
              <div
                key={i}
                className={msg.sender === 'user' ? 'advisor-chat-bubble-user' : 'advisor-chat-bubble-ai'}
              >
                <div style={{ fontSize: '11px', fontWeight: 600, opacity: 0.7, marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                  {msg.sender === 'user' ? (
                    <>
                      <User size={12} /> You
                    </>
                  ) : (
                    <>
                      <Bot size={12} color="#6b8cff" /> Security Assistant
                    </>
                  )}
                </div>
                <div>{renderMarkdown(msg.text)}</div>
                {msg.citations && msg.citations.length > 0 && (
                  <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.1)', fontSize: '11px', color: 'var(--accent-blue)', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '6px' }}>
                    <span style={{ color: 'var(--text-tertiary)' }}>Citations:</span>
                    {msg.citations.map((c, ci) => (
                      <span key={ci} style={{ fontFamily: 'var(--font-mono)', background: 'rgba(8, 11, 18, 0.8)', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--border-default)' }}>
                        {c}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
          {chatLoading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-secondary)', fontStyle: 'italic', padding: '8px' }}>
              <RefreshCw size={14} className="animate-spin" color="var(--accent-blue)" />
              Generating grounded answer...
            </div>
          )}
        </div>

        {/* Chat Input */}
        <div className="advisor-chat-input-bar">
          <input
            type="text"
            value={chatQuestion}
            onChange={e => setChatQuestion(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleAskQuestion();
              }
            }}
            placeholder={
              assessment
                ? 'Ask a question about these vulnerabilities...'
                : 'Ask about any vulnerability, CVE, or package security risk...'
            }
            className="advisor-chat-input"
          />
          <button
            type="button"
            onClick={() => handleAskQuestion()}
            disabled={chatLoading || !chatQuestion.trim()}
            className="advisor-chat-send-btn"
          >
            <Send size={15} />
            Ask
          </button>
        </div>
      </div>
    </div>
  );
}
