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
  CheckCircle2,
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
  Lock,
  Globe,
  FileCheck,
  AlertCircle,
  Hash,
} from 'lucide-react';
import {
  Card,
  Badge,
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
  { id: 'pypi', label: 'PyPI (Python)' },
  { id: 'npm', label: 'npm (JavaScript / Node.js)' },
  { id: 'maven', label: 'Maven (Java)' },
  { id: 'go', label: 'Go Modules' },
  { id: 'crates.io', label: 'Crates.io (Rust)' },
  { id: 'nuget', label: 'NuGet (.NET)' },
  { id: 'packagist', label: 'Packagist (PHP)' },
  { id: 'rubygems', label: 'RubyGems (Ruby)' },
];

const PRESET_EXAMPLES = [
  {
    label: 'OpenSSL 3.0.0',
    mode: 'software',
    name: 'OpenSSL',
    vendor: 'OpenSSL Project',
    version: '3.0.0',
    ecosystem: 'generic',
  },
  {
    label: 'cryptography 41.0.0 (PyPI)',
    mode: 'package',
    name: 'cryptography',
    vendor: 'PyCA',
    version: '41.0.0',
    ecosystem: 'pypi',
  },
  {
    label: 'log4j-core 2.14.1 (Maven)',
    mode: 'package',
    name: 'org.apache.logging.log4j:log4j-core',
    vendor: 'Apache',
    version: '2.14.1',
    ecosystem: 'maven',
  },
  {
    label: 'express 4.17.1 (npm)',
    mode: 'package',
    name: 'express',
    vendor: 'OpenJS Foundation',
    version: '4.17.1',
    ecosystem: 'npm',
  },
];

export default function Advisor() {
  // Input state
  const [activeTab, setActiveTab] = useState<'software' | 'package' | 'file'>('software');
  const [productName, setProductName] = useState('');
  const [vendor, setVendor] = useState('');
  const [version, setVersion] = useState('');
  const [ecosystem, setEcosystem] = useState('generic');
  const [sourceUrl, setSourceUrl] = useState('');
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
          text: `Error retrieving grounded answer: ${err.message}`,
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
  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'KNOWN_VULNERABILITIES_FOUND':
        return {
          bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
          icon: <ShieldAlert className="w-5 h-5 text-rose-400" />,
          title: 'Known Vulnerabilities Confirmed',
        };
      case 'POTENTIAL_MATCH_REQUIRES_VERIFICATION':
        return {
          bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
          title: 'Potential Match (Requires Build Verification)',
        };
      case 'NO_MATCHING_VULNERABILITIES_FOUND':
        return {
          bg: 'bg-sky-500/10 border-sky-500/30 text-sky-400',
          icon: <ShieldCheck className="w-5 h-5 text-sky-400" />,
          title: 'No Matching Vulnerabilities in Queried Databases',
        };
      case 'SUSPICIOUS_INDICATORS_FOUND':
        return {
          bg: 'bg-purple-500/10 border-purple-500/30 text-purple-400',
          icon: <AlertCircle className="w-5 h-5 text-purple-400" />,
          title: 'Suspicious Security Indicators Detected',
        };
      default:
        return {
          bg: 'bg-slate-500/10 border-slate-500/30 text-slate-400',
          icon: <Info className="w-5 h-5 text-slate-400" />,
          title: 'Inconclusive / Insufficient Details',
        };
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
    <div className="space-y-6">
      <PageHeading
        title="Software Safety Advisor"
        description="Evidence-based software vulnerability and risk assessment powered by Snowflake CVE dataset, OSV.dev, and DeepSeek/NVIDIA AI."
        eyebrow="Evidence-Linked Security"
      />

      {/* ── Input Controls Card ── */}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
          {/* Mode Switcher Tabs */}
          <div className="flex items-center gap-2 p-1 bg-slate-900 border border-slate-800 rounded-lg">
            <button
              type="button"
              onClick={() => {
                setActiveTab('software');
                setEcosystem('generic');
              }}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                activeTab === 'software'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              Software & Version (Mode A)
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab('package');
                if (ecosystem === 'generic') setEcosystem('pypi');
              }}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                activeTab === 'package'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              Package Ecosystem (Mode B)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('file')}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                activeTab === 'file'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Upload className="w-3.5 h-3.5" />
              URL & Safe File (Mode C)
            </button>
          </div>

          {/* Quick Presets */}
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Quick Presets:</span>
            {PRESET_EXAMPLES.map((ex, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleQuickPreset(ex)}
                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
              >
                {ex.label}
              </button>
            ))}
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleRunAssessment} className="mt-4 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Field 1: Software/Package Name */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                {activeTab === 'package' ? 'Package Identifier *' : 'Software / Application Name *'}
              </label>
              <input
                type="text"
                value={productName}
                onChange={e => setProductName(e.target.value)}
                placeholder={activeTab === 'package' ? 'e.g. cryptography, express, log4j-core' : 'e.g. OpenSSL, Apache HTTP Server'}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
              />
            </div>

            {/* Field 2: Version */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Exact Version {activeTab === 'software' && <span className="text-slate-500">(Recommended)</span>}
              </label>
              <input
                type="text"
                value={version}
                onChange={e => setVersion(e.target.value)}
                placeholder="e.g. 3.0.0, 41.0.0, 2.14.1"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
              />
            </div>

            {/* Field 3: Vendor / Publisher */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Vendor / Publisher <span className="text-slate-500">(Optional)</span>
              </label>
              <input
                type="text"
                value={vendor}
                onChange={e => setVendor(e.target.value)}
                placeholder="e.g. Apache, Microsoft, OpenSSL"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
              />
            </div>
          </div>

          {/* Mode-Specific Sub-Rows */}
          {activeTab === 'package' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-slate-800/60">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Package Ecosystem *
                </label>
                <select
                  value={ecosystem}
                  onChange={e => setEcosystem(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-sky-500 transition-colors"
                >
                  {ECOSYSTEMS.filter(e => e.id !== 'generic').map(eco => (
                    <option key={eco.id} value={eco.id}>
                      {eco.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Package Source URL <span className="text-slate-500">(Optional advisory or registry URL)</span>
                </label>
                <input
                  type="url"
                  value={sourceUrl}
                  onChange={e => setSourceUrl(e.target.value)}
                  placeholder="https://pypi.org/project/cryptography/"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
                />
              </div>
            </div>
          )}

          {activeTab === 'file' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-slate-800/60">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Software Download URL <span className="text-slate-500">(Safe Anti-SSRF Validated)</span>
                </label>
                <input
                  type="url"
                  value={sourceUrl}
                  onChange={e => setSourceUrl(e.target.value)}
                  placeholder="https://vendor.example/downloads/app.zip"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Private networks, loopbacks (127.0.0.1), and cloud metadata endpoints are strictly blocked.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Upload Package / Binary <span className="text-slate-500">(Max 15MB, Static Inspection Only)</span>
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="file"
                    onChange={e => setSelectedFile(e.target.files?.[0] || null)}
                    className="block w-full text-xs text-slate-400 file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700 cursor-pointer"
                  />
                  {selectedFile && (
                    <button
                      type="button"
                      onClick={() => setSelectedFile(null)}
                      className="text-xs text-rose-400 hover:text-rose-300 px-2"
                    >
                      Clear
                    </button>
                  )}
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Uploaded binaries are never executed. SHA-256 and metadata are inspected in an isolated process.
                </p>
              </div>
            </div>
          )}

          {/* AI Provider and Action Row */}
          <div className="flex flex-wrap items-center justify-between gap-4 pt-4 border-t border-slate-800">
            <div className="flex items-center gap-3">
              <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-sky-400" />
                AI Analysis Engine:
              </span>
              <select
                value={provider}
                onChange={e => setProvider(e.target.value)}
                className="px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500"
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
              className="flex items-center gap-2 px-5 py-2 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium text-sm rounded-lg shadow-sm transition-all"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Assessing Risk...
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  Assess Software Safety
                </>
              )}
            </button>
          </div>
        </form>
      </Card>

      {/* ── Loading State ── */}
      {loading && (
        <Card>
          <div className="py-12 text-center space-y-4">
            <Loading />
            <p className="text-sm font-medium text-slate-300">
              Querying Snowflake vulnerability database and authoritative sources...
            </p>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Cross-referencing package ranges, verifying fixed releases, inspecting static indicators, and grounding assessment evidence.
            </p>
          </div>
        </Card>
      )}

      {/* ── Assessment Results Dashboard ── */}
      {assessment && !loading && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Executive Verdict Banner */}
          {(() => {
            const vStyle = getVerdictBadge(assessment.verdict);
            return (
              <div className={`p-5 rounded-xl border ${vStyle.bg} flex flex-col md:flex-row items-start md:items-center justify-between gap-4`}>
                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800">
                    {vStyle.icon}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold uppercase tracking-wider opacity-80">
                        Executive Verdict
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded-full bg-slate-900/60 font-mono">
                        {assessment.assessment_id}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-100 mt-0.5">
                      {assessment.verdict_title}
                    </h3>
                    <p className="text-xs text-slate-300 mt-1 max-w-2xl">
                      {assessment.recommendation.explanation}
                    </p>
                  </div>
                </div>

                {/* Export / Copy Action Buttons */}
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={handleCopySummary}
                    className="p-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700/60 text-slate-300 hover:text-white transition-colors"
                    title="Copy Summary"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExport('json')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExport('markdown')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    Markdown
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExport('html')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
                  >
                    <Globe className="w-3.5 h-3.5" />
                    HTML
                  </button>
                </div>
              </div>
            );
          })()}

          {/* Metric Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card>
              <div className="text-xs font-medium text-slate-400">Total Vulnerabilities Found</div>
              <div className="text-2xl font-bold text-slate-100 mt-1">
                {assessment.total_findings}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                {assessment.exact_matches_count} confirmed exact matches
              </div>
            </Card>

            <Card>
              <div className="text-xs font-medium text-slate-400">Identified Software Version</div>
              <div className="text-xl font-bold text-slate-100 mt-1 truncate">
                {assessment.software.version || 'Unspecified'}
              </div>
              <div className="text-[11px] text-slate-500 mt-1 truncate">
                {assessment.software.product_name} ({assessment.software.ecosystem})
              </div>
            </Card>

            <Card>
              <div className="text-xs font-medium text-slate-400">Verified Fixed Release</div>
              <div className="text-xl font-bold text-emerald-400 mt-1 truncate">
                {assessment.verified_fixed_version ? `v${assessment.verified_fixed_version}` : 'No known fix'}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                {assessment.verified_fixed_version ? 'Upgrade path verified by advisory' : 'Check vendor for mitigations'}
              </div>
            </Card>

            <Card>
              <div className="text-xs font-medium text-slate-400">Recommended Action</div>
              <div className="text-sm font-bold text-sky-400 mt-1 truncate">
                {assessment.recommendation.action}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                Confidence: {assessment.software.confidence}
              </div>
            </Card>
          </div>

          {/* Potential Impacts Section */}
          {assessment.potential_impacts.length > 0 && (
            <Card>
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <h4 className="text-sm font-semibold text-slate-200">
                  Documented Potential Impacts
                </h4>
              </div>
              <div className="flex flex-wrap gap-2">
                {assessment.potential_impacts.map((impact, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-300 border border-amber-500/20"
                  >
                    {impact}
                  </span>
                ))}
              </div>
            </Card>
          )}

          {/* AI Grounded Summary Card */}
          {assessment.ai && (
            <Card>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-sky-400" />
                  <h4 className="text-sm font-semibold text-slate-100">
                    Evidence-Grounded AI Assessment
                  </h4>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    {assessment.ai.provider}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[10px]">
                    {assessment.ai.model}
                  </span>
                </div>
              </div>

              <div className="mt-4 space-y-4 text-sm text-slate-300 leading-relaxed">
                {assessment.ai.executive_summary && (
                  <div>
                    <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                      Executive Summary
                    </h5>
                    <p className="bg-slate-900/50 p-3 rounded-lg border border-slate-800/80">
                      {assessment.ai.executive_summary}
                    </p>
                  </div>
                )}

                {assessment.ai.plain_english_impact && (
                  <div>
                    <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                      Plain-English Impact Analysis
                    </h5>
                    <p className="bg-slate-900/50 p-3 rounded-lg border border-slate-800/80">
                      {assessment.ai.plain_english_impact}
                    </p>
                  </div>
                )}

                {assessment.ai.verification_steps && assessment.ai.verification_steps.length > 0 && (
                  <div>
                    <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                      Recommended Verification Steps
                    </h5>
                    <ul className="list-disc list-inside space-y-1 bg-slate-900/50 p-3 rounded-lg border border-slate-800/80">
                      {assessment.ai.verification_steps.map((step, idx) => (
                        <li key={idx} className="text-xs text-slate-300">
                          {step}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* Static File Inspection Metadata (if uploaded) */}
          {assessment.file_metadata && (
            <Card>
              <div className="flex items-center gap-2 mb-3">
                <FileCheck className="w-4 h-4 text-sky-400" />
                <h4 className="text-sm font-semibold text-slate-200">
                  Static File Inspection Metadata
                </h4>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-400">Filename:</span> {assessment.file_metadata.filename}
                </div>
                <div>
                  <span className="text-slate-400">Size:</span> {(assessment.file_metadata.size_bytes / 1024).toFixed(1)} KB
                </div>
                <div className="col-span-1 md:col-span-2 truncate">
                  <span className="text-slate-400">SHA-256:</span> {assessment.file_metadata.sha256}
                </div>
                <div>
                  <span className="text-slate-400">Format:</span> {assessment.file_metadata.detected_type}
                </div>
                <div>
                  <span className="text-slate-400">Execution Status:</span> Non-executed (Safe Static Only)
                </div>
              </div>
              {assessment.file_metadata.suspicious_flags.length > 0 && (
                <div className="mt-3 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-xs text-rose-300">
                  <span className="font-bold">Static Flags:</span> {assessment.file_metadata.suspicious_flags.join('; ')}
                </div>
              )}
            </Card>
          )}

          {/* Vulnerability Findings Table */}
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
              <div className="flex items-center gap-2">
                <Search className="w-4 h-4 text-slate-400" />
                <h4 className="text-sm font-semibold text-slate-100">
                  Vulnerability Findings ({assessment.total_findings})
                </h4>
              </div>
              <input
                type="text"
                value={findingsFilter}
                onChange={e => setFindingsFilter(e.target.value)}
                placeholder="Filter findings by CVE, severity, or description..."
                className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 w-72"
              />
            </div>

            {filteredFindings.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                {assessment.total_findings === 0
                  ? 'No matching vulnerability records found in checked sources.'
                  : 'No findings match the current filter term.'}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Identifier</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">CVSS</th>
                      <th className="py-2.5 px-3">Match Type</th>
                      <th className="py-2.5 px-3">Affected Range / Fix</th>
                      <th className="py-2.5 px-3">Summary</th>
                      <th className="py-2.5 px-3">Advisory</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredFindings.map((f, i) => (
                      <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-medium text-slate-200 whitespace-nowrap">
                          {f.id}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-300">
                          {f.cvss_score !== null ? f.cvss_score.toFixed(1) : '—'}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                              f.match_type === 'EXACT'
                                ? 'bg-rose-500/10 text-rose-300 border border-rose-500/30'
                                : f.match_type === 'RANGE_MATCH'
                                ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {f.match_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 text-[11px]">
                          <div>{f.range_description}</div>
                          {f.verified_fixed_version && (
                            <div className="text-emerald-400 font-medium">
                              Fix: v{f.verified_fixed_version}
                            </div>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 max-w-md truncate" title={f.details}>
                          {f.summary}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <a
                            href={f.source_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-sky-400 hover:text-sky-300 inline-flex items-center gap-1 font-medium"
                          >
                            Source
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* Sources Checked & Limitations Disclaimer */}
          <Card>
            <div className="flex items-center gap-2 mb-2">
              <Info className="w-4 h-4 text-slate-400" />
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Coverage, Sources & Assessment Limitations
              </h4>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-400 mt-2">
              <div>
                <span className="font-semibold text-slate-300">Sources Checked:</span>
                <ul className="list-disc list-inside mt-1 space-y-0.5">
                  {assessment.sources_checked.map((src, i) => (
                    <li key={i}>{src}</li>
                  ))}
                </ul>
              </div>
              <div>
                <span className="font-semibold text-slate-300">Important Disclaimers:</span>
                <ul className="list-disc list-inside mt-1 space-y-0.5">
                  {assessment.limitations.map((lim, i) => (
                    <li key={i}>{lim}</li>
                  ))}
                </ul>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* ── Interactive AI Grounded Software Security Chat (Always Visible) ── */}
      <Card>
        <div className="flex flex-wrap items-center justify-between pb-3 border-b border-slate-800 gap-2">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-sky-400" />
            <h4 className="text-sm font-semibold text-slate-100">
              {assessment ? 'Ask AI About This Assessment' : 'AI Software Security Assistant & Chat'}
            </h4>
          </div>
          <span className="text-[11px] text-slate-400 font-mono bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
            {assessment
              ? `Context: ${assessment.software.product_name} (${assessment.total_findings} findings)`
              : `Provider: ${provider.toUpperCase()}`}
          </span>
        </div>

        {/* Quick Suggested Questions */}
        <div className="flex flex-wrap gap-2 mt-3">
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
              className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-sky-500/50 text-[11px] text-slate-300 hover:text-white transition-colors"
            >
              {q}
            </button>
          ))}
        </div>

        {/* Chat Messages Thread */}
        <div className="mt-4 space-y-3 max-h-80 overflow-y-auto pr-2">
          {chatMessages.length === 0 ? (
            <div className="py-6 text-center text-xs text-slate-500">
              {assessment
                ? 'Have questions about this software assessment? Type below or pick a suggested question above.'
                : 'Ask questions about any software package, CVE, or security practice, or run an assessment above to ground the analysis.'}
            </div>
          ) : (
            chatMessages.map((msg, i) => (
              <div
                key={i}
                className={`flex flex-col ${
                  msg.sender === 'user' ? 'items-end' : 'items-start'
                }`}
              >
                <div
                  className={`max-w-2xl px-3.5 py-2.5 rounded-xl text-xs leading-relaxed ${
                    msg.sender === 'user'
                      ? 'bg-sky-600 text-white'
                      : 'bg-slate-900 border border-slate-800 text-slate-200'
                  }`}
                >
                  {msg.text}
                  {msg.citations && msg.citations.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-slate-800 text-[10px] text-sky-400 flex items-center gap-1">
                      <span>Citations:</span>
                      {msg.citations.map((c, ci) => (
                        <span key={ci} className="font-mono bg-slate-800 px-1 py-0.5 rounded">
                          {c}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
          {chatLoading && (
            <div className="flex items-center gap-2 text-xs text-slate-400 italic">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-sky-400" />
              Generating grounded answer...
            </div>
          )}
        </div>

        {/* Chat Input */}
        <div className="mt-4 flex items-center gap-2">
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
            className="flex-1 px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
          />
          <button
            type="button"
            onClick={() => handleAskQuestion()}
            disabled={chatLoading || !chatQuestion.trim()}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium text-xs rounded-lg transition-colors flex items-center gap-1.5"
          >
            <Send className="w-3.5 h-3.5" />
            Ask
          </button>
        </div>
      </Card>
    </div>
  );
}
