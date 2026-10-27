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
  Check,
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
          bg: 'bg-rose-500/10 border-rose-500/30 text-rose-300',
          badgeBg: 'bg-rose-500/20 text-rose-300 border border-rose-500/40',
          icon: <ShieldAlert className="w-6 h-6 text-rose-400" />,
          title: 'Known Vulnerabilities Confirmed',
        };
      case 'POTENTIAL_MATCH_REQUIRES_VERIFICATION':
        return {
          bg: 'bg-amber-500/10 border-amber-500/30 text-amber-300',
          badgeBg: 'bg-amber-500/20 text-amber-300 border border-amber-500/40',
          icon: <AlertTriangle className="w-6 h-6 text-amber-400" />,
          title: 'Potential Match (Requires Build Verification)',
        };
      case 'NO_MATCHING_VULNERABILITIES_FOUND':
        return {
          bg: 'bg-sky-500/10 border-sky-500/30 text-sky-300',
          badgeBg: 'bg-sky-500/20 text-sky-300 border border-sky-500/40',
          icon: <ShieldCheck className="w-6 h-6 text-sky-400" />,
          title: 'No Matching Vulnerabilities in Queried Databases',
        };
      case 'SUSPICIOUS_INDICATORS_FOUND':
        return {
          bg: 'bg-purple-500/10 border-purple-500/30 text-purple-300',
          badgeBg: 'bg-purple-500/20 text-purple-300 border border-purple-500/40',
          icon: <AlertCircle className="w-6 h-6 text-purple-400" />,
          title: 'Suspicious Security Indicators Detected',
        };
      default:
        return {
          bg: 'bg-slate-500/10 border-slate-500/30 text-slate-300',
          badgeBg: 'bg-slate-500/20 text-slate-300 border border-slate-500/40',
          icon: <Info className="w-6 h-6 text-slate-400" />,
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
    <div className="space-y-8 max-w-[1440px] mx-auto pb-16">
      {/* ── Page Header ── */}
      <PageHeading
        title="Software Safety Advisor"
        description="Evidence-based software vulnerability and risk assessment powered by Snowflake CVE dataset, OSV.dev, and DeepSeek/NVIDIA AI."
        eyebrow="Evidence-Linked Security"
      />

      {/* ── Main Assessment Card ── */}
      <div className="rounded-2xl border border-slate-800/80 bg-gradient-to-b from-slate-900/90 to-slate-950 p-6 md:p-8 shadow-xl shadow-black/40 backdrop-blur-md">
        {/* Mode Switcher Tabs */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div className="inline-flex p-1.5 bg-slate-950/80 border border-slate-800/90 rounded-xl shadow-inner gap-1.5">
            <button
              type="button"
              onClick={() => {
                setActiveTab('software');
                setEcosystem('generic');
              }}
              className={`flex items-center justify-center gap-2.5 px-4 py-2.5 text-xs font-semibold rounded-lg transition-all ${
                activeTab === 'software'
                  ? 'bg-gradient-to-r from-sky-600 to-blue-600 text-white shadow-md shadow-sky-950'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <Cpu className="w-4 h-4" />
              Software & Version (Mode A)
            </button>

            <button
              type="button"
              onClick={() => {
                setActiveTab('package');
                if (ecosystem === 'generic') setEcosystem('pypi');
              }}
              className={`flex items-center justify-center gap-2.5 px-4 py-2.5 text-xs font-semibold rounded-lg transition-all ${
                activeTab === 'package'
                  ? 'bg-gradient-to-r from-sky-600 to-blue-600 text-white shadow-md shadow-sky-950'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <Layers className="w-4 h-4" />
              Package Ecosystem (Mode B)
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('file')}
              className={`flex items-center justify-center gap-2.5 px-4 py-2.5 text-xs font-semibold rounded-lg transition-all ${
                activeTab === 'file'
                  ? 'bg-gradient-to-r from-sky-600 to-blue-600 text-white shadow-md shadow-sky-950'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <Upload className="w-4 h-4" />
              URL & Safe File (Mode C)
            </button>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Deterministic SemVer matching + Real-time CVE intelligence</span>
          </div>
        </div>

        {/* Quick Presets Bar */}
        <div className="flex flex-wrap items-center gap-2.5 py-4 my-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 mr-1 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-sky-400" />
            Quick Presets:
          </span>
          {PRESET_EXAMPLES.map((ex, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleQuickPreset(ex)}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 hover:text-white border border-slate-700/60 hover:border-sky-500/50 transition-all flex items-center gap-2 shadow-sm cursor-pointer"
            >
              <span>{ex.label}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900/90 text-sky-300 font-mono">
                {ex.tag}
              </span>
            </button>
          ))}
        </div>

        {/* Input Form */}
        <form onSubmit={handleRunAssessment} className="space-y-6 pt-2">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Field 1: Software/Package Name */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                {activeTab === 'package' ? 'Package Identifier *' : 'Software / Application Name *'}
              </label>
              <input
                type="text"
                value={productName}
                onChange={e => setProductName(e.target.value)}
                placeholder={activeTab === 'package' ? 'e.g. cryptography, express, log4j-core' : 'e.g. OpenSSL, Apache HTTP Server'}
                className="w-full h-12 px-4 bg-slate-950/70 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all"
              />
              <span className="text-[11px] text-slate-500 mt-1.5 block">
                {activeTab === 'package' ? 'Official package registry name' : 'Application or library identifier'}
              </span>
            </div>

            {/* Field 2: Version */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                Exact Version <span className="text-slate-500 font-normal lowercase">(recommended)</span>
              </label>
              <input
                type="text"
                value={version}
                onChange={e => setVersion(e.target.value)}
                placeholder="e.g. 3.0.0, 41.0.0, 2.14.1"
                className="w-full h-12 px-4 bg-slate-950/70 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all"
              />
              <span className="text-[11px] text-slate-500 mt-1.5 block">
                Required for accurate version range correlation
              </span>
            </div>

            {/* Field 3: Vendor / Publisher */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                Vendor / Publisher <span className="text-slate-500 font-normal lowercase">(optional)</span>
              </label>
              <input
                type="text"
                value={vendor}
                onChange={e => setVendor(e.target.value)}
                placeholder="e.g. Apache, Microsoft, PyCA"
                className="w-full h-12 px-4 bg-slate-950/70 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all"
              />
              <span className="text-[11px] text-slate-500 mt-1.5 block">
                Filters vendor-specific advisories
              </span>
            </div>
          </div>

          {/* Mode-Specific Sub-Rows */}
          {activeTab === 'package' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t border-slate-800/60">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                  Package Ecosystem *
                </label>
                <select
                  value={ecosystem}
                  onChange={e => setEcosystem(e.target.value)}
                  className="w-full h-12 px-4 bg-slate-950/70 border border-slate-800 rounded-xl text-sm text-slate-100 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all cursor-pointer"
                >
                  {ECOSYSTEMS.filter(e => e.id !== 'generic').map(eco => (
                    <option key={eco.id} value={eco.id}>
                      {eco.label}
                    </option>
                  ))}
                </select>
                <span className="text-[11px] text-slate-500 mt-1.5 block">
                  Authoritative OSV.dev repository lookup target
                </span>
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                  Package Source URL <span className="text-slate-500 font-normal lowercase">(optional registry link)</span>
                </label>
                <input
                  type="url"
                  value={sourceUrl}
                  onChange={e => setSourceUrl(e.target.value)}
                  placeholder="https://pypi.org/project/cryptography/"
                  className="w-full h-12 px-4 bg-slate-950/70 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all"
                />
                <span className="text-[11px] text-slate-500 mt-1.5 block">
                  Optional vendor verification reference
                </span>
              </div>
            </div>
          )}

          {activeTab === 'file' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t border-slate-800/60">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                  Software Download URL <span className="text-slate-500 font-normal lowercase">(anti-ssrf protected)</span>
                </label>
                <input
                  type="url"
                  value={sourceUrl}
                  onChange={e => setSourceUrl(e.target.value)}
                  placeholder="https://vendor.example/downloads/app.zip"
                  className="w-full h-12 px-4 bg-slate-950/70 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all"
                />
                <p className="text-[11px] text-slate-500 mt-1.5">
                  Private networks, loopbacks (127.0.0.1), and cloud metadata endpoints are strictly blocked.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                  Upload Package / Binary <span className="text-slate-500 font-normal lowercase">(max 15mb, static inspection only)</span>
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="file"
                    onChange={e => setSelectedFile(e.target.files?.[0] || null)}
                    className="block w-full text-xs text-slate-400 file:mr-3 file:py-2.5 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700 cursor-pointer h-12 pt-2 bg-slate-950/70 border border-slate-800 rounded-xl px-2"
                  />
                  {selectedFile && (
                    <button
                      type="button"
                      onClick={() => setSelectedFile(null)}
                      className="text-xs text-rose-400 hover:text-rose-300 px-3 py-2 rounded-lg bg-rose-500/10 border border-rose-500/20"
                    >
                      Clear
                    </button>
                  )}
                </div>
                <p className="text-[11px] text-slate-500 mt-1.5">
                  Binaries are never executed. SHA-256 and package structures are inspected in an isolated process.
                </p>
              </div>
            </div>
          )}

          {/* AI Provider and Action Row */}
          <div className="pt-6 border-t border-slate-800/80 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-sky-400" />
                AI Analysis Engine:
              </span>
              <select
                value={provider}
                onChange={e => setProvider(e.target.value)}
                className="h-11 px-4 bg-slate-950/80 border border-slate-800 rounded-xl text-xs font-medium text-slate-200 focus:outline-none focus:border-sky-500 cursor-pointer"
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
              className="h-12 px-7 bg-gradient-to-r from-sky-500 via-blue-600 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-600 text-white font-semibold text-sm rounded-xl shadow-lg shadow-sky-950/50 flex items-center justify-center gap-2.5 transition-all transform hover:-translate-y-0.5 active:translate-y-0 cursor-pointer"
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
      </div>

      {/* ── Loading State ── */}
      {loading && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-12 text-center space-y-4">
          <Loading />
          <p className="text-base font-semibold text-slate-200">
            Querying Snowflake vulnerability dataset and authoritative registries...
          </p>
          <p className="text-xs text-slate-400 max-w-lg mx-auto">
            Cross-referencing package ranges, verifying fixed releases, inspecting static indicators, and grounding assessment evidence.
          </p>
        </div>
      )}

      {/* ── Assessment Results Dashboard ── */}
      {assessment && !loading && (
        <div className="space-y-8 animate-in fade-in duration-300">
          {/* Executive Verdict Banner */}
          {(() => {
            const vStyle = getVerdictBadge(assessment.verdict);
            return (
              <div className={`p-6 md:p-8 rounded-2xl border ${vStyle.bg} flex flex-col md:flex-row items-start md:items-center justify-between gap-6 shadow-xl`}>
                <div className="flex items-start gap-4">
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 shadow-md">
                    {vStyle.icon}
                  </div>
                  <div>
                    <div className="flex items-center gap-2.5">
                      <span className={`text-xs px-2.5 py-1 rounded-full font-bold uppercase tracking-wider ${vStyle.badgeBg}`}>
                        {assessment.verdict}
                      </span>
                      <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-950/60 font-mono text-slate-400 border border-slate-800">
                        {assessment.assessment_id}
                      </span>
                    </div>
                    <h3 className="text-xl md:text-2xl font-bold text-slate-100 mt-2">
                      {assessment.verdict_title}
                    </h3>
                    <p className="text-sm text-slate-300 mt-2 max-w-3xl leading-relaxed">
                      {assessment.recommendation.explanation}
                    </p>
                  </div>
                </div>

                {/* Export / Copy Action Buttons */}
                <div className="flex flex-wrap items-center gap-2.5 shrink-0 self-start md:self-auto">
                  <button
                    type="button"
                    onClick={handleCopySummary}
                    className="p-2.5 rounded-xl bg-slate-950/80 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-all shadow-sm cursor-pointer"
                    title="Copy Summary"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExport('json')}
                    className="flex items-center gap-1.5 px-3.5 py-2.5 rounded-xl bg-slate-950/80 hover:bg-slate-800 border border-slate-800 text-xs font-semibold text-slate-200 transition-all shadow-sm cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExport('markdown')}
                    className="flex items-center gap-1.5 px-3.5 py-2.5 rounded-xl bg-slate-950/80 hover:bg-slate-800 border border-slate-800 text-xs font-semibold text-slate-200 transition-all shadow-sm cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    Markdown
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExport('html')}
                    className="flex items-center gap-1.5 px-3.5 py-2.5 rounded-xl bg-slate-950/80 hover:bg-slate-800 border border-slate-800 text-xs font-semibold text-slate-200 transition-all shadow-sm cursor-pointer"
                  >
                    <Globe className="w-3.5 h-3.5" />
                    HTML
                  </button>
                </div>
              </div>
            );
          })()}

          {/* Metric Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6">
            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-5 backdrop-blur-sm">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Vulnerabilities</div>
              <div className="text-3xl font-extrabold text-slate-100 mt-2">
                {assessment.total_findings}
              </div>
              <div className="text-xs text-slate-400 mt-1.5">
                {assessment.exact_matches_count} confirmed exact matches
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-5 backdrop-blur-sm">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Evaluated Version</div>
              <div className="text-2xl font-bold text-slate-100 mt-2 truncate">
                {assessment.software.version || 'Unspecified'}
              </div>
              <div className="text-xs text-slate-400 mt-1.5 truncate">
                {assessment.software.product_name} ({assessment.software.ecosystem})
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-5 backdrop-blur-sm">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Verified Fixed Release</div>
              <div className="text-2xl font-bold text-emerald-400 mt-2 truncate">
                {assessment.verified_fixed_version ? `v${assessment.verified_fixed_version}` : 'No known fix'}
              </div>
              <div className="text-xs text-slate-400 mt-1.5">
                {assessment.verified_fixed_version ? 'Upgrade path verified by advisory' : 'Check vendor for mitigations'}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-5 backdrop-blur-sm">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Recommended Action</div>
              <div className="text-sm font-bold text-sky-400 mt-2 truncate">
                {assessment.recommendation.action}
              </div>
              <div className="text-xs text-slate-400 mt-1.5">
                Confidence: <span className="font-semibold text-slate-300">{assessment.software.confidence}</span>
              </div>
            </div>
          </div>

          {/* Potential Impacts Section */}
          {assessment.potential_impacts.length > 0 && (
            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-sm">
              <div className="flex items-center gap-2.5 mb-4">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                <h4 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                  Documented Potential Impacts
                </h4>
              </div>
              <div className="flex flex-wrap gap-2.5">
                {assessment.potential_impacts.map((impact, i) => (
                  <span
                    key={i}
                    className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/30 shadow-sm"
                  >
                    {impact}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* AI Grounded Summary Card */}
          {assessment.ai && (
            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/70 p-6 md:p-8 backdrop-blur-md">
              <div className="flex items-center justify-between pb-4 border-b border-slate-800 gap-4">
                <div className="flex items-center gap-2.5">
                  <Sparkles className="w-5 h-5 text-sky-400" />
                  <h4 className="text-base font-bold text-slate-100">
                    Evidence-Grounded AI Assessment
                  </h4>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="px-3 py-1 rounded-lg bg-slate-950 text-slate-300 font-mono border border-slate-800">
                    {assessment.ai.provider}
                  </span>
                  <span className="px-3 py-1 rounded-lg bg-slate-950 text-slate-400 font-mono text-[11px] border border-slate-800">
                    {assessment.ai.model}
                  </span>
                </div>
              </div>

              <div className="mt-6 space-y-6 text-sm text-slate-300 leading-relaxed">
                {assessment.ai.executive_summary && (
                  <div>
                    <h5 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                      Executive Summary
                    </h5>
                    <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800/80 text-slate-200">
                      {assessment.ai.executive_summary}
                    </div>
                  </div>
                )}

                {assessment.ai.plain_english_impact && (
                  <div>
                    <h5 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                      Plain-English Impact Analysis
                    </h5>
                    <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800/80 text-slate-200">
                      {assessment.ai.plain_english_impact}
                    </div>
                  </div>
                )}

                {assessment.ai.verification_steps && assessment.ai.verification_steps.length > 0 && (
                  <div>
                    <h5 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                      Recommended Verification Steps
                    </h5>
                    <ul className="list-disc list-inside space-y-1.5 bg-slate-950/60 p-4 rounded-xl border border-slate-800/80 text-slate-300 text-xs">
                      {assessment.ai.verification_steps.map((step, idx) => (
                        <li key={idx}>
                          {step}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Static File Inspection Metadata (if uploaded) */}
          {assessment.file_metadata && (
            <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-sm">
              <div className="flex items-center gap-2.5 mb-4">
                <FileCheck className="w-5 h-5 text-sky-400" />
                <h4 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                  Static File Inspection Metadata
                </h4>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                <div>
                  <span className="text-slate-400 font-semibold">Filename:</span> {assessment.file_metadata.filename}
                </div>
                <div>
                  <span className="text-slate-400 font-semibold">Size:</span> {(assessment.file_metadata.size_bytes / 1024).toFixed(1)} KB
                </div>
                <div className="col-span-1 md:col-span-2 truncate">
                  <span className="text-slate-400 font-semibold">SHA-256:</span> {assessment.file_metadata.sha256}
                </div>
                <div>
                  <span className="text-slate-400 font-semibold">Format:</span> {assessment.file_metadata.detected_type}
                </div>
                <div>
                  <span className="text-slate-400 font-semibold">Execution Status:</span> Non-executed (Safe Static Only)
                </div>
              </div>
              {assessment.file_metadata.suspicious_flags.length > 0 && (
                <div className="mt-4 p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs text-rose-300">
                  <span className="font-bold">Static Warning Flags:</span> {assessment.file_metadata.suspicious_flags.join('; ')}
                </div>
              )}
            </div>
          )}

          {/* Vulnerability Findings Table */}
          <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 md:p-8 backdrop-blur-sm">
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 mb-6">
              <div className="flex items-center gap-2.5">
                <Search className="w-5 h-5 text-slate-400" />
                <h4 className="text-base font-bold text-slate-100">
                  Vulnerability Findings ({assessment.total_findings})
                </h4>
              </div>
              <input
                type="text"
                value={findingsFilter}
                onChange={e => setFindingsFilter(e.target.value)}
                placeholder="Filter findings by CVE, severity, or description..."
                className="h-10 px-4 bg-slate-950/70 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 w-full sm:w-80"
              />
            </div>

            {filteredFindings.length === 0 ? (
              <div className="py-12 text-center text-xs text-slate-500">
                {assessment.total_findings === 0
                  ? 'No matching vulnerability records found in checked sources.'
                  : 'No findings match the current filter term.'}
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-800/80">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4 font-semibold">Identifier</th>
                      <th className="py-3 px-4 font-semibold">Severity</th>
                      <th className="py-3 px-4 font-semibold">CVSS</th>
                      <th className="py-3 px-4 font-semibold">Match Type</th>
                      <th className="py-3 px-4 font-semibold">Affected Range / Fix</th>
                      <th className="py-3 px-4 font-semibold">Summary</th>
                      <th className="py-3 px-4 font-semibold">Advisory</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
                    {filteredFindings.map((f, i) => (
                      <tr key={i} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-4 font-mono font-medium text-slate-200 whitespace-nowrap">
                          {f.id}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-300">
                          {f.cvss_score !== null ? f.cvss_score.toFixed(1) : '—'}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span
                            className={`px-2.5 py-1 rounded-md text-[11px] font-semibold ${
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
                        <td className="py-3 px-4 text-slate-300 text-[11px]">
                          <div>{f.range_description}</div>
                          {f.verified_fixed_version && (
                            <div className="text-emerald-400 font-semibold mt-0.5">
                              Fix: v{f.verified_fixed_version}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-300 max-w-md truncate" title={f.details}>
                          {f.summary}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <a
                            href={f.source_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-sky-400 hover:text-sky-300 inline-flex items-center gap-1 font-semibold"
                          >
                            Source
                            <ExternalLink className="w-3.5 h-3.5" />
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
          <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6 backdrop-blur-sm">
            <div className="flex items-center gap-2 mb-3">
              <Info className="w-4 h-4 text-slate-400" />
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Coverage, Sources & Assessment Limitations
              </h4>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-slate-400 mt-2">
              <div>
                <span className="font-semibold text-slate-300 block mb-1">Sources Checked:</span>
                <ul className="list-disc list-inside space-y-1">
                  {assessment.sources_checked.map((src, i) => (
                    <li key={i}>{src}</li>
                  ))}
                </ul>
              </div>
              <div>
                <span className="font-semibold text-slate-300 block mb-1">Important Disclaimers:</span>
                <ul className="list-disc list-inside space-y-1">
                  {assessment.limitations.map((lim, i) => (
                    <li key={i}>{lim}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Interactive AI Grounded Software Security Chat (Spacious & Always Accessible) ── */}
      <div className="rounded-2xl border border-slate-800/80 bg-gradient-to-b from-slate-900/90 to-slate-950 p-6 md:p-8 shadow-xl shadow-black/40 backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-base font-bold text-slate-100">
                {assessment ? 'Ask AI About This Assessment' : 'AI Software Security Assistant & Chat'}
              </h4>
              <p className="text-xs text-slate-400 mt-0.5">
                {assessment
                  ? `Context-grounded analysis for ${assessment.software.product_name} v${assessment.software.version}`
                  : `Ask any software safety or CVE question powered by ${provider.toUpperCase()}`}
              </p>
            </div>
          </div>

          <span className="text-xs text-sky-400 font-mono bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800 flex items-center gap-1.5 shadow-sm">
            <Sparkles className="w-3.5 h-3.5" />
            {assessment
              ? `Evidence: ${assessment.total_findings} findings loaded`
              : `Engine: ${provider.toUpperCase()}`}
          </span>
        </div>

        {/* Quick Suggested Questions */}
        <div className="my-5">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2.5 flex items-center gap-1.5">
            <Bot className="w-3.5 h-3.5 text-sky-400" />
            Suggested Questions:
          </div>
          <div className="flex flex-wrap gap-2.5">
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
                className="px-3.5 py-2 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-sky-500/60 text-xs font-medium text-slate-300 hover:text-white transition-all shadow-sm flex items-center gap-1.5 cursor-pointer"
              >
                <span>{q}</span>
                <ArrowRight className="w-3 h-3 text-slate-500" />
              </button>
            ))}
          </div>
        </div>

        {/* Chat Messages Thread */}
        <div className="my-4 p-4 min-h-[180px] max-h-[380px] overflow-y-auto rounded-xl bg-slate-950/70 border border-slate-800/90 space-y-4">
          {chatMessages.length === 0 ? (
            <div className="py-10 text-center text-xs text-slate-500 flex flex-col items-center gap-2">
              <Bot className="w-8 h-8 text-slate-600 mb-1" />
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
                className={`flex flex-col ${
                  msg.sender === 'user' ? 'items-end' : 'items-start'
                }`}
              >
                <div
                  className={`max-w-2xl px-4 py-3 rounded-2xl text-xs md:text-sm leading-relaxed shadow-md ${
                    msg.sender === 'user'
                      ? 'bg-gradient-to-r from-sky-600 to-blue-600 text-white rounded-br-none'
                      : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-bl-none'
                  }`}
                >
                  <div className="font-semibold text-[11px] mb-1 opacity-70 flex items-center gap-1">
                    {msg.sender === 'user' ? (
                      <>
                        <User className="w-3 h-3" /> You
                      </>
                    ) : (
                      <>
                        <Bot className="w-3 h-3 text-sky-400" /> Security Assistant
                      </>
                    )}
                  </div>
                  <div className="whitespace-pre-wrap">{msg.text}</div>
                  {msg.citations && msg.citations.length > 0 && (
                    <div className="mt-3 pt-2.5 border-t border-slate-800 text-[11px] text-sky-400 flex flex-wrap items-center gap-1.5">
                      <span className="font-semibold text-slate-400">Citations:</span>
                      {msg.citations.map((c, ci) => (
                        <span key={ci} className="font-mono bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
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
            <div className="flex items-center gap-2.5 text-xs text-slate-400 italic py-2">
              <RefreshCw className="w-4 h-4 animate-spin text-sky-400" />
              Generating grounded answer...
            </div>
          )}
        </div>

        {/* Chat Input */}
        <div className="pt-2 flex items-center gap-3">
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
            className="flex-1 h-12 px-4 bg-slate-950/80 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all"
          />
          <button
            type="button"
            onClick={() => handleAskQuestion()}
            disabled={chatLoading || !chatQuestion.trim()}
            className="h-12 px-6 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-600 text-white font-semibold text-xs rounded-xl shadow-md transition-all flex items-center gap-2 cursor-pointer"
          >
            <Send className="w-4 h-4" />
            Ask
          </button>
        </div>
      </div>
    </div>
  );
}
