/**
 * ThreatLens AI — App Shell & Shared Components
 *
 * Contains the sidebar navigation, top bar, and reusable UI primitives
 * used across all pages.
 */

import { ReactNode, useEffect, useState, useCallback } from 'react';
import {
  Activity,
  AlertCircle,
  Blocks,
  CheckCircle,
  ChartNoAxesCombined,
  CircleAlert,
  Database,
  FileText,
  Info,
  LayoutDashboard,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  Sparkles,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';

// ─── Navigation config ───────────────────────────────────────────────

const NAV_ITEMS = [
  ['Overview', LayoutDashboard],
  ['Vulnerability Explorer', Search],
  ['Threat Trends', ChartNoAxesCombined],
  ['Risk Analysis', ShieldCheck],
  ['ML Insights', Sparkles],
  ['Data Explorer', Database],
  ['Reports', FileText],
  ['Settings', Settings2],
] as const;

// ─── Toast notification system ───────────────────────────────────────

interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info';
}

let toastId = 0;
let toastListeners: Array<(toasts: Toast[]) => void> = [];
let currentToasts: Toast[] = [];

export function showToast(message: string, type: Toast['type'] = 'info') {
  const id = ++toastId;
  const toast: Toast = { id, message, type };
  currentToasts = [...currentToasts, toast];
  toastListeners.forEach(fn => fn(currentToasts));

  setTimeout(() => {
    currentToasts = currentToasts.filter(t => t.id !== id);
    toastListeners.forEach(fn => fn(currentToasts));
  }, 4000);
}

function ToastContainer() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    toastListeners.push(setToasts);
    return () => {
      toastListeners = toastListeners.filter(fn => fn !== setToasts);
    };
  }, []);

  if (toasts.length === 0) return null;

  const icon = {
    success: <CheckCircle size={16} />,
    error: <AlertCircle size={16} />,
    info: <Info size={16} />,
  };

  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type}`}>
          {icon[t.type]}
          <span>{t.message}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Shell (main layout) ─────────────────────────────────────────────

interface ShellProps {
  page: string;
  setPage: (page: string) => void;
  source?: any;
  children: ReactNode;
}

export function Shell({ page, setPage, source, children }: ShellProps) {
  // Keyboard shortcut: Ctrl/Cmd + K to jump to explorer
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setPage('Vulnerability Explorer');
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [setPage]);

  return (
    <div className="app-shell">
      {/* ── Sidebar ─────────────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={19} />
          </div>
          <div>
            <b>ThreatLens</b>
            <small>CYBER INTELLIGENCE</small>
          </div>
        </div>

        <div className="workspace">
          <span className="workspace-dot" />
          Security Operations
          <span className="chevron">⌄</span>
        </div>

        <div className="nav-label">WORKSPACE</div>

        <nav>
          {NAV_ITEMS.map(([name, Icon]) => (
            <button
              key={name}
              className={`nav-item ${page === name ? 'active' : ''}`}
              onClick={() => setPage(name)}
              aria-label={`Navigate to ${name}`}
            >
              <Icon size={17} />
              <span>{name}</span>
              {name === 'Vulnerability Explorer' && (
                <span className="nav-count">↗</span>
              )}
            </button>
          ))}
        </nav>

        <div className="side-bottom">
          <div className="source-mini">
            <div className="source-mini-icon">
              <Blocks size={15} />
            </div>
            <div>
              <small>DATA SOURCE</small>
              <b>{source?.mode ?? 'CONNECTING'}</b>
            </div>
            <span className={`status-dot ${source?.connected ? '' : 'dim'}`} />
          </div>

          <div className="user-row">
            <div className="avatar">TL</div>
            <div>
              <b>Analyst workspace</b>
              <small>Local environment</small>
            </div>
            <span className="dots">•••</span>
          </div>
        </div>
      </aside>

      {/* ── Main content area ───────────────────────────────────── */}
      <main className="main-area">
        <header className="topbar">
          <div className="crumb">
            <span>ThreatLens AI</span>
            <i>/</i>
            <b>{page}</b>
          </div>
          <div className="top-actions">
            <div className={`connection ${source?.connected ? '' : 'offline'}`}>
              {source?.connected ? <Wifi size={14} /> : <WifiOff size={14} />}
              <span>{source?.mode ?? 'Checking'} source</span>
            </div>
            <div className="top-avatar">TL</div>
          </div>
        </header>

        <div className="page-content">
          {children}
        </div>

        <footer>
          ThreatLens AI
          <span>•</span>
          Evidence-backed vulnerability intelligence
          <span className="footer-right">
            Data informs investigation. It does not confirm an active attack.
          </span>
        </footer>
      </main>

      <ToastContainer />
    </div>
  );
}

// ─── Page heading ────────────────────────────────────────────────────

interface PageHeadingProps {
  eyebrow?: string;
  title: string;
  description: string;
  action?: ReactNode;
}

export function PageHeading({ eyebrow, title, description, action }: PageHeadingProps) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="heading-action">{action}</div>}
    </div>
  );
}

// ─── Card ────────────────────────────────────────────────────────────

interface CardProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function Card({ title, subtitle, children, action, className = '' }: CardProps) {
  return (
    <section className={`card ${className}`}>
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

// ─── Loading / Error state ───────────────────────────────────────────

interface LoadingProps {
  error?: string;
  onRetry?: () => void;
}

export function Loading({ error, onRetry }: LoadingProps) {
  if (error) {
    return (
      <div className="state-box">
        <CircleAlert size={24} />
        <b>Couldn't load this data</b>
        <span>{error}</span>
        {onRetry && (
          <button className="button-secondary" onClick={onRetry}>
            Try again
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="state-box">
      <div className="loading-spinner" />
      <span>Loading analysis…</span>
    </div>
  );
}

// ─── Skeleton loaders ────────────────────────────────────────────────

export function SkeletonCards({ count = 4 }: { count?: number }) {
  return (
    <div className="metric-grid">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton skeleton-card" />
      ))}
    </div>
  );
}

export function SkeletonText({ lines = 3 }: { lines?: number }) {
  return (
    <div>
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className={`skeleton skeleton-text ${i === lines - 1 ? 'short' : 'medium'}`}
        />
      ))}
    </div>
  );
}

// ─── Badge ───────────────────────────────────────────────────────────

interface BadgeProps {
  children: ReactNode;
  tone?: string;
}

export function Badge({ children, tone = 'blue' }: BadgeProps) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

// ─── Severity badge ──────────────────────────────────────────────────

const SEVERITY_TONES: Record<string, string> = {
  critical: 'red',
  high: 'amber',
  medium: 'yellow',
  low: 'green',
  none: 'gray',
  unknown: 'gray',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toLowerCase();
  const tone = SEVERITY_TONES[key] ?? 'gray';

  return (
    <Badge tone={tone}>
      <i className="badge-dot" />
      {severity || 'UNKNOWN'}
    </Badge>
  );
}
