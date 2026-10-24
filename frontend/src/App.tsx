/**
 * ThreatLens AI — Root Application Component
 *
 * Manages page routing, data source status, and renders the shell layout.
 */

import { useEffect, useState } from 'react';

import { Shell } from './components/Shell';
import Overview from './pages/Overview';
import Explorer from './pages/Explorer';
import {
  Trends,
  Risk,
  ML,
  DataExplorer,
  Reports,
  Settings,
} from './pages/Analysis';
import { api, SourceStatus } from './api';

// ─── Page routing map ────────────────────────────────────────────────

const PAGES: Record<string, React.FC<any>> = {
  'Overview': Overview,
  'Vulnerability Explorer': Explorer,
  'Threat Trends': Trends,
  'Risk Analysis': Risk,
  'ML Insights': ML,
  'Data Explorer': DataExplorer,
  'Reports': Reports,
  'Settings': Settings,
};

// ─── App ─────────────────────────────────────────────────────────────

export default function App() {
  const [page, setPage] = useState('Overview');
  const [source, setSource] = useState<SourceStatus | undefined>();

  // Fetch data source status on mount
  useEffect(() => {
    api<{ active: SourceStatus }>('/data-sources')
      .then(data => setSource(data.active))
      .catch(() =>
        setSource({
          mode: 'UNAVAILABLE',
          connected: false,
          dataset: '',
          provider: '',
          updated_at: null,
          record_count: 0,
          note: 'Data source could not be reached.',
        })
      );
  }, []);

  // Determine which page component to render
  const PageComponent = PAGES[page] ?? Overview;

  // Pass appropriate props based on page
  const pageProps: Record<string, any> = {};
  if (page === 'Overview') {
    pageProps.source = source;
    pageProps.onSelect = setPage;
  } else if (page === 'Data Explorer' || page === 'Settings') {
    pageProps.source = source;
  }

  return (
    <Shell page={page} setPage={setPage} source={source}>
      <PageComponent {...pageProps} />
    </Shell>
  );
}
