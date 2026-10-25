import { useEffect, useMemo, useState } from 'react';
import { ArrowUpRight, Info, Save, ShieldCheck } from 'lucide-react';
import { api } from '../api';
import { Badge, Card, Loading, PageHeading } from '../components/Shell';

type Dataset = {
  id: string; name: string; category: string; source_type: string; license: string;
  url: string; connected_by_default: boolean; description: string; schema: string[];
};
type Template = { id: string; name: string; description: string; datasets: string[]; metrics: string[]; guardrail: string };
type AuditData = {
  available: boolean; reason?: string; events: any[]; members: { member: string; points: number }[];
  peer_reviews: any[]; evaluations: any[]; model_benchmarks?: any; scoring_policy?: string;
};

export default function ProjectStudio() {
  const [catalog, setCatalog] = useState<{ datasets: Dataset[]; templates: Template[] } | null>(null);
  const [audit, setAudit] = useState<AuditData | null>(null);
  const [templateId, setTemplateId] = useState('vulnerability-prioritization');
  const [title, setTitle] = useState('NVD vulnerability prioritization');
  const [goal, setGoal] = useState('Build an explainable workflow that helps analysts review the most severe public vulnerabilities and verify relevance against their own assets.');
  const [savedScopes, setSavedScopes] = useState<any[]>(() => {
    try { return JSON.parse(localStorage.getItem('threatlens.projectScopes.v1') || '[]'); } catch { return []; }
  });
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([api<{ datasets: Dataset[]; templates: Template[] }>('/project-catalog'), api<AuditData>('/contributions')])
      .then(([nextCatalog, nextAudit]) => { setCatalog(nextCatalog); setAudit(nextAudit); })
      .catch((err: Error) => setError(err.message || 'Project catalog could not be loaded.'))
      .finally(() => setBusy(false));
  }, []);

  const selectedTemplate = useMemo(() => catalog?.templates.find(item => item.id === templateId), [catalog, templateId]);
  const createScope = async () => {
    if (!selectedTemplate) return;
    setError('');
    try {
      const result = await api<any>('/project-scopes', {
        method: 'POST',
        body: JSON.stringify({
          template_id: selectedTemplate.id,
          title,
          goal,
          success_metrics: selectedTemplate.metrics,
          dataset_ids: selectedTemplate.datasets,
        }),
      });
      const next = [result.scope, ...savedScopes].slice(0, 10);
      setSavedScopes(next);
      localStorage.setItem('threatlens.projectScopes.v1', JSON.stringify(next));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Project scope could not be saved.');
    }
  };

  if (busy) return <Loading />;
  if (error && !catalog) return <Loading error={error} />;
  if (!catalog) return null;

  const benchmarkTasks = audit?.model_benchmarks?.sources
    ? Object.entries(audit.model_benchmarks.sources).flatMap(([source, tasks]: [string, any]) =>
      Object.entries(tasks || {}).filter(([, task]: [string, any]) => task?.status).map(([task, report]: [string, any]) => ({ source, task, ...report })))
    : [];

  return (
    <div className="projects-page animate-fade-in">
      <PageHeading eyebrow="TEAM NOVA · OPEN-SOURCE CYBERSECURITY ECOSYSTEM" title="ThreatLens AI Project Studio" description="Discover public security datasets, scope reproducible project templates, and inspect auditable team and model-evaluation evidence." />

      {error && <div className="notice" role="alert"><Info size={16} /><div><b>Could not validate this scope</b><span>{error}</span></div></div>}
      <div className="section-title-wrap"><h2>1 · Dataset & Template Discovery</h2><p>Catalog entries distinguish connected application data from sources that require separate installation or import.</p></div>
      <div className="cluster-grid">
        {catalog.datasets.map(dataset => (
          <Card key={dataset.id} title={dataset.name} subtitle={dataset.category}>
            <div className="term-cloud"><Badge tone={dataset.connected_by_default ? 'green' : 'gray'}>{dataset.connected_by_default ? 'APP SOURCE' : 'DISCOVERY ONLY'}</Badge><Badge tone="blue">{dataset.source_type}</Badge></div>
            <p>{dataset.description}</p>
            <p className="limitation-footer"><b>License:</b> {dataset.license}</p>
            <p className="limitation-footer"><b>Schema preview:</b> {dataset.schema.join(' · ')}</p>
            <a className="text-action" href={dataset.url} target="_blank" rel="noreferrer">Open source details <ArrowUpRight size={13} /></a>
          </Card>
        ))}
      </div>

      <div className="section-title-wrap"><h2>2 · Define Project Scope</h2><p>Choose a task template, set a measurable goal, then save the scope in this browser workspace.</p></div>
      <div className="method-grid">
        <Card title="Project brief" subtitle="Scope is validated by the Flask API and saved in this browser only.">
          <label className="field-label" htmlFor="project-template">Project template</label>
          <select id="project-template" className="button-secondary" value={templateId} onChange={event => {
            const nextTemplate = catalog.templates.find(item => item.id === event.target.value);
            setTemplateId(event.target.value);
            if (nextTemplate) {
              setTitle(`${nextTemplate.name} pilot`);
              setGoal(`${nextTemplate.description} Evaluate on held-out source data and document data limitations, model metrics, and reproducibility.`);
            }
          }}>
            {catalog.templates.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
          <label className="field-label" htmlFor="project-title">Project name</label>
          <input id="project-title" className="search-input" value={title} maxLength={120} onChange={event => setTitle(event.target.value)} />
          <label className="field-label" htmlFor="project-goal">Goal and measurable outcome</label>
          <textarea id="project-goal" className="search-input" rows={4} maxLength={1200} value={goal} onChange={event => setGoal(event.target.value)} />
          {selectedTemplate && <><p><b>Suggested datasets:</b> {selectedTemplate.datasets.join(', ')}</p><p><b>Success metrics:</b> {selectedTemplate.metrics.join(' · ')}</p><div className="notice"><Info size={15} /><div><span>{selectedTemplate.guardrail}</span></div></div></>}
          <button className="button-primary" onClick={createScope}><Save size={15} /> Validate & save scope</button>
        </Card>
        <Card title="Saved project scopes" subtitle="Browser-local scopes; no Snowflake compute or project resources are allocated by saving.">
          {savedScopes.length === 0 ? <p className="limitation-footer">No project scopes saved in this browser yet.</p> : savedScopes.map((scope, index) => <div className="setting-row" key={`${scope.title}-${index}`}><div><b>{scope.title}</b><p>{scope.goal}</p><small>{scope.template_id} · {scope.dataset_ids?.join(', ')}</small></div><Badge tone="green">SCOPED</Badge></div>)}
        </Card>
      </div>

      <div className="section-title-wrap"><h2>3 · Audit & Traceability</h2><p>Contribution points, peer reviews, and held-out verification are shown only when backed by recorded events or training reports.</p></div>
      {!audit?.available && <div className="notice"><Info size={17} /><div><b>Snowflake audit ledger not enabled</b><span>{audit?.reason || 'Apply snowflake/contributions.sql and configure a dedicated audit identity to publish team events.'}</span></div></div>}
      <div className="method-grid">
        <Card title="Team contributions" subtitle="Additive points from append-only contribution events.">
          {audit?.members?.length ? audit.members.map(member => <div className="setting-row" key={member.member}><div><b>{member.member}</b><p>Recorded contribution points</p></div><Badge tone="violet">{member.points.toFixed(1)} pts</Badge></div>) : <p className="limitation-footer">No member totals available. Scores are not inferred from names, commits, or activity that has not been recorded.</p>}
          {audit?.scoring_policy && <p className="limitation-footer">{audit.scoring_policy}</p>}
        </Card>
        <Card title="Peer review history" subtitle="Recorded reviews remain traceable to the submitted actor and project.">
          {audit?.peer_reviews?.length ? audit.peer_reviews.map((review, index) => <div className="setting-row" key={review.event_id || index}><div><b>{review.actor} reviewed {review.reviewee}</b><p>{review.project_id} · {review.event_date} · {review.details || 'No review note provided'}</p></div><Badge tone="blue">{review.review_rating}/5</Badge></div>) : <p className="limitation-footer">No peer-review events are recorded in the connected audit store.</p>}
        </Card>
      </div>
      <Card title="Held-out model verification" subtitle="Task-specific metrics from the committed training report; these do not validate NVD score accuracy.">
        {benchmarkTasks.length ? <div className="cluster-grid">{benchmarkTasks.map(item => <div className="metric-card" key={`${item.source}-${item.task}`}><small>{item.task.replace(/_/g, ' ')}</small><strong>{item.status === 'trained' ? (item.metrics?.macro_f1 == null ? '—' : Number(item.metrics.macro_f1).toFixed(3)) : item.status}</strong><span>{item.source} · held-out macro F1 · {item.test_rows ?? 0} test rows</span></div>)}</div> : <p className="limitation-footer">{audit?.model_benchmarks?.reason || 'No held-out model report is available yet.'}</p>}
      </Card>
      {audit?.events?.length ? <Card title="Recent audit events" subtitle="Append-only ledger history, newest first."><div className="table-wrap"><table className="analysis-table"><thead><tr><th>EVENT</th><th>PROJECT</th><th>ACTOR</th><th>DATE</th><th>ARTIFACT / DETAILS</th></tr></thead><tbody>{audit.events.slice(0, 25).map((event, index) => <tr key={event.event_id || index}><td><Badge tone={event.event_type === 'PEER_REVIEW' ? 'blue' : 'violet'}>{event.event_type}</Badge></td><td>{event.project_id}</td><td>{event.actor}</td><td>{event.event_date}</td><td>{event.artifact_url ? <a href={event.artifact_url} target="_blank" rel="noreferrer" className="text-action">Open artifact <ArrowUpRight size={12} /></a> : event.details || '—'}</td></tr>)}</tbody></table></div></Card> : null}
      <div className="notice blue-notice"><ShieldCheck size={17} /><div><b>Evidence rules</b><span>Dataset availability, marketplace installation, contribution points, model metrics, and actual AI use are reported as separate claims. Snowflake schema discovery does not imply that a listing is installed.</span></div></div>
    </div>
  );
}
