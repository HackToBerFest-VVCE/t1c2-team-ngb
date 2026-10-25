import { useEffect, useMemo, useState } from 'react';
import { ArrowUpRight, CheckCircle2, Info, PlusCircle, Save, ShieldCheck } from 'lucide-react';
import { api } from '../api';
import { Badge, Card, Loading, PageHeading } from '../components/Shell';

type Dataset = {
  id: string; name: string; category: string; source_type: string; license: string;
  url: string; connected_by_default: boolean; description: string; schema: string[];
};
type Template = { id: string; name: string; description: string; datasets: string[]; metrics: string[]; guardrail: string };
type AuditData = {
  available: boolean; storage?: string; storage_label?: string; reason?: string;
  events: any[]; members: { member: string; points: number }[];
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

  // Interactive audit recording state
  const [showEventForm, setShowEventForm] = useState(false);
  const [eventType, setEventType] = useState<'CONTRIBUTION' | 'PEER_REVIEW'>('PEER_REVIEW');
  const [actor, setActor] = useState('');
  const [reviewee, setReviewee] = useState('Yogesh');
  const [reviewRating, setReviewRating] = useState(5);
  const [contribType, setContribType] = useState('code');
  const [artifactUrl, setArtifactUrl] = useState('https://github.com/yogesh-37911/Threat-Lens-Ai');
  const [eventDetails, setEventDetails] = useState('');
  const [eventStatus, setEventStatus] = useState('');

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

  const recordAuditEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!actor.trim()) {
      setError('Please provide an actor/author name.');
      return;
    }
    setError('');
    setEventStatus('Recording audit event...');
    try {
      const payload: any = {
        event_type: eventType,
        project_id: 'threatlens-ai',
        actor: actor.trim(),
        details: eventDetails.trim() || undefined,
      };
      if (eventType === 'PEER_REVIEW') {
        payload.reviewee = reviewee.trim();
        payload.review_rating = Number(reviewRating);
      } else {
        payload.contribution_type = contribType;
        payload.artifact_url = artifactUrl.trim() || 'https://github.com/yogesh-37911/Threat-Lens-Ai';
      }
      await api('/contributions', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const updatedAudit = await api<AuditData>('/contributions');
      setAudit(updatedAudit);
      setEventStatus('Event successfully appended to the audit ledger!');
      setTimeout(() => {
        setEventStatus('');
        setShowEventForm(false);
      }, 2000);
    } catch (err: any) {
      setError(err?.message || 'Failed to record audit event.');
      setEventStatus('');
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

      {error && <div className="notice" role="alert"><Info size={16} /><div><b>Notice</b><span>{error}</span></div></div>}
      {eventStatus && <div className="notice blue-notice" role="status"><CheckCircle2 size={16} /><div><b>Audit Update</b><span>{eventStatus}</span></div></div>}

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

      <div className="section-title-wrap">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', width: '100%', gap: '0.75rem' }}>
          <div>
            <h2>3 · Audit & Traceability</h2>
            <p>Contribution points, peer reviews, and held-out verification are backed by an append-only verifiable ledger.</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Badge tone="green">{audit?.storage_label || 'Append-Only Ledger'}</Badge>
            <button className="button-secondary" onClick={() => setShowEventForm(!showEventForm)}>
              <PlusCircle size={14} /> {showEventForm ? 'Cancel' : 'Record Team Event'}
            </button>
          </div>
        </div>
      </div>

      {showEventForm && (
        <Card title="Record Team Event or Peer Review" subtitle="Appends an auditable record to the Team Nova contribution ledger.">
          <form onSubmit={recordAuditEvent} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
              <div>
                <label className="field-label">Event Type</label>
                <select className="button-secondary" style={{ width: '100%' }} value={eventType} onChange={e => setEventType(e.target.value as any)}>
                  <option value="PEER_REVIEW">Peer Review (Rating & Evaluation)</option>
                  <option value="CONTRIBUTION">Project Contribution (Code, Model, Data)</option>
                </select>
              </div>
              <div>
                <label className="field-label">Your Name / Reviewer Handle</label>
                <input className="search-input" placeholder="e.g. Hackathon Mentor, Alice" value={actor} onChange={e => setActor(e.target.value)} required />
              </div>
            </div>

            {eventType === 'PEER_REVIEW' ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
                <div>
                  <label className="field-label">Reviewee (Team Member)</label>
                  <input className="search-input" value={reviewee} onChange={e => setReviewee(e.target.value)} required />
                </div>
                <div>
                  <label className="field-label">Rating (1 to 5 Stars)</label>
                  <select className="button-secondary" style={{ width: '100%' }} value={reviewRating} onChange={e => setReviewRating(Number(e.target.value))}>
                    <option value={5}>5 / 5 — Outstanding Quality & Provenance</option>
                    <option value={4}>4 / 5 — Exceeds Requirements</option>
                    <option value={3}>3 / 5 — Meets Specifications</option>
                    <option value={2}>2 / 5 — Needs Verification</option>
                    <option value={1}>1 / 5 — Incomplete Evidence</option>
                  </select>
                </div>
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
                <div>
                  <label className="field-label">Contribution Category</label>
                  <select className="button-secondary" style={{ width: '100%' }} value={contribType} onChange={e => setContribType(e.target.value)}>
                    <option value="code">Code Implementation (5 pts)</option>
                    <option value="model">Machine Learning Model (6 pts)</option>
                    <option value="dataset">Dataset Curation / ETL (4 pts)</option>
                    <option value="documentation">Documentation & Specs (2 pts)</option>
                    <option value="peer_review">Peer Review Audit (3 pts)</option>
                    <option value="other">Other Milestones (1 pt)</option>
                  </select>
                </div>
                <div>
                  <label className="field-label">Artifact URL (GitHub / Demo)</label>
                  <input className="search-input" value={artifactUrl} onChange={e => setArtifactUrl(e.target.value)} required />
                </div>
              </div>
            )}

            <div>
              <label className="field-label">Review Notes / Contribution Summary</label>
              <textarea className="search-input" rows={2} placeholder="Explain what was reviewed or delivered..." value={eventDetails} onChange={e => setEventDetails(e.target.value)} />
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
              <button type="submit" className="button-primary"><Save size={15} /> Append to Audit Ledger</button>
              <button type="button" className="button-secondary" onClick={() => setShowEventForm(false)}>Cancel</button>
            </div>
          </form>
        </Card>
      )}

      <div className="method-grid">
        <Card title="Team contributions" subtitle="Additive points from append-only contribution events.">
          {audit?.members?.length ? audit.members.map(member => (
            <div className="setting-row" key={member.member}>
              <div><b>{member.member}</b><p>Recorded contribution points</p></div>
              <Badge tone="violet">{member.points.toFixed(1)} pts</Badge>
            </div>
          )) : <p className="limitation-footer">No member totals available. Scores are not inferred from names, commits, or activity that has not been recorded.</p>}
          {audit?.scoring_policy && <p className="limitation-footer">{audit.scoring_policy}</p>}
        </Card>
        <Card title="Peer review history" subtitle="Recorded reviews remain traceable to the submitted actor and project.">
          {audit?.peer_reviews?.length ? audit.peer_reviews.map((review, index) => (
            <div className="setting-row" key={review.event_id || index}>
              <div><b>{review.actor} reviewed {review.reviewee}</b><p>{review.project_id} · {review.event_date} · {review.details || 'No review note provided'}</p></div>
              <Badge tone="blue">{review.review_rating}/5</Badge>
            </div>
          )) : <p className="limitation-footer">No peer-review events are recorded in the connected audit store.</p>}
        </Card>
      </div>

      <Card title="Held-out model verification" subtitle="Task-specific metrics from the committed training report; these do not validate NVD score accuracy.">
        {benchmarkTasks.length ? (
          <div className="cluster-grid">
            {benchmarkTasks.map(item => (
              <div className="metric-card" key={`${item.source}-${item.task}`}>
                <small>{item.task.replace(/_/g, ' ')}</small>
                <strong>{item.status === 'trained' ? (item.metrics?.macro_f1 == null ? '—' : Number(item.metrics.macro_f1).toFixed(3)) : item.status}</strong>
                <span>{item.source} · held-out macro F1 · {item.test_rows ?? 0} test rows</span>
              </div>
            ))}
          </div>
        ) : <p className="limitation-footer">{audit?.model_benchmarks?.reason || 'No held-out model report is available yet.'}</p>}
      </Card>

      {audit?.events?.length ? (
        <Card title="Recent audit events" subtitle="Append-only ledger history, newest first.">
          <div className="table-wrap">
            <table className="analysis-table">
              <thead><tr><th>EVENT</th><th>PROJECT</th><th>ACTOR</th><th>DATE</th><th>ARTIFACT / DETAILS</th></tr></thead>
              <tbody>
                {audit.events.slice(0, 25).map((event, index) => (
                  <tr key={event.event_id || index}>
                    <td><Badge tone={event.event_type === 'PEER_REVIEW' ? 'blue' : 'violet'}>{event.event_type}</Badge></td>
                    <td>{event.project_id}</td>
                    <td>{event.actor}</td>
                    <td>{event.event_date}</td>
                    <td>{event.artifact_url ? <a href={event.artifact_url} target="_blank" rel="noreferrer" className="text-action">Open artifact <ArrowUpRight size={12} /></a> : event.details || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}

      <div className="notice blue-notice"><ShieldCheck size={17} /><div><b>Evidence rules</b><span>Dataset availability, marketplace installation, contribution points, model metrics, and actual AI use are reported as separate claims. Snowflake schema discovery does not imply that a listing is installed.</span></div></div>
    </div>
  );
}
