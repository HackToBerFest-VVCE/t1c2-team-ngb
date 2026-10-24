# ThreatLens AI

**From Open Cyber Data to Explainable Intelligence**

ThreatLens AI is an evidence-linked vulnerability analysis dashboard built with React, Flask, pandas, scikit-learn, optional generative analysis through NVIDIA NIM, and a Snowflake data provider. Its local default is visibly labeled DEMO. Configure the provider to read a compatible live Snowflake Marketplace table/view; see [snowflake/setup.md](snowflake/setup.md).

## Current implementation status

- Usable local dashboard and Flask REST API over source-backed NVD sample data.
- Filtering, pagination, CVE drill-down, evidence links, CSV/JSON exports, and readable HTML report.
- Severity/publication metrics, data-quality inspection, transparent priority heuristic, deterministic text clusters, and anomaly exploration. ML is deterministically sampled at 5,000 records for resource bounds while aggregates use all loaded rows.
- Rolling trend horizons with month buckets, explicit date boundaries, zero-activity months, and stale-request protection when changing the selector.
- Optional, click-to-run generative analysis that cites supplied CVE IDs and distinguishes source fields from unsupervised signals.
- NVD 2.0 annual-feed import for a local DEMO copy or configured Snowflake target.
- Snowflake connector/provider with password or key-pair authentication, plus bounded read-only access to a configured table or compatibility view.
- **Live Snowflake access and a hackathon-qualifying Snowflake dataset are unverified** because no account access or credentials were available. The project is not ready for a submission claiming a live Snowflake dataset.
- CoCo was unavailable; actual use is not claimed. See `docs/coco-workflow.md`.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the Mermaid data flow. CoCo supports the human development workflow only; it is not in the running application's analytical path.

## Start locally

Requirements: Python 3.11+ (tested target is 3.13) and Node.js 20+.

```powershell
Copy-Item .env.example .env
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
# Run backend (from workspace root):
python backend\run.py
# Note: If your terminal is already inside the 'backend' folder, use: python run.py
```

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Flask API is at `http://localhost:5000/api`. `DATA_SOURCE=demo` is the safe default. To use the configured Snowflake provider, follow [snowflake/setup.md](snowflake/setup.md), set `DATA_SOURCE=snowflake`, populate secrets in `.env`, and restart the backend. Live status requires a successful query to the configured table.

## Data and attribution

The bundled snapshot is 30 records fetched from NIST NVD API 2.0 during setup. See [docs/dataset.md](docs/dataset.md) and `data/snapshot_metadata.json` for the query window, fields, missing data, limitations, and rights notes. This snapshot is not refreshed automatically. Snowflake's documented TPC-H/TPC-DS samples are not cybersecurity datasets and are not represented as a qualifying source here.

To enlarge local data from NIST's annual compressed CVE 2.0 feeds (default: current year and two prior years):

```powershell
python -m backend.app.data.nvd_sync
# Full NVD history, 2002 to current year:
python -m backend.app.data.nvd_sync --start-year 2002
```

The raw historical catalog is large and stays out of Git. A compressed copy of the current public NVD catalog is bundled for the hosted DEMO so it matches the full-catalog local view; refresh it by regenerating `data/vulnerabilities.full.json` and its metadata, then recompressing the JSON file. NVD records are distinct from evidence of observed attacks: CVSS severity does not mean a vulnerability was exploited.

### Optional Hugging Face datasets and training

Install the Python requirements, then import the reviewed public datasets and train their separate task models:

```powershell
python -m backend.app.data.hf_sync
python -m backend.app.data.train_models
```

The import reads `hitoshura25/cvefixes` (Apache-2.0), `vinitvek/cybersecurityattacks` (Unlicense), and `pyToshka/network-intrusion-detection` (BSD-3-Clause) from Hugging Face. CVEfixes can require a large download. Downloaded source data stays local and ignored by Git; the trained task artifacts and evaluation report are bundled so the hosted ML Insights page matches the local results. The trainer keeps tasks separate, uses deterministic held-out evaluation, groups CVE code examples by CVE during splitting, and reports limitations at `GET /api/ml/training` and in the ML Insights page. The small honeypot dataset may not contain enough balanced labels to train a model; in that case the report explains why it was skipped. Dataset licenses, provenance, and labels should be reviewed before downstream use.

For the live Snowflake dataset, configure `DATA_SOURCE=snowflake` and point `SNOWFLAKE_TABLE` at a table or compatibility view exposing the canonical CVE columns. Snowflake-backed dashboard aggregates, clustering, and anomaly analysis use that active source. Hugging Face supervised models remain a separate training path and are trained from the selected HF datasets by `train_models`; a Snowflake marketplace table is not silently mixed into those training sets. The optional `nvd_sync --target snowflake` command loads NVD-origin records into a writable Snowflake table; it is not a Marketplace dataset. No account credentials or Marketplace dataset identity are available in this workspace, so a live source has not yet been connected or verified.

## Snowflake and CoCo

The provider reads a fixed set of canonical CVE columns and bounds results using `SNOWFLAKE_MAX_ROWS` (500,000 default, 1,000,000 maximum). Credentials remain backend-side; key-pair authentication is supported. A real CoCo usage log is pending an accessible Snowflake account; suggested prompts are labeled as future prompts in `docs/coco-workflow.md`.

## Optional generative analysis

Put each provider's own API key in its matching backend-only variable (`NVIDIA_API_KEY`, `KIMI_API_KEY`, or `DEEPSEEK_API_KEY`) in `.env`, then restart Flask. The ML Insights page can select Nemotron, Kimi, or DeepSeek when its matching key is configured, and runs analysis only when **Analyze patterns** is clicked. The action sends summary metrics, up to 80 Critical/High CVEs (severity Critical/High or CVSS ≥ 7), plus up to 20 lower-severity comparison examples, and up to five ML anomaly candidates to the selected provider's endpoint. Do not put keys in frontend variables, source control, screenshots, or logs. See [docs/methodology.md](docs/methodology.md) for scope and limitations.

## API

`GET /api/health`, `/api/data-sources`, `/api/metrics`, `/api/vulnerabilities?q=&severity=&min_score=&max_score=&from=&to=&sort=&order=&page=&per_page=`, `/api/vulnerabilities/<cve_id>`, `/api/trends?days=`, `/api/ai/status`, `POST /api/ai/insights` (`{"days":90}`), `/api/risk-analysis`, `/api/ml/clusters`, `/api/ml/anomalies`, `/api/data-quality`, `/api/reports/summary`, and `POST /api/reports/export` (`{"format":"csv|json","q":"","severity":[]}`). Errors use `{ "error": {"code":"...","message":"..."} }`. CORS is restricted to `FRONTEND_ORIGINS`; request inputs are validated and unrestricted SQL is unavailable.

## Method and limitations

Risk methodology and ML evaluation are detailed in [docs/methodology.md](docs/methodology.md). CVSS/severity remain source fields. The custom score is not official CVSS. Unsupervised model results have no labeled ground truth and are not threat confirmation. Snowflake's configurable 500,000-row default bound, missing values, source date coverage, and local demo snapshot constrain findings.

## Development checks

```powershell
pytest backend/tests
cd frontend; npm test; npm run build
```

This code is licensed under MIT; third-party datasets and NVD data terms remain separate. External datasets and model artifacts are excluded from source control.

## License

MIT for project code. Third-party data and dependency terms remain applicable.

## Deploy to Render

This repository includes a Render Blueprint and a multi-stage Docker build. The initial service runs in DEMO mode and serves the React application and Flask API from one origin. To deploy, open [ThreatLens AI on Render Blueprints](https://dashboard.render.com/blueprint/new?repo=https://github.com/yogesh-37911/Threat-Lens-Ai), connect the GitHub repository, review the Blueprint, and apply it. Render builds and deploys on pushes to `main`.

Add any provider API key and Snowflake credentials in the Render service's Environment settings only; never put secrets in Git or frontend `VITE_*` variables. The Blueprint intentionally contains no credentials. Snowflake remains disabled until you provide the Marketplace dataset identity and configure the matching table and credentials. The service health check is `/api/health`.
