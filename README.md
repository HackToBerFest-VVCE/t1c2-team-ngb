# ThreatLens AI

**From Open Cyber Data to Explainable Intelligence**

ThreatLens AI is an evidence-linked vulnerability analysis dashboard built with React, Flask, pandas, scikit-learn, optional generative analysis through NVIDIA NIM, and a Snowflake data provider. Its local development environment is connected to a Snowflake table populated from official NIST NVD CVE feeds; this is NVD-origin data stored in Snowflake, not a Marketplace listing. See [Snowflake setup and current connection](snowflake/setup.md).

## Current implementation status

- Usable local dashboard and Flask REST API over source-backed NVD sample data.
- Vulnerability Explorer filters by text, severity, publication dates, CVSS range, and CWE; sort and pagination controls are available, and CSV/JSON exports preserve the active filter scope.
- CVE drill-down with NVD evidence links and a readable HTML report.
- Severity/publication metrics, data-quality inspection, transparent priority heuristic, deterministic text clusters, and anomaly exploration. ML is deterministically sampled at 5,000 records for resource bounds while aggregates use all loaded rows.
- Rolling trend horizons with month buckets, explicit date boundaries, zero-activity months, and stale-request protection when changing the selector.
- Optional, click-to-run generative analysis that cites supplied CVE IDs and distinguishes source fields from unsupervised signals.
- NVD 2.0 annual-feed import for a local DEMO copy or configured Snowflake target.
- Snowflake connector/provider with password or key-pair authentication, plus bounded read-only access to a configured table or compatibility view.
- **Live Snowflake connection verified:** `THREATLENS_DB.THREATLENS.VULNERABILITIES`, populated with NVD annual feeds for 2024–2026. The service role is read-only and uses a capped X-Small warehouse. This is not a Snowflake Marketplace dataset; confirm the hackathon's source eligibility separately.
- CoCo was unavailable; actual use is not claimed. See `docs/coco-workflow.md`.

## Architecture

![Halloween-themed ThreatLens AI system architecture](docs/architecture.svg)

See the [architecture notes](docs/architecture.md). CoCo supports the human development workflow only; it is not in the running application's analytical path.

## Working application screenshots

These screenshots are captured from the running app using its configured live Snowflake source: [Overview](screenshots/overview.png), [Vulnerability Explorer](screenshots/explorer.png), and [ML Insights](screenshots/ml-insights.png). DEMO and LIVE mode are visibly identified in the app.

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

Open `http://localhost:5173`. Flask API is at `http://localhost:5000/api`. This workspace's ignored `.env` selects `DATA_SOURCE=snowflake`; for a clean clone, `DATA_SOURCE=demo` remains the safe default. See [snowflake/setup.md](snowflake/setup.md) for this account's configuration and verification.

## Data and attribution

The bundled snapshot is 30 records fetched from NIST NVD API 2.0 during setup. See [docs/dataset.md](docs/dataset.md) and `data/snapshot_metadata.json` for the query window, fields, missing data, limitations, and source terms. This snapshot is not refreshed automatically. Account checks found the shared `SNOWFLAKE_SAMPLE_DATA` database contains only TPC-H/TPC-DS schemas, which are not cybersecurity datasets. The account's Marketplace catalog was also reviewed; source-selection evidence is in [docs/dataset.md](docs/dataset.md).

To enlarge local data from NIST's annual compressed CVE 2.0 feeds (default: current year and two prior years):

```powershell
python -m backend.app.data.nvd_sync
# Full NVD history, 2002 to current year:
python -m backend.app.data.nvd_sync --start-year 2002
```

The raw historical catalog stays out of Git. A compact Parquet artifact of the current public NVD catalog is bundled for the hosted DEMO so it matches the full-catalog local view; refresh it from the generated `data/vulnerabilities.full.json` catalog with pandas' PyArrow Parquet support. NVD records are distinct from evidence of observed attacks: CVSS severity does not mean a vulnerability was exploited. `render.yaml` currently selects Render's free plan; if the full catalog or ML workload exceeds its memory limit, choose an appropriately sized plan before deployment (paid plans may incur charges).

### Optional Hugging Face datasets and training

Install the Python requirements, then import the reviewed public datasets and train their separate task models:

```powershell
python -m backend.app.data.hf_sync
python -m backend.app.data.train_models
```

The import reads `hitoshura25/cvefixes` (Apache-2.0), `vinitvek/cybersecurityattacks` (Unlicense), and `pyToshka/network-intrusion-detection` (BSD-3-Clause) from Hugging Face. CVEfixes can require a large download. Downloaded source data stays local and ignored by Git; the trained task artifacts and evaluation report are bundled so the hosted ML Insights page matches the local results. The trainer keeps tasks separate, uses deterministic held-out evaluation, groups CVE code examples by CVE during splitting, and reports limitations at `GET /api/ml/training` and in the ML Insights page. The small honeypot dataset may not contain enough balanced labels to train a model; in that case the report explains why it was skipped. Dataset licenses, provenance, and labels should be reviewed before downstream use.

The connected Snowflake table contains NVD-origin CVE records imported from the official 2024, 2025, and 2026 annual feeds. Snowflake-backed dashboard aggregates, clustering, and anomaly analysis use that active source. Hugging Face supervised models remain a separate training path and are trained from the selected HF datasets by `train_models`; NVD records stored in Snowflake are not a Marketplace dataset and are not silently mixed into those training sets. See [the connected account's sample and Marketplace source review](docs/dataset.md#source-selection-check-in-the-connected-account-october-25-2026).

## Snowflake and CoCo

The provider reads a fixed set of canonical CVE columns and bounds results using `SNOWFLAKE_MAX_ROWS` (500,000 default, 1,000,000 maximum). Credentials remain backend-side; key-pair authentication is supported. This account's dedicated service role has read-only table access. Two genuine CoCo requests were submitted but both failed before analysis with a Snowflake Cortex Code service-entitlement error; no CoCo output is claimed. See the exact prompts and request ID in `docs/coco-workflow.md`.

## Optional generative analysis

Put each provider's own API key in its matching backend-only variable (`NVIDIA_API_KEY`, `KIMI_API_KEY`, or `DEEPSEEK_API_KEY`) in `.env`, then restart Flask to enable generated AI commentary. Without a key, **Analyze locally** still produces a deterministic, evidence-grounded summary from the active dataset and ML outputs; it makes no third-party AI request. With a key configured, the ML Insights page can select Nemotron, Kimi, or DeepSeek, and sends bounded summary metrics and CVE examples only after **Analyze patterns** is clicked. Do not put keys in frontend variables, source control, screenshots, or logs. See [docs/methodology.md](docs/methodology.md) for scope and limitations.

## API

`GET /api/health`, `/api/data-sources`, `/api/metrics`, `/api/summary`, `/api/vulnerabilities?q=&severity=&from=&to=&min_score=&max_score=&cwe=&sort=&order=&page=&per_page=`, `/api/vulnerabilities/<cve_id>`, `/api/trends?days=`, `/api/ai/status`, `POST /api/ai/insights` (`{"days":90}`), `/api/risk-analysis`, `/api/ml/clusters`, `/api/ml/anomalies`, `/api/ml/training`, `/api/data-quality`, `/api/reports/summary`, and `POST /api/reports/export` (accepts the same filters as the Explorer plus `format: csv|json`). Errors use `{ "error": {"code":"...","message":"..."} }`. CORS is restricted to `FRONTEND_ORIGINS`; request inputs are validated and unrestricted SQL is unavailable.

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

Add any provider API key and Snowflake credentials in the Render service's Environment settings only; never put secrets in Git or frontend `VITE_*` variables. The Blueprint intentionally contains no credentials. To deploy against Snowflake, provision a separate service identity/key and warehouse for the deployment, then configure its matching table and credentials. The service health check is `/api/health`.
