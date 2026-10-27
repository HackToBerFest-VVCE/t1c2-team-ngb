# Evaluation and verification record

## Runtime and source verification

Verified October 25, 2026 in the local workspace:

- The Flask API reports `LIVE` for `THREATLENS_DB.THREATLENS.VULNERABILITIES`; source health is `connected: true`.
- The app excludes 3,722 rejected/withdrawn rows from the 164,568 source rows and analyzes 160,846 active records. The source table has 164,568 distinct CVE IDs, and publication dates range from 2023-11-28 through 2026-10-24.
- Read-only schema, NULL, severity, CWE, and sample-record results are in [Snowflake setup](../snowflake/setup.md); reproducible SQL is in [exploration.sql](../snowflake/exploration.sql).
- API reporting includes a rolling 30-day UTC period plus full-corpus metrics. The supervised task models are separate from the active Snowflake corpus.

## Automated checks

- Backend: `pytest backend/tests` — 50 passed.
- Frontend: `npm test` — 13 passed.
- Frontend production bundle: `npm run build` — passed. Vite reports the minified JS chunk is about 657 kB, above its 500 kB advisory threshold; this is a code-splitting/performance opportunity, not a build failure.

Tests explicitly use DEMO mode for deterministic offline behavior. The separate LIVE health/data-source checks used the configured root `.env` and the dedicated read-only service identity.

## ML evaluation

### Active-corpus unsupervised analysis

The October 25 LIVE report used 5,000 deterministically sampled descriptions out of 160,846 active source records (the sample size is capped for CPU/RAM). TF-IDF/K-means produced a silhouette score of 0.056 and a most-frequent-cluster baseline share of 0.703. These are descriptive unsupervised diagnostics, not classification accuracy; the low silhouette indicates weak cluster separation in this sample. Isolation Forest was used only to rank unusual records. Neither method proves exploitation.

### Separate supervised task models

These are held-out results from separate Hugging Face datasets, not models trained on Snowflake NVD rows:

| Task | Test rows | Accuracy | Macro F1 | Limitation |
|---|---:|---:|---:|---|
| Vulnerable vs. fixed code snippets | 2,413 | 0.6917 | 0.6904 | Research triage; can miss vulnerabilities; grouped split by CVE |
| CVE severity from description | 1,539 | 0.7537 | 0.7148 | Labels and source coverage may be incomplete or biased |
| Incident event type | 2,648 | 0.8829 | 0.8580 | Dataset-specific held-out score, not a general incident detector |
| Malicious vs. benign honeypot | unavailable | — | — | 100 labeled rows contain only the malicious class |

All models used random state 42. Metrics only describe their held-out datasets; no score establishes the model's performance in production.

## Hackathon requirements still blocked

- **CoCo:** Two actual prompts were submitted in Snowsight on October 25. Both failed before SQL generation with “Cortex Code is not enabled or the usage limit has been reached,” even though CoCo Admin showed access enabled and the account had trial credits remaining. The request ID for the second attempt is recorded in [coco-workflow.md](coco-workflow.md). Direct SQL results above are not CoCo results.
- **Marketplace interpretation:** Account catalog checks found 4,373 visible listings. The free eSentire Threat Intelligence listing is IOC data, not a CVE catalog. The Cybersixgill vulnerability/exploit listing is by-request and not ready for import in this account. The selected NVD data is freely accessible and ingested into Snowflake, but it is not a Marketplace listing. Organizer rules must permit that source route for this requirement to count.

These are external account/eligibility conditions. No CoCo execution, listing approval, or qualification is fabricated in this project.
