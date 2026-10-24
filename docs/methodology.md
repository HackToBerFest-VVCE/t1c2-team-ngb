# Methodology

## Severity and priority

Official severity and CVSS values are displayed exactly as available from NVD/the configured table. ThreatLens priority is a separate 0–100 heuristic:

`100 × (0.8 × CVSS/10 + 0.2 × max(0, 1 - age_days/365))`

Publication age is computed in UTC from `PUBLISHED`. The recency term reaches zero at 365 days. When CVSS is absent, the available recency component is rescaled to its 20-point contribution; when publication date is absent, CVSS contributes its full normalized 80-point weight. If both are missing, priority is unavailable. This is only an investigation ordering aid; it is not CVSS, an exploit prediction, or proof of active attack.

## ML

Descriptions are vectorized with TF-IDF (unigrams and bigrams, max 500 features); K-means uses deterministic seed 42 and a cluster count bounded by sample size. Cluster top terms and representative records are exposed. Silhouette is reported only when defined. A most-frequent-cluster baseline is reported descriptively, not as accuracy. Isolation Forest uses the text vector and median-imputed CVSS, 100 trees, seed 42; lower decision values are more unusual. When more than 5,000 described rows are available, a deterministic 5,000-row sample is used for ML to bound CPU/RAM; dashboards and aggregates use the full loaded result set. The minimum dataset for either analysis is four non-empty descriptions. No labels exist, so accuracy/precision/recall are not reported. Text clusters and anomaly scores do not establish maliciousness or exploitation.

Optional Hugging Face models are trained separately from `hitoshura25/cvefixes`, `vinitvek/cybersecurityattacks`, and `pyToshka/network-intrusion-detection`. Tasks are vulnerable-versus-fixed code snippet classification, CVE severity-from-description classification, incident event-type classification, and malicious-versus-benign honeypot classification when enough labels exist. TF-IDF plus logistic regression uses seed 42 and a held-out split; code examples are grouped by CVE to limit train/test leakage. Scores describe performance on the selected dataset only. The honeypot dataset has only 100 rows according to its Hub viewer and may be skipped if labels are insufficient. No model is a production IDS or a substitute for validation, security review, or source verification. Downloaded datasets and model artifacts stay local and outside Git.

Optional generative analysis is available through NVIDIA NIM's OpenAI-compatible chat-completions API. Provider choices map to NVIDIA-hosted Nemotron, Kimi, and DeepSeek models. An explicit user action sends counts, up to eight recent public CVE examples, and up to five anomaly candidate IDs to the selected provider; credentials stay server-side. Model output is an interpretation, not source evidence, and must not be treated as an exploitation verdict. No provider call is made until the user clicks **Analyze patterns**.

## Scope

Snowflake reads at most `SNOWFLAKE_MAX_ROWS` (default 500,000; maximum 1,000,000), latest publication first. Overview's recent measure is a rolling 30-day UTC window. Trends are bounded by the selected rolling days and include zero-count months so different windows remain visible. Missing publication dates are excluded from time charts; missingness is exposed in Data Explorer. DEMO mode reads the local NVD snapshot, which can be refreshed using the official annual NVD 2.0 feeds.

For NVD source rows, records whose English description begins `Rejected reason:` are omitted from analytical counts and modeling because the CVE was rejected or withdrawn.
