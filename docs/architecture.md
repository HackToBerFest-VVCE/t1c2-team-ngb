# Architecture

```mermaid
flowchart LR
  NVD[NVD API 2.0 / eligible Snowflake dataset] --> STG[Snowflake staging]
  STG --> SQL[Validated Snowflake transformations]
  SQL --> TAB[Canonical vulnerability table]
  TAB --> PROVIDER[Flask data-source abstraction]
  DEMO[Bundled, attributed NVD snapshot] --> PROVIDER
  PROVIDER --> ANALYTICS[pandas / scikit-learn analysis]
  ANALYTICS --> API[Flask REST API]
  API --> UI[React + Vite dashboard]
  UI --> REPORTS[CSV / JSON / HTML]
```

Snowflake CoCo may assist humans exploring the source and iterating on SQL, but it is not a runtime dependency or data source. Demo mode reads the bundled snapshot. Live mode requires configured Snowflake access and a real canonical table; API health only reports live after source access succeeds. The frontend never receives Snowflake credentials.
