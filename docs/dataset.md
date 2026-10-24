# Dataset and attribution

## Local DEMO dataset and refresh

- **Provider:** National Institute of Standards and Technology, National Vulnerability Database (NVD), CVE API 2.0.
- **Source:** [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities-2.0) at `https://services.nvd.nist.gov/rest/json/cves/2.0`; per-record source links `https://nvd.nist.gov/vuln/detail/{CVE_ID}`.
- **Access:** A small starter snapshot is included. Use `python -m backend.app.data.nvd_sync` to import the current year and two preceding annual official NVD CVE 2.0 JSON feeds into the local DEMO source. Use `--start-year 2002` for all available years. Import years, record counts, method, and retrieval time are stored in `data/snapshot_metadata.json`.
- **Fields:** CVE identifier, English description, publication and modification timestamps, CVSS v4.0/v3.1/v3.0/v2 base score and severity when provided, CWE values where provided, CPE product criteria where provided, and NVD detail URL.
- **Missing values:** NVD may omit CVSS, CWE, product configurations, or descriptions for individual records. Missing is represented as null/unknown, not inferred.
- **Cleaning:** NVD records whose English description begins `Rejected reason:` are excluded from the active analytical dataset because those CVE IDs have been withdrawn/rejected.
- **Usage terms:** NVD data is made available by NIST; review the current NVD terms, attribution, and API policies before republishing a refreshed data collection. This repository's MIT license covers project code, not third-party dataset rights.
- **Limitations:** Local feed imports are NVD data in a local file, not live Snowflake and not a Snowflake Marketplace dataset. They have no verified exploit-in-the-wild field; the app does not infer exploitation. An optional command can load these feeds into a configured Snowflake table, but that does not change the upstream source's identity or qualify it as Snowflake-originated data.

## Snowflake status

No account was available during implementation; no Marketplace dataset, shared sample source, ingestion, or live connection is verified. `SNOWFLAKE_SAMPLE_DATA` TPC-H/TPC-DS sources are general decision-support benchmarks and do not meet this cybersecurity use case. See `snowflake/setup.md`. The project's definition of completion for a live/qualifying Snowflake deployment is therefore not met.

The NVD importer supports `--target snowflake` when credentials and table write access are configured. This integration has not been executed or verified in the current workspace.
