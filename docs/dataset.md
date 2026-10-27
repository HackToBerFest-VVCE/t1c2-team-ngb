# Dataset and attribution

## Local DEMO dataset and refresh

- **Provider:** National Institute of Standards and Technology, National Vulnerability Database (NVD), CVE API 2.0.
- **Source:** [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities-2.0) at `https://services.nvd.nist.gov/rest/json/cves/2.0`; per-record source links `https://nvd.nist.gov/vuln/detail/{CVE_ID}`.
- **Access:** A small starter snapshot is included. Use `python -m backend.app.data.nvd_sync` to import the current year and two preceding annual official NVD CVE 2.0 JSON feeds into the local DEMO source. Use `--start-year 2002` for all available years. Import years, record counts, method, and retrieval time are stored in `data/snapshot_metadata.json`.
- **Fields:** CVE identifier, English description, publication and modification timestamps, CVSS v4.0/v3.1/v3.0/v2 base score and severity when provided, CWE values where provided, CPE product criteria where provided, and NVD detail URL.
- **Missing values:** NVD may omit CVSS, CWE, product configurations, or descriptions for individual records. Missing is represented as null/unknown, not inferred.
- **Cleaning:** NVD records whose English description begins `Rejected reason:` are excluded from the active analytical dataset because those CVE IDs have been withdrawn/rejected.
- **Usage terms:** The dataset is freely accessible through NIST's [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities-2.0) and [data feeds](https://nvd.nist.gov/vuln/data-feeds). Follow the current [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use), API policy, and any upstream CVE/CNA attribution requirements before republishing refreshed data. This repository's MIT license covers project code, not third-party dataset rights.
- **Limitations:** Local feed imports are NVD data in a local file, not live Snowflake and not a Snowflake Marketplace dataset. They have no verified exploit-in-the-wild field; the app does not infer exploitation. An optional command can load these feeds into a configured Snowflake table, but that does not change the upstream source's identity or qualify it as Snowflake-originated data.

## Snowflake status

The configured account contains NVD-origin vulnerability data in `THREATLENS_DB.THREATLENS.VULNERABILITIES`. Read-only verification found 164,568 table rows from the 2024–2026 annual feeds; 3,722 rows have an NVD rejected/withdrawn description and are excluded by the app, leaving 160,846 active records. The table has a unique CVE ID key. Published dates span 2023-11-28 through 2026-10-24. This is NVD data stored in Snowflake, not a Marketplace dataset or Snowflake-shared listing.

### Source-selection check in the connected account (October 25, 2026)

- `SHOW DATABASES LIKE 'SNOWFLAKE_SAMPLE_DATA'` found the shared sample database. `SHOW SCHEMAS IN DATABASE SNOWFLAKE_SAMPLE_DATA` returned `TPCH_SF1`, `TPCH_SF10`, `TPCH_SF100`, `TPCH_SF1000`, `TPCDS_SF10TCL`, and `TPCDS_SF100TCL`, plus `INFORMATION_SCHEMA`. These benchmark schemas do not contain the CVE fields required by ThreatLens.
- `SHOW AVAILABLE LISTINGS` returned 4,373 listings visible to the connected role. Title screening for CVE, vulnerability, cybersecurity, and threat intelligence surfaced seven candidates. The free, non-requested **Threat Intelligence** listing (`GZSVZGDE8N`, eSentire) describes static IOC indicators in `ES_PROD_DB.SECURE.TI_INCIDENT_INDICATORS_SAMPLE`; it is not a CVE history dataset. The relevant **Vulnerability and Exploit Intelligence** listing (`GZT0ZBOLWEA`, Cybersixgill) describes a `DVEFEED` with CVE IDs and exploit-intelligence fields, but is by request, not ready for import in this account/region, has no preview/dictionary in the account, and points to external terms. It was not installed or treated as an eligible free source.
- The selected source is therefore NVD CVE 2.0, which is freely accessible and already ingested and verified in the Snowflake account. This selection satisfies a “freely accessible dataset in Snowflake” interpretation if external public data ingested into Snowflake is allowed. If the hackathon requires a Marketplace listing specifically, that eligibility is not satisfied by this NVD table; organizer confirmation or access approval for an eligible listing is still required.

The source comparison was performed using the application's dedicated Snowflake service role with read-only `SHOW`/`DESCRIBE` commands. It is not CoCo output.

The NVD importer supports `--target snowflake`; this integration was executed and verified for 2024–2026. The app service role now has read-only access; import requires an authorized role with write privileges.
