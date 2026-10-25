# Connect a Snowflake cybersecurity dataset

ThreatLens can read a live Snowflake table or view. This workspace is connected to an NVD CVE table in the user's account. The source is NVD-origin data stored in Snowflake, not a Marketplace dataset. Do not use `SNOWFLAKE_SAMPLE_DATA` TPC-H/TPC-DS as threat intelligence.

## Dataset shape

The current dashboard is vulnerability-centric. Its Snowflake source expects these canonical columns: `CVE_ID`, `DESCRIPTION`, `PUBLISHED`, `LAST_MODIFIED`, `CVSS_SCORE`, `SEVERITY`, `CWE`, `AFFECTED_PRODUCTS`, and `SOURCE_URL`. Point `SNOWFLAKE_TABLE` at a compatible table, or create a view over the shared Marketplace table that aliases its fields to this schema. Keep the Marketplace table read-only; the application only runs a bounded `SELECT`.

Example view pattern (replace the placeholders with columns verified in your installed dataset):

```sql
CREATE OR REPLACE VIEW THREATLENS.CVE_SOURCE AS
SELECT
  <source_cve_id> AS CVE_ID,
  <source_description> AS DESCRIPTION,
  <source_published_timestamp> AS PUBLISHED,
  <source_modified_timestamp> AS LAST_MODIFIED,
  <source_cvss_score> AS CVSS_SCORE,
  <source_severity> AS SEVERITY,
  <source_cwe> AS CWE,
  <source_affected_products> AS AFFECTED_PRODUCTS,
  <source_advisory_url> AS SOURCE_URL
FROM <marketplace_database>.<marketplace_schema>.<marketplace_table>;
```

If your dataset contains network events or incident logs rather than CVE records, it does not fit this CVE view. Record its schema and intended analysis first; it needs an event-specific ingestion/analytics path instead of being relabeled as CVEs.

## Configure credentials

Copy `.env.example` to `.env`, then set `DATA_SOURCE=snowflake` and the following backend-only values:

- `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_WAREHOUSE`
- `SNOWFLAKE_DATABASE`, `SNOWFLAKE_SCHEMA`, `SNOWFLAKE_TABLE`
- Either `SNOWFLAKE_PRIVATE_KEY_PATH` (preferred locally), `SNOWFLAKE_PRIVATE_KEY_BASE64` (base64-encoded PEM for serverless deployments), or `SNOWFLAKE_PASSWORD`; optionally set `SNOWFLAKE_PRIVATE_KEY_PASSPHRASE` for an encrypted key
- Optional `SNOWFLAKE_ROLE`; `SNOWFLAKE_MAX_ROWS` defaults to 500,000 and cannot exceed 1,000,000

For key-pair authentication, register the corresponding public key on a dedicated Snowflake service user and store the private PKCS#8 key outside Git. The connector uses Snowflake JWT authentication. Never commit the private key or passphrase, and do not send credentials in chat or screenshots. The password option remains for accounts where it is appropriate.

For Vercel, set the base64-encoded PEM in the **backend project's encrypted environment variable** `SNOWFLAKE_PRIVATE_KEY_BASE64`. Also set the account, user, warehouse, database, schema, table, role, and `DATA_SOURCE=snowflake` values as production-only environment variables. Never use a `VITE_` prefix. Vercel injects these values at runtime; no private-key file needs to be checked into the repository.

Restart Flask, then check `GET /api/health` and `GET /api/data-sources`. The source reports `LIVE` only after it successfully reads the configured table/view. A green result confirms connectivity and schema compatibility; it does not establish Marketplace eligibility. Keep the listing name, provider, license, share/table name, and any competition eligibility evidence in `docs/dataset.md`.

## NVD alternative

The included `python -m backend.app.data.nvd_sync --start-year 2002 --target snowflake` command loads official NVD feeds into a writable canonical table. This is NVD-origin data stored in Snowflake, not a Snowflake Marketplace dataset. Importing requires write grants; the app service identity is read-only.

## Current verification

The live connection was verified through `GET /api/health` on October 25, 2026. The API returned `LIVE`, connected, and read 160,846 active records from `THREATLENS_DB.THREATLENS.VULNERABILITIES` (after excluding NVD rejected/withdrawn CVEs). The source has 164,568 rows and distinct CVE IDs, including 3,722 rejected/withdrawn rows. Published values range from 2023-11-28 through 2026-10-24. The app uses service user `THREATLENS_APP_SVC`, role `THREATLENS_APP_ROLE`, a PKCS#8 private key stored outside the repository, and an X-Small warehouse `THREATLENS_WH` with 60-second auto-suspend. Resource monitor `THREATLENS_NVD_MONITOR` caps warehouse consumption at 2 credits per month and suspends at the cap. The service role has SELECT access and no table write or schema create grants. This table is NVD-origin data, not Marketplace data.

### Verified source schema and quality (October 25, 2026)

`DESC TABLE THREATLENS_DB.THREATLENS.VULNERABILITIES` returned the following columns: `CVE_ID VARCHAR NOT NULL PRIMARY KEY`; `DESCRIPTION VARCHAR`; `PUBLISHED TIMESTAMP_TZ(9)`; `LAST_MODIFIED TIMESTAMP_TZ(9)`; `CVSS_SCORE FLOAT`; `SEVERITY VARCHAR`; `CWE VARCHAR`; `AFFECTED_PRODUCTS VARCHAR`; `SOURCE_URL VARCHAR`; `INGESTED_AT TIMESTAMP_TZ(9) DEFAULT CURRENT_TIMESTAMP()` (all fields except CVE_ID are nullable).

Read-only aggregate results from that same table: NULL CVSS 7,378; NULL severity 0; NULL CWE 10,304; NULL affected-products 73,337. Severity values after excluding rejected records: MEDIUM 69,947; HIGH 60,305; CRITICAL 16,278; LOW 10,558; UNKNOWN 3,656; NONE 102. Top CWE tokens: CWE-79 22,051; CWE-89 9,984; CWE-862 8,227; NVD-CWE-noinfo 8,062; CWE-284 6,096; CWE-416 4,837; CWE-22 4,736; CWE-74 4,726; CWE-787 4,421; CWE-125 4,192. These CWE token counts can exceed record counts because a CVE can contain more than one CWE value.

`snowflake/exploration.sql` contains the reproducible `DESC` and `SELECT` statements used for schema and quality review. These results came from the service role's direct Snowflake SQL calls, not from CoCo.
