# Connect a Snowflake cybersecurity dataset

ThreatLens can read a live Snowflake table or view. The repository does not include Snowflake account credentials, and no Marketplace dataset has been installed or verified here. Select and install the dataset in your Snowflake account first; do not use `SNOWFLAKE_SAMPLE_DATA` TPC-H/TPC-DS as threat intelligence.

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
- Either `SNOWFLAKE_PRIVATE_KEY_PATH` (preferred) with optional `SNOWFLAKE_PRIVATE_KEY_PASSPHRASE`, or `SNOWFLAKE_PASSWORD`
- Optional `SNOWFLAKE_ROLE`; `SNOWFLAKE_MAX_ROWS` defaults to 500,000 and cannot exceed 1,000,000

For key-pair authentication, register the corresponding public key on a dedicated Snowflake service user and store the private PKCS#8 key outside Git. The connector uses Snowflake JWT authentication. Never commit the private key or passphrase, and do not send credentials in chat or screenshots. The password option remains for accounts where it is appropriate.

Restart Flask, then check `GET /api/health` and `GET /api/data-sources`. The source reports `LIVE` only after it successfully reads the configured table/view. A green result confirms connectivity and schema compatibility; it does not establish Marketplace eligibility. Keep the listing name, provider, license, share/table name, and any competition eligibility evidence in `docs/dataset.md`.

## NVD alternative

The included `python -m backend.app.data.nvd_sync --start-year 2002 --target snowflake` command loads official NVD feeds into a writable canonical table. This is NVD-origin data stored in Snowflake, not a Snowflake Marketplace dataset. It is useful for development but must not be presented as the Marketplace source.

## Current verification

The Python connector path and setup are implemented, including direct read-only table/view access and optional key-pair authentication. No live connection, Marketplace listing, dataset schema, or account-specific training run has been verified because account access and the dataset identity are not present in this workspace.
