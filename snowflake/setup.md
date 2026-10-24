# Snowflake setup and current verification status

## Account inspection

At initial implementation, the workspace had no Snowflake credentials or connector, no connected Snowflake/CoCo tool, and no Snowflake account access was provided. Thus no sample database, Marketplace listing, target table, or live connection could be inspected. **A qualifying Snowflake dataset is not yet verified or accessible in this project.** Do not use TPC-H/TPC-DS sample data as vulnerability intelligence; Snowflake documents these as decision-support benchmarks, not cyber datasets.

Snowflake documents `SNOWFLAKE_SAMPLE_DATA` as a shared sample database with TPC-H and TPC-DS. Marketplace listings require account inspection, which has not happened. The app defaults to bundled NVD DEMO mode until a real qualifying table is configured and verified.

## Configure a table

1. Review the current hackathon rules for data-source eligibility and obtain account access.
2. Find/verify an eligible vulnerability source in the account. Document its provider, listing/table name, license, access method, and eligibility evidence in `docs/dataset.md`.
3. Create a writable target database/schema/table using `schema.sql` (adjust the database/schema qualification).
4. Create the canonical table with `schema.sql`, then (once backend Snowflake credentials and write permissions are configured) run `python -m backend.app.data.nvd_sync --start-year 2002 --target snowflake` to download and upsert official annual NVD CVE 2.0 feeds. This is an NVD dataset loaded into Snowflake, not a Snowflake Marketplace dataset. Confirm hackathon eligibility before making a qualifying-source claim. The script processes years sequentially and may take time/warehouse resources.
5. Set the Snowflake environment variables from `.env.example`; set `DATA_SOURCE=snowflake`.
6. Start the API and request `/api/health`, `/api/data-sources`, `/api/data-quality`. LIVE is shown only after the connector can query the configured table.

Snowflake sample shared databases are read-only and query execution requires a running warehouse; copying into a writable target incurs normal warehouse usage. Limit the role to required table access. Never add credentials to source control.

The provider uses a fixed set of canonical columns and bounds reads using `SNOWFLAKE_MAX_ROWS` (default 500,000; maximum 1,000,000). `SNOWFLAKE_TABLE` is validated as a SQL identifier before interpolation; row-limit values are bound and no user SQL is accepted. The ML pipeline deterministically caps its model sample at 5,000 rows while aggregate counts use the complete active provider result.
