# Snowflake CoCo development workflow

## Actual usage record

**Attempted: October 25, 2026, in Snowsight CoCo.** CoCo chat was available in the UI, but it did not perform an analysis. Two read-only prompts returned the same service error: “Cortex Code is not enabled or the usage limit has been reached. Please upgrade your account to continue using Cortex Code.” The second request ID was `34e067e7-d99f-4038-9059-ffa31cf05729`. No CoCo-generated SQL or results are claimed, and no account setting was changed or upgrade made.

Read-only diagnosis in CoCo Admin and SQL: CoCo Admin reports **enabled for the account**, all regions enabled, two roles enabled, all users enabled, and 58 models. `CORTEX_ENABLED_CROSS_REGION` is `ANY_REGION`; `SNOWFLAKE.CORTEX_USER` is granted to `PUBLIC`; the account and `YOGIXXEE` user values for `CORTEX_CODE_SNOWSIGHT_DAILY_EST_CREDIT_LIMIT_PER_USER` are both `-1` (no configured daily limit). Despite those settings, the CoCo request still fails with the message above. This points to a remaining service entitlement or usage availability issue that cannot be corrected by the inspected account settings. The CoCo Admin usage chart counted two Snowsight requests on October 25; that count does not establish either request completed successfully.

First exact prompt submitted (read-only request):

> For the ThreatLens AI challenge, analyze the existing table `THREATLENS_DB.THREATLENS.VULNERABILITIES` using read-only SELECT queries only. Report the actual schema, total rows, distinct CVE_ID count, rejected/withdrawn rows whose DESCRIPTION starts with `Rejected reason:`, NULL counts for CVSS_SCORE, SEVERITY, CWE and AFFECTED_PRODUCTS, publication date range, and top severity/CWE counts. State clearly that the source is NVD public-feed data stored in this Snowflake account and whether this table itself proves it is a Marketplace listing (do not assume that). Do not create, modify, insert, delete, or grant anything; do not use another dataset. Include the SQL executed and actual results, and say if any item could not be verified.

The table was independently checked with read-only SQL using the application service role; these checks are recorded in `snowflake/setup.md` and `docs/dataset.md`. They are not CoCo results. CoCo must be enabled or its usage limit resolved in the Snowflake account before a genuine CoCo exploration can be completed.

Second exact prompt submitted in a new chat:

> Analyze `THREATLENS_DB.THREATLENS.VULNERABILITIES` for ThreatLens AI. Use read-only SELECT/DESCRIBE on this table only; make no changes. Show actual SQL and results: schema, total and distinct CVE count, rejected rows, NULL counts for CVSS_SCORE/SEVERITY/CWE/AFFECTED_PRODUCTS, publication date range, severity counts, top 10 CWEs, and 5 sample CVEs with scores, severity, CWE, date, source URL. Summarize findings and limitations. Identify source as NVD ingested into Snowflake; do not call it Marketplace data unless verified.

The second request also failed with the same service error before returning any SQL or analysis. CoCo is an explicit challenge requirement, so the submission is not fully compliant until this account-side service issue is resolved and a real assisted exploration is completed and verified.

The following prompts remain suggestions for a future real CoCo session, not a record of work already performed.

## Suggested prompts to run and record

1. “Inspect the eligible vulnerability data available in this account. Return exact database, schema, listing/source attribution, access method, terms, columns, sample null counts, and record counts. Do not guess Marketplace availability.”
2. “Given the verified source schema, propose a bounded Snowflake query that normalizes CVE ID, publication/modification dates, CVSS, severity, CWE, product criteria, and source URL. Identify all untrusted or missing fields.”
3. “Review this MERGE for idempotence, duplicate handling, date parsing, role permissions, and warehouse efficiency. Do not execute until I approve the exact SQL.”
4. “Summarize source-backed publication and severity trends; distinguish missing data from zero and include query text and time window.”

Record the date, exact prompt, generated SQL, team edits, query ID, actual result counts, validation checks, and failures here after the session. Never invent output or performance claims. `snowflake/transformations.sql` is a manually written example and was not generated or run by CoCo.
