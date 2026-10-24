# Snowflake CoCo development workflow

## Actual usage record

**No Snowflake CoCo prompts, generated code, executed queries, or outputs are claimed.** CoCo was not connected to this workspace, and no account credentials were available during implementation. The following prompts are suggested for a future real session, not a record of work already performed.

## Suggested prompts to run and record

1. “Inspect the eligible vulnerability data available in this account. Return exact database, schema, listing/source attribution, access method, terms, columns, sample null counts, and record counts. Do not guess Marketplace availability.”
2. “Given the verified source schema, propose a bounded Snowflake query that normalizes CVE ID, publication/modification dates, CVSS, severity, CWE, product criteria, and source URL. Identify all untrusted or missing fields.”
3. “Review this MERGE for idempotence, duplicate handling, date parsing, role permissions, and warehouse efficiency. Do not execute until I approve the exact SQL.”
4. “Summarize source-backed publication and severity trends; distinguish missing data from zero and include query text and time window.”

Record the date, exact prompt, generated SQL, team edits, query ID, actual result counts, validation checks, and failures here after the session. Never invent output or performance claims. `snowflake/transformations.sql` is a manually written example and was not generated or run by CoCo.
