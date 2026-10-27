# NVD CVE data

The project uses the NIST National Vulnerability Database (NVD) CVE 2.0 JSON
feeds: <https://nvd.nist.gov/vuln/data-feeds>. NVD data is publicly available;
NIST requests attribution and its terms/limitations apply. This dataset is
not an official statement that a vulnerability is exploitable in a given
environment. A CVE record may have missing CVSS, CWE, or product enrichment.

The checked-in starter snapshot is a small DEMO sample. Enlarge a local DEMO
copy from the official annual feeds (default: current year and two preceding
years):

```powershell
.venv\Scripts\Activate.ps1
python -m backend.app.data.nvd_sync
```

For all NVD history, pass `--start-year 2002`. Annual JSON feeds are large and
the complete import needs substantial disk, memory, and download time. The
script processes one annual compressed feed at a time, updates the local JSON
atomically, and records the imported years and retrieval time in
`snapshot_metadata.json`.

To upsert those official feed records to the configured canonical Snowflake
table instead of replacing the local DEMO file:

```powershell
python -m backend.app.data.nvd_sync --start-year 2002 --target snowflake
```

This requires working Snowflake credentials in the backend environment,
write access to the configured target table, and the schema from
`../snowflake/schema.sql`. NVD feeds are downloaded from NIST and loaded into
Snowflake; this does not imply that the source feed itself is a Snowflake
Marketplace dataset. Confirm the challenge's data-source eligibility rules
before describing it as a qualifying Snowflake-provided source. The optional
Snowflake provider will show LIVE only when its configured target can be
queried.

Provider, schema, and CVE status details: <https://nvd.nist.gov/developers/vulnerabilities>. NVD API v2.0 and annual feeds are maintained by NIST; this project does not control the timing or completeness of NVD enrichment.
