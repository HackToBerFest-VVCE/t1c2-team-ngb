"""Optional in-warehouse transforms for the canonical ThreatLens CVE table.

The Snowpark dependency is optional for Flask deployments. Invoke
``transform_vulnerabilities(session, table_name)`` from a Snowpark Python
worksheet or a job that already owns an authenticated Snowpark Session.

`TRIAGE_SCORE` is a transparent operational heuristic, never a CVSS score.
"""

from __future__ import annotations

import re


_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*){0,2}$")


def _normalize_cwe(value: str | None) -> str | None:
    if value is None:
        return None
    match = re.search(r"CWE\s*[-:]?\s*(\d+)", str(value), re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else str(value).strip()[:100] or None


def transform_vulnerabilities(session, table_name: str, register_udf: bool = True):
    """Return a lazy Snowpark DataFrame cleaned and normalized in Snowflake.

    Columns are canonicalized to the repository's CVE schema. Rows without a
    CVE identifier are excluded. The Python UDF runs in Snowflake; registering
    a temporary UDF requires Snowflake permission to create a temporary function.
    """
    if not _TABLE_RE.fullmatch(table_name):
        raise ValueError("table_name must be a one-to-three-part Snowflake identifier")

    from snowflake.snowpark.functions import call_function, col, upper, trim, when, lit, coalesce, current_timestamp, datediff, greatest
    from snowflake.snowpark.types import StringType

    source = session.table(table_name)
    available = {field.name.upper() for field in source.schema.fields}
    required = {"CVE_ID", "DESCRIPTION", "PUBLISHED", "CVSS_SCORE", "SEVERITY", "CWE"}
    missing = required - available
    if missing:
        raise ValueError("source table is missing required CVE columns: " + ", ".join(sorted(missing)))

    cwe_col = col("CWE")
    if register_udf:
        normalize_cwe = session.udf.register(
            _normalize_cwe,
            return_type=StringType(),
            input_types=[StringType()],
            is_permanent=False,
            name="THREATLENS_NORMALIZE_CWE",
            replace=True,
        )
        normalized_cwe = normalize_cwe(cwe_col)
    else:
        # SQL-only fallback avoids UDF creation grants; it standardizes whitespace/case.
        normalized_cwe = upper(trim(cwe_col))

    # Cast to STRING first so TRY_TO_* also handles already typed numeric and
    # timestamp columns (TRY_TO_TIMESTAMP_TZ(TIMESTAMP_TZ) is not valid SQL).
    score = call_function("TRY_TO_DOUBLE", col("CVSS_SCORE").cast("STRING"))
    cleaned = source.select(
        upper(trim(col("CVE_ID").cast("STRING"))).alias("CVE_ID"),
        trim(coalesce(col("DESCRIPTION").cast("STRING"), lit(""))).alias("DESCRIPTION"),
        call_function("TRY_TO_TIMESTAMP_TZ", col("PUBLISHED").cast("STRING")).alias("PUBLISHED"),
        call_function("TRY_TO_TIMESTAMP_TZ", col("LAST_MODIFIED").cast("STRING")).alias("LAST_MODIFIED") if "LAST_MODIFIED" in available else lit(None).cast("TIMESTAMP_TZ").alias("LAST_MODIFIED"),
        when(score.between(0.0, 10.0), score).otherwise(lit(None).cast("DOUBLE")).alias("CVSS_SCORE"),
        upper(trim(coalesce(col("SEVERITY").cast("STRING"), lit("UNKNOWN")))).alias("SEVERITY"),
        normalized_cwe.alias("CWE"),
        col("AFFECTED_PRODUCTS").cast("STRING").alias("AFFECTED_PRODUCTS") if "AFFECTED_PRODUCTS" in available else lit(None).cast("STRING").alias("AFFECTED_PRODUCTS"),
        col("SOURCE_URL").cast("STRING").alias("SOURCE_URL") if "SOURCE_URL" in available else lit(None).cast("STRING").alias("SOURCE_URL"),
    ).filter(col("CVE_ID").rlike(r"^CVE-[0-9]{4}-[0-9]{4,}$"))

    # Match the app's disclosed 80/20 CVSS + 365-day recency heuristic.
    # The score is deliberately named TRIAGE_SCORE to distinguish it from CVSS.
    age_days = greatest(lit(0), datediff("day", col("PUBLISHED"), current_timestamp()))
    recency = when(
        col("PUBLISHED").is_null(), lit(0.0)
    ).otherwise(greatest(lit(0.0), lit(1.0) - (age_days.cast("DOUBLE") / lit(365.0))) * lit(20.0))
    cvss_component = when(
        col("CVSS_SCORE").is_null(), lit(0.0)
    ).otherwise(col("CVSS_SCORE") / lit(10.0) * lit(80.0))
    return cleaned.with_column(
        "TRIAGE_SCORE",
        when(
            col("CVSS_SCORE").is_null() & col("PUBLISHED").is_null(),
            lit(None).cast("DOUBLE"),
        ).otherwise((cvss_component + recency).cast("DOUBLE")),
    )
