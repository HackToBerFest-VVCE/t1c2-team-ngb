"""ThreatLens AI native Snowflake Streamlit application.

Run in Snowflake Streamlit or locally with the optional requirements in
`requirements-streamlit.txt`. Local credentials are read only from environment
variables; Snowflake-native deployments use the active session.
"""

from __future__ import annotations

import os
import re

import pandas as pd
import streamlit as st


st.set_page_config(page_title="ThreatLens AI | Team Nova", page_icon="🛡️", layout="wide")
st.title("🛡️ ThreatLens AI")
st.caption("Team Nova · Open-source cybersecurity data explorer · Evidence-linked CVE analysis")


@st.cache_resource(show_spinner=False)
def _session():
    try:
        from snowflake.snowpark.context import get_active_session
        return get_active_session()
    except Exception:
        pass
    from snowflake.snowpark import Session
    required = ["SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_WAREHOUSE", "SNOWFLAKE_DATABASE", "SNOWFLAKE_SCHEMA"]
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise RuntimeError("No active Snowflake session. Configure Snowflake Streamlit or local Snowflake environment variables.")
    cfg = {key.removeprefix("SNOWFLAKE_").lower(): os.environ[key] for key in required}
    if os.getenv("SNOWFLAKE_PASSWORD"):
        cfg["password"] = os.environ["SNOWFLAKE_PASSWORD"]
    elif os.getenv("SNOWFLAKE_PRIVATE_KEY_BASE64"):
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
        pem = base64.b64decode(os.environ["SNOWFLAKE_PRIVATE_KEY_BASE64"], validate=True)
        key = serialization.load_pem_private_key(
            pem,
            password=os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "").encode() or None,
        )
        cfg["private_key"] = key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        cfg["authenticator"] = "SNOWFLAKE_JWT"
    elif os.getenv("SNOWFLAKE_PRIVATE_KEY_PATH"):
        cfg["private_key_file"] = os.environ["SNOWFLAKE_PRIVATE_KEY_PATH"]
        cfg["authenticator"] = "SNOWFLAKE_JWT"
    else:
        raise RuntimeError("Set a password or key-pair credential in the server environment.")
    if os.getenv("SNOWFLAKE_ROLE"):
        cfg["role"] = os.environ["SNOWFLAKE_ROLE"]
    return Session.builder.configs(cfg).create()


def _safe_table(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*){0,2}", value):
        raise ValueError("Invalid Snowflake table identifier")
    return value


try:
    session = _session()
    table = _safe_table(os.getenv("SNOWFLAKE_TABLE", "THREATLENS_DB.THREATLENS.VULNERABILITIES"))
    from snowflake.snowpark_transforms import transform_vulnerabilities
    from snowflake.snowpark.functions import col
    frame = transform_vulnerabilities(session, table, register_udf=False)
    limit = min(max(int(os.getenv("SNOWFLAKE_MAX_ROWS", "500000")), 1), 1_000_000)
    data = frame.sort(
        col("TRIAGE_SCORE").desc_nulls_last(),
        col("CVSS_SCORE").desc_nulls_last(),
        col("PUBLISHED").desc_nulls_last(),
        col("CVE_ID").asc(),
    ).limit(limit).to_pandas()
except Exception:
    st.error("Snowflake data is unavailable. Check connection settings, table access, and warehouse status.")
    st.info("In Snowflake Streamlit, use the app's active session. Locally, install `requirements-streamlit.txt` and configure backend-only Snowflake environment variables.")
    st.stop()

if data.empty:
    st.warning("The configured source table returned no records.")
    st.stop()

data["CVSS_SCORE"] = pd.to_numeric(data["CVSS_SCORE"], errors="coerce")
data["PUBLISHED"] = pd.to_datetime(data["PUBLISHED"], utc=True, errors="coerce")
severity_values = ["ALL"] + sorted(data["SEVERITY"].fillna("UNKNOWN").astype(str).str.upper().unique().tolist())
col_a, col_b, col_c = st.columns([2, 1, 1])
with col_a:
    query = st.text_input("Search CVE, product, or description", placeholder="e.g. CVE-2025-1234 or openssl")
with col_b:
    severity = st.selectbox("Severity", severity_values)
with col_c:
    minimum = st.slider("Minimum CVSS", min_value=0.0, max_value=10.0, value=0.0, step=0.1)

filtered = data.copy()
if severity != "ALL":
    filtered = filtered[filtered["SEVERITY"].fillna("UNKNOWN").astype(str).str.upper() == severity]
if minimum > 0:
    filtered = filtered[filtered["CVSS_SCORE"] >= minimum]
if query.strip():
    searchable = filtered[["CVE_ID", "DESCRIPTION", "AFFECTED_PRODUCTS"]].fillna("").astype(str)
    filtered = filtered[searchable.apply(lambda col: col.str.contains(query.strip(), case=False, regex=False)).any(axis=1)]

count, scored, critical, mean = st.columns(4)
count.metric("Matching records", f"{len(filtered):,}")
scored.metric("CVSS scored", f"{filtered['CVSS_SCORE'].notna().sum():,}")
critical.metric("Critical", f"{filtered['SEVERITY'].fillna('').str.upper().eq('CRITICAL').sum():,}")
mean.metric("Mean source CVSS", f"{filtered['CVSS_SCORE'].mean():.1f}" if filtered["CVSS_SCORE"].notna().any() else "—")

st.subheader("Priority drill-down")
st.caption("Snowpark cleanses and normalizes the source in Snowflake, then computes a separately named TRIAGE_SCORE (80% CVSS + 20% 365-day recency). The source CVSS remains unchanged; it measures severity, not organization-specific risk or active exploitation.")
display = filtered.sort_values(["TRIAGE_SCORE", "CVSS_SCORE", "PUBLISHED", "CVE_ID"], ascending=[False, False, False, True], na_position="last").head(100)
st.dataframe(display, use_container_width=True, hide_index=True, column_config={
    "SOURCE_URL": st.column_config.LinkColumn("NVD record", display_text="Open NVD"),
    "TRIAGE_SCORE": st.column_config.NumberColumn("Local triage heuristic", format="%.1f / 100"),
    "CVSS_SCORE": st.column_config.NumberColumn("Source CVSS", format="%.1f / 10"),
    "PUBLISHED": st.column_config.DatetimeColumn("Published (UTC)", format="YYYY-MM-DD HH:mm"),
})
st.caption(f"Snowflake source: `{table}` · displayed at most 100 of {len(filtered):,} filtered rows · values retain NVD source provenance.")
