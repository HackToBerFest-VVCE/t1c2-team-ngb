"""Reproducible, transparent analysis over the currently selected source.

All ML pipelines use fixed random seeds (42) so results are identical
for the same input snapshot.  Priority scoring follows a documented
formula and clearly separates source CVSS from local triage output.
"""

from datetime import datetime, timezone, timedelta
from functools import lru_cache
from hashlib import sha256
from typing import Any

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler


# ── Helpers ───────────────────────────────────────────────────────────

def safe_records(frame: pd.DataFrame) -> list[dict]:
    """Convert a DataFrame to a JSON-safe list of dicts."""
    return (
        frame
        .astype(object)
        .where(pd.notna(frame), None)
        .to_dict(orient="records")
    )


def _frame_fingerprint(frame: pd.DataFrame) -> str:
    """Cheap snapshot fingerprint; providers replace DataFrames on refresh."""
    key = f"{id(frame)}-{len(frame)}-{frame.columns.tolist()}"
    if not frame.empty and "cve_id" in frame.columns:
        key += f"-{frame['cve_id'].iloc[0]}-{frame['cve_id'].iloc[-1]}"
    return sha256(key.encode()).hexdigest()[:16]


def add_record_ids(frame: pd.DataFrame, *, copy: bool = True) -> pd.DataFrame:
    """Attach deterministic IDs, disambiguating duplicate source rows."""
    result = frame.copy() if copy else frame
    if result.empty:
        result["record_id"] = pd.Series(dtype=str)
        return result
    fields = [name for name in ("cve_id", "source_url", "published", "last_modified", "description") if name in result]
    identity = result[fields].fillna("").astype(str).agg("\x1f".join, axis=1)
    fingerprint = identity.map(lambda value: sha256(value.encode("utf-8")).hexdigest()[:24])
    occurrence = fingerprint.groupby(fingerprint, sort=False).cumcount()
    result["record_id"] = [f"{key}-{ordinal}" for key, ordinal in zip(fingerprint, occurrence)]
    return result


# ── Priority scoring ─────────────────────────────────────────────────

def priority(row) -> float | None:
    """
    0–100 local triage score.

    Formula:  100 × (0.8 × CVSS/10 + 0.2 × recency)
    Recency:  max(0, 1 - age_days/365)

    If CVSS is absent, use recency only (max 20).
    If publication date is absent, use CVSS only (max 80).
    If both are absent, score is unavailable (None).
    """
    cvss = row.get("cvss_score")
    cvss = float(cvss) if pd.notna(cvss) else None

    published = row.get("published")
    if pd.notna(published):
        age = max(0, (pd.Timestamp.now(tz="UTC") - published).days)
        recency = max(0.0, 1 - age / 365)
    else:
        recency = None

    if cvss is None and recency is None:
        return None
    if cvss is None:
        return round(recency * 20, 1)
    if recency is None:
        return round(cvss * 8, 1)
    return round((cvss / 10 * 0.8 + recency * 0.2) * 100, 1)


def add_priority(frame: pd.DataFrame, *, copy: bool = True) -> pd.DataFrame:
    """Attach the local priority_score column to the frame (vectorised)."""
    result = frame.copy() if copy else frame
    if result.empty:
        result["priority_score"] = pd.Series(dtype=float)
        return result

    # Vectorised computation — avoids row-by-row apply() on large frames
    now = pd.Timestamp.now(tz="UTC")
    result["published"] = pd.to_datetime(result["published"], errors="coerce", utc=True)
    has_cvss = result["cvss_score"].notna()
    has_pub = result["published"].notna()

    age_days = np.where(
        has_pub,
        (now - result["published"]).dt.total_seconds() / 86400,
        np.nan,
    )
    recency = np.clip(1 - age_days / 365, 0, 1)

    cvss = result["cvss_score"].to_numpy(dtype=float, na_value=np.nan)

    # Full formula: 100 * (0.8 * cvss/10 + 0.2 * recency)
    score = np.where(
        has_cvss & has_pub,
        (cvss / 10 * 0.8 + recency * 0.2) * 100,
        np.where(
            has_cvss & ~has_pub,
            cvss * 8,
            np.where(
                ~has_cvss & has_pub,
                recency * 20,
                np.nan,
            ),
        ),
    )
    result["priority_score"] = np.round(score, 1)
    return result


def add_severity_review(frame: pd.DataFrame, *, copy: bool = True) -> pd.DataFrame:
    """Add evidence labels without changing source severity or CVSS."""
    result = frame.copy() if copy else frame
    if result.empty:
        result["cvss_indicated_severity"] = pd.Series(dtype=object)
        result["review_reasons"] = pd.Series(dtype=object)
        result["review_priority"] = pd.Series(dtype=object)
        return result

    score = pd.to_numeric(result["cvss_score"], errors="coerce")
    source = result["severity"].fillna("").astype(str).str.strip().str.upper()
    missing_severity = source.isin({"", "UNKNOWN", "UNSPECIFIED", "UNRATED", "N/A", "NONE REPORTED", "NULL", "NAN"})
    band = pd.Series(pd.NA, index=result.index, dtype="string")
    band.loc[score.eq(0)] = "NONE"
    band.loc[score.gt(0) & score.lt(4)] = "LOW"
    band.loc[score.ge(4) & score.lt(7)] = "MEDIUM"
    band.loc[score.ge(7) & score.lt(9)] = "HIGH"
    band.loc[score.ge(9) & score.le(10)] = "CRITICAL"
    result["cvss_indicated_severity"] = band

    missing_cvss = score.isna()
    invalid_cvss = score.notna() & ~score.between(0, 10)
    mismatch = (~missing_severity) & band.notna() & source.isin({"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}) & source.ne(band.fillna(""))
    description_missing = result.description.fillna("").astype(str).str.strip().eq("") if "description" in result else pd.Series(True, index=result.index)
    unknown_values = missing_severity.to_numpy(dtype=bool)
    missing_score_values = missing_cvss.to_numpy(dtype=bool)
    mismatch_values = mismatch.fillna(False).to_numpy(dtype=bool)
    invalid_values = invalid_cvss.fillna(False).to_numpy(dtype=bool)
    description_values = description_missing.to_numpy(dtype=bool)
    score_values = score.to_numpy(dtype=float, na_value=np.nan)
    critical_unknown = unknown_values & (score_values >= 9) & (score_values <= 10)
    high_unknown = unknown_values & (score_values >= 7) & (score_values < 9)
    priority_values = np.select(
        [critical_unknown, high_unknown, mismatch_values | invalid_values,
         unknown_values & missing_score_values, unknown_values, missing_score_values, description_values],
        ["URGENT_REVIEW", "HIGH_REVIEW", "VERIFY_SOURCE", "MANUAL_REVIEW", "REVIEW", "VERIFY_SCORE", "VERIFY_CONTEXT"],
        default="NO_REVIEW_FLAG",
    )
    reasons = [[] for _ in range(len(result))]
    review_positions = np.flatnonzero(
        unknown_values | missing_score_values | mismatch_values | invalid_values | description_values
    )
    for pos in review_positions:
        row_reasons = []
        if unknown_values[pos]:
            row_reasons.append("Source severity is UNKNOWN or missing")
        if missing_score_values[pos]:
            row_reasons.append("Source CVSS score is missing")
        if mismatch_values[pos]:
            row_reasons.append("Source severity conflicts with its CVSS-indicated band")
        if invalid_values[pos]:
            row_reasons.append("Source CVSS score is outside the valid 0–10 range")
        if description_values[pos]:
            row_reasons.append("Description missing; impact context is insufficient")
        reasons[pos] = row_reasons
    result["review_reasons"] = reasons
    result["review_priority"] = priority_values
    result["review_evidence_url"] = result.get("source_url", pd.Series("", index=result.index)).fillna("").astype(str)
    result["affected_product_evidence"] = result.get("affected_products", pd.Series("", index=result.index)).fillna("").astype(str)
    result["affected_version_evidence"] = None
    result["affected_version_evidence_status"] = "NOT_AVAILABLE_IN_ACTIVE_SCHEMA"
    result["advisory_evidence_status"] = "NOT_QUERIED"
    result["advisory_references"] = [[] for _ in range(len(result))]
    result["manual_verification_required"] = result.review_priority.ne("NO_REVIEW_FLAG")
    return result


# ── Aggregate metrics ─────────────────────────────────────────────────

_metrics_cache: dict[tuple[str, int], dict] = {}


def metrics(frame: pd.DataFrame) -> dict[str, Any]:
    """Compute top-level dashboard metrics from the active dataset."""
    fp = _frame_fingerprint(frame)
    now = pd.Timestamp.now(tz="UTC")
    # The recent-publication count is a rolling window, so expire cached
    # metrics at minute boundaries even when the underlying dataset is static.
    cache_key = (fp, int(now.timestamp() // 60))
    if cache_key in _metrics_cache:
        return _metrics_cache[cache_key]

    # Severity counts
    sev = frame.severity.value_counts().to_dict() if not frame.empty else {}

    # Recent publications (rolling 30-day UTC window)
    if not frame.empty:
        recent = frame[frame.published >= now - pd.Timedelta(days=30)]
    else:
        recent = frame

    # Top CWE categories
    cwes = (
        frame.cwe.fillna("").astype(str)
        .str.split(r"[,;]").explode().str.strip()
    )
    cwes = cwes[cwes.ne("") & cwes.ne("nan")].value_counts().head(8)

    # Top affected products
    prod = (
        frame.affected_products.fillna("").astype(str)
        .str.split(";").explode().str.strip()
    )
    prod = prod[prod.ne("") & prod.ne("nan")].value_counts().head(8)

    # Monthly publication trend (last 12 months)
    if not frame.empty:
        by_month = (
            frame.dropna(subset=["published"])
            .assign(month=lambda x: x.published.dt.strftime("%Y-%m"))
            .groupby("month").size()
            .tail(12)
        )
    else:
        by_month = pd.Series(dtype=int)

    # Average CVSS for records that have one
    avg_cvss = None
    if not frame.empty and frame.cvss_score.notna().any():
        avg_cvss = round(float(frame.cvss_score.dropna().mean()), 1)

    annotated = add_severity_review(frame)
    reasons = annotated["review_reasons"]
    normalized_severity = annotated.severity.fillna("").astype(str).str.strip().str.upper()
    unknown = normalized_severity.isin({"", "UNKNOWN", "UNSPECIFIED", "UNRATED", "N/A", "NONE REPORTED", "NULL", "NAN"})
    indicated = annotated.cvss_indicated_severity
    review = {
        "unknown_source_severity": int(unknown.sum()),
        "explicit_none_severity": int(normalized_severity.eq("NONE").sum()),
        "unknown_with_critical_cvss": int((unknown & indicated.eq("CRITICAL").fillna(False)).sum()),
        "unknown_with_high_or_critical_cvss": int((unknown & indicated.isin(["HIGH", "CRITICAL"])).sum()),
        "missing_cvss": int(annotated.cvss_score.isna().sum()),
        "missing_severity_and_cvss": int((unknown & annotated.cvss_score.isna()).sum()),
        "severity_score_mismatch": int(sum(any("conflicts" in reason for reason in item) for item in reasons)),
        "invalid_cvss": int((annotated.cvss_score.notna() & ~annotated.cvss_score.between(0, 10)).sum()),
        "needs_review": int(sum(bool(item) for item in reasons)),
    }
    res = {
        "total": int(len(frame)),
        "critical": int(sev.get("CRITICAL", 0)),
        "high": int(sev.get("HIGH", 0)),
        "medium": int(sev.get("MEDIUM", 0)),
        "low": int(sev.get("LOW", 0)),
        "new_30d": int(len(recent)),
        "avg_cvss": avg_cvss,
        "severity": [
            {"name": str(k), "value": int(v)} for k, v in sev.items()
        ],
        "publication_trend": [
            {"month": str(k), "count": int(v)} for k, v in by_month.items()
        ],
        "top_cwe": [
            {"name": str(k), "count": int(v)} for k, v in cwes.items()
        ],
        "top_products": [
            {"name": str(k), "count": int(v)} for k, v in prod.items()
        ],
        "analysis_scope": (
            "All records loaded from the active provider (Snowflake rows are "
            "bounded by SNOWFLAKE_MAX_ROWS; DEMO reads the full local NVD catalog when imported, "
            "otherwise the starter snapshot). New publications use a "
            "rolling 30-day UTC window."
        ),
        "review": review,
    }
    _metrics_cache[cache_key] = res
    if len(_metrics_cache) > 8:
        oldest = next(iter(_metrics_cache))
        del _metrics_cache[oldest]
    return res


# ── ML analysis (cached per dataset snapshot) ─────────────────────────

_ml_cache: dict[str, dict] = {}


def ml_results(frame: pd.DataFrame) -> dict[str, Any]:
    """
    Run clustering + anomaly detection.

    Results are cached by dataset fingerprint so repeated API calls
    within the same data snapshot don't re-train models.
    """
    fp = _frame_fingerprint(frame)
    if fp in _ml_cache:
        return _ml_cache[fp]

    result = _compute_ml(frame)
    _ml_cache[fp] = result
    # Keep cache bounded
    if len(_ml_cache) > 4:
        oldest = next(iter(_ml_cache))
        del _ml_cache[oldest]
    return result


def _compute_ml(frame: pd.DataFrame) -> dict[str, Any]:
    """Core ML computation — deterministic with random_state=42."""
    total_records = len(frame)
    frame = add_record_ids(frame)
    usable = frame.dropna(subset=["description"]).copy()
    usable = usable[usable.description.astype(str).str.strip().ne("")]

    # Bound CPU/RAM for large full-history NVD tables. Sampling is stable and
    # clearly reported; aggregate dashboards still use the complete dataset.
    dataset_size = len(usable)
    if dataset_size > 5000:
        usable = usable.sample(n=5000, random_state=42).sort_index()

    sample_candidate_count = len(usable)
    no_description_count = total_records - dataset_size
    outside_sample_count = dataset_size - sample_candidate_count

    def coverage(analyzed_count: int) -> dict[str, Any]:
        # Partition: no-description + outside-sample + in-sample analyzed +
        # in-sample below-minimum = total. The latter only occurs <4 rows.
        below_minimum_count = sample_candidate_count if analyzed_count == 0 else 0
        return {
            "total_active_records": int(total_records),
            "records_with_nonempty_descriptions": int(dataset_size),
            "eligible_records": int(dataset_size),
            "records_in_deterministic_sample": int(sample_candidate_count),
            "records_assigned_to_kmeans": int(analyzed_count),
            "records_scored_by_isolation_forest": int(analyzed_count),
            "excluded_missing_or_empty_description": int(no_description_count),
            "eligible_records_outside_sample": int(outside_sample_count),
            "sample_records_below_minimum": int(below_minimum_count),
            "records_not_analyzed": int(total_records - analyzed_count),
            "coverage_percent_of_active_records": round(analyzed_count * 100 / total_records, 2) if total_records else 0.0,
            "coverage_denominator": "all active non-rejected records loaded from the configured provider",
            "partition_note": "Counts in the three exclusion categories are non-overlapping: missing/empty description, eligible but outside sample, and in-sample below the four-record model minimum. Analyzed records are represented by the K-means and Isolation Forest counts.",
        }

    if len(usable) < 4:
        return {
            "available": False,
            "reason": (
                "At least four records with descriptions are needed for "
                "clustering and anomaly analysis."
            ),
            "clusters": [],
            "anomalies": [],
            "assignments": [],
            "sample_record_ids": usable.record_id.astype(str).tolist(),
            "evaluation": {
                "baseline": "No model; dataset below minimum size.",
                "total_records": int(total_records),
                "eligible_description_count": int(dataset_size),
                "model_sample_size": 0,
                "not_analyzed_count": int(total_records),
            },
            "coverage": coverage(0),
        }

    # ── TF-IDF vectorisation ──────────────────────────────────────────
    texts = usable.description.astype(str).tolist()
    vec = TfidfVectorizer(
        max_features=500,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=1,
    )
    X = vec.fit_transform(texts).toarray()

    # ── K-Means clustering ────────────────────────────────────────────
    k = max(2, min(5, int(np.sqrt(len(usable) / 2))))
    labels = KMeans(
        n_clusters=k, random_state=42, n_init=10
    ).fit_predict(X)

    terms = np.array(vec.get_feature_names_out())
    clusters = []
    for label in sorted(set(labels)):
        ix = np.where(labels == label)[0]
        means = X[ix].mean(axis=0)
        top_terms = terms[np.argsort(means)[-5:][::-1]].tolist()
        rep = usable.iloc[ix]
        clusters.append({
            "id": int(label),
            "count": int(len(ix)),
            "terms": top_terms,
            "representatives": safe_records(rep.head(3)),
        })

    # ── Silhouette score ──────────────────────────────────────────────
    score = None
    if len(set(labels)) > 1 and len(set(labels)) < len(labels):
        try:
            score = round(float(silhouette_score(X, labels)), 3)
        except Exception:
            pass

    # ── Isolation Forest anomaly detection ────────────────────────────
    # Features: TF-IDF vectors + normalised CVSS (median-imputed)
    cv = usable.cvss_score.astype(float)
    cv = cv.fillna(cv.median() if cv.notna().any() else 0)
    features = StandardScaler().fit_transform(
        np.column_stack([X, cv.to_numpy().reshape(-1, 1)])
    )
    model = IsolationForest(
        contamination="auto", random_state=42, n_estimators=100
    ).fit(features)
    raw = model.decision_function(features)

    out = usable.copy()
    if "cve_id" not in out.columns:
        out["cve_id"] = [f"ROW-{i}" for i in range(len(out))]
    if "record_id" not in out.columns:
        out["record_id"] = out["cve_id"]
    out["anomaly_score"] = raw
    out["cluster"] = labels
    anomalies = safe_records(out.sort_values("anomaly_score").head(10))
    assignment_cols = [c for c in ["record_id", "cve_id", "cluster", "anomaly_score"] if c in out.columns]
    assignments = safe_records(out[assignment_cols])

    return {
        "available": True,
        "clusters": clusters,
        "anomalies": anomalies,
        "evaluation": {
            "method": (
                "TF-IDF (max 500 terms, 1–2 grams), K-means "
                f"(k={k}, random_state=42)"
            ),
            "silhouette": score,
            "silhouette_note": (
                "Unsupervised cohesion/separation measure; only reported "
                "when mathematically defined; not classification accuracy."
            ),
            "baseline": (
                "Most-frequent-cluster baseline is n(max cluster)/n; "
                "no labeled ground truth is available."
            ),
            "baseline_score": round(
                max(np.bincount(labels)) / len(labels), 3
            ),
            "dataset_size": int(dataset_size),
            "model_sample_size": int(len(usable)),
            "total_records": int(total_records),
            "eligible_description_count": int(dataset_size),
            "not_analyzed_count": int(total_records - len(usable)),
            "anomaly_method": (
                "Isolation Forest (100 trees, random_state=42), TF-IDF "
                "plus median-imputed CVSS; lower decision score = more "
                "unusual."
            ),
            "limitations": (
                "Text similarity and feature rarity do not confirm "
                "exploitation or malicious activity."
            ),
        },
        "assignments": assignments,
        "sample_record_ids": usable.record_id.astype(str).tolist(),
        "coverage": coverage(len(usable)),
    }
