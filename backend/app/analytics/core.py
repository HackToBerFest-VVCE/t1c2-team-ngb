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
    """Cheap hash for cache invalidation when the underlying data changes."""
    key = f"{len(frame)}-{frame.columns.tolist()}"
    if not frame.empty and "cve_id" in frame.columns:
        key += f"-{frame['cve_id'].iloc[0]}-{frame['cve_id'].iloc[-1]}"
    return sha256(key.encode()).hexdigest()[:16]


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
    usable = frame.dropna(subset=["description"]).copy()
    usable = usable[usable.description.astype(str).str.strip().ne("")]

    # Bound CPU/RAM for large full-history NVD tables. Sampling is stable and
    # clearly reported; aggregate dashboards still use the complete dataset.
    dataset_size = len(usable)
    if dataset_size > 5000:
        usable = usable.sample(n=5000, random_state=42).sort_index()

    if len(usable) < 4:
        return {
            "available": False,
            "reason": (
                "At least four records with descriptions are needed for "
                "clustering and anomaly analysis."
            ),
            "clusters": [],
            "anomalies": [],
            "evaluation": {
                "baseline": "No model; dataset below minimum size.",
            },
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
    out["anomaly_score"] = raw
    out["cluster"] = labels
    anomalies = safe_records(out.sort_values("anomaly_score").head(10))

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
    }
