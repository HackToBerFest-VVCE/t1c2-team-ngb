"""ThreatLens AI — Flask REST API routes.

All endpoints return structured JSON with consistent error shapes.
Input is validated via Pydantic where appropriate and manual checks
elsewhere.  No user-supplied SQL is executed.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import pandas as pd
from flask import Blueprint, Response, jsonify, request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..analytics.core import add_priority, metrics, ml_results, safe_records
from ..services.ai import AIServiceError, MODELS, analyze, analyze_locally, configuration, provider_options, select_cve_examples
from ..services.provider import ProviderError, get_provider, get_records, mode

api = Blueprint("api", __name__)
log = logging.getLogger("threatlens.api")
ROOT = Path(__file__).resolve().parents[3]

__version__ = "1.0.0"

# ── Process-level cache for priority-scored records ───────────────────
_PRIORITY_CACHE: tuple[int, pd.DataFrame] | None = None
_SUMMARY_CACHE: tuple[int, int, dict] | None = None
_TRENDS_CACHE: dict[tuple[int, int, int], dict] = {}
_DATA_QUALITY_CACHE: tuple[int, dict] | None = None


# ── Helpers ───────────────────────────────────────────────────────────

def _error(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def _records():
    """Load records from the active provider and attach priority scores.

    Uses an identity-based cache: if get_records() returns the same
    DataFrame object (from its own TTL cache), skip re-computing
    priority scores.
    """
    global _PRIORITY_CACHE
    raw = get_records()
    raw_id = id(raw)
    if _PRIORITY_CACHE is not None and _PRIORITY_CACHE[0] == raw_id:
        return _PRIORITY_CACHE[1]
    scored = add_priority(raw, copy=False)
    _PRIORITY_CACHE = (raw_id, scored)
    return scored


def _public_rows(frame: pd.DataFrame) -> list[dict]:
    """Serialise a DataFrame to JSON-safe dicts."""
    out = safe_records(frame)
    for row in out:
        for key, val in list(row.items()):
            if hasattr(val, "isoformat"):
                row[key] = val.isoformat()
            elif hasattr(val, "item"):
                row[key] = val.item()
    return out


# ── Health & data sources ─────────────────────────────────────────────

@api.get("/health")
def health():
    """Service health check with source connectivity."""
    try:
        status = get_provider().status()
        return jsonify({
            "status": "ok",
            "source": status,
            "version": __version__,
        })
    except ProviderError:
        return jsonify({
            "status": "degraded",
            "source": {
                "mode": mode().upper(),
                "connected": False,
            },
            "version": __version__,
        }), 503


@api.get("/data-sources")
def data_sources():
    """Report active data source and available modes."""
    try:
        return jsonify({
            "active": get_provider().status(),
            "available": ["demo", "snowflake"],
        })
    except ProviderError as exc:
        return _error("data_source_unavailable", str(exc), 503)


# ── Metrics ───────────────────────────────────────────────────────────

@api.get("/metrics")
def get_metrics():
    """Dashboard-level aggregate metrics."""
    return jsonify(metrics(_records()))


@api.get("/summary")
def summary():
    """Combined dashboard payload: metrics + recent vulnerabilities.

    Replaces two separate API calls (``/metrics`` + ``/vulnerabilities``)
    with one, cutting Overview page load time roughly in half.
    Cached by dataset identity for sub-millisecond repeat responses.
    """
    global _SUMMARY_CACHE
    frame = _records()
    frame_id = id(frame)
    cache_minute = int(time.time() // 60)
    if (
        _SUMMARY_CACHE is not None
        and _SUMMARY_CACHE[:2] == (frame_id, cache_minute)
    ):
        return jsonify(_SUMMARY_CACHE[2])

    m = metrics(frame)
    recent = frame.sort_values("published", ascending=False, na_position="last").head(6)
    payload = {
        "metrics": m,
        "recent": _public_rows(recent),
    }
    _SUMMARY_CACHE = (frame_id, cache_minute, payload)
    return jsonify(payload)


# ── Vulnerabilities ───────────────────────────────────────────────────

@api.get("/vulnerabilities")
def vulnerabilities():
    """Paginated, filterable vulnerability list."""
    try:
        frame = _records()

        # ── Text search ───────────────────────────────────────────────
        q = request.args.get("q", "").strip()
        if len(q) > 200:
            return _error(
                "invalid_parameter",
                "q must be at most 200 characters.",
                400,
            )
        if q:
            searchable = (
                frame[["cve_id", "description", "affected_products", "cwe"]]
                .fillna("").astype(str)
            )
            mask = searchable.apply(
                lambda col: col.str.contains(q, case=False, regex=False)
            ).any(axis=1)
            frame = frame[mask]

        # ── Severity filter ───────────────────────────────────────────
        severity = request.args.get("severity")
        if severity:
            vals = {x.strip().upper() for x in severity.split(",")}
            allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
            if not vals.issubset(allowed):
                return _error(
                    "invalid_parameter", "Unsupported severity.", 400
                )
            frame = frame[frame.severity.isin(vals)]

        # ── Date range filter ─────────────────────────────────────────
        date_bounds: dict[str, pd.Timestamp] = {}
        for param, comparator in (("from", "ge"), ("to", "le")):
            val = request.args.get(param)
            if val:
                try:
                    dt = pd.to_datetime(val, utc=True, errors="raise")
                    # Date inputs represent calendar days; include the full
                    # selected end date instead of stopping at midnight.
                    if comparator == "le" and len(val) == 10:
                        dt = dt + pd.Timedelta(days=1) - pd.Timedelta(nanoseconds=1)
                except Exception:
                    return _error(
                        "invalid_parameter",
                        f"{param} must be an ISO date.",
                        400,
                    )
                date_bounds[param] = dt
                if comparator == "ge":
                    frame = frame[frame.published >= dt]
                else:
                    frame = frame[frame.published <= dt]
        if "from" in date_bounds and "to" in date_bounds and date_bounds["from"] > date_bounds["to"]:
            return _error("invalid_parameter", "from cannot be after to.", 400)

        # ── Score range filter ────────────────────────────────────────
        score_bounds: dict[str, float] = {}
        for param, comparator in (("min_score", "ge"), ("max_score", "le")):
            val = request.args.get(param)
            if val:
                try:
                    score = float(val)
                except ValueError:
                    return _error(
                        "invalid_parameter",
                        f"{param} must be numeric.",
                        400,
                    )
                if not 0 <= score <= 10:
                    return _error(
                        "invalid_parameter",
                        f"{param} must be between 0 and 10.",
                        400,
                    )
                score_bounds[param] = score
                if comparator == "ge":
                    frame = frame[frame.cvss_score >= score]
                else:
                    frame = frame[frame.cvss_score <= score]
        if score_bounds.get("min_score", 0) > score_bounds.get("max_score", 10):
            return _error("invalid_parameter", "min_score cannot exceed max_score.", 400)

        # ── CWE filter ────────────────────────────────────────────────
        cwe = request.args.get("cwe")
        if cwe:
            frame = frame[
                frame.cwe.fillna("").astype(str)
                .str.contains(cwe, case=False, regex=False)
            ]

        # ── Sorting ───────────────────────────────────────────────────
        sort = request.args.get("sort", "published")
        allowed_sorts = {"published", "cvss_score", "priority_score", "cve_id"}
        if sort not in allowed_sorts:
            return _error(
                "invalid_parameter", "Unsupported sort field.", 400
            )

        order = request.args.get("order", "desc").lower()
        if order not in {"asc", "desc"}:
            return _error(
                "invalid_parameter", "order must be asc or desc.", 400
            )
        frame = frame.sort_values(
            sort, ascending=(order == "asc"), na_position="last"
        )

        # ── Pagination ────────────────────────────────────────────────
        try:
            page = max(1, int(request.args.get("page", "1")))
            per = max(1, min(100, int(request.args.get("per_page", "20"))))
        except ValueError:
            return _error(
                "invalid_parameter",
                "page and per_page must be integers.",
                400,
            )

        total = len(frame)
        pages = max(1, (total + per - 1) // per)
        start = (page - 1) * per
        items = _public_rows(frame.iloc[start : start + per])

        return jsonify({
            "items": items,
            "page": page,
            "per_page": per,
            "total": total,
            "pages": pages,
        })

    except ProviderError:
        return _error(
            "data_source_unavailable",
            "The configured data source is unavailable.",
            503,
        )


@api.get("/vulnerabilities/<cve_id>")
def vulnerability(cve_id: str):
    """Single CVE record by identifier."""
    if len(cve_id) > 64:
        return _error("invalid_parameter", "Invalid CVE identifier.", 400)

    frame = _records()
    match = frame[frame.cve_id.str.upper() == cve_id.upper()]
    if match.empty:
        return _error("not_found", "Vulnerability not found.", 404)

    return jsonify(_public_rows(match.head(1))[0])


# ── Trends ────────────────────────────────────────────────────────────

@api.get("/trends")
def trends():
    """Time-series publication and severity trends."""
    raw_records = _records()
    frame_id = id(raw_records)

    days_str = request.args.get("days", "365")
    try:
        days = int(days_str)
    except ValueError:
        return _error("invalid_parameter", "days must be an integer.", 400)
    if not 1 <= days <= 3650:
        return _error(
            "invalid_parameter", "days must be between 1 and 3650.", 400
        )

    cache_key = (frame_id, days, int(time.time() // 60))
    if cache_key in _TRENDS_CACHE:
        return jsonify(_TRENDS_CACHE[cache_key])

    frame = raw_records.dropna(subset=["published"])
    all_dated = frame

    end = pd.Timestamp.now(tz="UTC")
    start = end - pd.Timedelta(days=days)
    frame = frame[(frame.published >= start) & (frame.published <= end)].copy()
    previous = all_dated[
        (all_dated.published >= start - pd.Timedelta(days=days))
        & (all_dated.published < start)
    ]
    frame["month"] = frame.published.dt.strftime("%Y-%m")

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    # Include every calendar month touched by the rolling window, including
    # empty months. This makes horizon changes visible even when counts are 0.
    months = pd.period_range(
        start=start.tz_localize(None).to_period("M"),
        end=end.tz_localize(None).to_period("M"),
        freq="M",
    ).astype(str)
    counts = frame.groupby(["month", "severity"]).size().unstack(fill_value=0)
    ts = counts.reindex(index=months, columns=severities, fill_value=0).reset_index()
    ts = ts.rename(columns={"index": "month"})

    summary = metrics(frame)
    previous_count = int(len(previous))
    delta = int(len(frame)) - previous_count
    coverage_start = all_dated.published.min() if not all_dated.empty else None
    coverage_end = all_dated.published.max() if not all_dated.empty else None
    coverage_limited = bool(coverage_start is not None and coverage_start > start)
    payload = {
        "days": days,
        "items": _public_rows(ts),
        "count": int(len(frame)),
        "comparison": {
            "previous_count": previous_count,
            "delta": delta,
            "percent": round(delta / previous_count * 100, 1) if previous_count else None,
        },
        "top_cwe": summary["top_cwe"][:5],
        "top_products": summary["top_products"][:5],
        "coverage": {
            "from": coverage_start.isoformat() if coverage_start is not None else None,
            "to": coverage_end.isoformat() if coverage_end is not None else None,
            "dated_records": int(len(all_dated)),
            "limited_for_window": coverage_limited,
        },
        "from": start.isoformat(),
        "to": end.isoformat(),
        "bucket": "month",
        "limitations": (
            "Publication dates only; no inference about active exploitation. "
            "Counts are restricted to the selected rolling window and "
            "available source records; empty months outside source date coverage "
            "are unknown, not verified zero activity."
        ),
    }
    _TRENDS_CACHE[cache_key] = payload
    if len(_TRENDS_CACHE) > 24:
        del _TRENDS_CACHE[next(iter(_TRENDS_CACHE))]
    return jsonify(payload)


@api.get("/ai/status")
def ai_status():
    """Report configured model availability without exposing credentials."""
    config = configuration()
    return jsonify({
        "configured": config["configured"],
        "provider": config["provider"],
        "model": config["model"],
        "endpoint": config["endpoint"],
        "providers": provider_options(),
        "note": "API credentials remain server-side; analysis uses full-window aggregates, up to 80 Critical/High CVE examples, and up to 20 comparison examples.",
    })


@api.post("/ai/insights")
def ai_insights():
    """Generate a bounded, evidence-grounded analysis of the active dataset."""
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return _error("invalid_request", "Request body must be a JSON object.", 400)
    days = body.get("days", 90)
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650:
        return _error("invalid_parameter", "days must be an integer between 1 and 3650.", 400)
    selected_provider = body.get("provider")
    if selected_provider is not None:
        if not isinstance(selected_provider, str) or selected_provider.strip().lower() not in MODELS:
            return _error("invalid_parameter", "provider must be nvidia, kimi, or deepseek.", 400)
        selected_provider = selected_provider.strip().lower()
    try:
        frame = _records().dropna(subset=["published"])
        now = pd.Timestamp.now(tz="UTC")
        window = frame[(frame.published >= now - pd.Timedelta(days=days)) & (frame.published <= now)]
        summary = metrics(window)
        ai_records, cve_selection = select_cve_examples(window)
        ml = ml_results(window)
        anomalies = ml.get("anomalies", [])
        source = get_provider().status()
        analysis_source = {"mode": source["mode"], "dataset": source["dataset"], "record_count": source["record_count"]}
        kwargs = {
            "days": days,
            "summary": summary,
            "source": analysis_source,
            "anomalies": anomalies[:5],
            "records": ai_records,
            "cve_selection": cve_selection,
        }
        if body.get("local"):
            return jsonify(analyze_locally(**kwargs))
        return jsonify(analyze(**kwargs, provider=selected_provider))
    except AIServiceError as exc:
        return _error(exc.code, exc.public_message, exc.status_code)


# ── Risk analysis ─────────────────────────────────────────────────────

RISK_METHOD = {
    "name": "ThreatLens priority score",
    "formula": "100 × (0.8 × CVSS/10 + 0.2 × recency)",
    "recency": (
        "max(0, 1 - age_days/365), based on publication date in UTC"
    ),
    "missing": (
        "If CVSS is absent, use recency only (max 20); "
        "if publication date is absent, use CVSS only; "
        "if both are absent, score is unavailable."
    ),
    "warning": (
        "Custom investigation-priority heuristic; not an official CVSS "
        "score and not evidence of exploitation."
    ),
}


@api.get("/risk-analysis")
def risk():
    """Prioritised record list with transparent methodology."""
    frame = _records()
    top = frame.sort_values(
        ["priority_score", "published", "cvss_score"],
        ascending=[False, False, False],
        na_position="last",
    ).head(100)

    return jsonify({
        "method": RISK_METHOD,
        "items": _public_rows(top),
    })


# ── ML endpoints ──────────────────────────────────────────────────────

@api.get("/ml/clusters")
def clusters():
    """K-Means text clusters from vulnerability descriptions."""
    r = ml_results(_records())
    return jsonify({
        "available": r["available"],
        "reason": r.get("reason"),
        "clusters": r["clusters"],
        "evaluation": r["evaluation"],
    })


@api.get("/ml/anomalies")
def anomalies():
    """Isolation Forest anomaly scores."""
    r = ml_results(_records())
    anomaly_list = r["anomalies"]
    if anomaly_list and isinstance(anomaly_list[0], dict):
        items = anomaly_list
    else:
        items = _public_rows(pd.DataFrame(anomaly_list)) if anomaly_list else []

    return jsonify({
        "available": r["available"],
        "reason": r.get("reason"),
        "items": items,
        "evaluation": r["evaluation"],
    })


@api.get("/ml/training")
def training_report():
    """Return the latest local held-out metrics for imported HF task models."""
    report_path = ROOT / "data" / "models" / "training_report.json"
    if not report_path.exists():
        return jsonify({
            "available": False,
            "reason": "No training report exists yet. Import the public datasets and run the model training command.",
            "sources": {},
        })
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _error("training_report_unavailable", "The local model report could not be read.", 500)
    return jsonify({"available": True, **report})


# ── Data quality ──────────────────────────────────────────────────────

@api.get("/data-quality")
def data_quality():
    """Schema inspection and data-completeness summary."""
    global _DATA_QUALITY_CACHE
    frame = get_records()
    frame_id = id(frame)
    if _DATA_QUALITY_CACHE is not None and _DATA_QUALITY_CACHE[0] == frame_id:
        return jsonify(_DATA_QUALITY_CACHE[1])

    fields = []
    for col in frame.columns:
        missing = int(frame[col].isna().sum())
        pct = round(float(frame[col].isna().mean() * 100), 1) if len(frame) else 0
        fields.append({
            "name": col,
            "type": str(frame[col].dtype),
            "missing": missing,
            "missing_percent": pct,
        })

    last_pub = None
    if frame.published.notna().any():
        last_pub = frame.published.max().isoformat()

    payload = {
        "source": get_provider().status(),
        "record_count": len(frame),
        "fields": fields,
        "last_publication": last_pub,
        "ingestion": (
            "Source provider normalization: UTC publication dates, "
            "numeric CVSS parsing, uppercase CVE/severity, "
            "absent optional columns represented as null."
        ),
    }
    _DATA_QUALITY_CACHE = (frame_id, payload)
    return jsonify(payload)


# ── Reports ───────────────────────────────────────────────────────────

@api.get("/reports/summary")
def report_summary():
    """Generate a report summary for the active analysis scope."""
    frame = _records()
    now = datetime.now(timezone.utc)
    window_start = now - pd.Timedelta(days=30)
    dated = frame.published.dropna()
    ml = ml_results(frame)
    training_report = None
    try:
        training_path = ROOT / "data" / "models" / "training_report.json"
        raw_training = json.loads(training_path.read_text(encoding="utf-8"))
        tasks = []
        for source_name, source_data in raw_training.get("sources", {}).items():
            for task_name, task_data in source_data.items():
                if not isinstance(task_data, dict) or "status" not in task_data:
                    continue
                scores = task_data.get("metrics", {})
                tasks.append({
                    "source": source_name,
                    "task": task_data.get("task", task_name),
                    "status": task_data.get("status"),
                    "test_rows": task_data.get("test_rows"),
                    "accuracy": scores.get("accuracy"),
                    "macro_f1": scores.get("macro_f1"),
                    "limitations": task_data.get("limitations") or task_data.get("reason"),
                })
        training_report = {
            "trained_at": raw_training.get("trained_at"),
            "random_state": raw_training.get("random_state"),
            "notice": raw_training.get("notice"),
            "tasks": tasks,
        }
    except (OSError, json.JSONDecodeError):
        pass

    return jsonify({
        "generated_at": now.isoformat(),
        "reporting_period": {
            "start": window_start.isoformat(),
            "end": now.isoformat(),
            "label": "Rolling 30-day UTC publication window; corpus-wide metrics use all loaded records",
        },
        "source_coverage": {
            "from": dated.min().isoformat() if not dated.empty else None,
            "to": dated.max().isoformat() if not dated.empty else None,
            "dated_records": int(len(dated)),
        },
        "source": get_provider().status(),
        "metrics": metrics(frame),
        "ml": {
            "available": ml.get("available", False),
            "reason": ml.get("reason"),
            "evaluation": ml.get("evaluation", {}),
        },
        "supervised_models": training_report,
        "prioritized": _public_rows(
            frame.sort_values(
                "priority_score", ascending=False, na_position="last"
            ).head(10)
        ),
        "method": (
            "100 × (0.8 × CVSS/10 + 0.2 × max(0,1-age_days/365)); "
            "missing fields use available component only."
        ),
        "limitations": (
            "Priority is a local triage heuristic, not an official score "
            "or attack confirmation. Machine learning is unsupervised "
            "and has no labeled ground truth."
        ),
    })


class ExportRequest(BaseModel):
    """Validated export request body."""
    model_config = ConfigDict(populate_by_name=True)
    format: Literal["csv", "json"] = "csv"
    q: str = Field(default="", max_length=200)
    severity: list[str] = Field(default_factory=list)
    from_date: str | None = Field(default=None, alias="from", max_length=40)
    to_date: str | None = Field(default=None, alias="to", max_length=40)
    min_score: float | None = Field(default=None, ge=0, le=10)
    max_score: float | None = Field(default=None, ge=0, le=10)
    cwe: str | None = Field(default=None, max_length=100)
    sort: Literal["published", "cvss_score", "priority_score", "cve_id"] = "published"
    order: Literal["asc", "desc"] = "desc"


@api.post("/reports/export")
def export_report():
    """Export filtered records as CSV or JSON download."""
    try:
        body = ExportRequest.model_validate(
            request.get_json(silent=True) or {}
        )
    except ValidationError as exc:
        return _error("invalid_request", exc.errors()[0]["msg"], 400)

    frame = _records()

    if body.min_score is not None and body.max_score is not None and body.min_score > body.max_score:
        return _error("invalid_request", "min_score cannot exceed max_score.", 400)
    parsed_dates: dict[str, pd.Timestamp] = {}
    for key, value in (("from", body.from_date), ("to", body.to_date)):
        if value:
            try:
                parsed_dates[key] = pd.to_datetime(value, utc=True, errors="raise")
                if key == "to" and len(value) == 10:
                    parsed_dates[key] += pd.Timedelta(days=1) - pd.Timedelta(nanoseconds=1)
            except Exception:
                return _error("invalid_request", f"{key} must be an ISO date.", 400)
    if "from" in parsed_dates and "to" in parsed_dates and parsed_dates["from"] > parsed_dates["to"]:
        return _error("invalid_request", "from cannot be after to.", 400)

    # ── Apply optional text filter ────────────────────────────────────
    if body.q:
        searchable = (
            frame[["cve_id", "description", "affected_products", "cwe"]]
            .fillna("").astype(str)
        )
        mask = searchable.apply(
            lambda col: col.str.contains(body.q, case=False, regex=False)
        ).any(axis=1)
        frame = frame[mask]

    # ── Apply severity filter ─────────────────────────────────────────
    if body.severity:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
        upper = {x.upper() for x in body.severity}
        if not upper.issubset(allowed):
            return _error("invalid_request", "Unsupported severity.", 400)
        frame = frame[frame.severity.isin(upper)]

    if "from" in parsed_dates:
        frame = frame[frame.published >= parsed_dates["from"]]
    if "to" in parsed_dates:
        frame = frame[frame.published <= parsed_dates["to"]]
    if body.min_score is not None:
        frame = frame[frame.cvss_score >= body.min_score]
    if body.max_score is not None:
        frame = frame[frame.cvss_score <= body.max_score]
    if body.cwe:
        frame = frame[frame.cwe.fillna("").astype(str).str.contains(body.cwe, case=False, regex=False)]
    frame = frame.sort_values(body.sort, ascending=(body.order == "asc"), na_position="last")

    # ── JSON export ───────────────────────────────────────────────────
    if body.format == "json":
        return Response(
            json.dumps(_public_rows(frame), ensure_ascii=False),
            mimetype="application/json",
            headers={
                "Content-Disposition": (
                    "attachment; filename=threatlens-vulnerabilities.json"
                ),
            },
        )

    # ── CSV export (with formula-injection protection) ────────────────
    csv_frame = frame.copy()
    dangerous_prefixes = ("=", "+", "-", "@", "\t", "\r")
    for col in csv_frame.columns:
        if csv_frame[col].dtype == object:
            csv_frame[col] = csv_frame[col].map(
                lambda val: (
                    "'" + val
                    if isinstance(val, str) and val.startswith(dangerous_prefixes)
                    else val
                )
            )

    csv_data = csv_frame.to_csv(index=False)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                "attachment; filename=threatlens-vulnerabilities.csv"
            ),
        },
    )
