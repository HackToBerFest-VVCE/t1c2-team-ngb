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
from urllib.parse import urlsplit

import pandas as pd
from flask import Blueprint, Response, jsonify, request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..analytics.core import add_priority, metrics, ml_results, safe_records
from ..services.ai import AIServiceError, MODELS, analyze, analyze_locally, configuration, provider_options, select_cve_examples
from ..services.forecast import HORIZONS, add_cortex_interpretation, build_forecast
from ..services.provider import ProviderError, get_provider, get_records, mode
from ..services.projects import project_catalog
from ..services.audit import AuditUnavailable, append_event, audit_configured, list_events, summarize_events

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


# ── Dataset discovery and project scoping ─────────────────────────────

@api.get("/project-catalog")
def get_project_catalog():
    """Return curated public data sources and reusable project templates."""
    return jsonify(project_catalog())


@api.get("/datasets")
def datasets():
    """Compatibility endpoint for dataset-only discovery clients."""
    return jsonify({"items": project_catalog()["datasets"]})


class ProjectScopeRequest(BaseModel):
    template_id: str = Field(min_length=3, max_length=80)
    title: str = Field(min_length=3, max_length=120)
    goal: str = Field(min_length=20, max_length=1200)
    success_metrics: list[str] = Field(min_length=1, max_length=8)
    dataset_ids: list[str] = Field(min_length=1, max_length=8)


@api.post("/project-scopes")
def validate_project_scope():
    """Validate and return a project scope for the client to save in its workspace."""
    try:
        body = ProjectScopeRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return _error("invalid_request", exc.errors()[0]["msg"], 400)
    catalog = project_catalog()
    template = next((t for t in catalog["templates"] if t["id"] == body.template_id), None)
    known_datasets = {d["id"] for d in catalog["datasets"]}
    if not template:
        return _error("invalid_template", "Select a project template from the catalog.", 400)
    if any(item not in known_datasets for item in body.dataset_ids):
        return _error("invalid_dataset", "Select datasets from the discovery catalog.", 400)
    return jsonify({
        "status": "validated",
        "persistence": "browser workspace",
        "scope": body.model_dump(),
        "template": template,
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "notice": "The scope is stored in this browser only; no Snowflake compute or project resources were allocated.",
    }), 201


# ── Contribution, peer-review, and evaluation audit ───────────────────

class AuditEventRequest(BaseModel):
    event_type: Literal["CONTRIBUTION", "PEER_REVIEW", "EVALUATION"]
    project_id: str = Field(min_length=1, max_length=80)
    actor: str = Field(min_length=1, max_length=120)
    event_date: str | None = Field(default=None, max_length=40)
    contribution_type: str | None = Field(default=None, max_length=60)
    reviewee: str | None = Field(default=None, max_length=120)
    review_rating: int | None = Field(default=None, ge=1, le=5)
    artifact_url: str | None = Field(default=None, max_length=500)
    metric_name: str | None = Field(default=None, max_length=80)
    metric_value: float | None = Field(default=None, ge=0, le=1)
    details: str | None = Field(default=None, max_length=2000)


@api.get("/contributions")
def contributions():
    """Return append-only team activity, peer review, and held-out evaluations."""
    try:
        if not audit_configured():
            training = training_report().get_json()
            return jsonify({
                "available": False,
                "reason": "Configure the dedicated Snowflake audit table to publish team events. No contribution scores are fabricated.",
                "events": [], "members": [], "peer_reviews": [],
                "evaluations": [], "model_benchmarks": training,
                "scoring_policy": "Fixed event weights: code 5, documentation 2, dataset 4, model 6, peer review 3, other 1. Totals are auditable activity indicators, not identity verification or objective engineering-quality scores.",
            })
        events = list_events(200)
        training = training_report().get_json()
        return jsonify({"available": True, "events": events, "model_benchmarks": training, **summarize_events(events)})
    except AuditUnavailable:
        return jsonify({
            "available": False,
            "reason": "Audit table is unavailable; apply snowflake/contributions.sql and grant the audit role access.",
            "events": [], "members": [], "peer_reviews": [], "evaluations": []
        })


@api.post("/contributions")
def add_contribution_event():
    """Append a contribution/review/evaluation event using a server-side token."""
    try:
        body = AuditEventRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return _error("invalid_request", exc.errors()[0]["msg"], 400)
    event = body.model_dump()
    requirements = {
        "CONTRIBUTION": ("contribution_type", "artifact_url"),
        "PEER_REVIEW": ("reviewee", "review_rating"),
        "EVALUATION": ("metric_name", "metric_value"),
    }[body.event_type]
    if any(event.get(key) is None for key in requirements):
        return _error("invalid_request", f"{body.event_type} requires {', '.join(requirements)}.", 400)
    if body.event_type == "CONTRIBUTION":
        weights = {"code": 5.0, "documentation": 2.0, "dataset": 4.0, "model": 6.0, "peer_review": 3.0, "other": 1.0}
        contribution_type = str(body.contribution_type or "").strip().lower()
        if contribution_type not in weights:
            return _error("invalid_request", "contribution_type must be code, documentation, dataset, model, peer_review, or other.", 400)
        if not body.artifact_url:
            return _error("invalid_request", "Contribution events require an https artifact_url.", 400)
        event["contribution_type"] = contribution_type
        event["points"] = weights[contribution_type]
    if body.event_type == "PEER_REVIEW" and body.actor.strip().casefold() == str(body.reviewee).strip().casefold():
        return _error("invalid_request", "A peer review must identify a different reviewee.", 400)
    if body.event_date:
        try:
            datetime.strptime(body.event_date, "%Y-%m-%d")
        except ValueError:
            return _error("invalid_request", "event_date must use YYYY-MM-DD.", 400)
    if body.artifact_url:
        parsed_url = urlsplit(body.artifact_url)
        if parsed_url.scheme != "https" or not parsed_url.netloc or parsed_url.username or parsed_url.password:
            return _error("invalid_request", "artifact_url must be a valid https URL without embedded credentials.", 400)
    token = request.headers.get("X-ThreatLens-Audit-Token")
    try:
        event_id = append_event(event, token)
    except PermissionError:
        return _error("forbidden", "A valid server-side audit write token is required.", 403)
    except AuditUnavailable:
        return _error("audit_unavailable", "Configure the dedicated audit table and Snowflake write role first.", 503)
    return jsonify({"status": "recorded", "event_id": event_id}), 201


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
    # Overview should surface the most severe source-scored records first.
    # Missing CVSS values remain last and are never inferred or fabricated.
    recent = frame.sort_values(
        ["cvss_score", "published"],
        ascending=[False, False],
        na_position="last",
        kind="mergesort",
    ).head(6)
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
        # The unfiltered live catalog is the common pagination path. Ask
        # Snowflake for just the requested page instead of transferring and
        # sorting hundreds of thousands of rows inside a serverless request.
        q = request.args.get("q", "").strip()
        has_filters = any(request.args.get(key) for key in (
            "q", "severity", "from", "to", "min_score", "max_score", "cwe"
        ))
        sort = request.args.get("sort", "severity")
        order = request.args.get("order", "desc").lower()
        allowed_sorts = {"published", "cvss_score", "priority_score", "severity", "cve_id"}
        if sort not in allowed_sorts:
            return _error("invalid_parameter", "Unsupported sort field.", 400)
        if order not in {"asc", "desc"}:
            return _error("invalid_parameter", "order must be asc or desc.", 400)

        if len(q) > 200:
            return _error("invalid_parameter", "q must be at most 200 characters.", 400)

        try:
            page = max(1, int(request.args.get("page", "1")))
            per = max(1, min(100, int(request.args.get("per_page", "20"))))
        except ValueError:
            return _error("invalid_parameter", "page and per_page must be integers.", 400)

        if mode() == "snowflake" and not has_filters:
            provider = get_provider()
            page_reader = getattr(provider, "page_records", None)
            if page_reader and sort != "priority_score":
                page_frame, total = page_reader(page, per, sort, order)
                if not page_frame.empty:
                    for col in ("cve_id", "description", "published", "last_modified", "cvss_score", "severity", "cwe", "affected_products", "source_url"):
                        if col not in page_frame:
                            page_frame[col] = None
                    page_frame["published"] = pd.to_datetime(page_frame["published"], errors="coerce", utc=True)
                    page_frame["last_modified"] = pd.to_datetime(page_frame["last_modified"], errors="coerce", utc=True)
                    page_frame["cvss_score"] = pd.to_numeric(page_frame["cvss_score"], errors="coerce")
                    page_frame["severity"] = (
                        page_frame["severity"].fillna("").astype("string[pyarrow]")
                        .str.upper().replace({"": "UNKNOWN"})
                    )
                    page_frame["cve_id"] = page_frame["cve_id"].fillna("").astype("string[pyarrow]").str.upper()
                    page_frame = add_priority(page_frame, copy=False)
                return jsonify({
                    "items": _public_rows(page_frame),
                    "page": page,
                    "per_page": per,
                    "total": total,
                    "pages": max(1, (total + per - 1) // per),
                })

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
        sort_columns = [sort]
        ascending = [order == "asc"]
        if sort == "severity":
            severity_rank = frame["severity"].map({
                "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                "LOW": 3, "NONE": 4, "UNKNOWN": 5,
            })
            frame = frame.assign(_severity_rank=severity_rank)
            sort_columns = ["_severity_rank", "published", "cvss_score", "cve_id"]
            ascending = [True, False, False, True]
        elif sort == "cvss_score":
            sort_columns.extend(["published", "cve_id"])
            ascending.extend([False, True])
        elif sort == "published":
            sort_columns.append("cve_id")
            ascending.append(True)
        frame = frame.sort_values(
            sort_columns,
            ascending=ascending,
            na_position="last",
            kind="mergesort",
        )
        if sort == "severity":
            frame = frame.drop(columns=["_severity_rank"])

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
            return _error("invalid_parameter", "provider must be cortex or nvidia.", 400)
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
    "name": "NVD CVSS Base Score",
    "source": (
        "Source-provided CVSS Base Score and severity; follow each CVE link "
        "to confirm the NVD assessment, CVSS version, and vector."
    ),
    "scale": "0.0–10.0; displayed without recency or local score adjustments.",
    "ranking": (
        "Highest source CVSS Base Score first; ties use publication date, "
        "then CVE ID."
    ),
    "missing": (
        "Records with no source CVSS score remain unscored and are placed "
        "after scored records. No score is inferred."
    ),
    "warning": (
        "CVSS describes vulnerability severity, not organization-specific "
        "risk or proof of exploitation."
    ),
}


@api.get("/risk-analysis")
def risk():
    """Rank CVE records by the source-provided CVSS Base Score with tier filters."""
    tier = request.args.get("tier", "all").strip().lower()
    sort_by = request.args.get("sort", "cvss_desc").strip().lower()
    try:
        limit = min(max(int(request.args.get("limit", 200)), 10), 1000)
    except (ValueError, TypeError):
        limit = 200

    frame = _records()
    total_records = len(frame)
    scored = frame[frame["cvss_score"].notna()]
    unscored_count = total_records - len(scored)
    mean_score = round(float(scored["cvss_score"].mean()), 1) if not scored.empty else 0.0

    distribution = {
        "total": total_records,
        "scored": len(scored),
        "unscored": unscored_count,
        "exact_10": int((frame["cvss_score"] == 10.0).sum()),
        "critical": int((frame["cvss_score"] >= 9.0).sum()),
        "high": int(((frame["cvss_score"] >= 7.0) & (frame["cvss_score"] < 9.0)).sum()),
        "medium": int(((frame["cvss_score"] >= 4.0) & (frame["cvss_score"] < 7.0)).sum()),
        "low": int(((frame["cvss_score"] >= 0.1) & (frame["cvss_score"] < 4.0)).sum()),
        "mean_cvss": mean_score,
    }

    filtered = frame
    if tier == "critical":
        filtered = frame[frame["cvss_score"] >= 9.0]
    elif tier == "high":
        filtered = frame[(frame["cvss_score"] >= 7.0) & (frame["cvss_score"] < 9.0)]
    elif tier == "medium":
        filtered = frame[(frame["cvss_score"] >= 4.0) & (frame["cvss_score"] < 7.0)]
    elif tier == "low":
        filtered = frame[(frame["cvss_score"] >= 0.1) & (frame["cvss_score"] < 4.0)]
    elif tier == "unscored":
        filtered = frame[frame["cvss_score"].isna()]

    if sort_by == "cvss_asc":
        top = filtered.sort_values(
            ["cvss_score", "published", "cve_id"],
            ascending=[True, False, True],
            na_position="last",
            kind="mergesort",
        ).head(limit)
    elif sort_by == "published_desc":
        top = filtered.sort_values(
            ["published", "cvss_score", "cve_id"],
            ascending=[False, False, True],
            na_position="last",
            kind="mergesort",
        ).head(limit)
    else:  # cvss_desc (default)
        top = filtered.sort_values(
            ["cvss_score", "published", "cve_id"],
            ascending=[False, False, True],
            na_position="last",
            kind="mergesort",
        ).head(limit)

    items = _public_rows(top)
    for item in items:
        item.pop("priority_score", None)

    return jsonify({
        "method": RISK_METHOD,
        "distribution": distribution,
        "tier": tier,
        "sort": sort_by,
        "items": items,
    })


# ── ML endpoints ──────────────────────────────────────────────────────

@api.post("/ml/forecast")
def ml_forecast():
    """Build an NVD-based high/critical attack-family trend outlook.

    Cortex interprets bounded aggregates when available; local analysis remains
    complete if the account has no Cortex entitlement or the service is limited.
    """
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return _error("invalid_request", "Request body must be a JSON object.", 400)
    days = body.get("days", 90)
    if isinstance(days, bool) or not isinstance(days, int) or days not in HORIZONS:
        return _error("invalid_parameter", "days must be one of 90, 180, 730, or 1095.", 400)
    try:
        source = get_provider().status()
        report = build_forecast(_records(), days, {
            "mode": source["mode"],
            "dataset": source["dataset"],
            "provider": source["provider"],
            "record_count": source["record_count"],
        })
        report = add_cortex_interpretation(report)
        report.pop("cortex_prompt", None)
        return jsonify(report)
    except ProviderError as exc:
        return _error("data_source_unavailable", str(exc), 503)

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
    sort: Literal["published", "cvss_score", "priority_score", "severity", "cve_id"] = "published"
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
    if body.sort == "severity":
        rank = frame["severity"].map({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5})
        frame = frame.assign(_severity_rank=rank).sort_values(
            ["_severity_rank", "published", "cvss_score", "cve_id"],
            ascending=[body.order == "asc", False, False, True],
            na_position="last",
            kind="mergesort",
        ).drop(columns=["_severity_rank"])
    else:
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
