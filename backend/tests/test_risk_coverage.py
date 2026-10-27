"""Regression coverage for risk review, ML coverage, and source modes."""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from scipy.sparse import csr_matrix

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analytics import core
from app.analytics.core import add_priority, add_record_ids, add_severity_review
from app import create_app
from app.routes import api as api_routes
from app.services.evidence import UnconfiguredEvidenceAdapter
from app.services import provider as provider_module
from app.services.provider import DemoProvider, SnowflakeProvider, _rejected_mask, mode


def make_frame(rows):
    defaults = {
        "cve_id": "CVE-2026-1000",
        "description": "A sample buffer flaw in a network service",
        "published": pd.Timestamp("2026-01-01", tz="UTC"),
        "last_modified": pd.Timestamp("2026-01-02", tz="UTC"),
        "cvss_score": 8.0,
        "severity": "HIGH",
        "cwe": "CWE-119",
        "affected_products": "Example Product",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
    }
    return pd.DataFrame([{**defaults, **row} for row in rows])


class TestSeverityReview:
    def test_unknown_severity_with_high_cvss_is_flagged_without_overwrite(self):
        frame = make_frame([{"severity": "UNKNOWN", "cvss_score": 9.8}])
        result = add_severity_review(frame)
        assert result.loc[0, "severity"] == "UNKNOWN"
        assert result.loc[0, "cvss_indicated_severity"] == "CRITICAL"
        assert result.loc[0, "review_priority"] == "URGENT_REVIEW"

    def test_unknown_severity_with_missing_cvss_is_manual_review(self):
        result = add_severity_review(make_frame([{"severity": "UNKNOWN", "cvss_score": None}]))
        assert pd.isna(result.loc[0, "cvss_indicated_severity"])
        assert result.loc[0, "review_priority"] == "MANUAL_REVIEW"
        assert "Source CVSS score is missing" in result.loc[0, "review_reasons"]

    def test_explicit_none_is_not_unknown_or_missing(self):
        result = add_severity_review(make_frame([{"severity": "NONE", "cvss_score": 0.0}]))
        assert result.loc[0, "severity"] == "NONE"
        assert result.loc[0, "cvss_indicated_severity"] == "NONE"
        assert result.loc[0, "review_priority"] == "NO_REVIEW_FLAG"

    def test_known_source_and_cvss_conflict_is_flagged(self):
        result = add_severity_review(make_frame([{"severity": "LOW", "cvss_score": 9.1}]))
        assert result.loc[0, "severity"] == "LOW"
        assert result.loc[0, "cvss_indicated_severity"] == "CRITICAL"
        assert result.loc[0, "review_priority"] == "VERIFY_SOURCE"

    def test_missing_publication_date_does_not_fabricate_priority(self):
        frame = make_frame([{"published": pd.NaT, "cvss_score": 7.5}])
        result = add_priority(frame)
        assert result.loc[0, "priority_score"] == 60.0

    def test_unavailable_vendor_advisory_is_explicit_manual_verification(self):
        evidence = UnconfiguredEvidenceAdapter().lookup("CVE-2026-1000")
        assert evidence["status"] == "UNAVAILABLE"
        assert evidence["references"] == []
        assert "manually" in evidence["note"]


class TestStableIDsAndMLCoverage:
    def test_duplicate_records_receive_distinct_repeatable_stable_ids(self):
        frame = make_frame([{}, {}])
        ids_a = add_record_ids(frame)["record_id"].tolist()
        ids_b = add_record_ids(frame)["record_id"].tolist()
        assert len(set(ids_a)) == 2
        assert ids_a == ids_b

    def test_missing_description_is_not_analyzed(self):
        frame = make_frame([
            {"cve_id": f"CVE-2026-{i:04}", "description": f"Unique buffer flaw {i}"}
            for i in range(4)
        ] + [{"cve_id": "CVE-2026-9999", "description": None}])
        result = core._compute_ml(frame)
        assert result["coverage"]["excluded_missing_or_empty_description"] == 1
        assert result["coverage"]["records_assigned_to_kmeans"] == 4
        assert result["coverage"]["records_not_analyzed"] == 1

    def test_in_sample_records_have_cluster_and_isolation_forest_score(self):
        frame = make_frame([
            {"cve_id": f"CVE-2026-{i:04}", "description": f"Unique parser overflow issue {i}"}
            for i in range(6)
        ])
        result = core._compute_ml(frame)
        assert result["coverage"]["records_assigned_to_kmeans"] == 6
        assert result["coverage"]["records_scored_by_isolation_forest"] == 6
        assert all("record_id" in row and "cluster" in row for row in result["assignments"])
        assert all(isinstance(row["anomaly_score"], float) for row in result["assignments"])

    def test_eligible_records_outside_5000_row_sample_remain_unanalyzed(self, monkeypatch):
        class FakeVectorizer:
            def __init__(self, **kwargs): pass
            def fit_transform(self, texts): return csr_matrix(np.column_stack([np.ones(len(texts)), np.arange(len(texts)) % 2]))
            def get_feature_names_out(self): return np.array(["buffer", "parser"])

        class FakeKMeans:
            def __init__(self, n_clusters, **kwargs): self.k = n_clusters
            def fit_predict(self, values): return np.arange(len(values)) % self.k

        class FakeScaler:
            def fit_transform(self, values): return values

        class FakeForest:
            def __init__(self, **kwargs): pass
            def fit(self, values): self.n = len(values); return self
            def decision_function(self, values): return np.linspace(0.2, -0.2, len(values))

        monkeypatch.setattr(core, "TfidfVectorizer", FakeVectorizer)
        monkeypatch.setattr(core, "KMeans", FakeKMeans)
        monkeypatch.setattr(core, "StandardScaler", FakeScaler)
        monkeypatch.setattr(core, "IsolationForest", FakeForest)
        monkeypatch.setattr(core, "silhouette_score", lambda *args, **kwargs: 0.1)
        frame = make_frame([
            {"cve_id": f"CVE-2026-{i:05}", "description": f"Buffer parser vulnerability {i}"}
            for i in range(5001)
        ] + [{"cve_id": "CVE-2026-99999", "description": ""}])
        first = core._compute_ml(frame)
        second = core._compute_ml(frame)
        coverage = first["coverage"]
        assert coverage["total_active_records"] == 5002
        assert coverage["eligible_records"] == 5001
        assert coverage["records_in_deterministic_sample"] == 5000
        assert coverage["records_assigned_to_kmeans"] == 5000
        assert coverage["records_scored_by_isolation_forest"] == 5000
        assert coverage["eligible_records_outside_sample"] == 1
        assert coverage["excluded_missing_or_empty_description"] == 1
        assert coverage["records_not_analyzed"] == 2
        assert first["sample_record_ids"] == second["sample_record_ids"]
        assert len({row["record_id"] for row in first["assignments"]}) == 5000


class TestSourceModesAndRejectedRecords:
    def test_rejected_or_withdrawn_rows_are_excluded(self):
        frame = pd.DataFrame({"description": ["Rejected reason: withdrawn", "Active vulnerability"]})
        mask = _rejected_mask(frame)
        assert mask.tolist() == [True, False]

    def test_provider_removes_rejected_rows_from_active_records(self, monkeypatch, tmp_path):
        source = make_frame([
            {"cve_id": "CVE-2026-0001", "description": "Rejected reason: withdrawn"},
            {"cve_id": "CVE-2026-0002", "description": "Active parser vulnerability"},
        ])
        class FakeProvider:
            def records(self): return source.copy()
        monkeypatch.setattr(provider_module, "get_provider", lambda: FakeProvider())
        monkeypatch.setattr(provider_module, "_full_catalog_path", lambda: tmp_path / "missing.json")
        monkeypatch.setattr(provider_module, "_RECORDS_CACHE", None)
        active = provider_module._load_records()
        assert active.cve_id.tolist() == ["CVE-2026-0002"]

    def test_demo_provider_mode_is_local_and_available(self, monkeypatch):
        monkeypatch.setenv("DATA_SOURCE", "demo")
        # The demo provider has no remote or credential requirement.
        provider = DemoProvider()
        monkeypatch.setattr(provider, "records", lambda: make_frame([{}]))
        assert len(provider.records()) == 1

    def test_snowflake_query_is_bounded_and_uses_fixed_schema_columns(self, monkeypatch):
        class Cursor:
            description = [(column.upper(),) for column in (
                "cve_id", "description", "published", "last_modified", "cvss_score",
                "severity", "cwe", "affected_products", "source_url",
            )]
            def __init__(self): self.calls = []
            def execute(self, sql, params=None): self.calls.append((sql, params))
            def fetchall(self): return [("CVE-2026-1000", "example", None, None, None, "UNKNOWN", None, None, None)]
            def close(self): pass

        class Connection:
            def __init__(self, cursor): self._cursor = cursor
            def cursor(self): return self._cursor
            def close(self): pass

        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct")
        monkeypatch.setenv("SNOWFLAKE_USER", "reader")
        monkeypatch.setenv("SNOWFLAKE_WAREHOUSE", "wh")
        monkeypatch.setenv("SNOWFLAKE_DATABASE", "db")
        monkeypatch.setenv("SNOWFLAKE_SCHEMA", "schema")
        monkeypatch.setenv("SNOWFLAKE_TABLE", "CVE_TABLE")
        monkeypatch.setenv("SNOWFLAKE_PASSWORD", "test-only")
        monkeypatch.setenv("SNOWFLAKE_MAX_ROWS", "123")
        cursor = Cursor()
        provider = SnowflakeProvider()
        monkeypatch.setattr(provider, "_connection", lambda: Connection(cursor))
        frame = provider.records()
        assert len(frame) == 1
        monkeypatch.setenv("DATA_SOURCE", "snowflake")
        assert mode() == "snowflake"
        assert isinstance(provider_module.get_provider(), SnowflakeProvider)
        sql, params = cursor.calls[0]
        assert "CVE_ID" in sql and "SOURCE_URL" in sql
        assert "LIMIT %s" in sql
        assert params == (123,)


class TestReviewQueueAPI:
    def test_unknown_high_records_remain_visible_with_ml_sample_status(self, client, monkeypatch):
        frame = make_frame([
            {"cve_id": "CVE-2026-2001", "severity": "UNKNOWN", "cvss_score": 9.8},
            {"cve_id": "CVE-2026-2002", "severity": "UNKNOWN", "cvss_score": 7.2},
            {"cve_id": "CVE-2026-2003", "severity": "NONE", "cvss_score": 0.0},
            {"cve_id": "CVE-2026-2004", "severity": "LOW", "cvss_score": 2.0},
        ])
        frame = add_record_ids(frame)
        first = frame.iloc[0].record_id
        monkeypatch.setattr(api_routes, "_records", lambda: frame)
        monkeypatch.setattr(api_routes, "ml_results", lambda _: {
            "assignments": [{"record_id": first, "cluster": 1, "anomaly_score": -0.2}],
            "sample_record_ids": [first],
            "coverage": {"sample_records_below_minimum": 0},
        })
        response = client.get("/api/vulnerabilities?review=high_unknown&sort=cvss_score&order=desc")
        assert response.status_code == 200
        data = response.get_json()
        assert data["total"] == 2
        assert {row["cve_id"] for row in data["items"]} == {"CVE-2026-2001", "CVE-2026-2002"}
        sampled = next(row for row in data["items"] if row["cve_id"] == "CVE-2026-2001")
        unsampled = next(row for row in data["items"] if row["cve_id"] == "CVE-2026-2002")
        assert sampled["severity"] == "UNKNOWN"
        assert sampled["cvss_indicated_severity"] == "CRITICAL"
        assert sampled["ml_analysis_status"] == "ANALYZED"
        assert sampled["cluster"] == 1
        assert sampled["anomaly_score"] == -0.2
        assert unsampled["ml_analysis_status"] == "NOT_ANALYZED_OUTSIDE_SAMPLE"
        assert unsampled["cluster"] is None

    def test_demo_mode_coverage_endpoint_reports_computed_counts(self, client, monkeypatch):
        frame = add_record_ids(make_frame([
            {"cve_id": f"CVE-2026-{idx}", "description": f"Distinct issue {idx}"}
            for idx in range(4)
        ]))
        monkeypatch.setattr(api_routes, "_records", lambda: frame)
        monkeypatch.setattr(api_routes, "ml_results", lambda _: {
            "coverage": {
                "total_active_records": 4,
                "records_with_nonempty_descriptions": 4,
                "eligible_records": 4,
                "records_in_deterministic_sample": 4,
                "records_assigned_to_kmeans": 4,
                "records_scored_by_isolation_forest": 4,
                "excluded_missing_or_empty_description": 0,
                "eligible_records_outside_sample": 0,
                "sample_records_below_minimum": 0,
                "records_not_analyzed": 0,
                "coverage_percent_of_active_records": 100,
                "coverage_denominator": "all active non-rejected records",
                "partition_note": "non-overlapping",
            },
            "evaluation": {},
            "assignments": [],
        })
        response = client.get("/api/ml/coverage")
        assert response.status_code == 200
        assert response.get_json()["coverage"]["total_active_records"] == 4
        assert response.get_json()["coverage"]["coverage_percent_of_active_records"] == 100

    def test_unconfigured_evidence_route_does_not_claim_clean_result(self, client):
        response = client.get("/api/evidence/CVE-2026-0001")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["status"] == "UNAVAILABLE"
        assert payload["references"] == []
