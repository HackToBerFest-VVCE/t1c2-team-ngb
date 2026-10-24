"""Comprehensive test suite for ThreatLens AI backend.

Covers: analytics calculations, API validation, pagination, filtering,
export, error handling, and edge cases.
"""

import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from app.analytics.core import add_priority, metrics, ml_results, priority
from app.data.nvd_sync import parse_vulnerability


# ─────────────────────────────────────────────────────────────────────
# Analytics unit tests
# ─────────────────────────────────────────────────────────────────────

class TestPriority:
    """Priority scoring formula tests."""

    def test_perfect_score(self):
        row = pd.Series({
            "cvss_score": 10.0,
            "published": pd.Timestamp.now(tz="UTC"),
        })
        assert priority(row) == 100.0

    def test_both_missing_returns_none(self):
        row = pd.Series({"cvss_score": None, "published": None})
        assert priority(row) is None

    def test_missing_cvss_uses_recency_only(self):
        row = pd.Series({
            "cvss_score": None,
            "published": pd.Timestamp.now(tz="UTC"),
        })
        score = priority(row)
        assert score is not None
        assert 0 < score <= 20

    def test_missing_published_uses_cvss_only(self):
        row = pd.Series({"cvss_score": 7.5, "published": None})
        score = priority(row)
        assert score is not None
        assert score == 60.0  # 7.5 * 8

    def test_old_record_has_low_recency(self):
        row = pd.Series({
            "cvss_score": 5.0,
            "published": pd.Timestamp("2020-01-01", tz="UTC"),
        })
        score = priority(row)
        assert score is not None
        # Recency should be 0 (age > 365 days)
        assert score == 40.0  # 5/10 * 0.8 * 100

    def test_zero_cvss(self):
        row = pd.Series({
            "cvss_score": 0.0,
            "published": pd.Timestamp.now(tz="UTC"),
        })
        score = priority(row)
        assert score is not None
        assert score == 20.0  # 0 CVSS + 1.0 recency * 0.2 * 100


class TestMetrics:
    """Aggregate metrics calculation tests."""

    def test_empty_dataset(self):
        frame = pd.DataFrame(
            columns=["severity", "published", "cwe", "affected_products",
                     "cvss_score"]
        )
        result = metrics(frame)
        assert result["total"] == 0
        assert result["critical"] == 0
        assert result["high"] == 0
        assert result["medium"] == 0
        assert result["low"] == 0
        assert result["new_30d"] == 0
        assert result["avg_cvss"] is None

    def test_severity_counts(self):
        frame = pd.DataFrame({
            "severity": ["CRITICAL", "HIGH", "HIGH", "MEDIUM"],
            "published": pd.Timestamp.now(tz="UTC"),
            "cwe": ["CWE-79", "", "", "CWE-89"],
            "affected_products": ["", "", "", ""],
            "cvss_score": [9.8, 7.5, 8.0, 5.5],
        })
        frame["published"] = pd.to_datetime(frame["published"], utc=True)
        result = metrics(frame)
        assert result["critical"] == 1
        assert result["high"] == 2
        assert result["medium"] == 1
        assert result["total"] == 4

    def test_avg_cvss_calculated(self):
        frame = pd.DataFrame({
            "severity": ["HIGH", "MEDIUM"],
            "published": pd.Timestamp.now(tz="UTC"),
            "cwe": ["", ""],
            "affected_products": ["", ""],
            "cvss_score": [8.0, 4.0],
        })
        frame["published"] = pd.to_datetime(frame["published"], utc=True)
        result = metrics(frame)
        assert result["avg_cvss"] == 6.0


class TestAddPriority:
    """Tests for priority score attachment."""

    def test_empty_frame(self):
        frame = pd.DataFrame(
            columns=["cvss_score", "published"]
        )
        result = add_priority(frame)
        assert "priority_score" in result.columns
        assert len(result) == 0

    def test_adds_column(self):
        frame = pd.DataFrame({
            "cvss_score": [9.0],
            "published": [pd.Timestamp.now(tz="UTC")],
        })
        result = add_priority(frame)
        assert "priority_score" in result.columns
        assert result["priority_score"].iloc[0] is not None


class TestMLResults:
    """ML pipeline tests."""

    def test_too_few_records(self):
        frame = pd.DataFrame({
            "description": ["test"],
            "cvss_score": [5.0],
        })
        result = ml_results(frame)
        assert result["available"] is False
        assert "reason" in result

    def test_sufficient_records(self):
        frame = pd.DataFrame({
            "description": [
                "SQL injection in web app",
                "Cross-site scripting vulnerability",
                "Buffer overflow in kernel module",
                "Authentication bypass via LDAP",
                "Remote code execution in parser",
            ],
            "cvss_score": [9.0, 6.5, 8.0, 7.5, 9.5],
        })
        result = ml_results(frame)
        assert result["available"] is True
        assert len(result["clusters"]) >= 2
        assert len(result["anomalies"]) > 0
        assert "evaluation" in result


class TestNVDFeedParsing:
    def test_normalizes_cve_metrics_weakness_and_products(self):
        item = {"cve": {
            "id": "CVE-2025-1234",
            "descriptions": [{"lang": "en", "value": "Example flaw"}],
            "published": "2025-02-01T00:00:00.000",
            "lastModified": "2025-02-02T00:00:00.000",
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 9.8, "baseSeverity": "CRITICAL",
            }}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*",
            }]}]}],
        }}
        result = parse_vulnerability(item)
        assert result["cve_id"] == "CVE-2025-1234"
        assert result["cvss_score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert result["cwe"] == "CWE-79"
        assert result["affected_products"] == "example/product"


# ─────────────────────────────────────────────────────────────────────
# API integration tests
# ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Create a test client."""
    app = create_app({"TESTING": True})
    return app.test_client()


class TestHealthEndpoint:
    def test_returns_ok(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_includes_source(self, client):
        r = client.get("/api/health")
        data = r.get_json()
        assert "source" in data
        assert data["source"]["mode"] in ("DEMO", "LIVE")


class TestDataSources:
    def test_returns_active_and_available(self, client):
        r = client.get("/api/data-sources")
        assert r.status_code == 200
        data = r.get_json()
        assert "active" in data
        assert "available" in data
        assert "demo" in data["available"]


class TestVulnerabilities:
    def test_default_pagination(self, client):
        r = client.get("/api/vulnerabilities")
        assert r.status_code == 200
        data = r.get_json()
        assert "items" in data
        assert "page" in data
        assert "total" in data
        assert data["per_page"] == 20

    def test_invalid_severity(self, client):
        r = client.get("/api/vulnerabilities?severity=SEVERE")
        assert r.status_code == 400

    def test_invalid_page(self, client):
        r = client.get("/api/vulnerabilities?page=abc")
        assert r.status_code == 400

    def test_per_page_capped_at_100(self, client):
        r = client.get("/api/vulnerabilities?per_page=500")
        assert r.status_code == 200
        assert r.get_json()["per_page"] == 100

    def test_invalid_sort(self, client):
        r = client.get("/api/vulnerabilities?sort=sql")
        assert r.status_code == 400

    def test_invalid_order(self, client):
        r = client.get("/api/vulnerabilities?order=random")
        assert r.status_code == 400

    def test_long_query_rejected(self, client):
        r = client.get(f"/api/vulnerabilities?q={'x' * 201}")
        assert r.status_code == 400

    def test_date_filter_invalid(self, client):
        r = client.get("/api/vulnerabilities?from=not-a-date")
        assert r.status_code == 400

    def test_score_filter_out_of_range(self, client):
        r = client.get("/api/vulnerabilities?min_score=11")
        assert r.status_code == 400

    def test_score_filter_non_numeric(self, client):
        r = client.get("/api/vulnerabilities?min_score=abc")
        assert r.status_code == 400


class TestVulnerabilityDetail:
    def test_not_found(self, client):
        r = client.get("/api/vulnerabilities/CVE-1999-0000")
        assert r.status_code == 404

    def test_long_cve_id_rejected(self, client):
        r = client.get(f"/api/vulnerabilities/{'x' * 65}")
        assert r.status_code == 400


class TestTrends:
    def test_default(self, client):
        r = client.get("/api/trends")
        assert r.status_code == 200
        data = r.get_json()
        assert "days" in data
        assert "items" in data

    def test_invalid_days(self, client):
        r = client.get("/api/trends?days=abc")
        assert r.status_code == 400

    def test_days_out_of_range(self, client):
        r = client.get("/api/trends?days=9999")
        assert r.status_code == 400

    def test_horizon_changes_month_buckets(self, client):
        quarter = client.get("/api/trends?days=90").get_json()
        year = client.get("/api/trends?days=365").get_json()
        assert quarter["days"] == 90
        assert year["days"] == 365
        assert len(quarter["items"]) < len(year["items"])
        assert all("UNKNOWN" in item for item in year["items"])


class TestAIEndpoints:
    def test_status_never_exposes_token(self, client, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "nvidia")
        monkeypatch.setenv("NVIDIA_API_KEY", "test-token-that-must-not-leak")
        response = client.get("/api/ai/status")
        assert response.status_code == 200
        assert response.get_json()["configured"] is True
        assert "test-token-that-must-not-leak" not in response.get_data(as_text=True)

    def test_insights_requires_key(self, client, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "nvidia")
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        response = client.post("/api/ai/insights", json={"days": 90})
        assert response.status_code == 503
        assert response.get_json()["error"]["code"] == "ai_not_configured"

    def test_insights_validates_days(self, client):
        response = client.post("/api/ai/insights", json={"days": 0})
        assert response.status_code == 400

    def test_insights_validates_provider(self, client):
        response = client.post("/api/ai/insights", json={"days": 90, "provider": "unknown"})
        assert response.status_code == 400


class TestRiskAnalysis:
    def test_returns_method_and_items(self, client):
        r = client.get("/api/risk-analysis")
        assert r.status_code == 200
        data = r.get_json()
        assert "method" in data
        assert "items" in data
        assert data["method"]["name"] == "ThreatLens priority score"


class TestMLEndpoints:
    def test_clusters(self, client):
        r = client.get("/api/ml/clusters")
        assert r.status_code == 200
        data = r.get_json()
        assert "available" in data
        assert "evaluation" in data

    def test_anomalies(self, client):
        r = client.get("/api/ml/anomalies")
        assert r.status_code == 200
        data = r.get_json()
        assert "available" in data
        assert "items" in data


class TestDataQuality:
    def test_returns_schema(self, client):
        r = client.get("/api/data-quality")
        assert r.status_code == 200
        data = r.get_json()
        assert "fields" in data
        assert "record_count" in data
        assert "source" in data


class TestReports:
    def test_summary(self, client):
        r = client.get("/api/reports/summary")
        assert r.status_code == 200
        data = r.get_json()
        assert "generated_at" in data
        assert "metrics" in data
        assert "prioritized" in data

    def test_export_csv(self, client):
        r = client.post(
            "/api/reports/export",
            json={"format": "csv"},
        )
        assert r.status_code == 200
        assert "text/csv" in r.content_type

    def test_export_json(self, client):
        r = client.post(
            "/api/reports/export",
            json={"format": "json"},
        )
        assert r.status_code == 200

    def test_export_invalid_format(self, client):
        r = client.post(
            "/api/reports/export",
            json={"format": "xml"},
        )
        assert r.status_code == 400

    def test_export_with_severity_filter(self, client):
        r = client.post(
            "/api/reports/export",
            json={"format": "csv", "severity": ["CRITICAL"]},
        )
        assert r.status_code == 200

    def test_export_invalid_severity(self, client):
        r = client.post(
            "/api/reports/export",
            json={"format": "csv", "severity": ["INVALID"]},
        )
        assert r.status_code == 400


class TestErrorHandlers:
    def test_404_json(self, client):
        r = client.get("/api/nonexistent")
        assert r.status_code == 404
        data = r.get_json()
        assert data["error"]["code"] == "not_found"

    def test_405_json(self, client):
        r = client.delete("/api/health")
        assert r.status_code == 405
        data = r.get_json()
        assert data["error"]["code"] == "method_not_allowed"
