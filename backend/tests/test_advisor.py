"""ThreatLens AI — Software Safety Advisor Unit & Integration Tests.

Validates product identification, deterministic version matching, anti-SSRF protections,
safe static file inspection, AI grounding, and export endpoints.
"""

import json
from unittest.mock import MagicMock, patch
import pytest
from backend.app.services.advisor import (
    assess_software,
    validate_safe_url,
    inspect_file_safely,
    match_version_against_ranges,
    extract_potential_impacts,
    answer_assessment_follow_up,
)


def test_url_security_safeguards():
    """Verify anti-SSRF blocks private IPs, loopbacks, link-local metadata, and unsafe schemes."""
    # Loopback
    is_safe, err, _ = validate_safe_url("http://127.0.0.1/admin")
    assert not is_safe
    assert "loopback" in err.lower() or "blocked" in err.lower()

    # Localhost string
    is_safe, err, _ = validate_safe_url("http://localhost:8080/evil")
    assert not is_safe

    # AWS/Cloud metadata
    is_safe, err, _ = validate_safe_url("http://169.254.169.254/latest/meta-data/")
    assert not is_safe

    # Private RFC1918
    is_safe, err, _ = validate_safe_url("http://192.168.1.100/config")
    assert not is_safe

    # Prohibited scheme
    is_safe, err, _ = validate_safe_url("ftp://ftp.example.com/file")
    assert not is_safe
    assert "scheme" in err.lower()

    # Valid public URL
    is_safe, domain, canonical = validate_safe_url("https://github.com/advisories")
    assert is_safe
    assert "github.com" in domain


def test_file_safe_inspection():
    """Verify static inspection calculates SHA-256 and detects structure without execution."""
    sample_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200
    info = inspect_file_safely(sample_bytes, "test_binary.exe")
    assert info["is_executable_binary"]
    assert "sha256" in info
    assert len(info["sha256"]) == 64
    assert info["analysis_mode"] == "static_metadata_only"


def test_oversized_file_rejected():
    """Verify oversized uploads exceeding 15MB are safely rejected."""
    huge_data = b"0" * (16 * 1024 * 1024)
    with pytest.raises(ValueError, match="exceeds safety limit"):
        inspect_file_safely(huge_data, "huge.bin")


def test_version_range_matching():
    """Test deterministic version matching against introduced and fixed ranges."""
    ranges = [
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "1.0.0"},
                {"fixed": "1.4.2"},
            ],
        }
    ]

    # Vulnerable version
    m_type, fixed, desc = match_version_against_ranges("1.2.0", ranges, [])
    assert m_type == "RANGE_MATCH"
    assert fixed == "1.4.2"

    # Patched version
    m_type, fixed, desc = match_version_against_ranges("1.4.2", ranges, [])
    assert m_type == "NOT_AFFECTED"

    # Exact list match
    m_type, fixed, desc = match_version_against_ranges("2.0.0", [], ["2.0.0", "2.0.1"])
    assert m_type == "EXACT"


def test_extract_potential_impacts():
    """Test plain-English impact extraction from vulnerability descriptions."""
    impacts = extract_potential_impacts(
        "A remote code execution vulnerability allows unauthenticated attackers to execute arbitrary code.",
        "CWE-78",
    )
    assert "Remote Code Execution (RCE)" in impacts

    impacts_priv = extract_potential_impacts(
        "Elevation of privilege vulnerability in service daemon",
        "CWE-269",
    )
    assert "Privilege Escalation" in impacts_priv


def test_assessment_exact_package_match():
    """Test assessing a known vulnerable package version via mocked OSV data."""
    mock_osv_vulns = [
        {
            "id": "GHSA-1234-5678-90ab",
            "summary": "Critical remote code execution in demo-pkg",
            "details": "Allows remote code execution via insecure deserialization.",
            "severity": [{"type": "CVSS_V3", "score": 9.8}],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.5.0"},
                            ],
                        }
                    ],
                    "versions": ["1.2.0"],
                }
            ],
            "references": [{"url": "https://example.com/advisory"}],
        }
    ]

    with patch("backend.app.services.advisor.query_osv_package", return_value=mock_osv_vulns), \
         patch("backend.app.services.advisor.search_local_vulnerabilities", return_value=[]):
        res = assess_software(
            product_name="demo-pkg",
            version="1.2.0",
            ecosystem="pypi",
            provider="deterministic",
        )

        assert res["verdict"] == "KNOWN_VULNERABILITIES_FOUND"
        assert res["exact_matches_count"] >= 1
        assert res["verified_fixed_version"] == "1.5.0"
        assert "Remote Code Execution (RCE)" in res["potential_impacts"]
        assert "1.5.0" in res["recommendation"]["action"]


def test_assessment_no_vulnerabilities_found():
    """Test assessment when no CVEs or advisories are matched."""
    with patch("backend.app.services.advisor.query_osv_package", return_value=[]), \
         patch("backend.app.services.advisor.search_local_vulnerabilities", return_value=[]):
        res = assess_software(
            product_name="clean-library",
            version="3.0.0",
            ecosystem="pypi",
            provider="deterministic",
        )

        assert res["verdict"] == "NO_MATCHING_VULNERABILITIES_FOUND"
        # Never label completely safe or clean
        assert res["verdict"] != "SAFE"
        assert "Absence of CVE records does NOT guarantee" in " ".join(res["limitations"])


def test_assessment_insufficient_identification():
    """Test handling of missing product name."""
    res = assess_software(product_name="", version="1.0.0")
    assert res["verdict"] == "INSUFFICIENT_IDENTIFICATION"


def test_api_software_assessment_endpoint(client):
    """Test Flask POST /api/software-assessment."""
    payload = {
        "product_name": "requests",
        "version": "2.20.0",
        "ecosystem": "pypi",
        "provider": "nvidia",
    }
    with patch("backend.app.services.advisor.query_osv_package", return_value=[]), \
         patch("backend.app.services.advisor.search_local_vulnerabilities", return_value=[]):
        resp = client.post("/api/software-assessment", json=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "verdict" in data
        assert "software" in data
        assert data["software"]["product_name"] == "requests"


def test_api_software_assessment_export(client):
    """Test exporting assessment in JSON, HTML, and Markdown formats."""
    assessment_mock = {
        "assessment_id": "TL-SA-TEST-999",
        "verdict": "KNOWN_VULNERABILITIES_FOUND",
        "verdict_title": "1 Known Vulnerability Confirmed",
        "software": {"product_name": "TestLib", "version": "1.0.0", "ecosystem": "pypi"},
        "findings": [{"id": "CVE-2024-0001", "severity": "HIGH", "cvss_score": 8.5, "summary": "Sample finding", "source_url": "https://example.com"}],
        "potential_impacts": ["Remote Code Execution (RCE)"],
        "recommendation": {"action": "UPGRADE", "explanation": "Upgrade recommended."},
        "generated_at": "2026-10-27T12:00:00Z",
    }

    # JSON export
    resp_json = client.post("/api/software-assessment/export", json={"assessment": assessment_mock, "format": "json"})
    assert resp_json.status_code == 200
    assert resp_json.mimetype == "application/json"

    # Markdown export
    resp_md = client.post("/api/software-assessment/export", json={"assessment": assessment_mock, "format": "markdown"})
    assert resp_md.status_code == 200
    assert resp_md.mimetype == "text/markdown"
    assert b"ThreatLens AI" in resp_md.data

    # HTML export
    resp_html = client.post("/api/software-assessment/export", json={"assessment": assessment_mock, "format": "html"})
    assert resp_html.status_code == 200
    assert resp_html.mimetype == "text/html"
    assert b"<!DOCTYPE html>" in resp_html.data
