"""Optional authoritative evidence adapter contract.

The default adapter performs no network calls. Deployments may inject an
adapter that consults the NVD and official vendor advisory sources, returning
traceable references. An unavailable lookup always remains a manual-review
case; it is never interpreted as evidence that a CVE is safe.
"""

from typing import Any, Protocol


class OfficialEvidenceAdapter(Protocol):
    def lookup(self, cve_id: str) -> dict[str, Any]:
        """Return status, affected-version evidence, and authoritative refs."""


class UnconfiguredEvidenceAdapter:
    def lookup(self, cve_id: str) -> dict[str, Any]:
        return {
            "status": "UNAVAILABLE",
            "affected_version_evidence": None,
            "references": [],
            "note": "No official-advisory adapter is configured; verify the linked source record manually.",
        }


_adapter: OfficialEvidenceAdapter = UnconfiguredEvidenceAdapter()


def configure_evidence_adapter(adapter: OfficialEvidenceAdapter) -> None:
    """Install an optional deployment-provided evidence adapter."""
    global _adapter
    _adapter = adapter


def lookup_official_evidence(cve_id: str) -> dict[str, Any]:
    """Return normalized, traceable evidence without fabricating a match."""
    try:
        evidence = _adapter.lookup(cve_id)
        if not isinstance(evidence, dict):
            raise TypeError("adapter must return a dictionary")
        return {
            "status": str(evidence.get("status", "UNAVAILABLE")),
            "affected_version_evidence": evidence.get("affected_version_evidence"),
            "references": [str(ref) for ref in evidence.get("references", []) if ref],
            "note": str(evidence.get("note", "")),
        }
    except Exception:
        return UnconfiguredEvidenceAdapter().lookup(cve_id)
