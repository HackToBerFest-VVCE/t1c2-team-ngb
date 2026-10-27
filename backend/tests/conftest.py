"""Shared test fixtures for ThreatLens AI backend test suite."""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app


@pytest.fixture
def client(monkeypatch):
    """Create a deterministic test client using demo data source."""
    monkeypatch.setenv("DATA_SOURCE", "demo")
    app = create_app({"TESTING": True})
    return app.test_client()
