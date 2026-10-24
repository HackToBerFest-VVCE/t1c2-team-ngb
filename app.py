"""Vercel entrypoint for the ThreatLens Flask application."""

from backend.app import create_app

app = create_app()
