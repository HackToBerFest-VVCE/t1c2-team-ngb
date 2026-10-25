"""Vercel serverless function entrypoint."""
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from backend.app import create_app

app = create_app()
