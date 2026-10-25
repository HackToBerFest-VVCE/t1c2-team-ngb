"""Vercel entrypoint when project root is configured as backend."""
import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from backend.app import create_app

app = create_app()
