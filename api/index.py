"""Vercel serverless function entrypoint."""
import os
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from backend.app import create_app

flask_app = create_app()


class VercelMiddleware:
    """WSGI middleware to normalize PATH_INFO on Vercel."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path.endswith("/api/index.py") or path == "/api/index.py":
            req_uri = environ.get("REQUEST_URI", "") or environ.get("RAW_URI", "")
            if req_uri and not req_uri.startswith("/api/index.py"):
                clean_path = req_uri.split("?")[0]
                environ["PATH_INFO"] = clean_path
        return self.wsgi_app(environ, start_response)


app = VercelMiddleware(flask_app)
