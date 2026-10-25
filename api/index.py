"""Vercel serverless function entrypoint."""
import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlencode

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from backend.app import create_app

flask_app = create_app()


class VercelMiddleware:
    """WSGI middleware to normalize PATH_INFO and handle routing on Vercel."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query_string = environ.get("QUERY_STRING", "")
        qs = parse_qs(query_string)

        # 1. Direct debug inspection
        path_info = environ.get("PATH_INFO", "")
        if "__debug" in qs or path_info in ("/api/debug", "/debug"):
            headers = [("Content-Type", "application/json")]
            start_response("200 OK", headers)
            info = {k: str(v) for k, v in environ.items() if not k.startswith("wsgi.input")}
            return [json.dumps(info, indent=2).encode("utf-8")]

        resolved_path = None

        # 2. Extract path from __path query parameter if supplied by Vercel rewrite
        if "__path" in qs:
            raw_val = qs.pop("__path")[0].strip()
            environ["QUERY_STRING"] = urlencode(qs, doseq=True)
            if raw_val:
                resolved_path = raw_val if raw_val.startswith("/") else f"/{raw_val}"
            else:
                resolved_path = "/health"

        # 3. Fallback: check headers / environment variables
        if not resolved_path:
            for key in ("HTTP_X_FORWARDED_URI", "REQUEST_URI", "RAW_URI"):
                val = environ.get(key)
                if val and not val.startswith("/api/index.py"):
                    resolved_path = val.split("?")[0]
                    break

        if not resolved_path:
            matched = environ.get("HTTP_X_MATCHED_PATH", "")
            if matched and not matched.startswith("/api/index.py"):
                resolved_path = matched.split("?")[0]

        # 4. Normalize path for Flask
        if resolved_path:
            if not resolved_path.startswith("/api"):
                resolved_path = f"/api{resolved_path}"
            environ["PATH_INFO"] = resolved_path

        # If PATH_INFO is still /api/index.py, /api, or empty, route to /api/health
        if environ.get("PATH_INFO") in ("/api/index.py", "/api", "/api/", "", None):
            environ["PATH_INFO"] = "/api/health"

        return self.wsgi_app(environ, start_response)


app = VercelMiddleware(flask_app)
