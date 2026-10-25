"""Vercel serverless function entrypoint."""
import os
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from backend.app import create_app

flask_app = create_app()


@flask_app.route("/debug")
@flask_app.route("/api/debug")
@flask_app.route("/api/index.py")
def _debug():
    import flask
    return {
        "path": flask.request.path,
        "environ_PATH_INFO": flask.request.environ.get("PATH_INFO"),
        "environ_REQUEST_URI": flask.request.environ.get("REQUEST_URI"),
        "environ_RAW_URI": flask.request.environ.get("RAW_URI"),
        "headers": dict(flask.request.headers),
        "url_map": [str(rule) for rule in flask_app.url_map.iter_rules() if "health" in str(rule) or "summary" in str(rule)],
    }


class VercelMiddleware:
    """WSGI middleware to normalize PATH_INFO on Vercel."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        # Check X-Matched-Path or REQUEST_URI
        matched = environ.get("HTTP_X_MATCHED_PATH") or environ.get("REQUEST_URI", "") or environ.get("RAW_URI", "")
        if matched and not matched.startswith("/api/index.py"):
            environ["PATH_INFO"] = matched.split("?")[0]
        elif path.endswith("/api/index.py") or path == "/api/index.py":
            # If path was rewritten to /api/index.py, check if query param or path is available
            pass
        return self.wsgi_app(environ, start_response)


app = VercelMiddleware(flask_app)
