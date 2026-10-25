"""ThreatLens AI Flask application factory."""
import logging
import os
import time
from pathlib import Path

from flask import Flask, abort, g, jsonify, request as flask_request, send_from_directory
from flask_cors import CORS

from .routes.api import api
from .services.provider import ProviderError

__version__ = "1.0.0"


def create_app(test_config=None):
    """Create and configure the Flask application."""
    try:
        from dotenv import load_dotenv
        root = Path(__file__).resolve().parents[2]
        load_dotenv(root / ".env")
        load_dotenv(root / "backend" / ".env")
    except Exception:
        pass

    frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    app = Flask(__name__, static_folder=None)
    app.config.from_mapping(
        JSON_SORT_KEYS=False,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    # ── CORS ──────────────────────────────────────────────────────────
    default_origins = (
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:5000,http://127.0.0.1:5000,"
        "http://localhost:3000,http://127.0.0.1:3000"
    )
    raw_origins = os.getenv("FRONTEND_ORIGINS", default_origins)
    if raw_origins.strip() == "*":
        origins = "*"
    else:
        origins = [x.strip() for x in raw_origins.split(",") if x.strip()]

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": origins,
                "methods": ["GET", "POST", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
                "expose_headers": ["Content-Disposition"],
            }
        },
    )

    # ── Logging ───────────────────────────────────────────────────────
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-5s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Request lifecycle ─────────────────────────────────────────────
    @app.before_request
    def start_timer():
        g.start_time = time.perf_counter()

    @app.after_request
    def log_request(response):
        duration = (time.perf_counter() - g.get("start_time", 0)) * 1000
        app.logger.info(
            "%s %s %s %.1fms",
            flask_request.method,
            flask_request.path,
            response.status_code,
            duration,
        )
        # Allow short browser caching for GET API responses (data refreshes
        # every 60s server-side anyway). POST / mutating requests stay no-store.
        if flask_request.path.startswith("/api/"):
            if flask_request.method == "GET" and response.status_code == 200:
                response.headers.setdefault(
                    "Cache-Control", "public, max-age=30"
                )
            else:
                response.headers["Cache-Control"] = "no-store"
        return response

    # ── Blueprints ────────────────────────────────────────────────────
    app.register_blueprint(api, url_prefix="/api")
    app.register_blueprint(api, name="api_direct")

    # In the Render Docker deployment, serve the built SPA and API from one
    # origin. Local Vite development continues to use its /api proxy.
    if (frontend_dist / "index.html").is_file():
        @app.get("/")
        def frontend_index():
            return send_from_directory(frontend_dist, "index.html")

        @app.get("/<path:frontend_path>")
        def frontend_assets(frontend_path):
            if frontend_path == "api" or frontend_path.startswith("api/"):
                abort(404)
            candidate = frontend_dist / frontend_path
            if candidate.is_file():
                return send_from_directory(frontend_dist, frontend_path)
            if Path(frontend_path).suffix:
                abort(404)
            return send_from_directory(frontend_dist, "index.html")

    # ── Error handlers ────────────────────────────────────────────────
    @app.errorhandler(ProviderError)
    def provider_error(error):
        app.logger.exception("Data provider request failed")
        return jsonify({
            "error": {
                "code": "data_source_unavailable",
                "message": "The configured data source is unavailable.",
            }
        }), 503

    @app.errorhandler(400)
    def bad_request(_):
        return jsonify({
            "error": {"code": "bad_request", "message": "Invalid request."}
        }), 400

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({
            "error": {"code": "not_found", "message": "Resource not found."},
            "debug": {
                "request_path": flask_request.path,
                "path_info": flask_request.environ.get("PATH_INFO"),
                "query_string": flask_request.environ.get("QUERY_STRING"),
                "x_matched_path": flask_request.environ.get("HTTP_X_MATCHED_PATH"),
                "x_forwarded_uri": flask_request.environ.get("HTTP_X_FORWARDED_URI"),
                "request_uri": flask_request.environ.get("REQUEST_URI"),
                "raw_uri": flask_request.environ.get("RAW_URI"),
            }
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify({
            "error": {"code": "method_not_allowed", "message": "Method not allowed."}
        }), 405

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({
            "error": {
                "code": "request_too_large",
                "message": "Request payload exceeds 2 MB.",
            }
        }), 413

    @app.errorhandler(429)
    def rate_limited(_):
        return jsonify({
            "error": {
                "code": "rate_limited",
                "message": "Too many requests. Please try again shortly.",
            }
        }), 429

    @app.errorhandler(500)
    def internal_error(_):
        app.logger.exception("Internal server error")
        return jsonify({
            "error": {
                "code": "internal_error",
                "message": "An unexpected error occurred.",
            }
        }), 500

    # ── Warm up data cache in background ──────────────────────────────
    # Serverless functions should load data on demand: detached threads may
    # be frozen after a response and compete with request memory.
    # DEMO data is local and can be warmed cheaply. Defer LIVE reads until
    # the first API request so health/source checks share the same Snowflake
    # query instead of racing a background connection at process startup.
    if (
        not os.environ.get("VERCEL")
        and os.getenv("DATA_SOURCE", "demo").lower() == "demo"
    ):
        import threading

        def _warmup():
            """Pre-load the NVD dataset so the first request is fast."""
            try:
                from .services.provider import get_records
                from .analytics.core import add_priority
                app.logger.info("⏳ Warming up data cache (background)…")
                frame = get_records()
                add_priority(frame, copy=False)
                app.logger.info("✅ Data cache warm — %d records ready", len(frame))
            except Exception:
                app.logger.warning("⚠ Background warm-up failed; first request will be slower")

    # Only warm up in the main process, not in the Werkzeug reloader child
        if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            threading.Thread(target=_warmup, daemon=True).start()

    return app
