"""ThreatLens AI Flask application factory."""
import logging
import os
import time

from flask import Flask, g, jsonify, request as flask_request
from flask_cors import CORS

from .routes.api import api
from .services.provider import ProviderError

__version__ = "1.0.0"


def create_app(test_config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)
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
        # Prevent caching of API responses by default
        if flask_request.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # ── Blueprints ────────────────────────────────────────────────────
    app.register_blueprint(api, url_prefix="/api")

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
            "error": {"code": "not_found", "message": "Resource not found."}
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

    return app
