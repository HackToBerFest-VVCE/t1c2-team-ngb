"""Snowflake-backed append-only contribution and evaluation audit events."""

import base64
import hmac
import os
import re
from datetime import datetime, timezone
from uuid import uuid4


IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*){0,2}$")


class AuditUnavailable(RuntimeError):
    """Raised when the optional audit store is not configured or reachable."""


def audit_configured() -> bool:
    required = (
        "SNOWFLAKE_AUDIT_ACCOUNT", "SNOWFLAKE_AUDIT_USER", "SNOWFLAKE_AUDIT_WAREHOUSE",
        "SNOWFLAKE_AUDIT_DATABASE", "SNOWFLAKE_AUDIT_SCHEMA", "SNOWFLAKE_AUDIT_TABLE",
    )
    has_auth = any(os.getenv(key, "").strip() for key in (
        "SNOWFLAKE_AUDIT_PASSWORD", "SNOWFLAKE_AUDIT_PRIVATE_KEY_PATH", "SNOWFLAKE_AUDIT_PRIVATE_KEY_BASE64"
    ))
    return all(os.getenv(key, "").strip() for key in required) and has_auth


def _table() -> str:
    parts = [
        os.getenv("SNOWFLAKE_AUDIT_DATABASE", ""),
        os.getenv("SNOWFLAKE_AUDIT_SCHEMA", ""),
        os.getenv("SNOWFLAKE_AUDIT_TABLE", "THREATLENS_AUDIT_EVENTS"),
    ]
    table = ".".join(parts)
    if not IDENTIFIER.fullmatch(table):
        raise AuditUnavailable("Audit table configuration is invalid")
    return table


def _connection():
    if not audit_configured():
        raise AuditUnavailable("Audit storage requires a dedicated Snowflake audit identity")
    config = {
        "account": os.environ["SNOWFLAKE_AUDIT_ACCOUNT"],
        "user": os.environ["SNOWFLAKE_AUDIT_USER"],
        "warehouse": os.environ["SNOWFLAKE_AUDIT_WAREHOUSE"],
        "database": os.environ["SNOWFLAKE_AUDIT_DATABASE"],
        "schema": os.environ["SNOWFLAKE_AUDIT_SCHEMA"],
        "login_timeout": 10,
        "network_timeout": 20,
    }
    role = os.getenv("SNOWFLAKE_AUDIT_ROLE", "").strip()
    if role:
        config["role"] = role
    password = os.getenv("SNOWFLAKE_AUDIT_PASSWORD", "").strip()
    key_path = os.getenv("SNOWFLAKE_AUDIT_PRIVATE_KEY_PATH", "").strip()
    key_b64 = os.getenv("SNOWFLAKE_AUDIT_PRIVATE_KEY_BASE64", "").strip()
    if key_b64 or key_path:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
            if key_b64:
                pem = base64.b64decode(key_b64, validate=True)
                private_key = serialization.load_pem_private_key(
                    pem,
                    password=os.getenv("SNOWFLAKE_AUDIT_PRIVATE_KEY_PASSPHRASE", "").encode() or None,
                )
                config.update(
                    authenticator="SNOWFLAKE_JWT",
                    private_key=private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
                )
            else:
                config.update(authenticator="SNOWFLAKE_JWT", private_key_file=key_path)
                passphrase = os.getenv("SNOWFLAKE_AUDIT_PRIVATE_KEY_PASSPHRASE", "")
                if passphrase:
                    config["private_key_file_pwd"] = passphrase
        except Exception as exc:
            raise AuditUnavailable("Audit key-pair authentication is invalid") from exc
    else:
        config["password"] = password
    try:
        import snowflake.connector
        return snowflake.connector.connect(**config)
    except Exception as exc:
        raise AuditUnavailable("Audit Snowflake connection failed") from exc


import json
from pathlib import Path
from threading import Lock

ROOT = Path(__file__).resolve().parents[3]
LOCAL_AUDIT_FILE = ROOT / "data" / "audit_events.json"
_LOCAL_LOCK = Lock()


def _load_local_events() -> list[dict]:
    if not LOCAL_AUDIT_FILE.exists():
        return []
    try:
        with open(LOCAL_AUDIT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def _save_local_events(events: list[dict]) -> None:
    LOCAL_AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCAL_AUDIT_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, default=str)


def list_events(limit: int = 200) -> list[dict]:
    if audit_configured():
        conn = _connection()
        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT EVENT_ID, EVENT_TYPE, PROJECT_ID, ACTOR, EVENT_DATE, "
                    f"CONTRIBUTION_TYPE, POINTS, REVIEWEE, REVIEW_RATING, ARTIFACT_URL, "
                    f"METRIC_NAME, METRIC_VALUE, DETAILS, CREATED_AT "
                    f"FROM {_table()} ORDER BY CREATED_AT DESC LIMIT %s",
                    (max(1, min(int(limit), 500)),),
                )
                columns = [item[0].lower() for item in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
            finally:
                cur.close()
        except Exception as exc:
            raise AuditUnavailable("Audit table could not be queried") from exc
        finally:
            conn.close()

    with _LOCAL_LOCK:
        events = _load_local_events()
        events.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
        return events[:max(1, min(int(limit), 500))]


def append_event(event: dict, token: str | None) -> str:
    expected = os.getenv("THREATLENS_AUDIT_WRITE_TOKEN", "")
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise PermissionError("A valid server-side audit write token is required")
    if not audit_configured():
        raise AuditUnavailable("Audit storage is not configured")
    if audit_configured():
        conn = _connection()
        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"INSERT INTO {_table()} (EVENT_ID, EVENT_TYPE, PROJECT_ID, ACTOR, "
                    f"EVENT_DATE, CONTRIBUTION_TYPE, POINTS, REVIEWEE, REVIEW_RATING, "
                    f"ARTIFACT_URL, METRIC_NAME, METRIC_VALUE, DETAILS, CREATED_AT) "
                    f"VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        event_id, event["event_type"], event["project_id"], event["actor"],
                        event.get("event_date") or datetime.now(timezone.utc).date().isoformat(),
                        event.get("contribution_type"), event.get("points"), event.get("reviewee"),
                        event.get("review_rating"), event.get("artifact_url"),
                        event.get("metric_name"), event.get("metric_value"), event.get("details"),
                        datetime.now(timezone.utc).replace(tzinfo=None),
                    ),
                )
                conn.commit()
            finally:
                cur.close()
        finally:
            conn.close()
        return event_id

    with _LOCAL_LOCK:
        events = _load_local_events()
        record = {
            "event_id": event_id,
            "event_type": event["event_type"],
            "project_id": event["project_id"],
            "actor": event["actor"],
            "event_date": event.get("event_date") or datetime.now(timezone.utc).date().isoformat(),
            "contribution_type": event.get("contribution_type"),
            "points": event.get("points"),
            "reviewee": event.get("reviewee"),
            "review_rating": event.get("review_rating"),
            "artifact_url": event.get("artifact_url"),
            "metric_name": event.get("metric_name"),
            "metric_value": event.get("metric_value"),
            "details": event.get("details"),
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        }
        events.insert(0, record)
        _save_local_events(events)
        return event_id


def summarize_events(events: list[dict]) -> dict:
    contributions: dict[str, float] = {}
    reviews = []
    evaluations = []
    for event in events:
        kind = str(event.get("event_type", "")).upper()
        if kind == "CONTRIBUTION":
            actor = str(event.get("actor", "Unknown"))
            contributions[actor] = contributions.get(actor, 0.0) + float(event.get("points") or 0)
        elif kind == "PEER_REVIEW":
            reviews.append(event)
        elif kind == "EVALUATION":
            evaluations.append(event)
    return {
        "members": [
            {"member": name, "points": round(points, 2)}
            for name, points in sorted(contributions.items(), key=lambda item: (-item[1], item[0]))
        ],
        "peer_reviews": reviews,
        "evaluations": evaluations,
        "scoring_policy": "Fixed event weights: code 5, documentation 2, dataset 4, model 6, peer review 3, other 1. Totals are auditable activity indicators, not identity verification or objective engineering-quality scores.",
    }
