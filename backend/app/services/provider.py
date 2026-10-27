"""Source abstraction.

DEMO  → reads a bundled NVD JSON snapshot (transparent, offline-capable).
SNOWFLAKE → connects to a configured Snowflake table (live, requires creds).

The application clearly labels output as LIVE or DEMO.
"""

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

import pandas as pd

ROOT = Path(__file__).resolve().parents[3]
SNAPSHOT_DATA = ROOT / "data" / "vulnerabilities.json"
FULL_CATALOG_DATA = ROOT / "data" / "vulnerabilities.full.json"
FULL_CATALOG_GZIP = ROOT / "data" / "vulnerabilities.full.json.gz"
FULL_CATALOG_PARQUET = ROOT / "data" / "vulnerabilities.full.parquet"
_DEMO_CACHE: tuple[int, int, pd.DataFrame] | None = None
TABLE_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*){0,2}$"
)

# ── Process-level cache for fully normalised records ──────────────────
_RECORDS_CACHE: tuple[float, int, int, pd.DataFrame] | None = None
_RECORDS_TTL = 300  # seconds; keep the live catalog warm while analysts paginate
_SNOWFLAKE_LAST_REFRESH: str | None = None
_RECORDS_LOCK = RLock()


class ProviderError(RuntimeError):
    """Raised when the data provider cannot fulfil a request."""


def mode() -> str:
    """Return the current data-source mode (lowercase)."""
    return os.getenv("DATA_SOURCE", "demo").lower()


def _full_catalog_path() -> Path | None:
    """Return the full NVD catalog in raw or compressed form when available."""
    if FULL_CATALOG_PARQUET.exists():
        return FULL_CATALOG_PARQUET
    if FULL_CATALOG_DATA.exists():
        return FULL_CATALOG_DATA
    if FULL_CATALOG_GZIP.exists():
        return FULL_CATALOG_GZIP
    return None


# ─────────────────────────────────────────────────────────────────────
# Demo provider — bundled NVD snapshot
# ─────────────────────────────────────────────────────────────────────

class DemoProvider:
    """Serves a bundled local JSON snapshot for development and demos."""

    def records(self) -> pd.DataFrame:
        global _DEMO_CACHE
        data_path = _full_catalog_path() or SNAPSHOT_DATA
        if not data_path.exists():
            return pd.DataFrame()
        try:
            stat = data_path.stat()
            if _DEMO_CACHE and _DEMO_CACHE[:2] == (stat.st_mtime_ns, stat.st_size):
                return _DEMO_CACHE[2]
            if data_path.suffix == ".parquet":
                frame = pd.read_parquet(data_path, dtype_backend="pyarrow")
            else:
                # Arrow-backed strings use substantially less RAM than Python
                # objects for the full NVD catalog. Let pandas stream-decode
                # the gzip JSON instead of materializing Python dictionaries.
                frame = pd.read_json(
                    data_path,
                    orient="records",
                    compression="gzip" if data_path.suffix == ".gz" else "infer",
                    encoding="utf-8-sig",
                    dtype_backend="pyarrow",
                )
            _DEMO_CACHE = (stat.st_mtime_ns, stat.st_size, frame)
            return frame
        except Exception as exc:
            raise ProviderError("Demo data could not be read") from exc

    def status(self) -> dict:
        metadata: dict = {}
        try:
            metadata_path = (
                ROOT / "data" / "full_catalog_metadata.json"
                if _full_catalog_path() is not None
                else ROOT / "data" / "snapshot_metadata.json"
            )
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass

        frame = self.records()
        rejected = _rejected_mask(frame)

        return {
            "mode": "DEMO",
            "connected": True,
            "dataset": "Full local NVD catalog" if _full_catalog_path() is not None else "Local NVD snapshot",
            "provider": "NIST National Vulnerability Database (NVD)",
            "updated_at": metadata.get("retrieved_at"),
            "record_count": int((~rejected).sum()),
            "note": (
                "Full local NVD catalog; not live Snowflake data."
                if _full_catalog_path() is not None
                else "Local NVD sample for demonstration; not live Snowflake data."
            ),
        }


# ─────────────────────────────────────────────────────────────────────
# Snowflake provider — live data
# ─────────────────────────────────────────────────────────────────────

class SnowflakeProvider:
    """Connects to a configured Snowflake table for live analysis."""

    def _config(self) -> dict[str, str]:
        required = {
            k: os.getenv(k)
            for k in (
                "SNOWFLAKE_ACCOUNT",
                "SNOWFLAKE_USER",
                "SNOWFLAKE_WAREHOUSE",
                "SNOWFLAKE_DATABASE",
                "SNOWFLAKE_SCHEMA",
                "SNOWFLAKE_TABLE",
            )
        }
        missing = [k for k, v in required.items() if not v]
        password = os.getenv("SNOWFLAKE_PASSWORD", "").strip()
        private_key = os.getenv("SNOWFLAKE_PRIVATE_KEY_PATH", "").strip()
        private_key_base64 = os.getenv("SNOWFLAKE_PRIVATE_KEY_BASE64", "").strip()
        if not password and not private_key and not private_key_base64:
            missing.append(
                "SNOWFLAKE_PASSWORD, SNOWFLAKE_PRIVATE_KEY_PATH, or "
                "SNOWFLAKE_PRIVATE_KEY_BASE64"
            )
        if missing:
            raise ProviderError("Snowflake configuration is incomplete")
        if not TABLE_RE.fullmatch(required["SNOWFLAKE_TABLE"]):
            raise ProviderError("Invalid Snowflake table identifier")
        required["SNOWFLAKE_PASSWORD"] = password
        required["SNOWFLAKE_PRIVATE_KEY_PATH"] = private_key
        required["SNOWFLAKE_PRIVATE_KEY_BASE64"] = private_key_base64
        return required  # type: ignore[return-value]

    def _connection(self):
        try:
            import snowflake.connector

            c = self._config()
            connection = dict(
                account=c["SNOWFLAKE_ACCOUNT"],
                user=c["SNOWFLAKE_USER"],
                warehouse=c["SNOWFLAKE_WAREHOUSE"],
                database=c["SNOWFLAKE_DATABASE"],
                schema=c["SNOWFLAKE_SCHEMA"],
                role=os.getenv("SNOWFLAKE_ROLE"),
                login_timeout=10,
                network_timeout=20,
            )
            if c["SNOWFLAKE_PRIVATE_KEY_BASE64"]:
                import base64
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.serialization import (
                    Encoding,
                    NoEncryption,
                    PrivateFormat,
                )

                pem_data = base64.b64decode(
                    c["SNOWFLAKE_PRIVATE_KEY_BASE64"], validate=True
                )
                passphrase = os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "")
                private_key = serialization.load_pem_private_key(
                    pem_data,
                    password=passphrase.encode("utf-8") if passphrase else None,
                )
                connection.update(
                    authenticator="SNOWFLAKE_JWT",
                    private_key=private_key.private_bytes(
                        Encoding.DER,
                        PrivateFormat.PKCS8,
                        NoEncryption(),
                    ),
                )
            elif c["SNOWFLAKE_PRIVATE_KEY_PATH"]:
                connection.update(
                    authenticator="SNOWFLAKE_JWT",
                    private_key_file=c["SNOWFLAKE_PRIVATE_KEY_PATH"],
                )
                passphrase = os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "")
                if passphrase:
                    connection["private_key_file_pwd"] = passphrase
            else:
                connection["password"] = c["SNOWFLAKE_PASSWORD"]
            return snowflake.connector.connect(**connection)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                "Could not connect to configured Snowflake source"
            ) from exc

    def cortex_complete(self, prompt: str, model: str) -> str:
        """Run a single bounded Cortex completion in the configured account."""
        if len(prompt) > 24000:
            raise ProviderError("Cortex prompt exceeds the configured size limit")
        conn = self._connection()
        try:
            cur = conn.cursor()
            try:
                # 1. Try AI_COMPLETE if available for the account
                try:
                    cur.execute("SELECT AI_COMPLETE(%s, %s)", (model, prompt))
                    row = cur.fetchone()
                    if row and isinstance(row[0], str) and row[0].strip():
                        return row[0].strip()[:16000]
                except Exception:
                    pass

                # 2. Try native Snowflake AI_SUMMARIZE (supported on trial accounts)
                cur.execute("SELECT AI_SUMMARIZE(%s)", (prompt[:4000],))
                row = cur.fetchone()
                if row and isinstance(row[0], str) and row[0].strip():
                    return row[0].strip()[:16000]

                raise ProviderError("Snowflake Cortex returned an empty completion")
            finally:
                cur.close()
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("Snowflake Cortex is currently unavailable") from exc
        finally:
            conn.close()

    def page_records(self, page: int, per_page: int, sort: str, order: str) -> tuple[pd.DataFrame, int]:
        """Fetch one unfiltered catalog page from Snowflake without downloading the full table."""
        table = self._config()["SNOWFLAKE_TABLE"]
        order_by = {
            "severity": (
                "CASE UPPER(COALESCE(SEVERITY, '')) "
                "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
                "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 "
                f"WHEN 'NONE' THEN 4 WHEN 'UNKNOWN' THEN 5 ELSE 6 END {'ASC' if order == 'desc' else 'DESC'}, "
                "PUBLISHED DESC NULLS LAST, CVSS_SCORE DESC NULLS LAST, CVE_ID ASC"
            ),
            "cvss_score": f"CVSS_SCORE {'ASC' if order == 'asc' else 'DESC'} NULLS LAST, PUBLISHED DESC NULLS LAST, CVE_ID ASC",
            "published": f"PUBLISHED {'ASC' if order == 'asc' else 'DESC'} NULLS LAST, CVE_ID ASC",
            "cve_id": f"CVE_ID {'ASC' if order == 'asc' else 'DESC'}",
            "priority_score": f"CVSS_SCORE {'ASC' if order == 'asc' else 'DESC'} NULLS LAST, PUBLISHED DESC NULLS LAST, CVE_ID ASC",
        }[sort]
        columns = (
            "CVE_ID, DESCRIPTION, PUBLISHED, LAST_MODIFIED, CVSS_SCORE, "
            "SEVERITY, CWE, AFFECTED_PRODUCTS, SOURCE_URL"
        )
        offset = (page - 1) * per_page
        conn = self._connection()
        try:
            cur = conn.cursor()
            try:
                # Escape `%` for the connector's pyformat parameter binding;
                # Snowflake receives a single SQL wildcard after binding.
                visible = "COALESCE(DESCRIPTION, '') NOT ILIKE 'Rejected reason:%%'"
                cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {visible}")
                total = int(cur.fetchone()[0])
                cur.execute(
                    f"SELECT {columns} FROM {table} WHERE {visible} ORDER BY {order_by} LIMIT %s OFFSET %s",
                    (per_page, offset),
                )
                names = [item[0].lower() for item in cur.description]
                return pd.DataFrame(cur.fetchall(), columns=names), total
            finally:
                cur.close()
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("Could not query a page from the configured Snowflake table") from exc
        finally:
            conn.close()

    def records(self) -> pd.DataFrame:
        global _SNOWFLAKE_LAST_REFRESH
        table = self._config()["SNOWFLAKE_TABLE"]
        try:
            row_limit = int(os.getenv("SNOWFLAKE_MAX_ROWS", "500000"))
        except ValueError as exc:
            raise ProviderError("SNOWFLAKE_MAX_ROWS must be an integer") from exc
        if not 1 <= row_limit <= 1_000_000:
            raise ProviderError("SNOWFLAKE_MAX_ROWS must be between 1 and 1000000")
        conn = self._connection()
        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT CVE_ID, DESCRIPTION, PUBLISHED, LAST_MODIFIED, "
                    f"CVSS_SCORE, SEVERITY, CWE, AFFECTED_PRODUCTS, SOURCE_URL "
                    f"FROM {table} ORDER BY PUBLISHED DESC LIMIT %s",
                    (row_limit,),
                )
                cols = [x[0].lower() for x in cur.description]
                frame = pd.DataFrame(cur.fetchall(), columns=cols)
                _SNOWFLAKE_LAST_REFRESH = datetime.now(timezone.utc).isoformat()
                return frame
            finally:
                cur.close()
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                "Could not query configured Snowflake table"
            ) from exc
        finally:
            conn.close()

    def status(self) -> dict:
        frame = get_records()
        return {
            "mode": "LIVE",
            "connected": True,
            "dataset": (
                f"{os.getenv('SNOWFLAKE_DATABASE')}."
                f"{os.getenv('SNOWFLAKE_SCHEMA')}."
                f"{os.getenv('SNOWFLAKE_TABLE')}"
            ),
            "provider": "Configured Snowflake table",
            "updated_at": _SNOWFLAKE_LAST_REFRESH,
            "record_count": int(len(frame)),
            "note": "Live Snowflake data; results bounded by SNOWFLAKE_MAX_ROWS.",
        }


# ─────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────

def _rejected_mask(frame: pd.DataFrame) -> pd.Series:
    """Boolean mask: True for records whose description starts with
    'Rejected reason:' (NVD-withdrawn CVE IDs)."""
    if "description" not in frame.columns:
        return pd.Series(False, index=frame.index)
    return frame.description.fillna("").str.match(
        r"^Rejected reason:", case=False
    ).fillna(False)


def get_provider():
    """Return the appropriate provider based on DATA_SOURCE env."""
    selected = mode()
    if selected == "demo":
        return DemoProvider()
    if selected == "snowflake":
        return SnowflakeProvider()
    raise ProviderError("DATA_SOURCE must be demo or snowflake")


def get_records() -> pd.DataFrame:
    """Return the active normalized snapshot, coalescing concurrent loads."""
    with _RECORDS_LOCK:
        return _load_records()


def _load_records() -> pd.DataFrame:
    """Fetch, normalise, and clean records from the active provider.

    Results are cached for up to ``_RECORDS_TTL`` seconds so that rapid
    successive API calls (dashboard page loads) don't re-parse the full
    268 MB JSON each time.
    """
    global _RECORDS_CACHE

    # Determine current data-file identity for cache validation
    data_path = _full_catalog_path() or SNAPSHOT_DATA
    try:
        stat = data_path.stat()
        file_mtime, file_size = stat.st_mtime_ns, stat.st_size
    except OSError:
        file_mtime, file_size = 0, 0

    now = time.time()
    if (
        _RECORDS_CACHE is not None
        and (now - _RECORDS_CACHE[0]) < _RECORDS_TTL
        and _RECORDS_CACHE[1] == file_mtime
        and _RECORDS_CACHE[2] == file_size
    ):
        return _RECORDS_CACHE[3]

    frame = get_provider().records()

    # Ensure all expected columns exist
    for col in (
        "cve_id", "description", "published", "last_modified",
        "cvss_score", "severity", "cwe", "affected_products", "source_url",
    ):
        if col not in frame:
            frame[col] = None

    if not frame.empty:
        frame["published"] = pd.to_datetime(
            frame["published"], errors="coerce", utc=True
        )
        frame["last_modified"] = pd.to_datetime(
            frame["last_modified"], errors="coerce", utc=True
        )
        frame["cvss_score"] = pd.to_numeric(
            frame["cvss_score"], errors="coerce"
        )
        frame["severity"] = (
            frame["severity"].fillna("").astype("string[pyarrow]")
            .str.upper().replace({"": "UNKNOWN"})
        )
        frame["cve_id"] = (
            frame["cve_id"].fillna("").astype("string[pyarrow]").str.upper()
        )
        # NVD includes withdrawn CVE IDs — exclude them from all analysis
        rejected = _rejected_mask(frame)
        # Drop withdrawn records in place so the cached raw dataframe and the
        # normalized dataframe do not occupy memory as two full copies.
        frame.drop(index=frame.index[rejected], inplace=True)

    _RECORDS_CACHE = (now, file_mtime, file_size, frame)
    return frame
