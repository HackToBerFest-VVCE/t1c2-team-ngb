"""Source abstraction.

DEMO  → reads a bundled NVD JSON snapshot (transparent, offline-capable).
SNOWFLAKE → connects to a configured Snowflake table (live, requires creds).

The application clearly labels output as LIVE or DEMO.
"""

import json
import os
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "data" / "vulnerabilities.json"
_DEMO_CACHE: tuple[int, int, pd.DataFrame] | None = None
TABLE_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*){0,2}$"
)


class ProviderError(RuntimeError):
    """Raised when the data provider cannot fulfil a request."""


def mode() -> str:
    """Return the current data-source mode (lowercase)."""
    return os.getenv("DATA_SOURCE", "demo").lower()


# ─────────────────────────────────────────────────────────────────────
# Demo provider — bundled NVD snapshot
# ─────────────────────────────────────────────────────────────────────

class DemoProvider:
    """Serves a bundled local JSON snapshot for development and demos."""

    def records(self) -> pd.DataFrame:
        global _DEMO_CACHE
        if not DATA.exists():
            return pd.DataFrame()
        try:
            stat = DATA.stat()
            if _DEMO_CACHE and _DEMO_CACHE[:2] == (stat.st_mtime_ns, stat.st_size):
                return _DEMO_CACHE[2].copy()
            raw = json.loads(DATA.read_text(encoding="utf-8-sig"))
            frame = pd.DataFrame(raw)
            _DEMO_CACHE = (stat.st_mtime_ns, stat.st_size, frame)
            return frame.copy()
        except Exception as exc:
            raise ProviderError("Demo data could not be read") from exc

    def status(self) -> dict:
        metadata: dict = {}
        try:
            metadata = json.loads(
                (ROOT / "data" / "snapshot_metadata.json")
                .read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            pass

        frame = self.records()
        rejected = _rejected_mask(frame)

        return {
            "mode": "DEMO",
            "connected": True,
            "dataset": "Local NVD snapshot",
            "provider": "NIST National Vulnerability Database (NVD)",
            "updated_at": metadata.get("retrieved_at"),
            "record_count": int((~rejected).sum()),
            "note": (
                "Local NVD data for demonstration; "
                "not live Snowflake data."
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
                "SNOWFLAKE_PASSWORD",
                "SNOWFLAKE_WAREHOUSE",
                "SNOWFLAKE_DATABASE",
                "SNOWFLAKE_SCHEMA",
                "SNOWFLAKE_TABLE",
            )
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            raise ProviderError("Snowflake configuration is incomplete")
        if not TABLE_RE.fullmatch(required["SNOWFLAKE_TABLE"]):
            raise ProviderError("Invalid Snowflake table identifier")
        return required  # type: ignore[return-value]

    def _connection(self):
        try:
            import snowflake.connector

            c = self._config()
            return snowflake.connector.connect(
                account=c["SNOWFLAKE_ACCOUNT"],
                user=c["SNOWFLAKE_USER"],
                password=c["SNOWFLAKE_PASSWORD"],
                warehouse=c["SNOWFLAKE_WAREHOUSE"],
                database=c["SNOWFLAKE_DATABASE"],
                schema=c["SNOWFLAKE_SCHEMA"],
                role=os.getenv("SNOWFLAKE_ROLE"),
                login_timeout=10,
                network_timeout=20,
            )
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                "Could not connect to configured Snowflake source"
            ) from exc

    def records(self) -> pd.DataFrame:
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
                return pd.DataFrame(cur.fetchall(), columns=cols)
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
        frame = self.records()
        rejected = _rejected_mask(frame)
        return {
            "mode": "LIVE",
            "connected": True,
            "dataset": (
                f"{os.getenv('SNOWFLAKE_DATABASE')}."
                f"{os.getenv('SNOWFLAKE_SCHEMA')}."
                f"{os.getenv('SNOWFLAKE_TABLE')}"
            ),
            "provider": "Configured Snowflake table",
            "updated_at": None,
            "record_count": int((~rejected).sum()),
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
    return (
        frame.description.fillna("").astype(str)
        .str.match(r"^Rejected reason:", case=False)
    )


def get_provider():
    """Return the appropriate provider based on DATA_SOURCE env."""
    selected = mode()
    if selected == "demo":
        return DemoProvider()
    if selected == "snowflake":
        return SnowflakeProvider()
    raise ProviderError("DATA_SOURCE must be demo or snowflake")


def get_records() -> pd.DataFrame:
    """Fetch, normalise, and clean records from the active provider."""
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
            frame["severity"].fillna("").astype(str)
            .str.upper().replace({"": "UNKNOWN"})
        )
        frame["cve_id"] = (
            frame["cve_id"].fillna("").astype(str).str.upper()
        )
        # NVD includes withdrawn CVE IDs — exclude them from all analysis
        rejected = _rejected_mask(frame)
        frame = frame.loc[~rejected].copy()

    return frame
