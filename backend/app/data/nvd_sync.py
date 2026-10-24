"""Import yearly official NVD CVE 2.0 feeds into local DEMO or Snowflake.

Examples (from repository root):
  python -m backend.app.data.nvd_sync --start-year 2025
  python -m backend.app.data.nvd_sync --start-year 2002 --target snowflake

The yearly feeds are public; Snowflake writes require the configured service
account. Local imports atomically replace data/vulnerabilities.json.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[3]
DATA_FILE = ROOT / "data" / "vulnerabilities.json"
META_FILE = ROOT / "data" / "snapshot_metadata.json"
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip"


def _severity(score, provided):
    value = str(provided or "").upper()
    if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}:
        return value
    if score is None:
        return "UNKNOWN"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"


def parse_vulnerability(item: dict) -> dict | None:
    cve = item.get("cve", {})
    cve_id = str(cve.get("id") or "").upper()
    if not cve_id.startswith("CVE-"):
        return None
    descriptions = cve.get("descriptions", [])
    description = next((x.get("value") for x in descriptions if x.get("lang") == "en"), None)
    if description is None and descriptions:
        description = descriptions[0].get("value")

    score = severity = None
    metrics = cve.get("metrics", {})
    for field in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(field) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            break

    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value not in cwes:
                cwes.append(value)

    products = []
    def visit(nodes):
        for node in nodes or []:
            for match in node.get("cpeMatch", []):
                parts = str(match.get("criteria", "")).split(":")
                if len(parts) > 4 and parts[3] not in {"*", "-"} and parts[4] not in {"*", "-"}:
                    label = f"{parts[3]}/{parts[4]}"
                    if label not in products:
                        products.append(label)
            visit(node.get("nodes", []))
            visit(node.get("children", []))
    visit(cve.get("configurations", []))

    published = cve.get("published")
    modified = cve.get("lastModified")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    return {
        "cve_id": cve_id,
        "description": description,
        "published": published,
        "last_modified": modified,
        "cvss_score": score,
        "severity": _severity(score, severity),
        "cwe": "; ".join(cwes) or None,
        "affected_products": "; ".join(products[:80]) or None,
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def fetch_year(year: int) -> list[dict]:
    request = urllib.request.Request(
        FEED_URL.format(year=year),
        headers={"User-Agent": "ThreatLensAI/1.0 (NVD public CVE feed importer)"},
    )
    download_path = None
    try:
        curl = shutil.which("curl.exe") or shutil.which("curl")
        if curl:
            fd, download_path = tempfile.mkstemp(prefix=f"nvd-{year}-", suffix=".zip")
            os.close(fd)
            print(f"Downloading NVD annual feed for {year}…", flush=True)
            subprocess.run(
                [curl, "-4", "--fail", "--location", "--silent", "--show-error",
                 "--connect-timeout", "15", "--max-time", "300",
                 FEED_URL.format(year=year), "--output", download_path],
                check=True,
                capture_output=True,
                text=True,
            )
            archive = Path(download_path)
        else:
            with urllib.request.urlopen(request, timeout=90) as response:
                archive = BytesIO(response.read())
        with zipfile.ZipFile(archive) as zipped:
            json_name = next((n for n in zipped.namelist() if n.endswith(".json")), None)
            if not json_name:
                raise RuntimeError(f"NVD feed for {year} contains no JSON file")
            with zipped.open(json_name) as stream:
                document = json.load(stream)
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
        raise RuntimeError(f"NVD feed for {year} was invalid") from exc
    except (urllib.error.URLError, subprocess.CalledProcessError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Could not download NVD feed for {year}; check network access and retry") from exc
    finally:
        if download_path:
            try: Path(download_path).unlink(missing_ok=True)
            except OSError: pass
    return [r for item in document.get("vulnerabilities", []) if (r := parse_vulnerability(item))]


def _existing_ids() -> set[str]:
    if not DATA_FILE.exists():
        return set()
    try:
        with DATA_FILE.open(encoding="utf-8-sig") as f:
            return {str(row.get("cve_id", "")).upper() for row in json.load(f)}
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()


def _local_import(years: list[int]) -> int:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    old_ids = _existing_ids()
    added = 0
    fd, temp_name = tempfile.mkstemp(prefix="threatlens-nvd-", suffix=".json", dir=DATA_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write("[")
            first = True
            # Retain older local rows outside the imported year range.
            if DATA_FILE.exists():
                with DATA_FILE.open(encoding="utf-8-sig") as f:
                    for old in json.load(f):
                        try:
                            year = int(str(old.get("cve_id", "")).split("-")[1])
                        except (IndexError, ValueError):
                            year = -1
                        if year not in years:
                            if not first: out.write(",")
                            json.dump(old, out, ensure_ascii=False, separators=(",", ":"))
                            first = False
            for year in years:
                rows = fetch_year(year)
                for row in rows:
                    if row["cve_id"] in old_ids and int(row["cve_id"].split("-")[1]) not in years:
                        continue
                    if not first: out.write(",")
                    json.dump(row, out, ensure_ascii=False, separators=(",", ":"))
                    first = False
                    added += 1
                print(f"Imported {len(rows):,} NVD records for {year}", flush=True)
            out.write("]")
        os.replace(temp_name, DATA_FILE)
    except BaseException:
        try: os.unlink(temp_name)
        except OSError: pass
        raise
    return added


def _snowflake_import(years: list[int], batch_size: int = 500):
    from ..services.provider import SnowflakeProvider

    provider = SnowflakeProvider()
    config = provider._config()
    conn = provider._connection()
    target = config["SNOWFLAKE_TABLE"]
    stage = "THREATLENS_NVD_STAGE"
    columns = "CVE_ID, DESCRIPTION, PUBLISHED, LAST_MODIFIED, CVSS_SCORE, SEVERITY, CWE, AFFECTED_PRODUCTS, SOURCE_URL"
    placeholders = ",".join(["%s"] * 9)
    total = 0
    try:
        cur = conn.cursor()
        try:
            cur.execute(f"CREATE TEMPORARY TABLE {stage} (CVE_ID VARCHAR, DESCRIPTION VARCHAR, PUBLISHED TIMESTAMP_TZ, LAST_MODIFIED TIMESTAMP_TZ, CVSS_SCORE FLOAT, SEVERITY VARCHAR, CWE VARCHAR, AFFECTED_PRODUCTS VARCHAR, SOURCE_URL VARCHAR)")
            for year in years:
                records = fetch_year(year)
                for offset in range(0, len(records), batch_size):
                    part = records[offset:offset + batch_size]
                    values = [tuple(row.get(k) for k in ("cve_id", "description", "published", "last_modified", "cvss_score", "severity", "cwe", "affected_products", "source_url")) for row in part]
                    cur.executemany(f"INSERT INTO {stage} ({columns}) VALUES ({placeholders})", values)
                cur.execute(
                    f"MERGE INTO {target} t USING (SELECT * FROM {stage} WHERE CVE_ID LIKE %s QUALIFY ROW_NUMBER() OVER (PARTITION BY CVE_ID ORDER BY LAST_MODIFIED DESC NULLS LAST)=1) s ON t.CVE_ID=s.CVE_ID "
                    "WHEN MATCHED THEN UPDATE SET DESCRIPTION=s.DESCRIPTION, PUBLISHED=s.PUBLISHED, LAST_MODIFIED=s.LAST_MODIFIED, CVSS_SCORE=s.CVSS_SCORE, SEVERITY=s.SEVERITY, CWE=s.CWE, AFFECTED_PRODUCTS=s.AFFECTED_PRODUCTS, SOURCE_URL=s.SOURCE_URL, INGESTED_AT=CURRENT_TIMESTAMP() "
                    "WHEN NOT MATCHED THEN INSERT (CVE_ID,DESCRIPTION,PUBLISHED,LAST_MODIFIED,CVSS_SCORE,SEVERITY,CWE,AFFECTED_PRODUCTS,SOURCE_URL) VALUES (s.CVE_ID,s.DESCRIPTION,s.PUBLISHED,s.LAST_MODIFIED,s.CVSS_SCORE,s.SEVERITY,s.CWE,s.AFFECTED_PRODUCTS,s.SOURCE_URL)",
                    (f"CVE-{year}-%",),
                )
                cur.execute(f"DELETE FROM {stage}")
                total += len(records)
                print(f"Loaded {len(records):,} NVD records for {year}", flush=True)
        finally:
            cur.close()
    finally:
        conn.close()
    return total


def main():
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description="Import official NVD CVE 2.0 yearly feeds")
    parser.add_argument("--start-year", type=int, default=max(2002, datetime.now().year - 2), help="First CVE year (use 2002 for full history)")
    parser.add_argument("--end-year", type=int, default=datetime.now().year)
    parser.add_argument("--target", choices=("local", "snowflake"), default="local")
    args = parser.parse_args()
    current = datetime.now(timezone.utc).year
    if args.start_year < 2002 or args.end_year > current or args.start_year > args.end_year:
        parser.error(f"Years must satisfy 2002 <= start <= end <= {current}")
    years = list(range(args.start_year, args.end_year + 1))
    try:
        if args.target == "snowflake":
            count = _snowflake_import(years)
        else:
            count = _local_import(years)
        metadata = {}
        if META_FILE.exists():
            try: metadata = json.loads(META_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError): pass
        metadata.update({
            "provider": "NIST National Vulnerability Database (NVD)",
            "api": "https://nvd.nist.gov/vuln/data-feeds",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "import_method": "Official NVD CVE 2.0 yearly JSON feeds",
            "imported_years": years,
            "target": args.target,
            "live_snowflake": args.target == "snowflake",
            "imported_records": count,
        })
        if args.target == "local":
            metadata["bundled_records"] = len(_existing_ids())
            META_FILE.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        print(f"Completed {args.target} import: {count:,} source rows across {len(years)} year feeds.")
    except Exception as exc:
        print(f"NVD import failed: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
