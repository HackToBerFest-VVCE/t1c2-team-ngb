"""Import reviewed public cybersecurity datasets from Hugging Face.

Only selected analysis fields are persisted. Network identifiers, raw payloads,
organization names, and code diffs are intentionally excluded from the local
feature store; code excerpts are read only by the defensive CVEfixes trainer.

Run from the repository root:
  python -m backend.app.data.hf_sync
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
import requests

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "data" / "external"
MANIFEST = OUT / "manifest.json"

DATASETS = {
    "cvefixes": "hitoshura25/cvefixes",
    "incident_reports": "vinitvek/cybersecurityattacks",
    "honeypot_intrusions": "pyToshka/network-intrusion-detection",
}


def _clean(value, limit=8000):
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return None
    return text[:limit]


def _project(name, row):
    """Project remote rows to bounded fields and remove direct identifiers."""
    if name == "cvefixes":
        return {
            "cve_id": _clean(row.get("cve_id"), 32),
            "description": _clean(row.get("cve_description"), 5000),
            "severity": _clean(row.get("severity"), 40),
            "cwe_id": _clean(row.get("cwe_id"), 80),
            "vulnerable_code": _clean(row.get("vulnerable_code"), 6000),
            "fixed_code": _clean(row.get("fixed_code"), 6000),
        }
    if name == "incident_reports":
        return {
            "event_year": row.get("event_year"),
            "affected_country": _clean(row.get("affected_country"), 120),
            "affected_industry": _clean(row.get("affected_industry"), 160),
            "event_type": _clean(row.get("event_type"), 100),
            "event_subtype": _clean(row.get("event_subtype"), 120),
            "motive": _clean(row.get("motive"), 120),
            "description": _clean(row.get("description"), 3000),
            "actor_type": _clean(row.get("actor_type"), 100),
        }
    # Keep only coarse network event fields. Exclude IPs, hostnames, packet
    # payloads, usernames, and raw telemetry blobs from the local dataset.
    return {
        "dest_port": row.get("dest_port"),
        "src_port": row.get("src_port"),
        "proto": _clean(row.get("proto"), 40),
        "app_proto": _clean(row.get("app_proto"), 60),
        "direction": _clean(row.get("direction"), 40),
        "event_type": _clean(row.get("event_type"), 80),
        "alert": _clean(row.get("alert"), 240),
        "attack_vectors": _clean(row.get("attack_vectors"), 200),
        "is_malicious": row.get("is_malicious"),
        "primary_label": _clean(row.get("primary_label"), 100),
    }


def _import_one(name, repo_id):
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise RuntimeError(
            "Install backend requirements first (datasets is required for HF imports)."
        ) from exc

    path = OUT / f"{name}.jsonl"
    temp = path.with_suffix(".jsonl.tmp")
    OUT.mkdir(parents=True, exist_ok=True)
    total = 0
    # Resolve the Hub's generated Parquet exports through the public Dataset
    # Viewer API. This avoids executing a dataset repo's Python loader script,
    # and streaming avoids keeping CVEfixes in memory.
    listing = requests.get(
        "https://datasets-server.huggingface.co/parquet",
        params={"dataset": repo_id}, timeout=30,
    )
    listing.raise_for_status()
    parquet_files = listing.json().get("parquet_files", [])
    if not parquet_files:
        raise RuntimeError(f"Hugging Face has no Parquet export for {repo_id}")
    config_name = "default" if any(x["config"] == "default" for x in parquet_files) else parquet_files[0]["config"]
    config_files = [x for x in parquet_files if x["config"] == config_name]
    split_name = "train" if any(x["split"] == "train" for x in config_files) else config_files[0]["split"]
    parquet_urls = [x["url"] for x in config_files if x["split"] == split_name]
    stream = load_dataset(
        "parquet", data_files={split_name: parquet_urls},
        split=split_name, streaming=True,
    )
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as out:
            for row in stream:
                projected = _project(name, row)
                if name == "cvefixes" and not (projected["vulnerable_code"] or projected["fixed_code"]):
                    continue
                out.write(json.dumps(projected, ensure_ascii=False, default=str) + "\n")
                total += 1
                if total % 1000 == 0:
                    print(f"{repo_id}: imported {total:,} projected rows", flush=True)
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    return total


def main():
    load_dotenv(ROOT / ".env")
    manifest = {
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "sources": {},
        "privacy_note": (
            "Only selected fields are stored. Network IPs, hostnames, raw payloads, "
            "organization names, and incident source URLs are excluded."
        ),
    }
    try:
        for name, repo_id in DATASETS.items():
            count = _import_one(name, repo_id)
            manifest["sources"][name] = {
                "repo_id": repo_id,
                "license": {
                    "cvefixes": "apache-2.0",
                    "incident_reports": "unlicense",
                    "honeypot_intrusions": "bsd-3-clause",
                }[name],
                "rows": count,
                "file": f"{name}.jsonl",
            }
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"Imported {len(manifest['sources'])} Hugging Face datasets to {OUT}")
    except Exception as exc:
        print(f"Hugging Face dataset import failed: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
