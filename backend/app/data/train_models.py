"""Train small, task-specific defensive models from imported public datasets.

Models are separate by task and dataset; records from different schemas are
never concatenated into a single training table. Reports include held-out
metrics and are written locally under data/models/.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[3]
EXTERNAL = ROOT / "data" / "external"
MODELS = ROOT / "data" / "models"
RANDOM_STATE = 42


def _read(name):
    path = EXTERNAL / f"{name}.jsonl"
    return pd.read_json(path, lines=True) if path.exists() else pd.DataFrame()


def _text_model():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=20000, ngram_range=(1, 2), min_df=2,
            strip_accents="unicode", sublinear_tf=True,
        )),
        ("classifier", LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE,
        )),
    ])


def _metric_payload(y_true, y_pred):
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "weighted_f1": round(float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 4),
        "per_class": classification_report(
            y_true, y_pred, output_dict=True, zero_division=0,
        ),
    }


def _train_text_task(name, frame, text_columns, label_column, *, min_per_class=10):
    if frame.empty or label_column not in frame:
        return {"status": "unavailable", "reason": f"Missing {label_column} source data."}
    working = frame.copy()
    working["_label"] = working[label_column].fillna("").astype(str).str.strip()
    working = working[working["_label"].ne("")]
    working = working[~working["_label"].str.lower().isin({"nan", "none", "unknown", "undetermined"})]
    counts = working["_label"].value_counts()
    working = working[working["_label"].isin(counts[counts >= min_per_class].index)].copy()
    if working["_label"].nunique() < 2 or len(working) < 40:
        return {
            "status": "unavailable",
            "reason": "Not enough supported labeled examples for a held-out classification model.",
            "rows_available": int(len(working)),
        }
    working["_text"] = working[text_columns].fillna("").astype(str).agg(" ".join, axis=1)
    x_train, x_test, y_train, y_test = train_test_split(
        working["_text"], working["_label"], test_size=0.2,
        random_state=RANDOM_STATE, stratify=working["_label"],
    )
    model = _text_model().fit(x_train, y_train)
    predictions = model.predict(x_test)
    joblib.dump(model, MODELS / f"{name}.joblib")
    return {
        "status": "trained",
        "task": f"Predict {label_column} from selected descriptive text",
        "source_rows": int(len(frame)),
        "labeled_rows": int(len(working)),
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "class_counts": {str(k): int(v) for k, v in working["_label"].value_counts().items()},
        "metrics": _metric_payload(y_test, predictions),
        "model_file": f"{name}.joblib",
        "limitations": "Held-out performance on this dataset only; dataset labels and source coverage may be incomplete or biased.",
    }


def _train_cve_code(frame):
    if frame.empty:
        return {"status": "unavailable", "reason": "CVEfixes import is missing."}
    examples = []
    groups = []
    # Balance the classes while allowing two snippets per CVE. Grouped splitting
    # keeps snippets from the same CVE out of both train and test partitions.
    for row in frame.itertuples(index=False):
        cve = getattr(row, "cve_id", None)
        for column, label in (("vulnerable_code", "vulnerable"), ("fixed_code", "fixed")):
            snippet = getattr(row, column, None)
            if isinstance(snippet, str) and len(snippet.strip()) >= 40:
                examples.append((snippet[:6000], label))
                groups.append(str(cve or len(groups)))
    if len(examples) > 12000:
        stride = max(1, len(examples) // 12000)
        examples = examples[::stride][:12000]
        groups = groups[::stride][:12000]
    if len({label for _, label in examples}) < 2 or len(examples) < 100 or len(set(groups)) < 10:
        return {
            "status": "unavailable",
            "reason": "Not enough paired, non-empty code examples across distinct CVEs.",
            "code_examples": int(len(examples)),
        }
    x = [item[0] for item in examples]
    y = [item[1] for item in examples]
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_STATE)
    train_indices, test_indices = next(splitter.split(x, y, groups))
    model = _text_model().fit([x[i] for i in train_indices], [y[i] for i in train_indices])
    y_test = [y[i] for i in test_indices]
    predictions = model.predict([x[i] for i in test_indices])
    joblib.dump(model, MODELS / "cve_code_vulnerability.joblib")
    return {
        "status": "trained",
        "task": "Distinguish vulnerable from fixed code snippets",
        "source_rows": int(len(frame)),
        "code_examples": int(len(examples)),
        "distinct_cves": int(len(set(groups))),
        "train_rows": int(len(train_indices)),
        "test_rows": int(len(test_indices)),
        "split": "Grouped by CVE identifier to reduce same-CVE train/test leakage.",
        "metrics": _metric_payload(y_test, predictions),
        "model_file": "cve_code_vulnerability.joblib",
        "limitations": "Research triage only; code-level predictions can miss vulnerabilities and must not replace review or testing.",
    }


def _train_intrusion(frame):
    if frame.empty or "is_malicious" not in frame:
        return {"status": "unavailable", "reason": "Honeypot import or is_malicious labels are missing."}
    working = frame.copy()
    working["_label"] = working["is_malicious"].map(
        lambda x: str(x).strip().lower() if pd.notna(x) else ""
    )
    working = working[working["_label"].isin({"true", "false", "1", "0"})].copy()
    working["_label"] = working["_label"].map({"true": "malicious", "1": "malicious", "false": "benign", "0": "benign"})
    if working["_label"].nunique() < 2 or working["_label"].value_counts().min() < 5:
        return {
            "status": "unavailable",
            "reason": "At least five labeled examples per class are required; small honeypot datasets are not treated as generalizable training truth.",
            "labeled_rows": int(len(working)),
            "class_counts": {str(k): int(v) for k, v in working["_label"].value_counts().items()},
        }
    # This dataset is small and highly sparse. Use only coarse network/event
    # fields; direct identifiers, payloads, and label-like columns are excluded.
    feature_cols = [c for c in ("dest_port", "src_port", "proto", "app_proto", "direction", "event_type", "alert", "attack_vectors") if c in working]
    working["_text"] = working[feature_cols].fillna("").astype(str).agg(" ".join, axis=1)
    x_train, x_test, y_train, y_test = train_test_split(
        working["_text"], working["_label"], test_size=0.25,
        random_state=RANDOM_STATE, stratify=working["_label"],
    )
    model = _text_model().fit(x_train, y_train)
    predictions = model.predict(x_test)
    joblib.dump(model, MODELS / "honeypot_intrusion.joblib")
    return {
        "status": "trained",
        "task": "Classify labeled honeypot events as malicious or benign",
        "source_rows": int(len(frame)),
        "labeled_rows": int(len(working)),
        "features": feature_cols,
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "metrics": _metric_payload(y_test, predictions),
        "model_file": "honeypot_intrusion.joblib",
        "limitations": "The Hub repository currently lists only 100 source rows; treat results as a pipeline demonstration, not production IDS performance.",
    }


def main():
    MODELS.mkdir(parents=True, exist_ok=True)
    cve = _read("cvefixes")
    incidents = _read("incident_reports")
    intrusions = _read("honeypot_intrusions")
    report = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_state": RANDOM_STATE,
        "sources": {},
        "notice": "Models are trained separately per task; scores are held-out dataset metrics, not proof of real-world detection capability.",
    }
    report["sources"]["cvefixes"] = {
        "repo_id": "hitoshura25/cvefixes",
        "license": "apache-2.0",
        "code_vulnerability": _train_cve_code(cve),
        "severity_from_description": _train_text_task(
            "cve_severity", cve,
            [c for c in ("description", "cwe_id") if c in cve.columns],
            "severity", min_per_class=20,
        ) if not cve.empty else {"status": "unavailable", "reason": "CVEfixes import is missing."},
    }
    report["sources"]["incident_reports"] = {
        "repo_id": "vinitvek/cybersecurityattacks",
        "license": "unlicense",
        "event_type": _train_text_task(
            "incident_event_type", incidents,
            [c for c in ("description", "affected_industry", "motive") if c in incidents.columns],
            "event_type", min_per_class=30,
        ),
    }
    report["sources"]["honeypot_intrusions"] = {
        "repo_id": "pyToshka/network-intrusion-detection",
        "license": "bsd-3-clause",
        "malicious_event": _train_intrusion(intrusions),
    }
    path = MODELS / "training_report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        key: {
            task: result.get("status")
            for task, result in value.items()
            if isinstance(result, dict) and "status" in result
        }
        for key, value in report["sources"].items()
    }, indent=2))
    print(f"Saved training report: {path}")


if __name__ == "__main__":
    main()
