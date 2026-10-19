"""Repeat the synthetic benchmark with independent ground truth and baselines.

This is a reproducible simulator study, not evidence from production agents.
Run: python model/research_experiment.py --runs 30 --output-dir results/research_runs
"""

import argparse
import hashlib
import io
import json
import platform
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from build_features import build_and_save
from server.traffic_simulator import generate_dataset

FEATURE_COLS = [
    "n_calls", "n_lookup_calls", "n_email_calls", "max_records_requested",
    "avg_time_between_calls", "min_time_between_calls", "recipient_mismatch_rate",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def evaluate(y_true, y_pred, scores):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, scores),
        "average_precision": average_precision_score(y_true, scores),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "specificity": tn / (tn + fp) if (tn + fp) else 0.0,
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def rule_baseline(frame):
    """Explicit detector rules, evaluated against separately stored labels."""
    return (
        (frame["max_records_requested"] > 1)
        | (frame["recipient_mismatch_rate"] > 0)
        | ((frame["min_time_between_calls"] >= 0) & (frame["min_time_between_calls"] < 0.1))
        | (frame["n_lookup_calls"] >= 5)
    ).astype(int).to_numpy()


def run_one(seed: int, output_dir: Path, save_model: bool = False):
    run_dir = output_dir / f"seed_{seed}"
    data_dir = run_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    log_path, labels_path = generate_dataset(output_dir=data_dir, seed=seed)
    feature_path = data_dir / "session_features.csv"
    frame = build_and_save(log_path, labels_path, feature_path)

    X = frame[FEATURE_COLS].astype(float)
    y = frame["label"].astype(int).to_numpy()
    train_idx, test_idx = train_test_split(
        np.arange(len(frame)), test_size=0.30, random_state=seed, stratify=y,
    )
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    scenarios_test = frame.iloc[test_idx]["scenario"].to_numpy()

    # Unsupervised baseline: train only on normal sessions in the training fold.
    iforest = IsolationForest(n_estimators=200, contamination=0.10, random_state=seed)
    iforest.fit(X_train.iloc[y_train == 0])
    anomaly_scores = -iforest.decision_function(X_test)
    iforest_pred = (iforest.predict(X_test) == -1).astype(int)

    # Supervised reference baseline, included as an upper-bound style comparator.
    supervised = make_pipeline(
        StandardScaler(),
        LogisticRegression(class_weight="balanced", max_iter=1000, random_state=seed),
    )
    supervised.fit(X_train, y_train)
    supervised_scores = supervised.predict_proba(X_test)[:, 1]
    supervised_pred = (supervised_scores >= 0.5).astype(int)

    rules_pred = rule_baseline(frame.iloc[test_idx])
    predictions = {
        "isolation_forest": (iforest_pred, anomaly_scores),
        "supervised_logistic": (supervised_pred, supervised_scores),
        "explicit_rules": (rules_pred, rules_pred.astype(float)),
        "allow_all": (np.zeros_like(y_test), np.zeros_like(y_test, dtype=float)),
    }

    rows = []
    for method, (pred, scores) in predictions.items():
        metrics = evaluate(y_test, pred, scores)
        metrics.update({"seed": seed, "method": method, "test_sessions": len(test_idx)})
        for scenario in sorted(set(scenarios_test)):
            mask = scenarios_test == scenario
            metrics[f"recall_{scenario}"] = float(np.mean(pred[mask] == 1)) if mask.any() else None
        rows.append(metrics)

    model_buffer = io.BytesIO()
    joblib.dump({"model": iforest, "feature_cols": FEATURE_COLS}, model_buffer)
    model_bytes = model_buffer.getvalue()
    model_path = run_dir / "isolation_forest.joblib"
    if save_model:
        model_path.write_bytes(model_bytes)
    manifest = {
        "seed": seed,
        "python": sys.version,
        "platform": platform.platform(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit_learn": sklearn.__version__,
        "split": {"strategy": "stratified session split", "test_size": 0.30, "random_state": seed},
        "features": FEATURE_COLS,
        "isolation_forest": {"n_estimators": 200, "contamination": 0.10, "random_state": seed},
        "input_sha256": {"traffic_log.jsonl": sha256(log_path), "session_labels.csv": sha256(labels_path)},
        "feature_table_sha256": sha256(feature_path),
        "isolation_forest_sha256": sha256_bytes(model_bytes),
        "label_source": "independent simulator session manifest; labels were not derived from features",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=30, help="Independent generated datasets (default: 30)")
    parser.add_argument("--seed-start", type=int, default=20261019)
    parser.add_argument("--output-dir", type=Path, default=Path("results/research_runs"))
    args = parser.parse_args(argv)
    if args.runs < 2:
        parser.error("--runs must be at least 2 to report variability")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for offset in range(args.runs):
        seed = args.seed_start + offset
        rows.extend(run_one(seed, args.output_dir, save_model=(offset == 0)))
    results = pd.DataFrame(rows)
    results.to_csv(args.output_dir / "per_run_metrics.csv", index=False)

    metric_names = ["precision", "recall", "f1", "roc_auc", "average_precision",
                    "balanced_accuracy", "specificity", "false_positive_rate"]
    summary = {}
    for method, subset in results.groupby("method", sort=True):
        summary[method] = {}
        for metric in metric_names:
            values = subset[metric].dropna().astype(float)
            mean = float(values.mean())
            std = float(values.std(ddof=1))
            half_width = 1.96 * std / np.sqrt(len(values))
            summary[method][metric] = {
                "mean": mean,
                "std": std,
                "ci95_normal_approx": [max(0.0, mean - half_width), min(1.0, mean + half_width)],
            }
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"Per-run metrics: {args.output_dir / 'per_run_metrics.csv'}")
    print(f"Reproduction artifacts: {args.output_dir}")


if __name__ == "__main__":
    main()
