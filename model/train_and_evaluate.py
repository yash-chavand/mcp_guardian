"""
Train the anomaly detector (Isolation Forest) on session-level features and
evaluate it against the held-out test set with precision/recall/F1/ROC-AUC.

Also computes a "baseline" (no detector at all -- everything passes through)
to show the before/after comparison your paper needs.
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, classification_report
)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA_DIR = Path(__file__).parent.parent / "data"
RESULTS_DIR = Path(__file__).parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

FEATURE_COLS = [
    "n_calls", "n_lookup_calls", "n_email_calls", "max_records_requested",
    "avg_time_between_calls", "min_time_between_calls", "recipient_mismatch_rate",
]


def main():
    df = pd.read_csv(DATA_DIR / "session_features.csv")
    X = df[FEATURE_COLS].copy()
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # Train the model ONLY on features from sessions labeled normal in the
    # training split -- this mimics a real deployment where you calibrate
    # on known-good traffic before going live.
    X_train_normal_only = X_train[y_train == 0]

    contamination_rate = 0.10  # assume ~10% of live traffic might be attacks
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination_rate,
        random_state=42,
    )
    model.fit(X_train_normal_only)

    # Persist the trained model so it can be reused to score REAL agent
    # traffic later (see real_mcp/evaluate_real_traffic.py)
    model_path = RESULTS_DIR.parent / "model" / "trained_isolation_forest.joblib"
    joblib.dump({"model": model, "feature_cols": FEATURE_COLS}, model_path)
    print(f"Trained model saved to: {model_path}")

    # -1 = anomaly, 1 = normal -> convert to 1 = attack, 0 = normal
    raw_preds = model.predict(X_test)
    y_pred = np.where(raw_preds == -1, 1, 0)

    # anomaly score (higher = more anomalous) for ROC-AUC
    scores = -model.decision_function(X_test)

    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, scores)
    cm = confusion_matrix(y_test, y_pred)

    # ---- Baseline: no detection system at all ----
    baseline_pred = np.zeros_like(y_test)  # everything let through
    baseline_recall = recall_score(y_test, baseline_pred, zero_division=0)

    # ---- Print results ----
    print("=" * 60)
    print("ANOMALY DETECTION MODEL - EVALUATION RESULTS")
    print("=" * 60)
    print(f"Test set size: {len(y_test)}  (attacks: {y_test.sum()}, normal: {len(y_test)-y_test.sum()})")
    print()
    print(f"Precision : {precision:.3f}")
    print(f"Recall    : {recall:.3f}")
    print(f"F1-score  : {f1:.3f}")
    print(f"ROC-AUC   : {auc:.3f}")
    print()
    print("Confusion Matrix [rows=actual, cols=predicted] (0=normal, 1=attack):")
    print(cm)
    print()
    print(classification_report(y_test, y_pred, target_names=["normal", "attack"]))
    print("-" * 60)
    print(f"BASELINE (no detection system) attack catch rate: {baseline_recall:.3f}")
    print(f"YOUR MODEL attack catch rate (recall):             {recall:.3f}")
    print("=" * 60)

    # ---- Save results to file for the paper ----
    with open(RESULTS_DIR / "evaluation_report.txt", "w") as f:
        f.write("MCP Anomaly Detection - Evaluation Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Test set size: {len(y_test)} (attacks: {y_test.sum()}, normal: {len(y_test)-y_test.sum()})\n\n")
        f.write(f"Precision : {precision:.3f}\n")
        f.write(f"Recall    : {recall:.3f}\n")
        f.write(f"F1-score  : {f1:.3f}\n")
        f.write(f"ROC-AUC   : {auc:.3f}\n\n")
        f.write("Confusion Matrix [rows=actual, cols=predicted]:\n")
        f.write(str(cm) + "\n\n")
        f.write(classification_report(y_test, y_pred, target_names=["normal", "attack"]))
        f.write("\n\nBaseline (no detection) attack catch rate: {:.3f}\n".format(baseline_recall))
        f.write("Model attack catch rate (recall):           {:.3f}\n".format(recall))

    # ---- Confusion matrix plot ----
    fig, ax = plt.subplots(figsize=(4.5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Predicted\nNormal", "Predicted\nAttack"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Actual\nNormal", "Actual\nAttack"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=14, fontweight="bold")
    ax.set_title("Confusion Matrix - MCP Anomaly Detector")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=150)
    plt.close()

    # ---- Bar chart: baseline vs model ----
    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(["Baseline\n(no detection)", "Proposed\nML Model"],
                   [baseline_recall, recall], color=["#c0392b", "#2471a3"])
    ax.set_ylabel("Attack Detection Rate (Recall)")
    ax.set_ylim(0, 1.05)
    ax.set_title("Attack Detection: Baseline vs. Proposed System")
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.2f}", (bar.get_x() + bar.get_width()/2, h), ha="center", va="bottom", fontweight="bold")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "baseline_vs_model.png", dpi=150)
    plt.close()

    print(f"\nResults saved to: {RESULTS_DIR}")
    return dict(precision=precision, recall=recall, f1=f1, auc=auc)


if __name__ == "__main__":
    main()
