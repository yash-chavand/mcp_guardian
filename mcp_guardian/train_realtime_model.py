"""
Trains the REAL-TIME anomaly detector: scores each individual request as it
arrives, using only information available up to that point in the session
(no lookahead). This is the model the deployable mcp_guardian extension
actually uses in production.
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report

DATA_DIR = Path(__file__).parent.parent / "data"
FEATURE_COLS = [
    "call_index_in_session", "records_requested", "cumulative_records_in_session",
    "time_since_last_call", "recipient_mismatch", "tool_is_email",
]


def main():
    df = pd.read_csv(DATA_DIR / "request_level_features.csv")
    X = df[FEATURE_COLS]
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    X_train_normal = X_train[y_train == 0]

    model = IsolationForest(n_estimators=300, contamination=0.06, random_state=42)
    model.fit(X_train_normal)

    y_pred = np.where(model.predict(X_test) == -1, 1, 0)
    scores = -model.decision_function(X_test)

    print("=" * 55)
    print("REAL-TIME (PER-REQUEST) MODEL - EVALUATION")
    print("=" * 55)
    print(f"Precision: {precision_score(y_test, y_pred):.3f}")
    print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
    print(f"F1       : {f1_score(y_test, y_pred):.3f}")
    print(f"ROC-AUC  : {roc_auc_score(y_test, scores):.3f}")
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred, target_names=["normal", "attack-like"]))

    model_path = Path(__file__).parent / "realtime_model.joblib"
    joblib.dump({"model": model, "feature_cols": FEATURE_COLS}, model_path)
    print(f"\nSaved real-time model -> {model_path}")


if __name__ == "__main__":
    main()
