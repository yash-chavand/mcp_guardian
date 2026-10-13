"""
Machine Learning Pipeline & Model Versioning for MCP Guardian V2 (Feature 19).
"""

from pathlib import Path
from typing import Dict, Any, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score


class MLTrainingPipeline:
    """Manages dataset preparation, model training, validation, and safe artifact deployment."""

    FEATURE_COLS = [
        "call_index_in_session", "records_requested", "cumulative_records_in_session",
        "time_since_last_call", "recipient_mismatch", "tool_is_email"
    ]

    def __init__(self, data_dir: Path = None, model_dir: Path = None):
        self.data_dir = data_dir or (Path(__file__).parent.parent.parent / "data")
        self.model_dir = model_dir or (Path(__file__).parent.parent)

    def train_isolation_forest(self, contamination: float = 0.06) -> Dict[str, Any]:
        data_file = self.data_dir / "request_level_features.csv"
        if not data_file.exists():
            raise FileNotFoundError(f"Training dataset not found at {data_file}")

        df = pd.read_csv(data_file)
        X = df[self.FEATURE_COLS]
        y = df["label"].values

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
        X_train_normal = X_train[y_train == 0]

        model = IsolationForest(n_estimators=300, contamination=contamination, random_state=42)
        model.fit(X_train_normal)

        y_pred = np.where(model.predict(X_test) == -1, 1, 0)
        scores = -model.decision_function(X_test)

        metrics = {
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, zero_division=0)),
            "f1": float(f1_score(y_test, y_pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_test, scores)),
            "sample_size": len(df)
        }

        # Safe deployment check: candidate model must have high recall & precision
        if metrics["f1"] >= 0.80:
            target_path = self.model_dir / "realtime_model.joblib"
            joblib.dump({"model": model, "feature_cols": self.FEATURE_COLS, "metrics": metrics}, target_path)
            metrics["status"] = "deployed"
            metrics["model_path"] = str(target_path)
        else:
            metrics["status"] = "rejected_low_f1"

        return metrics
