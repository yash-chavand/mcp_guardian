"""
Isolation Forest Real-Time Inference Scorer for MCP Guardian V2.
"""

from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import joblib
import pandas as pd
from ..core.events import RiskReason

DEFAULT_MODEL_PATH = Path(__file__).parent.parent / "realtime_model.joblib"


class IsolationForestScorer:
    """Wrapper around trained Isolation Forest with calibrated anomaly probability output."""

    def __init__(self, model_path: Path = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.feature_cols = [
            "call_index_in_session", "records_requested", "cumulative_records_in_session",
            "time_since_last_call", "recipient_mismatch", "tool_is_email"
        ]
        self._load()

    def _load(self):
        if self.model_path and Path(self.model_path).exists():
            try:
                bundle = joblib.load(self.model_path)
                self.model = bundle["model"]
                self.feature_cols = bundle.get("feature_cols", self.feature_cols)
            except Exception as e:
                print(f"[IsolationForest] Load error ({e}), initialized fallback.")

    def score(self, features: Dict[str, Any], sensitivity: float = 1.0) -> Tuple[float, float, bool, Optional[RiskReason]]:
        """
        Score a feature vector.
        Returns: (raw_score, normalized_score [0.0, 1.0], is_blocked [bool], Optional[RiskReason])
        """
        if self.model is None:
            rec = features.get("records_requested", 1)
            mis = features.get("recipient_mismatch", 0)
            blocked = (rec > 10 or mis == 1)
            return (0.90 if blocked else 0.10), (0.90 if blocked else 0.10), blocked, None

        X = pd.DataFrame([features])[self.feature_cols]
        raw_score = float(-self.model.decision_function(X)[0])

        # Exact threshold boundary matching V1 calibration
        threshold = 0.03 * (1 - sensitivity)
        is_ml_blocked = raw_score > threshold

        # Normalized probability score
        norm_score = max(0.0, min(1.0, (raw_score + 0.15) / 0.35))

        reason = None
        if is_ml_blocked or norm_score > 0.60:
            reason = RiskReason(
                type="isolation_forest_anomaly",
                severity="high" if raw_score > 0.05 else "medium",
                message=f"Unsupervised Isolation Forest detected statistical feature anomaly (raw: {raw_score:.3f}, threshold: {threshold:.3f})."
            )

        return round(raw_score, 4), round(norm_score, 4), is_ml_blocked, reason
