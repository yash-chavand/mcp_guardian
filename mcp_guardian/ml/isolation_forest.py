"""
Isolation Forest Real-Time Inference Scorer for MCP Guardian V2.
"""

from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import logging
try:
    import joblib
    import pandas as pd
except ImportError:  # optional anomaly-model dependencies
    joblib = None
    pd = None
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
        if self.model_path and Path(self.model_path).exists() and joblib is not None and pd is not None:
            try:
                bundle = joblib.load(self.model_path)
                self.model = bundle["model"]
                self.feature_cols = bundle.get("feature_cols", self.feature_cols)
            except Exception as e:
                logging.getLogger("mcp_guardian").warning(
                    "Isolation Forest model could not be loaded; using rules-only fallback (%s)",
                    type(e).__name__,
                )

    def score(self, features: Dict[str, Any], sensitivity: float = 1.0) -> Tuple[float, float, bool, Optional[RiskReason]]:
        """
        Score a feature vector.
        Returns: (raw_score, normalized_score [0.0, 1.0], is_blocked [bool], Optional[RiskReason])
        """
        if self.model is None:
            # Rules-only installation: deterministic controls remain active in
            # RuleEngine. Missing optional ML dependencies never fail open for
            # the rules and never invent an ML verdict.
            return 0.0, 0.0, False, None

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
