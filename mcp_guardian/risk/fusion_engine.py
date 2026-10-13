"""
Risk Fusion Engine for MCP Guardian V2 (Feature 8).
Fuses multi-layer security signals with configurable weights into a unified composite risk score.
"""

from typing import Dict, Any, Tuple
from ..core.config import RiskWeights


class RiskFusionEngine:
    """Combines deterministic, statistical, sequence, semantic, drift, entity and graph risk signals."""

    def __init__(self, weights: RiskWeights = None):
        self.weights = weights or RiskWeights()

    def fuse(self, sub_scores: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        """
        Compute weighted composite risk score in range [0.0, 1.0].
        Returns: (composite_score, normalized_weights)
        """
        norm_weights = self.weights.normalized()
        composite_score = 0.0

        for key, w in norm_weights.items():
            s = sub_scores.get(key, 0.0)
            composite_score += w * s

        # Hard-rule priority override: if deterministic rules score 1.0, composite is locked to 1.0
        if sub_scores.get("rules", 0.0) >= 0.99:
            composite_score = max(composite_score, 0.99)

        # Critical injection priority override
        if sub_scores.get("injection", 0.0) >= 0.90:
            composite_score = max(composite_score, 0.95)

        # Critical entity mismatch priority override
        if sub_scores.get("entity", 0.0) >= 0.90:
            composite_score = max(composite_score, 0.95)

        composite_score = min(1.0, max(0.0, round(composite_score, 4)))
        return composite_score, norm_weights
