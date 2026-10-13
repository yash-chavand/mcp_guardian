"""
Adaptive Dynamic Threshold Engine for MCP Guardian V2 (Feature 4).
Computes multi-tiered baselines across Servers, Tools and Sessions to replace static thresholds.
"""

import time
import math
from typing import Dict, Any, Tuple, Optional
from collections import defaultdict
from ..core.events import RiskReason


class AdaptiveThresholdEngine:
    """
    Computes dynamic thresholds for request rates, data volume, and response size
    using hierarchical Server + Tool + Session baselines.
    """

    def __init__(self, default_zscore_multiplier: float = 3.0):
        self.default_zscore_multiplier = default_zscore_multiplier

        # Hierarchical baselines: (level, key, metric) -> {"mean": float, "std": float, "count": int}
        self.baselines: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {"mean": 1.0, "std": 0.5, "count": 10}
        )

        # Seed realistic initial standard baselines
        self.baselines["server:primary:request_rate"] = {"mean": 2.0, "std": 1.0, "count": 20}
        self.baselines["server:primary:data_volume"] = {"mean": 1.0, "std": 0.5, "count": 20}
        self.baselines["tool:get_customer_order:records"] = {"mean": 1.0, "std": 0.2, "count": 20}
        self.baselines["tool:send_email:records"] = {"mean": 0.0, "std": 0.1, "count": 20}

    def _get_key(self, level: str, identifier: str, metric: str) -> str:
        return f"{level}:{identifier}:{metric}"

    def update_baseline(self, level: str, identifier: str, metric: str, value: float):
        """Update rolling stats using Welford's algorithm."""
        key = self._get_key(level, identifier, metric)
        b = self.baselines[key]
        b["count"] += 1
        delta = value - b["mean"]
        b["mean"] += delta / b["count"]
        delta2 = value - b["mean"]
        if b["count"] > 1:
            var = ((b["std"] ** 2) * (b["count"] - 2) + delta * delta2) / (b["count"] - 1)
            b["std"] = max(0.01, math.sqrt(max(0.0001, var)))

    def evaluate(
        self,
        server_id: str,
        tool_name: str,
        session_id: str,
        metric: str,
        current_value: float,
        sensitivity: float = 1.0
    ) -> Tuple[float, Dict[str, Any], Optional[RiskReason]]:
        """
        Evaluate current value against adaptive thresholds.
        Returns: (risk_score [0.0, 1.0], details_dict, Optional[RiskReason])
        """
        # Retrieve tool and server baselines
        tool_key = self._get_key("tool", tool_name, metric)
        server_key = self._get_key("server", server_id, metric)

        b_tool = self.baselines[tool_key]
        b_server = self.baselines[server_key]

        # Blended mean and std: 70% tool-specific, 30% server-wide
        blended_mean = 0.70 * b_tool["mean"] + 0.30 * b_server["mean"]
        blended_std = max(0.05, 0.70 * b_tool["std"] + 0.30 * b_server["std"])

        # Dynamic threshold computation adjusted by sensitivity
        z_multiplier = self.default_zscore_multiplier / max(0.1, sensitivity)
        dynamic_threshold = blended_mean + z_multiplier * blended_std

        # Compute z-score deviation
        deviation = (current_value - blended_mean) / blended_std

        risk = "low"
        risk_score = 0.0
        reason: Optional[RiskReason] = None

        if current_value > dynamic_threshold:
            if deviation > 6.0:
                risk = "critical"
                risk_score = 0.95
            elif deviation > 4.0:
                risk = "high"
                risk_score = 0.75
            else:
                risk = "medium"
                risk_score = 0.45

            reason = RiskReason(
                type="adaptive_threshold_exceeded",
                severity=risk,
                message=f"Metric '{metric}' ({current_value:.2f}) exceeded dynamic threshold ({dynamic_threshold:.2f}, deviation: {deviation:.1f}σ)."
            )
        else:
            # Safe observation within threshold -> update baseline
            self.update_baseline("tool", tool_name, metric, current_value)
            self.update_baseline("server", server_id, metric, current_value)

        details = {
            "metric": metric,
            "current": round(current_value, 3),
            "baseline_mean": round(blended_mean, 3),
            "baseline_std": round(blended_std, 3),
            "dynamic_threshold": round(dynamic_threshold, 3),
            "deviation": round(deviation, 2),
            "risk": risk
        }

        return round(risk_score, 4), details, reason

    def get_all_baselines(self) -> Dict[str, Dict[str, float]]:
        return {k: {kk: round(vv, 4) for kk, vv in v.items()} for k, v in self.baselines.items()}
