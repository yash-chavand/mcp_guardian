"""
Behavioral Drift Detection & Candidate Baseline Validator for MCP Guardian V2 (Feature 3).
"""

import time
import math
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, field, asdict
from .adwin import ADWIN
from ..core.events import RiskReason


@dataclass
class MetricBaseline:
    name: str
    mean: float = 0.0
    std: float = 1.0
    count: int = 0
    min_val: float = 0.0
    max_val: float = 0.0
    last_updated: float = field(default_factory=time.time)

    def update(self, val: float):
        self.count += 1
        delta = val - self.mean
        self.mean += delta / self.count
        delta2 = val - self.mean
        # Welford's algorithm for rolling variance
        if self.count > 1:
            var = ((self.std ** 2) * (self.count - 2) + delta * delta2) / (self.count - 1)
            self.std = max(0.01, math.sqrt(max(0.0001, var)))
        self.min_val = min(self.min_val, val) if self.count > 1 else val
        self.max_val = max(self.max_val, val) if self.count > 1 else val
        self.last_updated = time.time()


@dataclass
class CandidateBaseline:
    metric_name: str
    proposed_mean: float
    proposed_std: float
    sample_count: int
    created_at: float
    observations: List[float] = field(default_factory=list)
    approved: bool = False


class BehavioralDriftDetector:
    """
    Monitors behavioral drift across request rate, data volume, and tool frequency.
    Implements a safe candidate-baseline validation window to avoid training on attacks.
    """

    def __init__(self, delta: float = 0.002, validation_window_size: int = 50):
        self.validation_window_size = validation_window_size
        self.adwin_trackers: Dict[str, ADWIN] = {
            "request_rate": ADWIN(delta=delta),
            "data_volume": ADWIN(delta=delta),
            "response_size": ADWIN(delta=delta),
            "error_rate": ADWIN(delta=delta),
            "novelty_rate": ADWIN(delta=delta)
        }
        self.active_baselines: Dict[str, MetricBaseline] = {
            "request_rate": MetricBaseline(name="request_rate", mean=1.0, std=0.5, count=10),
            "data_volume": MetricBaseline(name="data_volume", mean=1.0, std=0.5, count=10),
            "response_size": MetricBaseline(name="response_size", mean=100.0, std=50.0, count=10),
            "error_rate": MetricBaseline(name="error_rate", mean=0.01, std=0.05, count=10),
            "novelty_rate": MetricBaseline(name="novelty_rate", mean=0.0, std=0.1, count=10)
        }
        self.candidate_baselines: Dict[str, CandidateBaseline] = {}
        self.drift_history: List[Dict[str, Any]] = []

    def observe(self, metric_name: str, value: float) -> Tuple[float, Optional[RiskReason]]:
        """
        Record a new metric observation.
        Returns: (drift_score [0.0, 1.0], Optional[RiskReason])
        """
        if metric_name not in self.adwin_trackers:
            self.adwin_trackers[metric_name] = ADWIN()
            self.active_baselines[metric_name] = MetricBaseline(name=metric_name, mean=value, std=1.0, count=1)

        adwin = self.adwin_trackers[metric_name]
        baseline = self.active_baselines[metric_name]

        is_drift = adwin.add_element(value)
        drift_score = 0.0
        reason: Optional[RiskReason] = None

        # Compute z-score relative to established active baseline
        z_score = abs(value - baseline.mean) / max(0.01, baseline.std)

        if is_drift:
            # Significant distribution shift detected by ADWIN
            drift_score = min(1.0, 0.50 + min(0.50, z_score * 0.10))
            reason = RiskReason(
                type="behavioral_drift",
                severity="high" if z_score > 3.0 else "medium",
                message=f"Statistical concept drift detected in '{metric_name}' (Current: {value:.2f}, Baseline Mean: {baseline.mean:.2f}, z-score: {z_score:.2f})."
            )

            # Initiate a Candidate Baseline instead of instantly adopting it
            candidate = CandidateBaseline(
                metric_name=metric_name,
                proposed_mean=adwin.mean,
                proposed_std=baseline.std,
                sample_count=adwin.size,
                created_at=time.time(),
                observations=[value]
            )
            self.candidate_baselines[metric_name] = candidate

            record = {
                "timestamp": time.time(),
                "metric_name": metric_name,
                "current_value": value,
                "baseline_mean": baseline.mean,
                "z_score": round(z_score, 2),
                "drift_score": round(drift_score, 3),
                "status": "candidate_staged"
            }
            self.drift_history.append(record)

        elif z_score > 3.5:
            drift_score = min(1.0, z_score * 0.15)
            reason = RiskReason(
                type="baseline_outlier",
                severity="high",
                message=f"Value '{value:.2f}' severely deviates from baseline '{baseline.name}' (z-score: {z_score:.2f})."
            )
        else:
            # Safe observation within normal variation -> smoothly update active baseline
            baseline.update(value)

        # Process candidate baseline validation window
        if metric_name in self.candidate_baselines:
            cand = self.candidate_baselines[metric_name]
            cand.observations.append(value)
            if len(cand.observations) >= self.validation_window_size:
                # Validated safe window -> update active baseline
                cand_mean = sum(cand.observations) / len(cand.observations)
                baseline.mean = cand_mean
                baseline.count += len(cand.observations)
                cand.approved = True
                del self.candidate_baselines[metric_name]

        return round(drift_score, 4), reason

    def get_status(self) -> Dict[str, Any]:
        return {
            "baselines": {k: asdict(v) for k, v in self.active_baselines.items()},
            "candidates": {k: {"metric": v.metric_name, "samples": len(v.observations), "approved": v.approved}
                           for k, v in self.candidate_baselines.items()},
            "recent_drifts": self.drift_history[-20:]
        }
