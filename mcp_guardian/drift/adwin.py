"""
ADWIN (Adaptive Windowing) Concept Drift Detector for MCP Guardian V2 (Feature 3).
Detects distribution shifts in streaming time-series metrics.
"""

import math
from typing import List, Optional


class ADWIN:
    """
    Adaptive Sliding Window algorithm for concept drift detection.
    Maintains a variable-length window that shrinks when a statistically significant
    change in mean is detected between sub-windows.
    """

    def __init__(self, delta: float = 0.002, max_buckets: int = 5, min_window_length: int = 10):
        self.delta = delta
        self.max_buckets = max_buckets
        self.min_window_length = min_window_length
        self.window: List[float] = []
        self.total: float = 0.0
        self.variance: float = 0.0
        self.drift_detected: bool = False
        self.last_drift_timestamp: float = 0.0

    def add_element(self, value: float) -> bool:
        """
        Add a new real-valued observation to the window.
        Returns True if a concept drift was detected at this step.
        """
        self.window.append(float(value))
        self.total += value
        self.drift_detected = False

        if len(self.window) < self.min_window_length:
            return False

        # Evaluate potential split points in the window
        n = len(self.window)
        # Check sub-windows at fractions: 1/4, 1/2, 3/4
        for split in [int(n * 0.25), int(n * 0.5), int(n * 0.75)]:
            if split < 4 or (n - split) < 4:
                continue

            w0 = self.window[:split]
            w1 = self.window[split:]

            n0, n1 = len(w0), len(w1)
            mean0 = sum(w0) / n0
            mean1 = sum(w1) / n1

            # Harmonic mean of sub-window sizes
            m = 1.0 / (1.0 / n0 + 1.0 / n1)
            delta_prime = self.delta / math.log(n + 1)
            epsilon_cut = math.sqrt((1.0 / (2.0 * m)) * math.log(4.0 / delta_prime))

            if abs(mean0 - mean1) > epsilon_cut:
                # Drift detected! Drop older sub-window w0
                self.window = self.window[split:]
                self.total = sum(self.window)
                self.drift_detected = True
                break

        return self.drift_detected

    @property
    def mean(self) -> float:
        return (self.total / len(self.window)) if self.window else 0.0

    @property
    def size(self) -> int:
        return len(self.window)
