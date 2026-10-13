"""
Multi-Level Decision Engine for MCP Guardian V2 (Feature 9).
Categorizes composite risk scores into ALLOW, MONITOR, and BLOCK decisions.
"""

from typing import Dict, Any, Tuple
from ..core.types import Decision, RiskLevel


class DecisionEngine:
    """Evaluates composite risk score and hard rule indicators to output actionable decisions."""

    def __init__(self, monitor_threshold: float = 0.35, block_threshold: float = 0.60):
        self.monitor_threshold = monitor_threshold
        self.block_threshold = block_threshold

    def decide(
        self,
        composite_score: float,
        is_hard_blocked: bool = False,
        sensitivity: float = 1.0
    ) -> Tuple[Decision, RiskLevel]:
        """
        Evaluate score and return (Decision, RiskLevel).
        """
        # Dynamic threshold shifting based on sensitivity
        # High sensitivity (>1.0) lowers the bar to block
        effective_block_threshold = self.block_threshold / max(0.2, sensitivity)
        effective_monitor_threshold = self.monitor_threshold / max(0.2, sensitivity)

        risk_level = RiskLevel.from_score(composite_score)

        if is_hard_blocked or composite_score >= effective_block_threshold:
            return Decision.BLOCK, RiskLevel.CRITICAL if is_hard_blocked else risk_level

        if composite_score >= effective_monitor_threshold:
            return Decision.MONITOR, RiskLevel.MEDIUM

        return Decision.ALLOW, RiskLevel.LOW
