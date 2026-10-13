"""
Deterministic Rule Engine for MCP Guardian V2.
Handles zero-ambiguity hard security constraints (bulk caps, rapid-fire rate limits, allow-lists).
"""

from typing import Dict, Any, Tuple, Optional, Set
from ..core.events import RiskReason


class RuleEngine:
    """Fast deterministic rule evaluator for instantaneous high-confidence decisions."""

    def __init__(
        self,
        bulk_threshold: int = 10,
        rapid_seconds_threshold: float = 0.05,
        allow_list_sessions: Set[str] = None,
        max_records_per_window: int = 25,
        max_calls_per_window: int = 20
    ):
        self.bulk_threshold = bulk_threshold
        self.rapid_seconds_threshold = rapid_seconds_threshold
        self.allow_list_sessions = allow_list_sessions or set()
        self.max_records_per_window = max_records_per_window
        self.max_calls_per_window = max_calls_per_window

    def evaluate(
        self,
        session_id: str,
        tool_name: str,
        records_requested: int,
        time_since_last_call: float,
        arguments: Dict[str, Any] = None,
        window_records: int = 0,
        window_calls: int = 0
    ) -> Tuple[float, bool, Optional[RiskReason]]:
        """
        Evaluate hard rules.
        Returns: (rule_score [0.0, 1.0], is_hard_blocked [bool], Optional[RiskReason])
        """
        if session_id in self.allow_list_sessions:
            return 0.0, False, RiskReason(type="allow_listed", severity="low", message="Session is allow-listed.")

        # 1. Bulk Record Cap Hard Rule
        if records_requested > self.bulk_threshold:
            return 1.0, True, RiskReason(
                type="bulk_request_exceeds_threshold",
                severity="critical",
                message=f"Requested {records_requested} records, which exceeds hard maximum threshold of {self.bulk_threshold}."
            )

        # Check for wildcard bulk sentinel values in arguments
        if arguments:
            for k in ["order_id", "id", "customer_id", "records", "limit", "filter"]:
                val = str(arguments.get(k, "")).upper().strip()
                if val in ["ALL", "*", "ANY", "EVERYTHING", "10000"]:
                    return 1.0, True, RiskReason(
                        type="bulk_wildcard_detected",
                        severity="critical",
                        message=f"Wildcard bulk exfiltration parameter '{k}={val}' detected in tool arguments."
                    )

        # 2. Cumulative Records Sliding-Window Rule (Catches chunked evasion attacks)
        if window_records > self.max_records_per_window:
            return 1.0, True, RiskReason(
                type="cumulative_records_quota_exceeded",
                severity="critical",
                message=f"Cumulative records in window ({window_records}) exceeds maximum allowed threshold of {self.max_records_per_window}."
            )

        # 3. Rapid-Fire Rate Limiting Hard Rule
        if time_since_last_call != -1 and time_since_last_call < self.rapid_seconds_threshold:
            return 1.0, True, RiskReason(
                type="rapid_fire_rate_abuse",
                severity="critical",
                message=f"Tool call interval ({time_since_last_call:.4f}s) violates minimum rate-limit threshold of {self.rapid_seconds_threshold}s."
            )

        # 4. Sustained Call Frequency Sliding-Window Rule
        if window_calls > self.max_calls_per_window:
            return 1.0, True, RiskReason(
                type="sliding_window_rate_exceeded",
                severity="critical",
                message=f"Tool call frequency ({window_calls} calls in window) exceeds maximum allowed threshold of {self.max_calls_per_window}."
            )

        return 0.0, False, None
