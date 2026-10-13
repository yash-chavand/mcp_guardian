"""
Core types and enumerations for MCP Guardian V2.
"""

from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        if score >= 0.85:
            return cls.CRITICAL
        elif score >= 0.60:
            return cls.HIGH
        elif score >= 0.35:
            return cls.MEDIUM
        return cls.LOW


class EventType(str, Enum):
    TOOL_CALL = "tool_call"
    PROMPT_INJECTION = "prompt_injection"
    SCHEMA_CHANGE = "schema_change"
    DRIFT_ALERT = "drift_alert"
    ENTITY_MISMATCH = "entity_mismatch"
    RATE_ABUSE = "rate_abuse"
    UNKNOWN_DESTINATION = "unknown_destination"
    SEQUENCE_ANOMALY = "sequence_anomaly"
