"""
Core types and enumerations for MCP Guardian V2.
"""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


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


@dataclass(frozen=True)
class ToolCallContext:
    """Request context for one protected tool invocation."""
    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    server_id: str = "primary-server"
    session_id: str = "default"
    caller_id: Optional[str] = None
    schema: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class SecurityDecision:
    """Stable, explainable result of evaluating a tool call."""
    decision_id: str
    outcome: Decision
    tool_name: str
    server_id: str
    session_id: str
    risk_score: float
    reason: str
    matched_rules: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    policy_version: str = "1"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.outcome in (Decision.ALLOW, Decision.MONITOR)


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    tool_name: str
    server_id: str
    session_id: str
    expires_at: str
    status: str = "pending"
