"""
Security Data Model — Unified SecurityEvent schema for MCP Guardian V2.
"""

import uuid
import hashlib
import secrets
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from .types import Decision, RiskLevel, EventType


_PROCESS_HASH_SALT = secrets.token_bytes(32)


def hash_identifier(identifier: Optional[str], salt: Optional[str] = None) -> str:
    """Tokenize identifiers using a random per-process salt."""
    if not identifier:
        return "anonymous"
    salt_bytes = salt.encode("utf-8") if salt is not None else _PROCESS_HASH_SALT
    return hashlib.sha256(salt_bytes + b":" + identifier.encode("utf-8")).hexdigest()[:24]


@dataclass
class RiskReason:
    type: str
    severity: str  # low | medium | high | critical
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"type": self.type, "severity": self.severity, "message": self.message}


@dataclass
class SecurityEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = "default"
    tokenized_session_id: str = ""
    agent_id: str = "agent-default"
    tokenized_agent_id: str = ""
    server_id: str = "mcp-server-primary"
    tool_name: str = ""
    event_type: str = EventType.TOOL_CALL.value
    risk_score: float = 0.0
    risk_level: str = RiskLevel.LOW.value
    decision: str = Decision.ALLOW.value
    sub_scores: Dict[str, float] = field(default_factory=dict)
    reasons: List[Dict[str, str]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0

    def __post_init__(self):
        if not self.tokenized_session_id:
            self.tokenized_session_id = hash_identifier(self.session_id)
        if not self.tokenized_agent_id:
            self.tokenized_agent_id = hash_identifier(self.agent_id)
        if not self.risk_level:
            self.risk_level = RiskLevel.from_score(self.risk_score).value

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Keep raw identities only in memory, never in normal audit output.
        data["session_id"] = self.tokenized_session_id
        data["agent_id"] = self.tokenized_agent_id
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
