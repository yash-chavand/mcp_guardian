"""
Configuration system for MCP Guardian V2.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import Set, Dict, Any
import json


@dataclass
class RiskWeights:
    """Configurable weights for multi-signal risk fusion."""
    rules: float = 0.25
    isolation_forest: float = 0.15
    sequence: float = 0.15
    semantic: float = 0.15
    drift: float = 0.10
    entity: float = 0.10
    destination: float = 0.10
    graph: float = 0.10

    def normalized(self) -> Dict[str, float]:
        total = (
            self.rules + self.isolation_forest + self.sequence + self.semantic +
            self.drift + self.entity + self.destination + self.graph
        )
        if total <= 0:
            return {k: 1.0 / 8.0 for k in self.__dataclass_fields__}
        return {k: getattr(self, k) / total for k in self.__dataclass_fields__}


@dataclass
class GuardianV2Config:
    """Master configuration for MCP Guardian V2 adaptive security gateway."""

    # Decision boundaries
    monitor_threshold: float = 0.35
    block_threshold: float = 0.60
    sensitivity: float = 1.0

    # Risk Fusion Weights
    weights: RiskWeights = field(default_factory=RiskWeights)

    # Layer 1: Deterministic Hard Rules
    hard_block_bulk_threshold: int = 10
    hard_block_rapid_seconds: float = 0.05
    allow_list_sessions: Set[str] = field(default_factory=set)
    max_history_per_session: int = 300

    # Layer 2: Semantic Behavior Engine
    enable_semantic_verification: bool = True
    semantic_deviation_threshold: float = 0.50

    # Layer 3: Sequence Detection
    enable_sequence_detection: bool = True
    sequence_window_size: int = 8
    sequence_anomaly_threshold: float = 0.55

    # Layer 4: Behavioral Drift
    enable_drift_detection: bool = True
    adwin_delta: float = 0.002
    drift_validation_window: int = 50

    # Layer 5: Adaptive Thresholds
    enable_adaptive_thresholds: bool = True
    adaptive_zscore_threshold: float = 3.0

    # Layer 6: Entity Alignment
    enable_entity_alignment: bool = True
    strict_entity_validation: bool = True

    # Layer 7: Destination Novelty
    enable_destination_novelty: bool = True
    trusted_domains: Set[str] = field(default_factory=lambda: {
        "example.com", "example.org", "api.company.internal", "localhost", "127.0.0.1"
    })

    # Layer 8: Attack Graph
    enable_attack_graph: bool = True

    # Layer 9: Prompt Injection Analyzer
    enable_injection_analyzer: bool = True

    # Evasion Defense & Sliding Window Limits
    cumulative_window_seconds: float = 60.0
    max_records_per_window: int = 25
    max_calls_per_window: int = 20

    # Session Lifecycle & TTL Pruning
    session_ttl_seconds: float = 3600.0
    auto_prune_interval: int = 100

    # Storage & Persistence
    db_path: Path = field(default_factory=lambda: _get_default_data_dir() / "guardian_v2.db")
    log_path: Path = field(default_factory=lambda: _get_default_data_dir() / "guardian_decisions.jsonl")
    enable_sqlite: bool = True
    async_graph_processing: bool = True

    # Policy controls used by the reusable SDK API. Empty allow-list means
    # unrestricted unless default_deny is enabled.
    allowed_tools: Set[str] = field(default_factory=set)
    denied_tools: Set[str] = field(default_factory=set)
    default_deny: bool = False
    tool_schemas: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    server_policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    max_argument_bytes: int = 1_048_576
    max_argument_depth: int = 32
    policy_version: str = "1"
    approval_required_tools: Set[str] = field(default_factory=set)
    approval_ttl_seconds: float = 300.0
    trusted_caller_ids: Set[str] = field(default_factory=set)

    def __post_init__(self):
        if not 0 <= self.monitor_threshold <= 1 or not 0 <= self.block_threshold <= 1:
            raise ValueError("monitor_threshold and block_threshold must be between 0 and 1")
        if self.monitor_threshold > self.block_threshold or self.sensitivity <= 0:
            raise ValueError("monitor_threshold must not exceed block_threshold and sensitivity must be positive")
        if self.max_argument_bytes <= 0 or self.max_argument_depth <= 0:
            raise ValueError("argument limits must be positive")
        if self.approval_ttl_seconds <= 0:
            raise ValueError("approval_ttl_seconds must be positive")
        if self.hard_block_bulk_threshold < 0 or self.max_calls_per_window <= 0:
            raise ValueError("bulk and call limits must be non-negative/positive")
        if self.max_history_per_session <= 0 or self.max_records_per_window < 0:
            raise ValueError("session history and record quotas are invalid")
        weights = [getattr(self.weights, field) for field in self.weights.__dataclass_fields__]
        if any(weight < 0 for weight in weights) or sum(weights) <= 0:
            raise ValueError("risk weights must be non-negative with a positive total")
        if not isinstance(self.server_policies, dict) or not all(isinstance(p, dict) for p in self.server_policies.values()):
            raise ValueError("server_policies must map server names to objects")
        for name in ("allowed_tools", "denied_tools", "approval_required_tools", "allow_list_sessions", "trusted_domains", "trusted_caller_ids"):
            value = getattr(self, name)
            if not isinstance(value, (set, frozenset, list, tuple)) or not all(isinstance(v, str) and v for v in value):
                raise ValueError(f"{name} must contain non-empty strings")
            setattr(self, name, set(value))
        for server_id, policy in self.server_policies.items():
            for name in ("allowed_tools", "denied_tools", "approval_required_tools"):
                if name in policy:
                    value = policy[name]
                    if not isinstance(value, (set, frozenset, list, tuple)) or not all(isinstance(v, str) and v for v in value):
                        raise ValueError(f"server_policies[{server_id!r}].{name} must contain non-empty strings")
            if "default_deny" in policy and not isinstance(policy["default_deny"], bool):
                raise ValueError(f"server_policies[{server_id!r}].default_deny must be boolean")

    @classmethod
    def from_file(cls, path: str) -> "GuardianV2Config":
        """Load a JSON configuration file without executing configuration code."""
        try:
            with open(path, "r", encoding="utf-8") as config_file:
                value = json.load(config_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not load Guardian JSON configuration: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("Guardian configuration root must be a JSON object")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"Unknown Guardian configuration fields: {', '.join(sorted(unknown))}")
        if "weights" in value and isinstance(value["weights"], dict):
            value["weights"] = RiskWeights(**value["weights"])
        for key in ("allowed_tools", "denied_tools", "allow_list_sessions", "trusted_domains", "approval_required_tools", "trusted_caller_ids"):
            if key in value and isinstance(value[key], list):
                value[key] = set(value[key])
        return cls(**value)


def _get_default_data_dir() -> Path:
    """Safely determines default data dir across repo checkouts and pip site-packages installs."""
    repo_data = Path(__file__).parent.parent.parent / "data"
    try:
        if repo_data.exists() or repo_data.parent.name == "mcp-security-project":
            return repo_data
    except Exception:
        pass
    # Fallback to local ./data in current working directory
    local_data = Path.cwd() / "data"
    local_data.mkdir(parents=True, exist_ok=True)
    return local_data
