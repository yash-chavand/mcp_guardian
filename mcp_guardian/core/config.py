"""
Configuration system for MCP Guardian V2.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import Set, Dict


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
