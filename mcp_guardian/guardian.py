"""
MCP Guardian V2 — Enterprise Adaptive Security Gateway for Model Context Protocol (MCP).

Orchestrates a 10-layer multi-signal security pipeline:
  1. Deterministic Hard Rules (Bulk caps & rate limits)
  2. Isolation Forest ML Anomaly Scorer
  3. GRU Sequence Anomaly Detector / Statistical Fallback
  4. Semantic Expected vs Actual Behavior Verifier
  5. Behavioral Concept Drift Detector (ADWIN)
  6. Adaptive Dynamic Threshold Engine
  7. Stateful Entity Relationship Validator
  8. Destination Novelty & Reputation Tracker
  9. Session Attack Graph Correlation Analyzer
 10. Multi-Layer Prompt Injection Analyzer

Maintains 100% backward compatibility with MCP Guardian V1 APIs and decorators.
"""

import time
import json
from pathlib import Path
from functools import wraps
from collections import defaultdict
from typing import Dict, List, Any, Optional, Set, Tuple

from .core.types import Decision, RiskLevel, EventType
from .core.events import SecurityEvent, RiskReason
from .core.config import GuardianV2Config, RiskWeights
from .rules.rule_engine import RuleEngine
from .ml.isolation_forest import IsolationForestScorer
from .ml.sequence_model import SequenceInferenceService
from .semantic.profile_generator import ExpectedBehaviorProfileGenerator, ExpectedBehaviorProfile
from .semantic.behavior_verifier import SemanticBehaviorVerifier
from .drift.drift_detector import BehavioralDriftDetector
from .adaptive.threshold_engine import AdaptiveThresholdEngine
from .entity.entity_graph import EntityRelationshipValidator
from .destination.novelty_tracker import DestinationNoveltyTracker
from .graph.attack_graph import SessionGraphStore
from .graph.analyzer import GraphRiskAnalyzer
from .injection.injection_analyzer import PromptInjectionAnalyzer
from .discovery.auto_discovery_v2 import AutoDiscoveryV2
from .risk.fusion_engine import RiskFusionEngine
from .risk.explainer import RiskExplanationBuilder
from .risk.decision_engine import DecisionEngine
from .storage.db import SecurityStorage

# Backward compatibility alias
GuardianConfig = GuardianV2Config
DEFAULT_MODEL_PATH = Path(__file__).parent / "realtime_model.joblib"
DEFAULT_LOG_PATH = Path(__file__).parent.parent / "data" / "guardian_decisions.jsonl"


class MCPGuardian:
    """Production-grade adaptive security gateway for MCP tool traffic."""

    def __init__(
        self,
        model_path: Path = DEFAULT_MODEL_PATH,
        log_path: Path = DEFAULT_LOG_PATH,
        verbose: bool = True,
        config: GuardianV2Config = None
    ):
        self.config = config or GuardianV2Config()
        self.verbose = verbose
        self.log_path = Path(log_path)

        # Persistence & Storage
        self.storage = SecurityStorage(
            db_path=self.config.db_path if self.config.enable_sqlite else None,
            jsonl_path=self.log_path
        )

        # Core Sub-Systems
        self.rules = RuleEngine(
            bulk_threshold=self.config.hard_block_bulk_threshold,
            rapid_seconds_threshold=self.config.hard_block_rapid_seconds,
            allow_list_sessions=self.config.allow_list_sessions,
            max_records_per_window=self.config.max_records_per_window,
            max_calls_per_window=self.config.max_calls_per_window
        )
        self.ml_scorer = IsolationForestScorer(model_path=model_path)
        self.sequence_service = SequenceInferenceService()
        self.drift_detector = BehavioralDriftDetector(
            delta=self.config.adwin_delta,
            validation_window_size=self.config.drift_validation_window
        )
        self.threshold_engine = AdaptiveThresholdEngine()
        self.entity_validator = EntityRelationshipValidator()
        self.destination_tracker = DestinationNoveltyTracker(trusted_domains=self.config.trusted_domains)
        self.graph_store = SessionGraphStore()
        self.discovery = AutoDiscoveryV2(storage=self.storage)
        self.fusion_engine = RiskFusionEngine(weights=self.config.weights)
        self.decision_engine = DecisionEngine(
            monitor_threshold=self.config.monitor_threshold,
            block_threshold=self.config.block_threshold
        )

        # In-memory session tracking & lifecycle
        self.sessions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._session_activity: Dict[str, float] = {}
        self._check_counter: int = 0
        self._decision_log: List[Dict[str, Any]] = []

    # ----------------- Feature Extraction -----------------
    def _extract_v1_features(
        self,
        session_id: str,
        tool_name: str,
        records_this_call: int,
        recipient_mismatch: bool,
        is_email: bool
    ) -> Tuple[Dict[str, Any], float, float]:
        history = self.sessions[session_id]
        now = time.time()
        time_since_last = (now - history[-1]["ts"]) if history else -1.0
        cumulative_records = sum(h.get("records", 1) for h in history) + records_this_call

        feats = {
            "call_index_in_session": len(history) + 1,
            "records_requested": records_this_call,
            "cumulative_records_in_session": cumulative_records,
            "time_since_last_call": time_since_last,
            "recipient_mismatch": int(recipient_mismatch),
            "tool_is_email": int(is_email),
        }
        return feats, now, time_since_last

    # ----------------- Core Fast Path Scoring API -----------------
    def check(
        self,
        session_id: str,
        tool_name: str,
        records_this_call: int = 1,
        recipient_mismatch: bool = False,
        is_email: bool = False,
        arguments: Dict[str, Any] = None,
        prompt_text: str = None,
        recipient_target: str = None,
        server_id: str = "primary-server",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Synchronous Fast-Path Security Check (< 5ms).
        Returns a rich decision dictionary compatible with V1 and extended with V2 intelligence.
        """
        if session_id in self.config.allow_list_sessions:
            decision_dict = {
                "timestamp": time.time(),
                "session_id": session_id,
                "tool": tool_name,
                "features": {},
                "anomaly_score": 0.0,
                "blocked": False,
                "decision": Decision.ALLOW.value,
                "risk_level": RiskLevel.LOW.value,
                "reason": "allow_listed",
                "reasons": [{"type": "allow_listed", "severity": "low", "message": "Session is allow-listed."}],
                "sub_scores": {},
                "latency_ms": 0.0,
                "correlation_id": "allow-listed"
            }
            self._decision_log.append(decision_dict)
            return decision_dict

        t_start = time.perf_counter()
        arguments = arguments or {}
        reasons_list: List[Optional[RiskReason]] = []
        sub_scores: Dict[str, float] = {}

        # Lifecycle Auto-Prune Trigger
        self._check_counter += 1
        if self._check_counter % self.config.auto_prune_interval == 0:
            self.prune_stale_sessions()

        # 1. Feature extraction
        feats, now, time_since_last = self._extract_v1_features(
            session_id, tool_name, records_this_call, recipient_mismatch, is_email
        )

        # Sliding-window metrics for cumulative evasion defense
        window_cutoff = now - self.config.cumulative_window_seconds
        recent_session_calls = [h for h in self.sessions[session_id] if h.get("ts", 0) >= window_cutoff]
        window_calls = len(recent_session_calls) + 1
        window_records = sum(h.get("records", 1) for h in recent_session_calls) + records_this_call

        # 2. Layer 1: Deterministic Hard Rules
        rule_score, is_hard_blocked, rule_reason = self.rules.evaluate(
            session_id=session_id,
            tool_name=tool_name,
            records_requested=records_this_call,
            time_since_last_call=time_since_last,
            arguments=arguments,
            window_records=window_records,
            window_calls=window_calls
        )
        sub_scores["rules"] = rule_score
        if rule_reason:
            reasons_list.append(rule_reason)

        # 3. Layer 2: Isolation Forest Anomaly Scoring
        raw_if_score, norm_if_score, is_ml_blocked, if_reason = self.ml_scorer.score(feats, sensitivity=self.config.sensitivity)
        sub_scores["isolation_forest"] = norm_if_score
        if if_reason:
            reasons_list.append(if_reason)

        # 4. Layer 3: Sequence-Based Anomaly Detection
        session_history = self.sessions[session_id] + [{
            "tool": tool_name,
            "time_since_last_call": time_since_last,
            "records": records_this_call,
            "recipient_mismatch": recipient_mismatch,
            "is_email": is_email,
            "arguments": arguments
        }]
        seq_score, seq_reason = self.sequence_service.score(session_history)
        sub_scores["sequence"] = seq_score
        if seq_reason:
            reasons_list.append(seq_reason)

        # 5. Layer 4: Semantic Expected vs Actual Deviation
        profile = self.discovery.get_profile(tool_name)
        sem_score, sem_reasons, actual_summary = SemanticBehaviorVerifier.verify(
            profile=profile,
            arguments=arguments,
            runtime_context={
                "records_requested": records_this_call,
                "recipient": recipient_target or arguments.get("customer_email", arguments.get("to", "")),
                "recipient_mismatch": recipient_mismatch,
                "destination_domain": recipient_target or arguments.get("customer_email", ""),
            }
        )
        sub_scores["semantic"] = sem_score
        reasons_list.extend(sem_reasons)

        # 6. Layer 5: Behavioral Concept Drift Detection
        drift_score, drift_reason = self.drift_detector.observe("request_rate", 1.0 / max(0.01, time_since_last if time_since_last > 0 else 1.0))
        sub_scores["drift"] = drift_score
        if drift_reason:
            reasons_list.append(drift_reason)

        # 7. Layer 6: Adaptive Dynamic Thresholds
        adap_score, adap_details, adap_reason = self.threshold_engine.evaluate(
            server_id=server_id,
            tool_name=tool_name,
            session_id=session_id,
            metric="records",
            current_value=float(records_this_call),
            sensitivity=self.config.sensitivity
        )
        if adap_reason:
            reasons_list.append(adap_reason)

        # 8. Layer 7: Stateful Entity Relationship Validation
        target_addr = recipient_target or arguments.get("customer_email", arguments.get("to", ""))
        entity_score, entity_reason = self.entity_validator.validate_destination(
            session_id=session_id,
            destination_target=target_addr,
            arguments=arguments
        )
        if recipient_mismatch:
            entity_score = max(entity_score, 0.95)
        sub_scores["entity"] = entity_score
        if entity_reason:
            reasons_list.append(entity_reason)

        # 9. Layer 8: Network Destination Novelty
        dest_score, dest_reason = self.destination_tracker.evaluate_destination(
            raw_destination=target_addr,
            tool_name=tool_name,
            session_id=session_id,
            data_sensitivity_level=profile.risk_level,
            records_count=records_this_call
        )
        sub_scores["destination"] = dest_score
        if dest_reason:
            reasons_list.append(dest_reason)

        # 10. Layer 9: Session Attack Graph Correlation
        graph = self.graph_store.get_or_create(session_id)
        graph.record_tool_call(
            tool_name=tool_name,
            server_id=server_id,
            records_requested=records_this_call,
            recipient=target_addr,
            risk_level="high" if (is_hard_blocked or recipient_mismatch) else "low",
            arguments=arguments
        )
        graph_score, graph_reason = GraphRiskAnalyzer.analyze(graph)
        sub_scores["graph"] = graph_score
        if graph_reason:
            reasons_list.append(graph_reason)

        # 11. Layer 10: Multi-Layer Prompt Injection Analysis
        if prompt_text:
            inj_score, inj_reason, _ = PromptInjectionAnalyzer.analyze(
                user_message=prompt_text,
                tool_name=tool_name,
                arguments=arguments,
                is_high_risk_tool=profile.risk_level in ["high", "critical"]
            )
            sub_scores["injection"] = inj_score
            if inj_reason:
                reasons_list.append(inj_reason)
        else:
            sub_scores["injection"] = 0.0

        # ---- Weighted Risk Fusion & Multi-Tier Decision ----
        composite_score, _ = self.fusion_engine.fuse(sub_scores)
        decision, risk_level = self.decision_engine.decide(
            composite_score=composite_score,
            is_hard_blocked=is_hard_blocked,
            sensitivity=self.config.sensitivity
        )

        # Legacy & V2 block reconciliation
        is_blocked = (is_hard_blocked or is_ml_blocked or decision == Decision.BLOCK)
        if is_blocked and decision != Decision.BLOCK:
            decision = Decision.BLOCK
            risk_level = RiskLevel.CRITICAL if is_hard_blocked else RiskLevel.HIGH

        # Determine primary reason string
        if is_hard_blocked and rule_reason:
            if records_this_call > self.config.hard_block_bulk_threshold:
                primary_reason_str = f"bulk_request_exceeds_{self.config.hard_block_bulk_threshold}_records"
            elif time_since_last != -1 and time_since_last < self.config.hard_block_rapid_seconds:
                primary_reason_str = f"calls_faster_than_{self.config.hard_block_rapid_seconds}s"
            else:
                primary_reason_str = rule_reason.type
        elif is_ml_blocked and not is_hard_blocked:
            primary_reason_str = "ml_anomaly_score"
        elif is_blocked:
            primary_reason_str = reasons_list[0].type if reasons_list else "anomalous_behavior_detected"
        else:
            primary_reason_str = "normal"

        # Format structured reasons -- combines rules, entity alignment, anomaly
        # detection (Isolation Forest + sequence), semantic behavior deviation,
        # drift, destination novelty and graph correlation into one clear,
        # decision-aware explanation list.
        structured_reasons = RiskExplanationBuilder.build_explanations(
            reasons_list, composite_score, decision=decision.value
        )

        t_end = time.perf_counter()
        latency_ms = round((t_end - t_start) * 1000, 2)

        # Build SecurityEvent
        sec_event = SecurityEvent(
            timestamp=now,
            session_id=session_id,
            server_id=server_id,
            tool_name=tool_name,
            event_type=EventType.TOOL_CALL.value,
            risk_score=composite_score,
            risk_level=risk_level.value,
            decision=decision.value,
            sub_scores={k: round(v, 4) for k, v in sub_scores.items()},
            reasons=structured_reasons,
            evidence={
                "features": feats,
                "arguments": arguments,
                "profile": profile.to_dict(),
                "adaptive": adap_details,
                "semantic": actual_summary
            },
            latency_ms=latency_ms
        )

        # Record to persistent storage & in-memory decision log
        self.storage.save_event(sec_event)

        # Update session memory
        self.sessions[session_id].append({
            "ts": now,
            "tool": tool_name,
            "records": records_this_call,
            "recipient_mismatch": recipient_mismatch,
            "is_email": is_email,
            "arguments": arguments,
            "decision": decision.value
        })
        self._session_activity[session_id] = now
        if len(self.sessions[session_id]) > self.config.max_history_per_session:
            self.sessions[session_id] = self.sessions[session_id][-self.config.max_history_per_session:]

        # Backward compatible dict representation
        legacy_decision = {
            "timestamp": now,
            "session_id": session_id,
            "tool": tool_name,
            "features": feats,
            "anomaly_score": round(raw_if_score, 4),
            "blocked": is_blocked,
            "decision": decision.value,
            "risk_level": risk_level.value,
            "reason": primary_reason_str,
            "reasons": structured_reasons,
            "sub_scores": sub_scores,
            "risk_score": composite_score,
            "latency_ms": latency_ms,
            "correlation_id": sec_event.correlation_id,
            "event_id": sec_event.event_id
        }
        self._decision_log.append(legacy_decision)

        if self.verbose:
            tag = f"🚩 [{decision.value}] ({primary_reason_str})" if is_blocked else f"  [{decision.value}]"
            try:
                print(f"[MCP Guardian V2] {tag} | session={session_id[:8]} tool={tool_name} risk={composite_score:.3f} ({latency_ms}ms)")
            except UnicodeEncodeError:
                print(f"[MCP Guardian V2] [{decision.value}] ({primary_reason_str}) | session={session_id[:8]} tool={tool_name} risk={composite_score:.3f}")

        return legacy_decision

    # ----------------- Decorator API -----------------
    def protect(self, records_fn=None, recipient_check_fn=None, is_email=False, on_block=None):
        """Decorator for wrapping MCP tool functions with V2 adaptive protection."""
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                session_id = kwargs.get("session_id", "default")
                if records_fn:
                    records = records_fn(kwargs)
                else:
                    oid = kwargs.get("order_id")
                    records = 500 if str(oid).upper() == "ALL" else 1

                mismatch = recipient_check_fn(kwargs) if recipient_check_fn else False

                decision = self.check(
                    session_id=session_id,
                    tool_name=fn.__name__,
                    records_this_call=records,
                    recipient_mismatch=mismatch,
                    is_email=is_email,
                    arguments=kwargs
                )

                if decision["blocked"]:
                    if on_block:
                        return on_block(kwargs, decision)
                    return {
                        "status": "blocked_by_guardian",
                        "reason": decision["reason"],
                        "reasons": decision["reasons"],
                        "risk_score": decision["anomaly_score"],
                        "correlation_id": decision["correlation_id"]
                    }

                return fn(*args, **kwargs)
            return wrapper
        return decorator

    # ----------------- Lifecycle & Memory Management -----------------
    def prune_stale_sessions(self, max_age_seconds: Optional[float] = None) -> int:
        """
        Prunes inactive sessions to prevent unbounded memory growth.
        Returns the number of pruned sessions.
        """
        ttl = max_age_seconds if max_age_seconds is not None else self.config.session_ttl_seconds
        cutoff = time.time() - ttl
        stale_sids = [sid for sid, last_t in list(self._session_activity.items()) if last_t < cutoff]
        for sid in stale_sids:
            self.sessions.pop(sid, None)
            self._session_activity.pop(sid, None)
            if hasattr(self.graph_store, "graphs") and isinstance(self.graph_store.graphs, dict):
                self.graph_store.graphs.pop(sid, None)
        return len(stale_sids)

    # ----------------- Client / Agent Protected Execution -----------------
    def execute_protected(
        self,
        session_id: str,
        tool_name: str,
        fn,
        arguments: Optional[Dict[str, Any]] = None,
        records_this_call: int = 1,
        recipient_mismatch: bool = False,
        is_email: bool = False,
        prompt_text: Optional[str] = None,
        **kwargs
    ) -> Any:
        """
        Executes a callable `fn` only if the MCP Guardian security check passes.
        Raises PermissionError if blocked.
        """
        arguments = arguments or {}
        decision = self.check(
            session_id=session_id,
            tool_name=tool_name,
            records_this_call=records_this_call,
            recipient_mismatch=recipient_mismatch,
            is_email=is_email,
            arguments=arguments,
            prompt_text=prompt_text,
            **kwargs
        )
        if decision.get("blocked"):
            raise PermissionError(f"Blocked by MCP Guardian: {decision.get('reason')}")
        return fn(**arguments) if callable(fn) else decision

    # ----------------- Reporting & Metrics -----------------
    def summary(self) -> Dict[str, Any]:
        total = len(self._decision_log)
        blocked = sum(1 for d in self._decision_log if d.get("decision") == Decision.BLOCK.value or d.get("blocked"))
        monitored = sum(1 for d in self._decision_log if d.get("decision") == Decision.MONITOR.value)
        allowed = total - (blocked + monitored)
        avg_latency = (sum(d.get("latency_ms", 0.0) for d in self._decision_log) / total) if total else 0.0

        return {
            "total_requests": total,
            "allowed": allowed,
            "monitored": monitored,
            "blocked": blocked,
            "block_rate": round(blocked / total, 4) if total else 0.0,
            "monitor_rate": round(monitored / total, 4) if total else 0.0,
            "average_latency_ms": round(avg_latency, 2)
        }


Guardian = MCPGuardian


def protect_server(server_instance, guardian: Optional[MCPGuardian] = None) -> MCPGuardian:
    """
    Auto-wraps all tools on a FastMCP or standard MCP server instance with MCP Guardian.

    Usage:
        from mcp.server.fastmcp import FastMCP
        from mcp_guardian import protect_server

        mcp = FastMCP("my-server")
        protect_server(mcp)
    """
    g = guardian or MCPGuardian(verbose=False)

    # 1. FastMCP tool manager support
    if hasattr(server_instance, "_tool_manager") and hasattr(server_instance._tool_manager, "_tools"):
        for tool_name, tool_obj in list(server_instance._tool_manager._tools.items()):
            if hasattr(tool_obj, "fn"):
                orig_fn = tool_obj.fn
                tool_obj.fn = g.protect()(orig_fn)

    # 2. Standard dict-based tools registry
    elif hasattr(server_instance, "tools") and isinstance(server_instance.tools, dict):
        for tool_name, tool_fn in list(server_instance.tools.items()):
            if callable(tool_fn):
                server_instance.tools[tool_name] = g.protect()(tool_fn)

    return g
