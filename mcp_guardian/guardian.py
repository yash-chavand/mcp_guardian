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
import logging
import json
import uuid
import inspect
import threading
import secrets
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from collections import defaultdict
from typing import Dict, List, Any, Optional, Set, Tuple

from .core.types import Decision, RiskLevel, EventType, SecurityDecision, ToolCallContext, ApprovalRequest
from .exceptions import PolicyDenied, ApprovalRequired
from .core.events import SecurityEvent, RiskReason, hash_identifier
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


def _synchronized(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._state_lock:
            return method(self, *args, **kwargs)
    return wrapped


def _json_depth(value: Any, depth: int = 0) -> int:
    if isinstance(value, dict):
        return max([depth + 1] + [_json_depth(v, depth + 1) for v in value.values()])
    if isinstance(value, (list, tuple)):
        return max([depth + 1] + [_json_depth(v, depth + 1) for v in value])
    return depth


def _arguments_digest(arguments: Dict[str, Any]) -> str:
    payload = json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_basic_schema(value: Any, schema: Dict[str, Any]) -> Optional[str]:
    """Small fail-closed subset of JSON Schema for common MCP argument shapes."""
    if not isinstance(schema, dict):
        return "schema_not_object"
    expected = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "integer": int,
             "number": (int, float), "boolean": bool, "null": type(None)}
    if expected:
        choices = expected if isinstance(expected, list) else [expected]
        if not any(t in types and isinstance(value, types[t]) and not
                   (t in {"integer", "number"} and isinstance(value, bool)) and
                   not (t == "integer" and isinstance(value, float) and not value.is_integer())
                   for t in choices):
            return "type_mismatch"
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                return f"missing_required:{key}"
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False and any(k not in props for k in value):
            return "unexpected_property"
        for key, child in value.items():
            if key in props:
                issue = _validate_basic_schema(child, props[key])
                if issue:
                    return f"{key}:{issue}"
    if isinstance(value, str) and len(value) > schema.get("maxLength", float("inf")):
        return "max_length_exceeded"
    if isinstance(value, list):
        if len(value) > schema.get("maxItems", float("inf")):
            return "max_items_exceeded"
        if "items" in schema:
            for index, child in enumerate(value):
                issue = _validate_basic_schema(child, schema["items"])
                if issue:
                    return f"item_{index}:{issue}"
    return None


class MCPGuardian:
    """Production-grade adaptive security gateway for MCP tool traffic."""

    @classmethod
    def from_config(cls, path: str, **kwargs) -> "MCPGuardian":
        """Create a guardian from a validated JSON config file."""
        try:
            config = GuardianV2Config.from_file(path)
        except (OSError, ValueError, TypeError) as exc:
            from .exceptions import ConfigurationError
            raise ConfigurationError(str(exc)) from exc
        return cls(config=config, **kwargs)

    def __init__(
        self,
        model_path: Path = DEFAULT_MODEL_PATH,
        log_path: Optional[Path] = DEFAULT_LOG_PATH,
        verbose: bool = True,
        config: GuardianV2Config = None
    ):
        self.config = config or GuardianV2Config()
        self.verbose = verbose
        self.log_path = Path(log_path) if log_path is not None else None

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
        self._state_lock = threading.RLock()
        self._approval_requests: Dict[str, Dict[str, Any]] = {}
        self._approval_tokens: Dict[str, str] = {}

    def evaluate(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None,
                 session_id: str = "default", server_id: str = "primary-server",
                 caller_id: Optional[str] = None, schema: Optional[Dict[str, Any]] = None,
                 records_this_call: int = 1, recipient_mismatch: bool = False,
                 is_email: bool = False, prompt_text: Optional[str] = None,
                 approval_token: Optional[str] = None) -> SecurityDecision:
        """Evaluate a call under static authorization, argument limits and risk signals."""
        started = time.perf_counter()
        context = ToolCallContext(tool_name, arguments or {}, server_id, session_id, caller_id, schema)
        violations = self._policy_violations(context)
        if violations:
            latency = round((time.perf_counter() - started) * 1000, 2)
            decision_id = str(uuid.uuid4())
            self.storage.save_event(SecurityEvent(
                event_id=decision_id, timestamp=datetime.now(timezone.utc).isoformat(),
                session_id=session_id, server_id=server_id, tool_name=tool_name,
                decision=Decision.BLOCK.value, risk_score=1.0, risk_level=RiskLevel.CRITICAL.value,
                reasons=[{"type": code, "severity": "critical", "message": code} for code in violations],
                evidence={"policy_version": self.config.policy_version}, latency_ms=latency,
            ))
            return SecurityDecision(
                decision_id=decision_id, outcome=Decision.BLOCK,
                tool_name=tool_name, server_id=server_id, session_id=session_id,
                risk_score=1.0, reason=violations[0], matched_rules=violations,
                policy_version=self.config.policy_version,
                latency_ms=latency,
            )
        policy = self.config.server_policies.get(server_id, {})
        approval_tools = set(self.config.approval_required_tools) | set(policy.get("approval_required_tools", ()))
        if tool_name in approval_tools and not self._approval_matches(context, approval_token):
            latency = round((time.perf_counter() - started) * 1000, 2)
            return SecurityDecision(
                decision_id=str(uuid.uuid4()), outcome=Decision.CHALLENGE,
                tool_name=tool_name, server_id=server_id, session_id=session_id,
                risk_score=1.0, reason="human_approval_required",
                matched_rules=["human_approval_required"],
                policy_version=self.config.policy_version, latency_ms=latency,
            )
        # Session tokens supplied by an MCP peer are untrusted correlation IDs.
        # Only an embedding app that has verified its caller may activate a
        # session allow-list bypass through this API.
        risk_session_id = session_id
        if session_id in self.config.allow_list_sessions and caller_id not in self.config.trusted_caller_ids:
            risk_session_id = f"unverified:{session_id}"
        decision = self.check(session_id=risk_session_id, server_id=server_id,
                              tool_name=tool_name, arguments=context.arguments,
                              records_this_call=records_this_call,
                              recipient_mismatch=recipient_mismatch,
                              is_email=is_email, prompt_text=prompt_text)
        outcome = Decision(decision.get("decision", Decision.ALLOW.value))
        return SecurityDecision(
            decision_id=str(decision.get("event_id") or uuid.uuid4()), outcome=outcome,
            tool_name=tool_name, server_id=server_id, session_id=session_id,
            risk_score=float(decision.get("risk_score", decision.get("anomaly_score", 0.0))),
            reason=str(decision.get("reason", "normal")),
            matched_rules=[r.get("type", "") for r in decision.get("reasons", []) if r.get("type")],
            evidence={"correlation_id": decision.get("correlation_id")},
            policy_version=self.config.policy_version,
            latency_ms=float(decision.get("latency_ms", (time.perf_counter() - started) * 1000)),
        )

    def _policy_violations(self, context: ToolCallContext) -> List[str]:
        if not isinstance(context.arguments, dict):
            return ["arguments_must_be_object"]
        policy = self.config.server_policies.get(context.server_id, {})
        global_allow = set(self.config.allowed_tools)
        server_allow = set(policy.get("allowed_tools", ()))
        allow = global_allow & server_allow if global_allow and server_allow else global_allow or server_allow
        deny = set(self.config.denied_tools) | set(policy.get("denied_tools", ()))
        if context.tool_name in deny:
            return ["tool_denied_by_policy"]
        if allow and context.tool_name not in allow:
            return ["tool_not_in_allow_list"]
        if (policy.get("default_deny", False) or self.config.default_deny) and not allow:
            return ["default_deny_requires_tool_allow_list"]
        try:
            encoded = json.dumps(context.arguments, allow_nan=False, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            return ["arguments_not_json_serializable"]
        if len(encoded) > self.config.max_argument_bytes:
            return ["arguments_exceed_size_limit"]
        if _json_depth(context.arguments) > self.config.max_argument_depth:
            return ["arguments_exceed_nesting_limit"]
        schemas = [schema for schema in (
            self.config.tool_schemas.get(context.tool_name),
            policy.get("tool_schemas", {}).get(context.tool_name),
            context.schema,
        ) if schema]
        for schema in schemas:
            error = _validate_basic_schema(context.arguments, schema)
            if error:
                return [f"arguments_schema_invalid:{error}"]
        return []

    def create_approval_request(self, context: ToolCallContext) -> ApprovalRequest:
        """Create a short-lived approval request; this does not authorize a call."""
        violations = self._policy_violations(context)
        if violations:
            raise PolicyDenied(f"Cannot request approval for denied call: {violations[0]}")
        server_policy = self.config.server_policies.get(context.server_id, {})
        required = set(self.config.approval_required_tools) | set(server_policy.get("approval_required_tools", ()))
        if context.tool_name not in required:
            raise ValueError("Tool is not configured to require human approval")
        request_id = secrets.token_urlsafe(24)
        now = time.monotonic()
        expires = now + self.config.approval_ttl_seconds
        digest = _arguments_digest(context.arguments)
        with self._state_lock:
            self._prune_approvals(now)
            self._approval_requests[request_id] = {
                "tool": context.tool_name, "server": context.server_id,
                "session": context.session_id, "caller": context.caller_id, "digest": digest,
                "expires": expires, "created": now, "status": "pending",
            }
        expires_at = datetime.fromtimestamp(time.time() + self.config.approval_ttl_seconds, timezone.utc).isoformat()
        return ApprovalRequest(request_id, context.tool_name, context.server_id,
                               context.session_id, expires_at)

    def approve_request(self, request_id: str, approver_id: str) -> str:
        """Approve one pending request and return a short-lived, single-use token.

        The embedding application must authenticate the human represented by
        ``approver_id`` before calling this method.
        """
        if not approver_id or not isinstance(approver_id, str):
            raise ValueError("An authenticated approver identifier is required")
        with self._state_lock:
            now = time.monotonic()
            self._prune_approvals(now)
            request = self._approval_requests.get(request_id)
            if not request or request["status"] != "pending" or request["expires"] <= now:
                raise PolicyDenied("Approval request is missing, expired, or already decided")
            token = secrets.token_urlsafe(32)
            request.update(status="approved", token=token, approver=approver_id)
            self._approval_tokens[token] = request_id
            return token

    def _prune_approvals(self, now: float):
        expired = [rid for rid, req in self._approval_requests.items() if req["expires"] <= now]
        for rid in expired:
            req = self._approval_requests.pop(rid)
            if req.get("token"):
                self._approval_tokens.pop(req["token"], None)

    def _approval_matches(self, context: ToolCallContext, token: Optional[str]) -> bool:
        if not token:
            return False
        with self._state_lock:
            self._prune_approvals(time.monotonic())
            request_id = self._approval_tokens.get(token)
            request = self._approval_requests.get(request_id) if request_id else None
            return bool(request and request["status"] == "approved" and
                        request["tool"] == context.tool_name and
                        request["server"] == context.server_id and
                        request["session"] == context.session_id and
                        request.get("caller") == context.caller_id and
                        request["digest"] == _arguments_digest(context.arguments))

    def _consume_approval(self, context: ToolCallContext, token: Optional[str]) -> bool:
        if not token:
            return False
        with self._state_lock:
            if not self._approval_matches(context, token):
                return False
            request_id = self._approval_tokens.pop(token, None)
            request = self._approval_requests.get(request_id) if request_id else None
            if not request or request["status"] != "approved":
                return False
            request["status"] = "used"
            return True

    def invoke(self, context: ToolCallContext, fn, approval_token: Optional[str] = None):
        """Execute a callable only after a permit decision; preserve its result."""
        decision = self.evaluate(context.tool_name, context.arguments, context.session_id,
                                 context.server_id, context.caller_id, context.schema,
                                 approval_token=approval_token)
        if not decision.allowed:
            if decision.outcome == Decision.CHALLENGE:
                raise ApprovalRequired(f"Human approval required: {decision.reason}")
            raise PolicyDenied(f"Blocked by MCP Guardian: {decision.reason}")
        if approval_token and not self._consume_approval(context, approval_token):
            raise PolicyDenied("Approval token is invalid, expired, or already used")
        return fn(**context.arguments)

    async def ainvoke(self, context: ToolCallContext, fn, approval_token: Optional[str] = None):
        """Execute a sync or async callable after authorization."""
        # Scoring is synchronous and bounded; run it before the first await so
        # cancellation cannot leave an unobserved background policy check.
        decision = self.evaluate(
            context.tool_name, context.arguments, context.session_id,
            context.server_id, context.caller_id, context.schema,
            approval_token=approval_token,
        )
        if not decision.allowed:
            if decision.outcome == Decision.CHALLENGE:
                raise ApprovalRequired(f"Human approval required: {decision.reason}")
            raise PolicyDenied(f"Blocked by MCP Guardian: {decision.reason}")
        if approval_token and not self._consume_approval(context, approval_token):
            raise PolicyDenied("Approval token is invalid, expired, or already used")
        result = fn(**context.arguments)
        return await result if inspect.isawaitable(result) else result

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
    @_synchronized
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
                "session_id": hash_identifier(session_id),
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
            if graph_reason.type in {
                "attack_graph_encode_exfiltration_chain",
                "attack_graph_bulk_exfiltration_chain",
            }:
                # These are specific, ordered read/transform/exfiltration
                # chains; treat them as deterministic critical policy hits.
                is_hard_blocked = True
                rule_score = 1.0
                sub_scores["rules"] = 1.0
                rule_reason = graph_reason

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

        # ML's raw binary threshold is diagnostic only. A model should contribute
        # risk through the calibrated fusion score; allowing its separate raw
        # threshold to override policy thresholds caused normal repeated calls
        # to be blocked even when the composite decision was below block level.
        is_blocked = (is_hard_blocked or decision == Decision.BLOCK)
        if is_blocked and decision != Decision.BLOCK:
            decision = Decision.BLOCK
            risk_level = RiskLevel.CRITICAL

        # Determine primary reason string
        if is_hard_blocked and rule_reason:
            if records_this_call > self.config.hard_block_bulk_threshold:
                primary_reason_str = f"bulk_request_exceeds_{self.config.hard_block_bulk_threshold}_records"
            elif time_since_last != -1 and time_since_last < self.config.hard_block_rapid_seconds:
                primary_reason_str = f"calls_faster_than_{self.config.hard_block_rapid_seconds}s"
            else:
                primary_reason_str = rule_reason.type
        elif decision == Decision.BLOCK and not is_hard_blocked:
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
                # Tool arguments can contain credentials, private records, and
                # attacker-controlled payloads. Keep only derived evidence in
                # the ordinary audit record.
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
            "session_id": hash_identifier(session_id),
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
                logging.getLogger("mcp_guardian").info(
                    "%s | session=%s tool=%s risk=%.3f (%sms)", tag,
                    hash_identifier(session_id)[:8], tool_name, composite_score, latency_ms,
                )
            except (UnicodeEncodeError, ValueError):
                logging.getLogger("mcp_guardian").info(
                    "[%s] (%s) | session=%s tool=%s risk=%.3f",
                    decision.value, primary_reason_str, hash_identifier(session_id)[:8],
                    tool_name, composite_score,
                )

        return legacy_decision

    # ----------------- Decorator API -----------------
    def protect(self, records_fn=None, recipient_check_fn=None, is_email=False, on_block=None):
        """Decorator for wrapping MCP tool functions with V2 adaptive protection."""
        def decorator(fn):
            def authorize(args, kwargs):
                try:
                    bound = inspect.signature(fn).bind_partial(*args, **kwargs)
                    tool_arguments = {k: v for k, v in bound.arguments.items() if k not in {"self", "cls"}}
                except (TypeError, ValueError):
                    tool_arguments = dict(kwargs)
                session_id = tool_arguments.get("session_id", "default")
                if records_fn:
                    records = records_fn(tool_arguments)
                else:
                    # Infer common bulk selectors at the SDK boundary. The tool
                    # schema remains authoritative; this is a conservative
                    # signal, not a substitute for schema validation.
                    records = 1
                    for key in ("records", "record_count", "count", "limit", "order_id", "id"):
                        if key not in tool_arguments:
                            continue
                        value = tool_arguments[key]
                        if isinstance(value, (int, float)) and not isinstance(value, bool):
                            records = max(1, int(value))
                        elif str(value).strip().upper() in {"ALL", "*", "ANY", "EVERYTHING"}:
                            records = self.config.hard_block_bulk_threshold + 1
                        break

                mismatch = recipient_check_fn(tool_arguments) if recipient_check_fn else False
                return tool_arguments, self.evaluate(
                    session_id=session_id,
                    tool_name=fn.__name__,
                    records_this_call=records,
                    recipient_mismatch=mismatch,
                    is_email=is_email,
                    arguments=tool_arguments
                )

            def blocked(kwargs, decision):
                if on_block:
                    return on_block(kwargs, {
                        "reason": decision.reason, "reasons": decision.matched_rules,
                        "risk_score": decision.risk_score, "decision_id": decision.decision_id,
                    })
                return {
                        "status": "blocked_by_guardian",
                        "reason": decision.reason,
                        "reasons": decision.matched_rules,
                        "risk_score": decision.risk_score,
                        "decision_id": decision.decision_id,
                    }

            if inspect.iscoroutinefunction(fn):
                @wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    tool_arguments, decision = authorize(args, kwargs)
                    if not decision.allowed:
                        result = blocked(tool_arguments, decision)
                        return await result if inspect.isawaitable(result) else result
                    return await fn(*args, **kwargs)
                return async_wrapper

            @wraps(fn)
            def wrapper(*args, **kwargs):
                tool_arguments, decision = authorize(args, kwargs)
                if not decision.allowed:
                    return blocked(tool_arguments, decision)
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
        decision = self.evaluate(
            session_id=session_id,
            tool_name=tool_name,
            records_this_call=records_this_call,
            recipient_mismatch=recipient_mismatch,
            is_email=is_email,
            arguments=arguments,
            prompt_text=prompt_text,
            **kwargs
        )
        if not decision.allowed:
            raise PolicyDenied(f"Blocked by MCP Guardian: {decision.reason}")
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
                def infer_records(arguments):
                    for key in ("records", "record_count", "count", "limit", "order_id", "id"):
                        if key not in arguments:
                            continue
                        value = arguments[key]
                        if isinstance(value, (int, float)) and not isinstance(value, bool):
                            return max(1, int(value))
                        if str(value).strip().upper() in {"ALL", "*", "ANY", "EVERYTHING"}:
                            return g.config.hard_block_bulk_threshold + 1
                        break
                    return 1

                server_instance.tools[tool_name] = g.protect(records_fn=infer_records)(tool_fn)

    return g
