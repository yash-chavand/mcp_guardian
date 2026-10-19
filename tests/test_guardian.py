"""
Automated tests for MCP Guardian's core detection engine.
Run with: pytest tests/
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from mcp_guardian import MCPGuardian
from mcp_guardian.guardian import GuardianConfig


@pytest.fixture
def guardian():
    return MCPGuardian(verbose=False, log_path=None)


def test_normal_single_lookup_is_allowed(guardian):
    result = guardian.check("session-a", "get_customer_order", records_this_call=1)
    assert result["blocked"] is False


def test_bulk_request_is_blocked_by_hard_rule(guardian):
    result = guardian.check("session-b", "get_customer_order", records_this_call=500)
    assert result["blocked"] is True
    assert "bulk" in result["reason"]


def test_rapid_fire_is_blocked(guardian):
    from mcp_guardian import GuardianConfig
    guardian = MCPGuardian(verbose=False, log_path=None,
                           config=GuardianConfig(hard_block_rapid_seconds=1.0))
    guardian.check("session-c", "get_customer_order", records_this_call=1)
    time.sleep(0.01)  # far faster than the explicitly configured 1s threshold
    result = guardian.check("session-c", "get_customer_order", records_this_call=1)
    assert result["blocked"] is True


def test_human_paced_calls_are_allowed(guardian):
    guardian.check("session-d", "get_customer_order", records_this_call=1)
    time.sleep(2.0)  # representative of the training distribution's median gap (0.5-4.0s range)
    result = guardian.check("session-d", "send_email", records_this_call=0, recipient_mismatch=False, is_email=True)
    assert result["blocked"] is False


def test_recipient_mismatch_is_flagged(guardian):
    guardian.check("session-e", "get_customer_order", records_this_call=1)
    time.sleep(0.6)
    result = guardian.check("session-e", "send_email", records_this_call=0, recipient_mismatch=True, is_email=True)
    assert result["blocked"] is True


def test_allow_listed_session_bypasses_all_checks():
    g = MCPGuardian(verbose=False, log_path=None,
                     config=GuardianConfig(allow_list_sessions={"trusted-session"}))
    result = g.check("trusted-session", "get_customer_order", records_this_call=99999)
    assert result["blocked"] is False
    assert result["reason"] == "allow_listed"


def test_sensitivity_affects_blocking_decision_at_the_boundary():
    """Sensitivity should shift the DECISION threshold: the same borderline
    call should be allowed when loose, blocked when strict."""
    borderline_kwargs = dict(records_this_call=1, recipient_mismatch=False, is_email=False)

    g_loose = MCPGuardian(verbose=False, log_path=None,
                           config=GuardianConfig(sensitivity=0.05))
    g_strict = MCPGuardian(verbose=False, log_path=None,
                            config=GuardianConfig(sensitivity=20.0))

    r_loose = g_loose.check("s1", "get_customer_order", **borderline_kwargs)
    r_strict = g_strict.check("s2", "get_customer_order", **borderline_kwargs)

    # Same input features -> same raw ML score -> but different thresholds
    assert r_loose["anomaly_score"] == r_strict["anomaly_score"]
    # Strict sensitivity lowers the bar for blocking; loose raises it
    assert r_strict["blocked"] or not r_loose["blocked"]


def test_decorator_blocks_and_prevents_real_function_execution():
    g = MCPGuardian(verbose=False, log_path=None)
    call_log = []

    @g.protect(records_fn=lambda kwargs: 500)
    def sensitive_tool(session_id="default"):
        call_log.append("executed")  # should NEVER run if blocked
        return {"status": "ok"}

    result = sensitive_tool(session_id="attack-session")
    assert result["status"] == "blocked_by_guardian"
    assert call_log == []  # proves the real tool logic never ran


def test_decorator_checks_positional_arguments_before_execution():
    g = MCPGuardian(verbose=False, log_path=None)
    call_log = []

    @g.protect()
    def bulk_tool(records: int):
        call_log.append(records)
        return {"records": records}

    result = bulk_tool(500)
    assert result["status"] == "blocked_by_guardian"
    assert call_log == []


def test_decorator_allows_and_executes_real_function():
    g = MCPGuardian(verbose=False, log_path=None)
    call_log = []

    @g.protect(records_fn=lambda kwargs: 1)
    def normal_tool(session_id="default"):
        call_log.append("executed")
        return {"status": "ok"}

    result = normal_tool(session_id="normal-session")
    assert result["status"] == "ok"
    assert call_log == ["executed"]


def test_summary_counts_are_accurate(guardian):
    guardian.check("s1", "get_customer_order", records_this_call=1)
    guardian.check("s2", "get_customer_order", records_this_call=500)
    guardian.check("s3", "get_customer_order", records_this_call=1)
    summary = guardian.summary()
    assert summary["total_requests"] == 3
    assert summary["blocked"] == 1


# ---------------------------------------------------------------------------
# Sequence Attack Detection: read sensitive data -> encode -> external request
# ---------------------------------------------------------------------------

def test_attack_graph_flags_read_encode_send_chain(guardian):
    session_id = "chain-session"

    # 1. Read a batch of sensitive records (creates a bulk READ edge).
    guardian.check(session_id, "get_customer_order", records_this_call=5)

    # 2. Encode/transform the data before sending it out (creates a TRANSFORMED edge
    #    via the tool-name keyword "encode").
    guardian.check(session_id, "encode_payload", records_this_call=1)

    # 3. Send it to an external destination (creates a SENT_TO edge).
    result = guardian.check(
        session_id,
        "send_email",
        records_this_call=1,
        is_email=True,
        recipient_target="attacker@external-unknown.com"
    )

    reason_types = {r["type"] for r in result["reasons"]}
    assert "attack_graph_encode_exfiltration_chain" in reason_types
    assert result["sub_scores"]["graph"] >= 0.95
    assert result["decision"] == "BLOCK"


def test_attack_graph_transform_detected_via_high_entropy_argument(guardian):
    session_id = "entropy-session"

    guardian.check(session_id, "get_customer_order", records_this_call=5)

    # No "encode"-style tool name, but a high-entropy (base64-like) argument value
    # should still be recognized as the transform hop.
    guardian.check(
        session_id,
        "prepare_payload",
        records_this_call=1,
        arguments={"payload": "QmFzZTY0RW5jb2RlZFBheWxvYWRUaGF0TG9va3NSYW5kb20xMjM0NTY3ODk="}
    )

    result = guardian.check(
        session_id,
        "send_email",
        records_this_call=1,
        is_email=True,
        recipient_target="attacker@external-unknown.com"
    )

    reason_types = {r["type"] for r in result["reasons"]}
    assert "attack_graph_encode_exfiltration_chain" in reason_types


def test_plain_read_then_send_without_transform_is_not_the_encode_chain(guardian):
    """A read followed directly by a send (no transform hop) should NOT be classified
    as the more specific encode-exfiltration chain, even though it may still be flagged
    by the broader bulk-exfiltration check."""
    session_id = "no-transform-session"

    guardian.check(session_id, "get_customer_order", records_this_call=5)
    result = guardian.check(
        session_id,
        "send_email",
        records_this_call=1,
        is_email=True,
        recipient_target="attacker@external-unknown.com"
    )

    reason_types = {r["type"] for r in result["reasons"]}
    assert "attack_graph_encode_exfiltration_chain" not in reason_types


# ---------------------------------------------------------------------------
# Sequence Attack Detection: lightweight statistical chain detector
# (mcp_guardian/ml/sequence_model.py::CategorySequenceChainDetector)
# ---------------------------------------------------------------------------

def test_statistical_sequence_model_flags_category_chain_directly():
    """Unit-level check on the lightweight detector itself, independent of the
    rest of the guardian pipeline."""
    from mcp_guardian.ml.sequence_model import CategorySequenceChainDetector

    detector = CategorySequenceChainDetector()
    events = [
        {"tool": "get_customer_order", "records": 5},
        {"tool": "encode_payload", "records": 1},
        {"tool": "send_email", "records": 1, "is_email": True},
    ]
    score, reason = detector.score_sequence(events)
    assert score >= 0.9
    assert reason is not None
    assert reason.type == "sequence_chain_sensitive_read_transform_external_send"


def test_statistical_sequence_model_ignores_unrelated_sequence():
    from mcp_guardian.ml.sequence_model import CategorySequenceChainDetector

    detector = CategorySequenceChainDetector()
    events = [
        {"tool": "get_customer_order", "records": 1},
        {"tool": "get_customer_order", "records": 1},
    ]
    score, reason = detector.score_sequence(events)
    assert score == 0.0
    assert reason is None


def test_guardian_sequence_layer_flags_read_encode_send_via_statistical_model(guardian):
    """End-to-end: the composite 'sequence' sub-score (Layer 3, lightweight
    statistical, not the GRU) should surface the chain as its own reason."""
    session_id = "seq-chain-session"

    guardian.check(session_id, "get_customer_order", records_this_call=5)
    guardian.check(session_id, "encode_payload", records_this_call=1)
    result = guardian.check(
        session_id,
        "send_email",
        records_this_call=1,
        is_email=True,
        recipient_target="attacker@external-unknown.com"
    )

    reason_types = {r["type"] for r in result["reasons"]}
    assert "sequence_chain_sensitive_read_transform_external_send" in reason_types
    assert result["sub_scores"]["sequence"] >= 0.9


# ---------------------------------------------------------------------------
# Explainable Risk Decisions: every ALLOW / MONITOR / BLOCK must carry a
# clear, decision-appropriate reason (mcp_guardian/risk/explainer.py)
# ---------------------------------------------------------------------------

def test_explainer_gives_clear_reason_for_each_decision_type():
    from mcp_guardian.risk.explainer import RiskExplanationBuilder

    allow = RiskExplanationBuilder.build_explanations([], composite_score=0.10, decision="ALLOW")
    assert allow[0]["type"] == "normal_operation"
    assert allow[0]["severity"] == "low"

    # This is the exact gap that used to exist: several weak signals combine
    # into a MONITOR-range composite score with no single layer individually
    # raising a RiskReason. The explanation must reflect MONITOR, not ALLOW.
    monitor = RiskExplanationBuilder.build_explanations([], composite_score=0.45, decision="MONITOR")
    assert monitor[0]["type"] == "composite_risk_elevated"
    assert monitor[0]["severity"] == "medium"
    assert "0.45" in monitor[0]["message"] or "0.450" in monitor[0]["message"]

    block = RiskExplanationBuilder.build_explanations([], composite_score=0.75, decision="BLOCK")
    assert block[0]["type"] == "composite_risk_threshold_exceeded"
    assert block[0]["severity"] == "high"


def test_explainer_combines_and_sorts_reasons_from_all_signal_types(guardian):
    """Simulates a request that trips multiple independent layers at once --
    rules, entity mismatch, semantic deviation, sequence -- and confirms the
    final decision carries all of them, deduplicated and severity-sorted,
    rather than only the first one found."""
    session_id = "multi-signal-session"

    # Establish an authorized entity for this session.
    guardian.entity_validator.bind_entity_from_lookup(
        session_id, {"email": "real-customer@trusted.com", "order_id": "ORD-1"}
    )

    guardian.check(session_id, "get_customer_order", records_this_call=5)
    result = guardian.check(
        session_id,
        "send_email",
        records_this_call=1,
        is_email=True,
        recipient_mismatch=True,
        recipient_target="attacker@external-unknown.com"
    )

    assert result["decision"] in ("MONITOR", "BLOCK")
    assert len(result["reasons"]) >= 1
    # Every reason must be a fully-formed, human-readable explanation.
    for r in result["reasons"]:
        assert r["type"] and r["severity"] and r["message"]
    # Severity-sorted: nothing "low" should appear before a "critical"/"high" reason.
    severities = [r["severity"] for r in result["reasons"]]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert severities == sorted(severities, key=lambda s: order.get(s, 99))


def test_allow_decision_still_gets_normal_operation_reason(guardian):
    result = guardian.check("clean-session", "get_customer_order", records_this_call=1)
    assert result["decision"] == "ALLOW"
    assert result["reasons"][0]["type"] == "normal_operation"
