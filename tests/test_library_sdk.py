"""
Tests for MCP Guardian library SDK interfaces, evasion defenses, and lifecycle management.
"""

import time
import pytest
from mcp_guardian import (
    MCPGuardian,
    GuardianConfig,
    protect_server,
    protect,
    Decision,
    RiskLevel
)


def test_top_level_library_exports():
    """Verify clean top-level SDK imports."""
    assert MCPGuardian is not None
    assert GuardianConfig is not None
    assert callable(protect_server)
    assert callable(protect)
    assert Decision.ALLOW == "ALLOW"
    assert Decision.BLOCK == "BLOCK"
    assert Decision.CHALLENGE == "CHALLENGE"
    assert RiskLevel.LOW == "low"
    assert RiskLevel.CRITICAL == "critical"


def test_execute_protected_allows_benign_call():
    """Verify execute_protected allows safe function calls."""
    g = MCPGuardian(verbose=False)

    def add_numbers(a: int, b: int):
        return a + b

    result = g.execute_protected(
        session_id="exec-session-1",
        tool_name="calculator",
        fn=add_numbers,
        arguments={"a": 3, "b": 4},
        records_this_call=1
    )
    assert result == 7


def test_execute_protected_blocks_dangerous_call():
    """Verify execute_protected blocks and raises PermissionError on attacks."""
    g = MCPGuardian(verbose=False)

    def delete_db(target: str):
        return "deleted"

    with pytest.raises(PermissionError) as exc_info:
        g.execute_protected(
            session_id="exec-session-2",
            tool_name="delete_db",
            fn=delete_db,
            arguments={"target": "ALL"},
            records_this_call=100
        )
    assert "Blocked by MCP Guardian" in str(exc_info.value)


def test_protect_server_wraps_all_tools():
    """Verify protect_server auto-wraps all registered tools on a server instance."""
    class DummyMCPServer:
        def __init__(self):
            self.call_log = []
            self.tools = {
                "fetch_data": self._fetch_data,
                "send_data": self._send_data
            }

        def _fetch_data(self, records: int = 1, session_id: str = "default"):
            self.call_log.append("fetched")
            return {"status": "ok"}

        def _send_data(self, to: str = "test@example.com", session_id: str = "default"):
            self.call_log.append("sent")
            return {"status": "sent"}

    server = DummyMCPServer()
    g = MCPGuardian(verbose=False)
    protect_server(server, guardian=g)

    # Allowed call
    res_allow = server.tools["fetch_data"](records=1, session_id="s1")
    assert res_allow["status"] == "ok"
    assert "fetched" in server.call_log

    # Bulk attack should be blocked by guardian wrapper
    res_block = server.tools["fetch_data"](records=500, session_id="s2")
    assert res_block["status"] == "blocked_by_guardian"
    # Ensure tool implementation was not executed for blocked call
    assert server.call_log == ["fetched"]


def test_cumulative_records_sliding_window_blocks_chunked_exfiltration():
    """
    Test evasion defense: attacker sends chunked requests (5 records x 6 calls = 30 records).
    Single-call threshold is 10, so each call would normally pass if evaluated in isolation.
    Sliding-window threshold (max 25 records / window) catches and blocks the chunked attack.
    """
    config = GuardianConfig(
        hard_block_bulk_threshold=10,
        max_records_per_window=25,
        cumulative_window_seconds=60.0
    )
    g = MCPGuardian(verbose=False, config=config)
    session_id = "chunked-attacker"

    # Calls 1 to 5: 5 * 5 = 25 records (within allowed quota)
    for i in range(5):
        res = g.check(session_id, "get_customer_order", records_this_call=5)
        assert res["blocked"] is False, f"Call {i+1} should be allowed"
        # The default per-session rapid-call rule is independent of the quota.
        # Space requests beyond that configured threshold to exercise the
        # cumulative-record boundary specifically.
        time.sleep(config.hard_block_rapid_seconds + 0.01)

    # Call 6: pushes cumulative window to 30 records -> MUST be blocked
    res_blocked = g.check(session_id, "get_customer_order", records_this_call=5)
    assert res_blocked["blocked"] is True
    reason_types = {r["type"] for r in res_blocked["reasons"]}
    assert "cumulative_records_quota_exceeded" in reason_types


def test_sliding_window_rate_blocks_sustained_frequency():
    """
    Test evasion defense: attacker calls at 0.1s intervals (bypassing 0.05s rapid-fire rule),
    but makes 25 calls in under a minute (exceeding max_calls_per_window=20).
    """
    config = GuardianConfig(
        hard_block_rapid_seconds=0.01,
        max_calls_per_window=20,
        cumulative_window_seconds=60.0
    )
    g = MCPGuardian(verbose=False, config=config)
    session_id = "frequency-bot"

    # Make 20 calls (allowed)
    for i in range(20):
        res = g.check(session_id, "lookup", records_this_call=1)
        assert res["blocked"] is False
        # The test exercises the 60-second call quota, not the independent
        # per-call rapid-fire rule.
        time.sleep(config.hard_block_rapid_seconds + 0.01)

    # 21st call exceeds 20 calls/minute limit
    res_blocked = g.check(session_id, "lookup", records_this_call=1)
    assert res_blocked["blocked"] is True
    reason_types = {r["type"] for r in res_blocked["reasons"]}
    assert "sliding_window_rate_exceeded" in reason_types


def test_prune_stale_sessions_frees_memory():
    """Verify that sessions inactive longer than TTL are pruned from memory."""
    config = GuardianConfig(session_ttl_seconds=10.0)
    g = MCPGuardian(verbose=False, config=config)

    # Active session
    g.check("active-session", "lookup", records_this_call=1)
    # Stale session simulated in past
    g.check("stale-session", "lookup", records_this_call=1)
    g._session_activity["stale-session"] = time.time() - 100.0

    assert "stale-session" in g.sessions
    assert "active-session" in g.sessions

    pruned = g.prune_stale_sessions(max_age_seconds=10.0)
    assert pruned == 1
    assert "stale-session" not in g.sessions
    assert "active-session" in g.sessions
