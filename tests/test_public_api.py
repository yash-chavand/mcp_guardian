import pytest
import json

from mcp_guardian import (
    ApprovalRequired, Decision, GuardianConfig, MCPGuardian, PolicyDenied, ToolCallContext,
)
from mcp_guardian.cli import main as guardian_cli




def test_evaluate_returns_stable_explanation_and_allow():
    guardian = MCPGuardian(verbose=False, config=GuardianConfig(allowed_tools={"lookup"}))
    decision = guardian.evaluate("lookup", {"key": "value"}, session_id="s", server_id="orders")
    assert decision.allowed
    assert decision.outcome in {Decision.ALLOW, Decision.MONITOR}
    assert decision.tool_name == "lookup"
    assert decision.server_id == "orders"
    assert decision.decision_id


def test_deny_list_blocks_before_tool_execution():
    guardian = MCPGuardian(verbose=False, config=GuardianConfig(denied_tools={"delete_all"}))
    invoked = []
    context = ToolCallContext("delete_all", {}, "db", "session")
    with pytest.raises(PolicyDenied):
        guardian.invoke(context, lambda: invoked.append(True))
    assert invoked == []


def test_schema_and_argument_limits_fail_closed():
    config = GuardianConfig(tool_schemas={"lookup": {
        "type": "object", "required": ["id"],
        "properties": {"id": {"type": "integer"}}, "additionalProperties": False,
    }})
    guardian = MCPGuardian(verbose=False, config=config)
    missing = guardian.evaluate("lookup", {})
    assert not missing.allowed
    assert "arguments_schema_invalid" in missing.reason
    too_large = MCPGuardian(verbose=False, config=GuardianConfig(max_argument_bytes=8))
    assert not too_large.evaluate("lookup", {"x": "large"}).allowed


def test_server_policies_are_isolated():
    config = GuardianConfig(server_policies={
        "orders": {"allowed_tools": ["lookup"]},
        "billing": {"allowed_tools": ["charge"]},
    })
    guardian = MCPGuardian(verbose=False, config=config)
    assert guardian.evaluate("lookup", {}, server_id="orders").allowed
    denied = guardian.evaluate("lookup", {}, server_id="billing")
    assert not denied.allowed
    assert denied.reason == "tool_not_in_allow_list"


def test_server_policy_cannot_override_global_deny_or_allow_constraints():
    config = GuardianConfig(
        allowed_tools={"lookup", "update"},
        denied_tools={"delete"},
        server_policies={"storage": {"allowed_tools": ["lookup", "delete", "export"]}},
    )
    guardian = MCPGuardian(verbose=False, config=config)
    assert guardian.evaluate("lookup", {}, server_id="storage").allowed
    assert guardian.evaluate("delete", {}, server_id="storage").reason == "tool_denied_by_policy"
    assert guardian.evaluate("export", {}, server_id="storage").reason == "tool_not_in_allow_list"


def test_caller_supplied_session_id_does_not_activate_allow_list():
    guardian = MCPGuardian(verbose=False, config=GuardianConfig(
        allow_list_sessions={"trusted-session"}, trusted_caller_ids={"verified-app-user"},
    ))
    untrusted = guardian.evaluate("lookup", {}, session_id="trusted-session")
    assert untrusted.reason != "allow_listed"
    trusted = guardian.evaluate("lookup", {}, session_id="trusted-session",
                                caller_id="verified-app-user")
    assert trusted.reason == "allow_listed"


def test_invoke_preserves_allowed_tool_result():
    guardian = MCPGuardian(verbose=False, config=GuardianConfig(allowed_tools={"lookup"}))
    context = ToolCallContext("lookup", {"value": 42})
    assert guardian.invoke(context, lambda value: {"value": value}) == {"value": 42}


def test_human_approval_is_context_bound_and_one_time():
    guardian = MCPGuardian(verbose=False, config=GuardianConfig(approval_required_tools={"delete"}))
    context = ToolCallContext("delete", {"path": "draft"}, "files", "session-1")
    assert guardian.evaluate("delete", context.arguments, context.session_id, context.server_id).outcome == Decision.CHALLENGE
    request = guardian.create_approval_request(context)
    token = guardian.approve_request(request.request_id, "authenticated-reviewer")
    wrong = ToolCallContext("delete", {"path": "other"}, "files", "session-1")
    assert guardian.evaluate("delete", wrong.arguments, wrong.session_id, wrong.server_id,
                            approval_token=token).outcome == Decision.CHALLENGE
    assert guardian.invoke(context, lambda path: path, approval_token=token) == "draft"
    with pytest.raises(ApprovalRequired):
        guardian.invoke(context, lambda path: path, approval_token=token)


def test_expired_approval_cannot_be_approved():
    guardian = MCPGuardian(verbose=False, config=GuardianConfig(
        approval_required_tools={"delete"}, approval_ttl_seconds=0.01,
    ))
    request = guardian.create_approval_request(ToolCallContext("delete", {}, "files", "s"))
    import time
    time.sleep(0.02)
    with pytest.raises(PolicyDenied):
        guardian.approve_request(request.request_id, "reviewer")


def test_audit_records_redact_session_and_tool_arguments(tmp_path):
    log = tmp_path / "events.jsonl"
    guardian = MCPGuardian(verbose=False, log_path=log,
                           config=GuardianConfig(enable_sqlite=False))
    guardian.check("secret-session-token", "lookup", arguments={"api_key": "secret-value"})
    content = log.read_text(encoding="utf-8")
    assert "secret-session-token" not in content
    assert "secret-value" not in content
    event = json.loads(content.splitlines()[-1])
    assert event["session_id"] != "secret-session-token"
    assert "arguments" not in event["evidence"]


def test_cli_validates_json_configuration(tmp_path, capsys):
    config_path = tmp_path / "guardian.json"
    config_path.write_text('{"allowed_tools": ["lookup"], "default_deny": true}', encoding="utf-8")
    assert guardian_cli(["validate-config", str(config_path)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
