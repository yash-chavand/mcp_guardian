"""Apply separate tool policies to two server identities."""

from mcp_guardian import Guardian, GuardianConfig


guardian = Guardian(config=GuardianConfig(
    default_deny=True,
    server_policies={
        "catalog": {"allowed_tools": ["search", "get_item"]},
        "billing": {"allowed_tools": ["get_invoice"], "denied_tools": ["refund"]},
    },
), verbose=False)

for server_id, tool_name in (("catalog", "search"), ("billing", "refund")):
    decision = guardian.evaluate(tool_name, {}, session_id="example", server_id=server_id)
    print(server_id, tool_name, decision.outcome.value, decision.reason)
