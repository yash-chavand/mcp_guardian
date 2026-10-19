"""Demonstrate an application-mediated, context-bound approval token."""

from mcp_guardian import Guardian, GuardianConfig, ToolCallContext


guardian = Guardian(config=GuardianConfig(
    allowed_tools={"send_payment"},
    approval_required_tools={"send_payment"},
), verbose=False)
context = ToolCallContext(
    "send_payment", {"amount": 25, "currency": "USD"},
    server_id="payments", session_id="checkout-17", caller_id="app-user-8",
)

# The host application should show the request to its authenticated approver.
request = guardian.create_approval_request(context)
print("Pending approval:", request.request_id, request.tool_name, request.expires_at)

# This call must happen only after the host application authenticates the human.
token = guardian.approve_request(request.request_id, approver_id="authenticated-approver-2")
receipt = guardian.invoke(context, lambda amount, currency: {"sent": amount, "currency": currency},
                          approval_token=token)
print(receipt)
