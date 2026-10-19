"""Protect a Python callable at the point where the application invokes it."""

from mcp_guardian import Guardian, GuardianConfig, ToolCallContext


def lookup_customer(customer_id: str) -> dict[str, str]:
    return {"customer_id": customer_id, "name": "Example Customer"}


guardian = Guardian(config=GuardianConfig(
    allowed_tools={"lookup_customer"},
    denied_tools={"delete_customer"},
    tool_schemas={
        "lookup_customer": {
            "type": "object",
            "required": ["customer_id"],
            "properties": {"customer_id": {"type": "string", "maxLength": 64}},
            "additionalProperties": False,
        }
    },
), verbose=False)

context = ToolCallContext(
    tool_name="lookup_customer",
    arguments={"customer_id": "C-42"},
    server_id="customers",
    session_id="example-session",
)
print(guardian.invoke(context, lookup_customer))
