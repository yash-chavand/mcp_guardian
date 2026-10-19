"""Inspect the structured decision returned by policy evaluation."""

from dataclasses import asdict
import json

from mcp_guardian import Guardian, GuardianConfig


guardian = Guardian(config=GuardianConfig(
    allowed_tools={"read_report"},
    tool_schemas={"read_report": {"type": "object", "required": ["report_id"]}},
), verbose=False)
decision = guardian.evaluate("read_report", {"report_id": "R-9"},
                             session_id="report-ui", server_id="reports")
print(json.dumps(asdict(decision), default=lambda value: value.value if hasattr(value, "value") else str(value),
                 indent=2))
