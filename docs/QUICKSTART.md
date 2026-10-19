# Quickstart

## Install from this checkout

The distribution name selected for this project is `mcp-guardian-shield`. It was not registered on PyPI when checked on 2026-10-19; publishing has not happened. For now, install this checkout directly:

```bash
python -m pip install -e ".[dev,proxy]"
```

Add `,ml` to the extra list to enable the shipped Isolation Forest (`.[dev,proxy,ml]`). Core policy enforcement runs without pandas, joblib, or scikit-learn. The proxy extra is required for the HTTP CLI.

## Protected Python call

```python
from mcp_guardian import Guardian, GuardianConfig, ToolCallContext

guardian = Guardian(config=GuardianConfig(
    allowed_tools={"lookup"},
    denied_tools={"delete_all"},
    max_argument_bytes=64_000,
))
context = ToolCallContext("lookup", {"record_id": "R-12"}, "orders", "demo")
result = guardian.invoke(context, lambda record_id: {"id": record_id})
print(result)
```

Allowed calls preserve the function result. Denials raise `PolicyDenied` before the callable runs. This only guards invocations routed through the wrapper.

## Configuration and CLI

Guardian configuration is JSON. Example `guardian.json`:

```json
{
  "allowed_tools": ["lookup"],
  "denied_tools": ["delete_all"],
  "default_deny": true,
  "tool_schemas": {
    "lookup": {
      "type": "object",
      "required": ["record_id"],
      "properties": {"record_id": {"type": "string", "maxLength": 100}},
      "additionalProperties": false
    }
  }
}
```

```bash
mcp-guardian-shield validate-config guardian.json
mcp-guardian-shield evaluate --config guardian.json --tool lookup --arguments '{"record_id":"R-12"}'
mcp-guardian-shield doctor
```

The validator implements common JSON Schema object/type/required/additional-property/string-length/array-item checks; it is not a complete JSON Schema implementation.

## Human approval

Configure `approval_required_tools`. Call `create_approval_request(context)`, show the request to an authenticated human, then call `approve_request(request_id, approver_id)` only after authorization. Pass the returned one-time token to `invoke`. Guardian does not authenticate the approver; the embedding application must do that.

## Transport entry points

Install the `proxy` extra. HTTP startup: `mcp-guardian-shield-proxy --upstream http://127.0.0.1:8100 --guardian-config guardian.json --port 8000`. Stdio startup: `mcp-guardian-shield-stdio --guardian-config guardian.json -- python server.py`; explicitly pass child environment names with repeated `--pass-env NAME` options. Both adapters' limitations are documented in [transport compatibility](TRANSPORT_COMPATIBILITY.md).

## Test with agent clients

Use the stdio bridge to wrap an existing local MCP server. Add the command to Claude Desktop, Claude Code, Cursor, or VS Code using the client-specific examples in [agent testing](AGENT_TESTING.md). Configure `guardian.json` with `default_deny: true` and an explicit `allowed_tools` list to see blocked calls fail before they reach the upstream server. Use a disposable test server and verify its call counter when trying deny rules.
