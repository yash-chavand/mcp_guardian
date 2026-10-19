# MCP Guardian

An experimental Python library for applying explicit policy checks and behavioral risk scoring to MCP tool calls.

## Install from this repository

The selected distribution name is `mcp-guardian-shield`. It was not registered on PyPI when checked on 2026-10-19, and this project has not been published. Install this checkout:

```bash
python -m pip install -e ".[dev,proxy]"
```

`ml` is an optional extra for Isolation Forest loading. Core policy checks need only NumPy. The HTTP proxy also requires the `proxy` extra.

## Protect a Python callable

```python
from mcp_guardian import Guardian, GuardianConfig, ToolCallContext

guardian = Guardian(config=GuardianConfig(
    allowed_tools={"lookup"},
    denied_tools={"delete_all"},
    max_argument_bytes=64_000,
))
context = ToolCallContext("lookup", {"record_id": "R-12"}, "orders", "demo")
result = guardian.invoke(context, lambda record_id: {"id": record_id})
```

An allowed call returns the original callable result. A blocked call raises `PolicyDenied` before execution. Only calls sent through the wrapper are protected; it does not intercept unrelated MCP connections.

For argument validation, configure `tool_schemas` with common JSON Schema fields: `type`, `required`, `properties`, `additionalProperties`, `maxLength`, `maxItems`, and `items`. This is a subset, not a full JSON Schema implementation.

## Multiple servers and approvals

`GuardianConfig.server_policies` accepts per-server allow/deny rules, schemas, and approval requirements. Session/caller IDs are correlation values, not authenticated identities.

Use `approval_required_tools` with `create_approval_request(context)`, then authenticate the human in the embedding app before calling `approve_request(request_id, approver_id)`. The returned token is bound to the tool, server, session and argument digest, expires, and can be used once with `invoke(..., approval_token=token)`.

## CLI

```bash
mcp-guardian-shield validate-config guardian.json
mcp-guardian-shield evaluate --config guardian.json --tool lookup --arguments '{"record_id":"R-12"}'
mcp-guardian-shield doctor
```

Configuration files are JSON. CLI output does not include raw tool arguments.

## Transports

- Python callable API: tested enforcement boundary.
- HTTP: experimental FastAPI forwarder with pre-execution checks, selected session/auth header forwarding, bounded request bodies, JSON responses and streamed non-JSON responses. MCP negotiation/session lifecycle/cancellation conformance is not established.
- stdio: experimental JSON-RPC line bridge with ID-based response multiplexing and call gating. MCP SDK interoperability and child failure/cancellation behavior need integration testing.
- `protect_server`: relies on private FastMCP internals and is version-sensitive.

See [transport compatibility](../docs/TRANSPORT_COMPATIBILITY.md), [threat model](../docs/THREAT_MODEL.md), and [limitations](../docs/LIMITATIONS.md). Do not treat model scores as authorization or a security guarantee.

## Tests and builds

```bash
python -m pytest tests -q
python -m build
```

The suite currently covers the Python API, deterministic rules, approvals, redaction and regressions. It does not yet establish MCP transport conformance or production security. See [implementation audit](../docs/IMPLEMENTATION_AUDIT.md).
