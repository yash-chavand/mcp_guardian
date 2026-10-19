# Integrations

## Python callable boundary

Install the project and wrap every protected callable:

```python
from mcp_guardian import MCPGuardian

guardian = MCPGuardian(verbose=False)

def lookup(records: int = 1):
    return {"records": records}

safe_lookup = guardian.protect()(lookup)
print(safe_lookup(records=1))
```

The wrapper preserves the function result on allow and returns a `blocked_by_guardian` mapping on block. It does not protect alternate references to `lookup`, direct backend connections, or tools registered after wrapping. For a raising interface, use `execute_protected`.

## HTTP proxy and stdio bridge

The repository provides `mcp-guardian-shield-proxy` and `mcp-guardian-shield-stdio`; their current protocol limitations are documented in [TRANSPORT_COMPATIBILITY.md](TRANSPORT_COMPATIBILITY.md). They must be treated as experimental and are not advertised as fully MCP-conformant integrations. HTTP route behavior is configured with `--upstream`; stdio takes an argv vector after `--`. `--guardian-config` loads deterministic allow/deny lists, argument schemas, and input limits; `--config` is the separate anomaly risk-profile file. Verify blocked calls using a backend-side invocation counter before any deployment.

No framework-wide compatibility is claimed. `protect_server` reaches some FastMCP internals and is version-sensitive.
