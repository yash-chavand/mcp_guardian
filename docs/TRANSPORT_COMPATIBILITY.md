# Transport compatibility

| Adapter | Current behavior | Compatibility status |
|---|---|---|
| Python decorator / callable | Synchronous wrapper around a Python callable | Supported as an explicit callable boundary; does not protect bypass paths. |
| HTTP proxy | Prechecks `tools/call`; forwards auth/session headers; supports POST, GET, DELETE and streams non-JSON responses | Experimental; protocol-version negotiation, initialization lifecycle, session expiry, cancellation, backpressure and authentication policy are unverified. |
| stdio proxy | Newline-delimited JSON-RPC subprocess bridge; maps in-flight IDs, prechecks `tools/call`, forwards notifications, drains child stderr | One end-to-end test passed on Windows with the official Python MCP SDK 2.0.0 client and server: initialization, tools/list, allowed tools/call, denied call, and upstream invocation trace. Full conformance, cancellation, reconnect, and multiple-client compatibility remain unverified. |
| FastMCP `protect_server` | Wraps registered callables using internal registry access | Version-sensitive; not a general MCP SDK compatibility claim. |

The optional `interop` extra targets MCP Python SDK 2.x for this focused stdio test; this is not a compatibility guarantee for every SDK 2.x release or every MCP client. Run `RUN_MCP_INTEGRATION=1 python -m pytest tests/test_mcp_stdio_integration.py -q` (PowerShell: `$env:RUN_MCP_INTEGRATION='1'; python -m pytest tests/test_mcp_stdio_integration.py -q`). HTTP compatibility remains unverified.
