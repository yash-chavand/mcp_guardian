# Current limitations

MCP Guardian 0.2.0 is an experimental security gateway. It is not a security boundary unless every tool call is forced through a supported, tested adapter.

- HTTP forwarding preserves selected headers and streams non-JSON responses, but initialization negotiation, session lifecycle, cancellation, backpressure, and authentication policy are not verified against the MCP SDK.
- The stdio bridge maps in-flight JSON-RPC IDs and gates `tools/call`, but it has no real-client protocol conformance run; request timeout behavior, shutdown under cancellation, and platform support remain unverified.
- `protect_server` depends on private FastMCP internals for one integration path. The generic callable decorator only protects invocations routed through the wrapped function.
- Tool schema validation covers common JSON Schema fields only and is not a complete JSON Schema implementation. Tool descriptions must never be treated as trusted access controls.
- Session state is process-local. Session IDs supplied by callers are not authenticated identities.
- The model is trained on simulated traffic. Model output can have false positives and false negatives, and loading joblib files can execute code; only load trusted artifacts.
- Persistent storage and dashboard APIs need deployment-specific access controls, retention settings and redaction review.
- Approver authentication is delegated to the embedding application. Shared approval state, distributed multi-replica policy state, failure-resistant configuration reload, and validated non-Python framework adapters are not implemented.

Use explicit deterministic allow/deny policies at the actual tool execution boundary for security-critical workloads. Reassess these limitations against the exact version and deployment before relying on the gateway.
