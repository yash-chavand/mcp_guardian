# Changelog

## 0.2.0

- Initial public prototype with anomaly scoring, Python guard, experimental HTTP and stdio proxies, and synthetic evaluation scripts.

## Unreleased

- Added an implementation audit and explicit architecture, threat, transport, and limitation documentation.
- Added stable `SecurityDecision`/`ToolCallContext` types, `evaluate`/`invoke`/`ainvoke` APIs, argument limits, per-server policies, a basic JSON Schema subset, and a short-lived one-time approval flow.
- Redacted raw arguments and process-salted session/agent identifiers from persisted and regular audit output.
- Fixed model-score fusion behavior and bulk-argument inference in Python tool wrappers.
- Reworked stdio to track in-flight JSON-RPC IDs, gate calls, forward notifications, bound message/pending limits, and filter child environment variables.
- Improved HTTP forwarding with pre-execution checks, MCP/auth header preservation, request size bounds, GET/DELETE, and streaming for non-JSON responses.
- Added a Guardian CLI, optional `ml`/`proxy` dependencies, CI checks, and a reproducible local SDK overhead benchmark.
- Selected the unregistered `mcp-guardian-shield` distribution name and added agent-client configuration examples plus a Guardian policy config option for both proxy launchers.
