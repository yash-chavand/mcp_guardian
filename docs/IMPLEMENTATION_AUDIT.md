# Implementation audit

Audit performed against the repository at `8357125` (2026-10-19), before changes in this work session.

## Summary

This repository contains a research prototype and a partially productized gateway. It is not yet a production-ready reusable MCP security library. The local checkout originally supplied with the task was a different project, so this audit is against the linked repository cloned into `D:\aiagent\mcp_guardian`.

## Feature status

| Area | Status | Evidence and limitations |
|---|---|---|
| Deterministic policies | Implemented in the Python SDK; partial in transports | `Guardian.evaluate` supports allow/deny lists, default-deny, per-server tool lists, argument size/depth bounds, and a tested JSON Schema subset. The schema implementation is not full JSON Schema. |
| Isolation Forest | Implemented, unverified for production | `ml/isolation_forest.py` loads a pickle-based joblib model. The model artifact and its provenance must be trusted; compatibility and performance are not release-tested. |
| Session/sequence detection | Partially implemented | In-memory session history, sequence detector, graph and drift components exist. There is no shared state across replicas and no authenticated identity binding. |
| Explainable decisions | Implemented for SDK result | `SecurityDecision` includes ID, outcome, tool/server/session, risk score, matched rules, evidence, policy version, timestamp, and latency. Legacy result dictionaries remain for compatibility. |
| HTTP proxy | Partially implemented; protocol compatibility unverified | It checks `tools/call` before forwarding, preserves end-to-end/MCP headers, limits request size, supports GET/DELETE, buffers bounded JSON responses, and streams other responses. No MCP SDK transport abstraction or protocol conformance suite is present. |
| Stdio bridge | Partially implemented; narrow SDK round-trip verified | It multiplexes responses by JSON-RPC ID, gates tool calls, forwards notifications, bounds lines/pending requests, writes diagnostics to stderr, and filters the child environment. One local Python MCP SDK 2.0.0 round-trip passed on Windows; broad conformance and live desktop agent support remain unverified. |
| Python guard/decorator | Implemented for explicit callable boundary; partial for framework integration | `evaluate`, `invoke`, `ainvoke`, `protect`, and `execute_protected` gate SDK calls. `protect_server` still relies on private FastMCP internals. Alternate references and direct backend calls bypass wrappers. |
| Audit logging | Partially implemented with redaction improvements | Raw arguments are excluded from event evidence; persisted session and agent identifiers are process-salted hashes. In-memory session state retains arguments for detection. Retention/access controls remain deployment-specific. |
| Human approval | Partially implemented | Context-bound, short-lived, one-time approval tokens and pending/approve lifecycle are implemented and tested. The embedding app must authenticate approvers. |
| Evaluation | Synthetic pilot, no proven ML advantage | Independent session labels, deterministic seeded data, manifests, repeated-run baselines, and scenario-level metrics are implemented. The ML model loses to simple rules on the current simulator; real independent agent data, ablations, and external replication are still missing. |
| Multiple server policies | Implemented in SDK | `GuardianConfig.server_policies` can map server identities to separate tool lists/schemas/approval requirements. Caller identity is not authenticated by Guardian. |
| Configuration validation/CLI diagnostics | Partially implemented | JSON config validation and `doctor`, `validate-config`, and `evaluate` commands exist. Full schema validation, hot reload, and richer diagnostics are not implemented. |
| Packaging | Build verified | `pyproject.toml` separates core, `ml`, `proxy`, `dev`, and optional `interop` extras. Wheel/sdist built; wheel imported successfully from a temporary `--no-deps` target with distribution metadata and CLI entry points checked. A fresh dependency-isolated install is not verified. |
| Distribution name | Selected, not published | Metadata now uses `mcp-guardian-shield`; PyPI returned 404 for that project URL during a direct check on 2026-10-19. The name could be claimed before a release; no publication was performed. |
| MCP SDK compatibility | Narrowly tested | Optional `interop` extra targets Python MCP SDK 2.x; one stdio scenario is tested. No general client/server SDK or HTTP conformance claim is made. |

## Baseline verification

Before changes in this work session, `python -m pytest -q` reported **23 passed, 3 failed**. The wrapper and decision path fixes resolved those failures. The current focused suite reports **42 passed**; the optional end-to-end stdio test additionally passed with MCP Python SDK 2.0.0 on Windows. HTTP proxy and live desktop-agent interoperability remain unverified. The 30-seed synthetic run is documented in `RESEARCH_RESULTS.md`; its baselines show that this simulator does not establish an ML advantage.

## Release blockers

1. Verify HTTP forwarding against MCP SDK transport primitives and protocol conformance suites.
2. Extend stdio integration coverage for cancellation, reconnect, child failure, and additional supported clients.
3. Complete schema handling, protected approval audit events, failure-mode coverage, and retention controls.
4. Verify rules-only operation in a clean install and model artifact provenance.
5. Claim the selected PyPI name when ready, test clean wheel installation, pin supported MCP SDK versions, and publish only after security review.

This audit describes repository evidence, not an independent security certification.
