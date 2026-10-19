# Architecture

`MCPGuardian.evaluate` applies static tool policy, argument limits, a supported subset of schema validation, and optional short-lived human approval before calling `MCPGuardian.check` for risk scoring. `check` combines deterministic rules, feature extraction, optional Isolation Forest scoring, session sequence and graph signals, semantic checks, and a decision engine. The Python `invoke`, `ainvoke`, decorator, and `execute_protected` APIs gate their target callable. The proxy modules provide separate HTTP and stdio entry points; their protocol limitations are listed in [LIMITATIONS.md](LIMITATIONS.md).

The stable API returns `SecurityDecision` from `evaluate`; `invoke` raises `PolicyDenied` or `ApprovalRequired` if execution is not permitted. The lower-level `check(...)` retains its legacy dictionary. `Guardian` and `GuardianConfig` are aliases exported from `mcp_guardian`.

The anomaly model is supplemental evidence, not a substitute for authorization. Policy, approval, and session state are process-local; the package does not establish caller identity or provide a distributed coordination service. Audit output hashes session and agent IDs using a per-process salt; this prevents raw ID logging but does not support cross-process correlation.
