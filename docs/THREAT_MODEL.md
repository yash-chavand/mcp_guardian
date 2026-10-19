# Threat model

## Assets

Tools may access files, databases, accounts, internal services, and user data. Guardian decision logs and model artifacts are also sensitive.

## Threats considered

Prompt injection and confused-deputy behavior may induce excessive reads, rapid calls, recipient changes, unknown destinations, or suspicious read-transform-send sequences. Malformed tool arguments may also cause unsafe behavior in the underlying tool.

## Trust boundaries and assumptions

Guardian protects only calls that pass through its enforcement hook. A process able to call the backend directly bypasses the controls. The current code does not authenticate session IDs, verify caller identity, guarantee distributed session consistency, validate every MCP message, or sandbox the tool process. Operators must protect the proxy endpoint and its dashboard, restrict backend reachability, and treat config/model files as trusted code/data.

## Out of scope

Guardian is not an OS sandbox, secrets manager, identity provider, network egress firewall, or proof that a tool's behavior matches its description. No anomaly score provides a security guarantee.
