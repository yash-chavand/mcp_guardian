# Security policy guidance

Use the deterministic bulk, wildcard, rate, and allow-list rules as signals and tune them to the actual tool contract. The current implementation does not provide a general per-tool authorization engine or JSON Schema enforcement. Add authorization in the tool implementation itself for sensitive operations, deny unknown operations, validate arguments against trusted schemas, constrain file/network/database access independently, and require a human-controlled approval path for high-impact actions. Do not use model scores or tool descriptions as authorization policy.
