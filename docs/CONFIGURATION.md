# Configuration

The current configuration object is `GuardianConfig` (`GuardianV2Config` internally). It exposes thresholds and detector toggles as Python dataclass fields. For example:

```python
from mcp_guardian import GuardianConfig, MCPGuardian

config = GuardianConfig(hard_block_bulk_threshold=10, sensitivity=1.0)
guardian = MCPGuardian(config=config, verbose=False)
```

The proxy accepts a JSON tool-risk profile (see `mcp_guardian/proxy/example_config.json`). The SDK's JSON configuration is not a complete policy schema. Do not put credentials in these files. Restrict file permissions and validate all configuration before starting a production process.

For the SDK, `allow_list_sessions` does not bypass checks through `Guardian.evaluate` unless the supplied caller is also present in `trusted_caller_ids`. Only the embedding application should set that caller ID after verifying its user/session. The lower-level legacy `check` method still honors session allow-lists for backward compatibility; do not expose it directly to untrusted callers.
