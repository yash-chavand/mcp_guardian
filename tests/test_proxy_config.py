import json

from mcp_guardian.proxy.stdio_proxy import StdioProxy


def test_stdio_proxy_loads_guardian_policy_file(tmp_path):
    policy = tmp_path / "guardian-policy.json"
    policy.write_text(json.dumps({
        "default_deny": True,
        "allowed_tools": ["read_public_note"],
        "max_argument_bytes": 4096,
    }), encoding="utf-8")

    proxy = StdioProxy(
        command=["python", "server.py"],
        guardian_config_path=str(policy),
    )

    assert proxy.guardian.config.default_deny is True
    assert proxy.guardian.config.allowed_tools == {"read_public_note"}
    assert proxy.guardian.config.max_argument_bytes == 4096
