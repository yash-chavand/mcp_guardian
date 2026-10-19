"""End-to-end stdio test using the installed MCP Python SDK, when available."""

import asyncio
import json
import os
from pathlib import Path
import sys

import pytest

mcp = pytest.importorskip("mcp", reason="install the optional MCP SDK to run transport integration tests")
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.integration
@pytest.mark.skipif(os.environ.get("RUN_MCP_INTEGRATION") != "1",
                    reason="set RUN_MCP_INTEGRATION=1 to run the subprocess MCP SDK test")
def test_stdio_bridge_with_official_mcp_sdk(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "default_deny": True,
        "allowed_tools": ["read_public_note"],
        "denied_tools": ["delete_everything"],
    }), encoding="utf-8")
    trace_path = tmp_path / "calls.jsonl"
    env = os.environ.copy()
    env["MCP_GUARDIAN_TRACE_PATH"] = str(trace_path)
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "mcp_guardian.proxy.stdio_cli",
            "--guardian-config", str(policy_path),
            "--pass-env", "MCP_GUARDIAN_TRACE_PATH",
            "--pass-env", "APPDATA",
            "--", sys.executable, str(ROOT / "examples" / "mcp_sdk_fixture_server.py"),
        ],
        env=env,
        cwd=str(ROOT),
    )

    async def exercise():
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == {"read_public_note", "delete_everything"}

                result = await session.call_tool("read_public_note", {"note_id": "N-1"})
                assert result.content and "fixture ran read_public_note" in result.content[0].text

                with pytest.raises(MCPError):
                    await session.call_tool("delete_everything", {})

    asyncio.run(asyncio.wait_for(exercise(), timeout=30))
    recorded = [json.loads(line)["tool"] for line in trace_path.read_text(encoding="utf-8").splitlines()]
    assert recorded == ["read_public_note"]
