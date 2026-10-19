"""Tiny official-MCP-SDK server fixture used by the stdio integration test."""

import asyncio
import json
import os
from pathlib import Path

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server


def record_call(name: str) -> None:
    trace_path = os.environ.get("MCP_GUARDIAN_TRACE_PATH")
    if trace_path:
        Path(trace_path).parent.mkdir(parents=True, exist_ok=True)
        with open(trace_path, "a", encoding="utf-8") as trace:
            trace.write(json.dumps({"tool": name}) + "\n")


async def list_tools(_context, _params):
    return types.ListToolsResult(tools=[
        types.Tool(
            name="read_public_note",
            description="Read a harmless fixture note.",
            inputSchema={
                "type": "object",
                "properties": {"note_id": {"type": "string"}},
                "required": ["note_id"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="delete_everything",
            description="A fixture tool that must be blocked by policy.",
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        ),
    ])


async def call_tool(_context, params):
    record_call(params.name)
    return types.CallToolResult(content=[types.TextContent(text=f"fixture ran {params.name}")])


async def main():
    server = Server("guardian-sdk-fixture", version="1.0.0", on_list_tools=list_tools,
                    on_call_tool=call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
