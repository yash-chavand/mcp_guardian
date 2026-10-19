# Test with AI agent clients

MCP Guardian is an MCP **server-side gateway**. An agent connects to the Guardian stdio process, and Guardian starts your existing stdio MCP server as its child. This lets you try the same tool backend from multiple MCP clients without changing the tool server. These adapters are experimental; see [transport compatibility](TRANSPORT_COMPATIBILITY.md) and verify each client/server version you use.

## 1. Install the checkout

From the repository root, create and activate a virtual environment, then install the proxy dependencies:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[proxy,ml,interop]"
```

The examples use the included official-SDK fixture server, which exposes harmless `read_public_note` and policy-blocked `delete_everything` tools. The sample policy uses `default_deny: true` and allows only `read_public_note`. Replace `C:/absolute/path/to/project` in the JSON files with the checkout's absolute path. The configs are Windows examples; on macOS/Linux use `.venv/bin/mcp-guardian-shield-stdio`, `.venv/bin/python`, and POSIX paths.

Each agent client launches a new stdio proxy process. Replace the example paths with absolute paths for your machine. The child environment is filtered; pass only required upstream environment variable names with `--pass-env NAME` and provide their values in the agent's server configuration.

## 2. Configure an agent

### Claude Desktop

Merge the `mcpServers` entry from [`claude_desktop.json`](../examples/agent_configs/claude_desktop.json) into Claude Desktop's MCP config. For Windows, use the absolute path to `.venv\\Scripts\\mcp-guardian-shield-stdio.exe`; use the platform-specific executable path elsewhere. Restart Claude Desktop and confirm that the test tools appear.

### Claude Code

Run this from the project directory, adjusting paths and server command:

```bash
claude mcp add --scope project guardian-shield --env MCP_GUARDIAN_TRACE_PATH=C:/absolute/path/to/project/.guardian_fixture_calls.jsonl -- .venv/Scripts/mcp-guardian-shield-stdio.exe --guardian-config examples/agent_configs/guardian-policy.json --pass-env MCP_GUARDIAN_TRACE_PATH -- .venv/Scripts/python.exe examples/mcp_sdk_fixture_server.py
```

On macOS/Linux, use `.venv/bin/mcp-guardian-shield-stdio`. Claude Code's MCP command syntax can vary by version; `claude mcp add --help` shows the installed CLI's options. Or merge [`claude_code.mcp.json`](../examples/agent_configs/claude_code.mcp.json) into the project `.mcp.json`.

### Cursor

Merge [`cursor.mcp.json`](../examples/agent_configs/cursor.mcp.json) into `.cursor/mcp.json` (workspace) or `~/.cursor/mcp.json` (user). Restart or refresh MCP servers in Cursor and confirm the Guardian server is connected.

### VS Code / GitHub Copilot

For the portable format, merge [`vscode.mcp.json`](../examples/agent_configs/vscode.mcp.json) into a workspace-root `.mcp.json`. This uses `mcpServers`, as does the GitHub Copilot portable configuration. VS Code's profile-specific `.vscode/mcp.json` instead uses a top-level `servers` object; use the VS Code MCP server editor to create that form if needed.

## 3. Exercise allow and deny behavior

1. Delete `.guardian_fixture_calls.jsonl` before each client run.
2. Ask the agent to call `read_public_note` with `note_id` set to `N-1`; confirm it returns a fixture response.
3. Ask it to call `delete_everything`; confirm the request is blocked.
4. Inspect `.guardian_fixture_calls.jsonl`: it must contain `read_public_note` only. This trace is written by the upstream fixture, so the missing delete entry shows the handler did not run.
5. Repeat in each client, recording client version, OS, MCP SDK version, observed outcome, and the trace file.

Do not rely on the agent's wording alone as evidence. The upstream handler trace is the check that the blocked operation did not execute. Tool-approval prompts shown by an agent client are a separate control from Guardian's human approval API. After the fixture works, replace the fixture command with your own disposable MCP server and add each server's required tool names to a copied policy file.

## 4. HTTP clients

For clients that accept a remote HTTP MCP endpoint, run `mcp-guardian-shield-proxy --upstream http://127.0.0.1:8100 --guardian-config examples/agent_configs/guardian-policy.json --port 8000` and point the client at `http://127.0.0.1:8000/mcp`. The HTTP adapter's initialize/session lifecycle and full Streamable HTTP behavior have not passed a protocol conformance suite; test with a disposable server before relying on it.

## Compatibility evidence

Configuration examples use current documented MCP config shapes: Claude Code's stdio `claude mcp add` flow, Cursor's `mcpServers` JSON, and VS Code's portable `.mcp.json` format. Configuration support does not establish successful runtime interoperability; run the steps above with each installed client. Official setup references: [Claude Code MCP](https://docs.anthropic.com/en/docs/claude-code/mcp), [Cursor MCP](https://docs.cursor.com/context/model-context-protocol), and [VS Code MCP servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers).
