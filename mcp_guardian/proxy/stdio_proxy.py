"""
MCP Guardian Stdio Proxy — Transparent JSON-RPC Stdio Interceptor for MCP Servers.

Designed for desktop AI agents (Claude Desktop, Cursor, Continue.dev, Zed).
Wraps any local MCP server subprocess and intercepts tools/call in real-time.
"""

import sys
import json
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any

from ..guardian import MCPGuardian
from ..core.config import GuardianV2Config
from .risk_profiles import RiskProfileRegistry


class StdioProxy:
    def __init__(
        self,
        command: List[str],
        config_path: Optional[str] = None,
        sensitivity: float = 1.0,
        guardian: Optional[MCPGuardian] = None
    ):
        self.command = command
        self.config = GuardianV2Config(sensitivity=sensitivity)
        self.guardian = guardian or MCPGuardian(verbose=False, config=self.config)
        self.registry = RiskProfileRegistry(config_path)
        self.process: Optional[asyncio.subprocess.Process] = None

    async def start(self):
        """Launch upstream subprocess and proxy bidirectional stdio."""
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        except Exception as e:
            sys.stderr.write(f"[MCP Guardian] Failed to spawn upstream command {self.command}: {e}\n")
            sys.stderr.flush()
            sys.exit(1)

        stderr_task = asyncio.create_task(self._forward_stderr())
        try:
            await self._handle_io_loop()
        finally:
            stderr_task.cancel()
            if self.process and self.process.returncode is None:
                try:
                    self.process.terminate()
                    await self.process.wait()
                except Exception:
                    pass

    async def _forward_stderr(self):
        """Stream upstream stderr directly to host stderr."""
        try:
            while True:
                line = await self.process.stderr.readline()
                if not line:
                    break
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def _handle_io_loop(self):
        """Read stdin from agent, evaluate, forward to upstream or block."""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line_bytes = await reader.readline()
            if not line_bytes:
                break

            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except Exception:
                self.process.stdin.write(line_bytes)
                await self.process.stdin.drain()
                resp = await self.process.stdout.readline()
                sys.stdout.buffer.write(resp)
                sys.stdout.buffer.flush()
                continue

            method = msg.get("method")
            req_id = msg.get("id")

            if method != "tools/call":
                self.process.stdin.write(line_bytes)
                await self.process.stdin.drain()

                if req_id is None:
                    continue

                resp_bytes = await self.process.stdout.readline()
                if method == "tools/list" and resp_bytes:
                    try:
                        resp_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
                        tools = resp_json.get("result", {}).get("tools", [])
                        self.registry.auto_discover_profiles(tools)
                        self.guardian.discovery.ingest_tools_list(tools)
                    except Exception:
                        pass

                sys.stdout.buffer.write(resp_bytes)
                sys.stdout.buffer.flush()
                continue

            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            session_id = arguments.get("session_id", "desktop-session")

            records, mismatch, is_email = self.registry.evaluate_call(tool_name, arguments)
            decision = self.guardian.check(
                session_id=session_id,
                tool_name=tool_name,
                records_this_call=records,
                recipient_mismatch=mismatch,
                is_email=is_email,
                arguments=arguments
            )

            if decision.get("blocked"):
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32001,
                        "message": f"Blocked by MCP Guardian: {decision.get('reason')}",
                        "data": {
                            "reason": decision.get("reason"),
                            "reasons": decision.get("reasons", []),
                            "risk_score": decision.get("risk_score", decision.get("anomaly_score", 0.9)),
                            "correlation_id": decision.get("correlation_id")
                        }
                    }
                }
                out = (json.dumps(error_resp) + "\n").encode("utf-8")
                sys.stdout.buffer.write(out)
                sys.stdout.buffer.flush()
            else:
                self.process.stdin.write(line_bytes)
                await self.process.stdin.drain()
                resp_bytes = await self.process.stdout.readline()

                if tool_name == "get_customer_order" and resp_bytes:
                    try:
                        resp_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
                        order_data = resp_json.get("result", {}).get("order", {})
                        if order_data:
                            self.guardian.entity_validator.bind_entity_from_lookup(session_id, order_data)
                    except Exception:
                        pass

                sys.stdout.buffer.write(resp_bytes)
                sys.stdout.buffer.flush()
