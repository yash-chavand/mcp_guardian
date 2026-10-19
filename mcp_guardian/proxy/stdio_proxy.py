"""JSON-RPC stdio bridge that gates MCP tool calls before forwarding them."""

import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional

from ..guardian import MCPGuardian
from ..core.config import GuardianV2Config
from ..proxy.risk_profiles import RiskProfileRegistry


class StdioProxy:
    """Subprocess stdio proxy for MCP's newline-delimited JSON-RPC transport.

    Child environment is intentionally restricted. Pass additional variable
    names through ``pass_env`` when the server explicitly needs credentials.
    The command is always executed as an argv vector, never through a shell.
    """

    SAFE_ENV = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT", "COMSPEC", "HOME", "USERPROFILE")

    def __init__(self, command: List[str], config_path: Optional[str] = None,
                 sensitivity: float = 1.0, guardian: Optional[MCPGuardian] = None,
                 pass_env: Optional[List[str]] = None, request_timeout: float = 60.0,
                 max_pending: int = 10000, guardian_config_path: Optional[str] = None):
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError("command must be a non-empty argv list")
        self.command = command
        self.config = (GuardianV2Config.from_file(guardian_config_path)
                       if guardian_config_path else GuardianV2Config(sensitivity=sensitivity))
        self.guardian = guardian or MCPGuardian(verbose=False, config=self.config)
        self.registry = RiskProfileRegistry(config_path)
        self.process: Optional[asyncio.subprocess.Process] = None
        self.pass_env = tuple(pass_env or ())
        self.request_timeout = request_timeout
        self.max_pending = max_pending
        self.pending: Dict[str, Dict[str, Any]] = {}
        self._output_lock = asyncio.Lock()

    def _child_environment(self) -> Dict[str, str]:
        names = set(self.SAFE_ENV) | set(self.pass_env)
        return {k: v for k, v in os.environ.items() if k in names}

    async def start(self):
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._child_environment(),
                limit=1024 * 1024,
            )
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Could not start MCP upstream process: {exc}") from exc

        stderr_task = asyncio.create_task(self._forward_stderr())
        input_task = asyncio.create_task(self._read_client())
        output_task = asyncio.create_task(self._read_upstream())
        try:
            done, _ = await asyncio.wait(
                {input_task, output_task}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                exc = task.exception()
                if exc:
                    raise exc
            if input_task in done:
                if self.process.stdin and not self.process.stdin.is_closing():
                    self.process.stdin.close()
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=self.request_timeout)
                except asyncio.TimeoutError:
                    self.process.terminate()
                    try:
                        await asyncio.wait_for(self.process.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        self.process.kill()
                        await self.process.wait()
            else:
                raise RuntimeError(f"MCP upstream exited unexpectedly (code {self.process.returncode})")
        finally:
            for task in (input_task, output_task):
                if not task.done():
                    task.cancel()
            stderr_task.cancel()
            if self.process and self.process.returncode is None:
                self.process.terminate()
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    self.process.kill()
                    await self.process.wait()
            await asyncio.gather(input_task, output_task, stderr_task, return_exceptions=True)

    async def _emit(self, payload: bytes):
        async with self._output_lock:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()

    async def _write_upstream(self, payload: bytes):
        if not self.process or not self.process.stdin or self.process.stdin.is_closing():
            raise RuntimeError("MCP upstream stdin is closed")
        self.process.stdin.write(payload)
        await asyncio.wait_for(self.process.stdin.drain(), timeout=self.request_timeout)

    @staticmethod
    def _id_key(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

    async def _read_client(self):
        while True:
            line = await asyncio.to_thread(sys.stdin.buffer.readline)
            if not line:
                return
            if len(line) > 1024 * 1024:
                await self._emit(self._error(None, -32600, "Message exceeds 1 MiB"))
                continue
            try:
                message = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                await self._emit(self._error(None, -32700, "Parse error"))
                continue
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                await self._emit(self._error(None, -32600, "Invalid Request"))
                continue
            method = message.get("method")
            request_id = message.get("id")
            key = self._id_key(request_id) if request_id is not None else None
            if key is not None and (isinstance(request_id, (dict, list, bool)) or
                                    (isinstance(request_id, float) and not request_id.is_integer())):
                await self._emit(self._error(None, -32600, "Invalid request id"))
                continue
            if key is not None and key in self.pending:
                await self._emit(self._error(request_id, -32600, "Duplicate in-flight request id"))
                continue
            if method == "tools/call":
                params = message.get("params")
                if not isinstance(params, dict) or not isinstance(params.get("name"), str) or not isinstance(params.get("arguments", {}), dict):
                    if request_id is not None:
                        await self._emit(self._error(request_id, -32602, "Invalid tools/call params"))
                    continue
                tool_name = params["name"]
                arguments = params.get("arguments", {})
                records, mismatch, is_email = self.registry.evaluate_call(tool_name, arguments)
                decision = self.guardian.evaluate(
                    tool_name, arguments, session_id="stdio-bridge",
                    records_this_call=records, recipient_mismatch=mismatch, is_email=is_email,
                )
                if not decision.allowed:
                    if request_id is not None:
                        await self._emit(self._error(request_id, -32001, "Blocked by MCP Guardian",
                            {"reason": decision.reason, "matched_rules": decision.matched_rules,
                             "risk_score": decision.risk_score, "decision_id": decision.decision_id}))
                    continue
            if request_id is not None:
                if len(self.pending) >= self.max_pending:
                    await self._emit(self._error(request_id, -32000, "Too many in-flight requests"))
                    continue
                self.pending[key] = {"method": method, "tool_name": (message.get("params") or {}).get("name") if isinstance(message.get("params"), dict) else None}
            await self._write_upstream(line if line.endswith(b"\n") else line + b"\n")

    @staticmethod
    def _error(request_id: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> bytes:
        error: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return (json.dumps({"jsonrpc": "2.0", "id": request_id, "error": error}, separators=(",", ":")) + "\n").encode()

    async def _read_upstream(self):
        while self.process and self.process.stdout:
            line = await self.process.stdout.readline()
            if not line:
                return
            try:
                response = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Never leak malformed child output onto the protocol stdout.
                sys.stderr.write("[MCP Guardian] Discarded invalid upstream JSON-RPC line\n")
                continue
            request_id = response.get("id") if isinstance(response, dict) else None
            metadata = self.pending.pop(self._id_key(request_id), None) if request_id is not None else None
            if metadata and metadata.get("method") == "tools/list":
                tools = response.get("result", {}).get("tools", []) if isinstance(response, dict) else []
                if isinstance(tools, list):
                    self.registry.auto_discover_profiles(tools)
                    self.guardian.discovery.ingest_tools_list(tools)
            await self._emit(line if line.endswith(b"\n") else line + b"\n")

    async def _forward_stderr(self):
        try:
            while self.process and self.process.stderr:
                line = await self.process.stderr.readline()
                if not line:
                    return
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()
        except asyncio.CancelledError:
            raise
