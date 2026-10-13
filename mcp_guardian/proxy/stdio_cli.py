"""
CLI runner for mcp-guardian-stdio command.
Usage:
    mcp-guardian-stdio -- python server.py
    mcp-guardian-stdio --command "python server.py" --config my_tools.json
"""

import sys
import argparse
import asyncio
from typing import List

from .stdio_proxy import StdioProxy


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-guardian-stdio",
        description="Zero-code stdio anomaly detection gateway for MCP servers (Claude Desktop, Cursor)."
    )
    parser.add_argument("--config", default=None, help="Path to tool risk config JSON")
    parser.add_argument("--sensitivity", type=float, default=1.0, help="Detection sensitivity (default: 1.0)")
    parser.add_argument("--command", default=None, help="Command string to execute upstream server")
    parser.add_argument("cmd_args", nargs="*", help="Upstream command and arguments following --")

    args = parser.parse_args()

    command: List[str] = []
    if args.command:
        command = args.command.split()
    elif args.cmd_args:
        command = args.cmd_args

    if not command:
        sys.stderr.write("Error: No upstream command specified. Example: mcp-guardian-stdio -- python my_server.py\n")
        sys.exit(1)

    proxy = StdioProxy(
        command=command,
        config_path=args.config,
        sensitivity=args.sensitivity
    )
    asyncio.run(proxy.start())


if __name__ == "__main__":
    main()
