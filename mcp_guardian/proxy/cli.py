"""
Command-line entry point for the installed `mcp-guardian-shield-proxy` command.

After `pip install .` (or `pip install mcp-guardian-shield` once published), any
developer can run:

    mcp-guardian-shield-proxy --upstream http://localhost:8100 --config my_tools.json --port 8000

...to protect their existing MCP server with zero code changes to it.
"""

import argparse
import uvicorn

from mcp_guardian.proxy.proxy_server import app, configure


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-guardian-shield-proxy",
        description="Real-time anomaly detection reverse proxy for any MCP server.",
    )
    parser.add_argument("--upstream", required=True,
                         help="URL of your real MCP server, e.g. http://localhost:8100")
    parser.add_argument("--config", default=None,
                         help="Path to a tool risk-profile config JSON (see example_config.json)")
    parser.add_argument("--guardian-config", default=None,
                         help="Path to Guardian policy JSON (allow/deny, schemas, limits, approvals)")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the proxy on (default: 8000)")
    parser.add_argument("--sensitivity", type=float, default=1.0,
                         help="Detection sensitivity multiplier. >1 = stricter, <1 = looser (default: 1.0)")
    args = parser.parse_args()

    guardian_config = None
    if args.guardian_config:
        from mcp_guardian.core.config import GuardianV2Config
        guardian_config = GuardianV2Config.from_file(args.guardian_config)
    configure(args.upstream, args.config, args.sensitivity, guardian_config=guardian_config)
    print(f"\nMCP Guardian Proxy starting on port {args.port}")
    print(f"  Protecting upstream server at: {args.upstream}")
    print(f"  Point your AI agent at: http://localhost:{args.port}/mcp")
    print(f"  Live dashboard at:      http://localhost:{args.port}/guardian/dashboard\n")

    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
