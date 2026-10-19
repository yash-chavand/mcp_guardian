"""Operational CLI for validating config and evaluating a tool call."""

import argparse
import importlib.util
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .core.config import GuardianV2Config
from .guardian import MCPGuardian


def main(argv=None):
    parser = argparse.ArgumentParser(prog="mcp-guardian-shield")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check local runtime and model readiness")
    validate = commands.add_parser("validate-config", help="Validate a JSON Guardian configuration")
    validate.add_argument("config")
    evaluate = commands.add_parser("evaluate", help="Evaluate one JSON tool-call argument object")
    evaluate.add_argument("--config", required=True)
    evaluate.add_argument("--tool", required=True)
    evaluate.add_argument("--arguments", default="{}", help="Tool arguments as a JSON object")
    evaluate.add_argument("--session-id", default="cli-session")
    evaluate.add_argument("--server-id", default="primary-server")
    args = parser.parse_args(argv)

    if args.command == "doctor":
        try:
            model_file = Path(__file__).parent / "realtime_model.joblib"
            details = {
                "status": "ready",
                "version": __version__,
                "python": sys.version.split()[0],
                "numpy_available": importlib.util.find_spec("numpy") is not None,
                "proxy_dependencies_available": all(
                    importlib.util.find_spec(name) is not None for name in ("fastapi", "uvicorn", "httpx")
                ),
                "ml_dependencies_available": all(
                    importlib.util.find_spec(name) is not None for name in ("sklearn", "pandas", "joblib")
                ),
                "model_artifact_present": model_file.is_file(),
            }
            print(json.dumps(details, indent=2))
            return 0
        except Exception as exc:
            print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
            return 1
    if args.command == "validate-config":
        try:
            config = GuardianV2Config.from_file(args.config)
            print(json.dumps({"valid": True, "policy_version": config.policy_version}))
            return 0
        except (OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}), file=sys.stderr)
            return 2
    try:
        arguments = json.loads(args.arguments)
        if not isinstance(arguments, dict):
            raise ValueError("--arguments must decode to a JSON object")
        guardian = MCPGuardian.from_config(args.config, verbose=False)
        decision = guardian.evaluate(args.tool, arguments, args.session_id, args.server_id)
        print(json.dumps(asdict(decision), default=lambda item: item.value if hasattr(item, "value") else str(item), indent=2))
        return 0 if decision.allowed else 3
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
