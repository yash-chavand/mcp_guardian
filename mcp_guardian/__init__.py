"""
MCP Guardian — Production-Grade Adaptive Security Gateway for Model Context Protocol (MCP).
"""

from .guardian import MCPGuardian, Guardian, protect_server
from .core.config import GuardianV2Config as GuardianConfig, RiskWeights
from .core.types import Decision, RiskLevel, SecurityDecision, ToolCallContext, ApprovalRequest
from .exceptions import GuardianError, ConfigurationError, PolicyDenied, ApprovalRequired, ArgumentValidationError

_lazy_default_guardian = None


def get_default_guardian() -> MCPGuardian:
    """Retrieve or lazily initialize the default MCPGuardian instance."""
    global _lazy_default_guardian
    if _lazy_default_guardian is None:
        _lazy_default_guardian = MCPGuardian(verbose=False)
    return _lazy_default_guardian


def protect(*args, **kwargs):
    """
    Convenience decorator for wrapping tool functions with default MCP Guardian.

    Usage:
        from mcp_guardian import protect

        @mcp.tool()
        @protect()
        def sensitive_tool(...):
            ...
    """
    return get_default_guardian().protect(*args, **kwargs)


__all__ = [
    "MCPGuardian",
    "Guardian",
    "GuardianConfig",
    "RiskWeights",
    "Decision",
    "RiskLevel",
    "SecurityDecision",
    "ToolCallContext",
    "ApprovalRequest",
    "GuardianError",
    "ConfigurationError",
    "PolicyDenied",
    "ApprovalRequired",
    "ArgumentValidationError",
    "protect",
    "protect_server",
    "get_default_guardian",
]

__version__ = "0.2.0"
