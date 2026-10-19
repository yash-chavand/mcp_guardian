"""Stable exceptions exposed by the MCP Guardian SDK."""


class GuardianError(Exception):
    """Base exception for Guardian failures."""


class ConfigurationError(GuardianError, ValueError):
    """Configuration is invalid or cannot be loaded."""


class PolicyDenied(GuardianError, PermissionError):
    """A protected tool call was denied by policy."""


class ApprovalRequired(PolicyDenied):
    """A tool call needs a valid, one-time human approval token."""


class ArgumentValidationError(GuardianError, ValueError):
    """Tool arguments violate configured structural or schema limits."""
