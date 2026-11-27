"""Typed domain and operational exceptions for the Financial AI Red Teaming Framework."""

from __future__ import annotations


class RedTeamError(Exception):
    """Base exception for all framework errors."""


class ConfigurationError(RedTeamError):
    """Raised when configuration or required fixture files are missing or malformed."""


class SchemaContractError(RedTeamError):
    """Raised when input or output data violates the versioned data contract."""


class UnsupportedInputError(RedTeamError):
    """Raised when an unsupported schema version, agent mode, tool, or provider is requested."""


class SafetyInvariantError(RedTeamError):
    """Raised when a non-synthetic secret or unsafe production-like identifier is detected."""
