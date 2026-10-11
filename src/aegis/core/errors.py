"""Tool-level errors. Data problems (bad files, network trouble) are Notices, not errors."""

from __future__ import annotations


class AegisError(Exception):
    """Base class for failures that stop the run (CLI exit code 2)."""

    exit_code = 2


class UsageError(AegisError):
    """Invalid invocation, such as a scan path that does not exist."""


class ConfigError(AegisError):
    """Invalid or unreadable configuration file."""
