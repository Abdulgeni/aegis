"""Tool-level errors. Data problems (bad files, network trouble) are Notices, not errors.

All classes here map to CLI exit code 2. Subclasses exist only for programmatic
classification; callers should catch ``AegisError`` when they want the general case.
"""

from __future__ import annotations


class AegisError(Exception):
    """Base class for failures that stop the run (CLI exit code 2)."""

    exit_code = 2


class UsageError(AegisError):
    """Invalid invocation, such as an unknown flag combination or bad argument."""


class ConfigError(AegisError):
    """Invalid or unreadable configuration file."""


class InputError(AegisError):
    """A scan target is missing, unreadable, or cannot be resolved."""
