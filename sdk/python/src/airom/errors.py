"""Exceptions raised by the AIROM SDK."""

from __future__ import annotations

__all__ = ["AiromError", "BinaryNotFoundError", "ScanError", "OutputError"]


class AiromError(Exception):
    """Base class for every error raised by this package."""


class BinaryNotFoundError(AiromError):
    """The ``airom`` binary could not be located.

    The SDK looks, in order, for a binary bundled in the wheel, then the
    ``AIROM_BINARY`` environment variable, then ``airom`` on ``PATH``.
    """


class ScanError(AiromError):
    """A scan failed fatally (``airom`` exit code 2).

    Per the AIROM exit-code contract only *source acquisition* and
    configuration problems are fatal: an unreadable target, a clone failure, a
    bad flag. Detector errors degrade to :class:`~airom.models.Unknown` records
    and never raise.

    Attributes:
        exit_code: the process exit status (2).
        stderr: the tool's stderr, which carries the diagnostic.
    """

    def __init__(self, message: str, *, exit_code: int, stderr: str = "") -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class OutputError(AiromError):
    """``airom`` produced output the SDK could not parse.

    Raised when the native JSON document is missing, malformed, or carries a
    ``schemaVersion`` this SDK does not support.
    """
