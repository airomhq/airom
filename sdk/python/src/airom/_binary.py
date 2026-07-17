"""Locating the ``airom`` binary."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .errors import BinaryNotFoundError

__all__ = ["find_binary", "BUNDLED_DIR"]

BUNDLED_DIR = Path(__file__).parent / "_bin"

_ENV_VAR = "AIROM_BINARY"


def _exe_name() -> str:
    return "airom.exe" if sys.platform == "win32" else "airom"


def _bundled() -> Path | None:
    p = BUNDLED_DIR / _exe_name()
    return p if p.is_file() else None


def find_binary(explicit: str | os.PathLike[str] | None = None) -> str:
    """Resolve the ``airom`` executable.

    Resolution order:

    1. ``explicit`` — the ``binary=`` argument, if given.
    2. The binary bundled in this wheel (``airom/_bin/airom``).
    3. ``$AIROM_BINARY``.
    4. ``airom`` on ``PATH``.

    Raises:
        BinaryNotFoundError: if no executable is found, with a message
            explaining every option.
    """
    if explicit is not None:
        p = Path(explicit)
        if not p.is_file():
            raise BinaryNotFoundError(f"binary={p!s}: no such file")
        return str(p)

    if (b := _bundled()) is not None:
        return str(b)

    if env := os.environ.get(_ENV_VAR):
        p = Path(env)
        if not p.is_file():
            raise BinaryNotFoundError(f"{_ENV_VAR}={env!r}: no such file")
        return str(p)

    if found := shutil.which("airom"):
        return found

    raise BinaryNotFoundError(
        "the 'airom' binary was not found. This wheel did not bundle one, and it is "
        "not on PATH.\n"
        "Fix it with any of:\n"
        "  • install a wheel that bundles the binary for your platform\n"
        "  • go install github.com/Roro1727/airom/cmd/airom@latest   "
        "(then ensure $(go env GOPATH)/bin is on PATH)\n"
        "  • download a release binary from https://github.com/Roro1727/airom/releases\n"
        f"  • point {_ENV_VAR} at an existing binary\n"
        "  • pass binary='/path/to/airom' to the scan call"
    )
