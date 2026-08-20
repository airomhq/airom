"""Build hook: compile the ``airom`` binary into the wheel.

The binary is installed as a **script**, not as package data: hatchling places it
in ``<name>-<version>.data/scripts/``, which pip copies into the environment's
``bin/`` (``Scripts\\`` on Windows) and marks executable. So ``pip install airom``
gives you a real ``airom`` command on PATH — the actual Go binary, with no Python
shim and no interpreter startup — as well as the importable library.

Wheels are therefore platform-specific, and this hook stamps the wheel tag. It
needs the Go toolchain and the repository checkout (the module root is two levels
up from this file).

If the binary cannot be built, this hook FAILS rather than quietly producing a
wheel with no ``airom`` command. That case is reached by ``pip install airom``
on a platform with no prebuilt wheel: pip falls back to the sdist, which
carries no binary and cannot build one (it does not contain the Go module). A
warning there produced the worst possible outcome — an install that reports
success and leaves the user with no scanner, discovered later as
``airom: command not found``.

Opt out with ``AIROM_SKIP_BUNDLE=1`` to build the pure-Python wheel on purpose:
the SDK then falls back to ``$AIROM_BINARY`` or ``airom`` on ``PATH`` at
runtime, which is what someone who already installed the standalone binary and
only wants ``import airom`` actually wants.

Cross-compile by setting ``GOOS``/``GOARCH`` (both are forwarded to ``go build``);
set ``AIROM_WHEEL_TAG`` to override the platform tag when doing so.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

HERE = Path(__file__).parent
# sdk/python/hatch_build.py -> sdk/python -> sdk -> <repo root>
REPO_ROOT = HERE.parent.parent
# Staged outside the package: the binary ships as a script, not package data.
BUILD_DIR = HERE / "build" / "bin"


def _exe_name() -> str:
    goos = os.environ.get("GOOS") or sys.platform
    return "airom.exe" if goos in ("win32", "windows") else "airom"


def _git(*args: str) -> str:
    """Run a git command in the checkout, or return "" if it is unavailable.

    Building from an exported tarball (no .git) must still work, so a failure
    here is never fatal — the field just falls back to "unknown".
    """
    try:
        r = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        )
        return r.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return ""


def _wheel_tag() -> str:
    if tag := os.environ.get("AIROM_WHEEL_TAG"):
        return tag
    # Not pure-Python, but ABI-independent: the payload is a standalone binary,
    # so the wheel works on any CPython for this platform.
    plat = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    return f"py3-none-{plat}"



def _refuse(reason: str) -> None:
    """Fail the build rather than ship a wheel that installs no command.

    Raised at `pip install` time, so the message is what the user sees.
    """
    raise RuntimeError(
        f"airom: cannot build the scanner binary ({reason}), and a wheel without "
        "it installs no `airom` command.\n"
        "\n"
        "You are most likely installing from the sdist because this platform has "
        "no prebuilt wheel. The sdist ships the Python library only; it cannot "
        "build the scanner.\n"
        "\n"
        "  * To get the scanner: install the binary for your platform from\n"
        "    https://github.com/airomhq/airom/releases and put it on your PATH.\n"
        "  * To install the Python library alone (you already have the binary,\n"
        "    or you are building a pure-Python wheel on purpose):\n"
        "        AIROM_SKIP_BUNDLE=1 pip install airom\n"
    )


class AiromBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        if self.target_name != "wheel":
            return

        if os.environ.get("AIROM_SKIP_BUNDLE"):
            self.app.display_waiting("AIROM_SKIP_BUNDLE set — building a pure-Python wheel")
            return

        if not (REPO_ROOT / "go.mod").is_file():
            _refuse(f"no Go module under {REPO_ROOT}")

        if shutil.which("go") is None:
            _refuse("the Go toolchain was not found")

        BUILD_DIR.mkdir(parents=True, exist_ok=True)
        out = BUILD_DIR / _exe_name()

        env = dict(os.environ)
        env["CGO_ENABLED"] = "0"  # invariant P8: the release binary is always static

        # Stamp the version, exactly as the Makefile and goreleaser do. Without
        # this the binary reports "dev" — and since ToolInfo is embedded in every
        # AIBOM it produces, a pip-installed airom would emit documents whose
        # provenance claims tool.version "dev". The wheel and the binary are
        # released together, so the package version is the honest answer.
        #
        # NB: the `version` argument of initialize() is the BUILD TARGET version
        # ("standard"/"editable"), not the package version — that is
        # self.metadata.version.
        # Only stamp what we actually know. An sdist carries no .git, and
        # stamping a placeholder there would be worse than stamping nothing:
        # main.go treats the unset sentinels ("dev"/"none"/"unknown") as its cue
        # to recover the values from the Go build info, so a made-up "unknown"
        # commit suppresses the very fallback that exists to answer this case.
        ldflags = ["-s", "-w", f"-X main.version={self.metadata.version}"]
        if commit := _git("rev-parse", "--short", "HEAD"):
            ldflags.append(f"-X main.commit={commit}")
        if date := _git("show", "-s", "--format=%cI", "HEAD"):
            ldflags.append(f"-X main.date={date}")

        cmd = [
            "go", "build", "-trimpath",
            "-ldflags", " ".join(ldflags),
            "-o", str(out), "./cmd/airom",
        ]
        self.app.display_info(f"bundling airom: {' '.join(cmd)} (in {REPO_ROOT})")
        try:
            subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"failed to build the airom binary: {e}") from e

        out.chmod(0o755)
        build_data["pure_python"] = False
        build_data["tag"] = _wheel_tag()
        # -> <name>-<version>.data/scripts/airom -> the environment's bin/ dir.
        build_data["shared_scripts"] = {str(out): _exe_name()}
