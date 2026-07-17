"""Build hook: compile the ``airom`` binary into the wheel.

Wheels are platform-specific because they carry a compiled Go binary, so this
hook also stamps the wheel tag. It needs the Go toolchain and the repository
checkout (the module root is three levels up from this file).

Opt out with ``AIROM_SKIP_BUNDLE=1`` — the resulting wheel is pure-Python and
falls back to ``$AIROM_BINARY`` or ``airom`` on ``PATH`` at runtime.

Cross-compile by setting ``GOOS``/``GOARCH`` (both are forwarded to ``go
build``); set ``AIROM_WHEEL_TAG`` to override the platform tag when doing so.
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
BIN_DIR = HERE / "src" / "airom" / "_bin"


def _exe_name() -> str:
    goos = os.environ.get("GOOS") or sys.platform
    return "airom.exe" if goos in ("win32", "windows") else "airom"


def _wheel_tag() -> str:
    if tag := os.environ.get("AIROM_WHEEL_TAG"):
        return tag
    # Not pure-Python, but ABI-independent: the payload is a standalone binary,
    # so the wheel works on any CPython for this platform.
    plat = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    return f"py3-none-{plat}"


class AiromBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        if self.target_name != "wheel":
            return

        if os.environ.get("AIROM_SKIP_BUNDLE"):
            self.app.display_waiting("AIROM_SKIP_BUNDLE set — building a pure-Python wheel")
            return

        if not (REPO_ROOT / "go.mod").is_file():
            self.app.display_warning(
                f"no go.mod under {REPO_ROOT} — building without a bundled binary "
                "(the SDK will fall back to $AIROM_BINARY or PATH)"
            )
            return

        if shutil.which("go") is None:
            self.app.display_warning(
                "the Go toolchain was not found — building without a bundled binary "
                "(set AIROM_SKIP_BUNDLE=1 to silence this)"
            )
            return

        BIN_DIR.mkdir(parents=True, exist_ok=True)
        out = BIN_DIR / _exe_name()

        env = dict(os.environ)
        env["CGO_ENABLED"] = "0"  # invariant P8: the release binary is always static

        cmd = ["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", str(out), "./cmd/airom"]
        self.app.display_info(f"bundling airom: {' '.join(cmd)} (in {REPO_ROOT})")
        try:
            subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"failed to build the airom binary: {e}") from e

        out.chmod(0o755)
        build_data["pure_python"] = False
        build_data["tag"] = _wheel_tag()
        build_data["artifacts"].append("src/airom/_bin/*")
