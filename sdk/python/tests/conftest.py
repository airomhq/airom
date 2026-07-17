"""Test fixtures.

The suite runs against the REAL airom binary: a wrapper SDK that is only ever
tested against mocks proves nothing about the contract it wraps. The binary is
built from the checkout once per session.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def airom_binary(tmp_path_factory) -> str:
    """Build the airom binary from the checkout and return its path."""
    if shutil.which("go") is None:
        pytest.skip("the Go toolchain is required to build the airom binary")
    if not (REPO_ROOT / "go.mod").is_file():
        pytest.skip(f"no go.mod under {REPO_ROOT}")

    out = tmp_path_factory.mktemp("bin") / ("airom.exe" if sys.platform == "win32" else "airom")
    subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/airom"],
        cwd=REPO_ROOT,
        env={"CGO_ENABLED": "0", **_env()},
        check=True,
    )
    return str(out)


def _env() -> dict:
    import os

    return dict(os.environ)


@pytest.fixture
def ai_project(tmp_path: Path) -> Path:
    """A small tree with real, detectable AI assets."""
    (tmp_path / "app.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "resp = client.chat.completions.create(\n"
        '    model="gpt-4.1",\n'
        "    temperature=0.2,\n"
        ")\n"
    )
    (tmp_path / "requirements.txt").write_text(
        "openai==1.30.0\nlangchain==0.2.0\nchromadb==0.5.0\n"
    )
    (tmp_path / "package.json").write_text(
        '{"name":"x","dependencies":{"@anthropic-ai/sdk":"^0.24.3"}}'
    )
    return tmp_path
