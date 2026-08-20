"""Verify an INSTALLED airom wheel actually works on this machine.

The packaging tests in sdk/python/tests inspect the wheel as a zip: they prove
the binary is in `.data/scripts/` and carries the right version stamp. They
cannot prove it runs, because they run on the machine that built it. Every
wheel except linux/amd64 is cross-compiled on an x86-64 Linux runner, so
until this script runs on the target platform, "the binary works there" is an
assumption.

Usage:  python smoke_wheel.py <bin-dir> <expected-version>

<bin-dir> is the venv's scripts directory, i.e. exactly where pip put the
`airom` command. Passing it explicitly rather than searching PATH is the
point: the claim under test is that `pip install airom` puts a working
command there.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Enough to exercise the real pipeline: walk, classify, run a manifest
# detector, assemble, and project into a writer.
FIXTURE = "openai==1.99.1\nlangchain==0.3.0\n"

# Offline and deterministic. The overlays are on by default and reach the
# network; a smoke test that fails when OSV.dev is slow tells you nothing
# about the wheel. Turning them off also proves the offline path works.
OFFLINE = ["--no-cve", "--no-eol", "--auto-update-rules=false"]


def fail(msg: str) -> None:
    sys.exit(f"smoke: {msg}")


def run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def main() -> None:
    if len(sys.argv) != 3:
        fail(f"usage: {sys.argv[0]} <bin-dir> <expected-version>")
    bindir, expected = Path(sys.argv[1]).resolve(), sys.argv[2]

    exe = bindir / ("airom.exe" if sys.platform == "win32" else "airom")
    if not exe.exists():
        listing = "\n  ".join(sorted(p.name for p in bindir.iterdir())) or "(empty)"
        fail(f"pip installed no `airom` command in {bindir}. Contents:\n  {listing}")

    # The binary must be the Go executable itself, not a Python launcher. A
    # `[project.scripts]` entry point would put a shim here instead, costing an
    # interpreter start on every invocation. Guard the design, not just the path.
    head = exe.open("rb").read(4)
    if head[:2] == b"#!":
        fail(f"{exe} is a script shim, not the compiled binary: {exe.open().readline()!r}")
    if head not in (b"\x7fELF", b"MZ\x90\x00") and head[:2] != b"MZ" and head[:4] not in (
        b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little-endian
        b"\xca\xfe\xba\xbe",  # Mach-O universal
    ):
        fail(f"{exe} has an unrecognised header {head!r}: not a native executable")

    # 1. It runs at all, on this OS and architecture.
    p = run([str(exe), "--version"])
    if p.returncode != 0:
        fail(f"`airom --version` exited {p.returncode}\n{p.stdout}{p.stderr}")
    print(f"  --version: {p.stdout.strip()}")

    # 2. It reports the version the wheel claims. A pip-installed airom stamps
    #    ToolInfo into every AIBOM it writes, so a wrong version here is a wrong
    #    provenance record in every document a user produces.
    if expected not in p.stdout:
        fail(f"`airom --version` says {p.stdout.strip()!r}, expected to contain {expected!r}")

    # 3. It completes a real scan and finds what is there.
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "requirements.txt").write_text(FIXTURE)
        p = run([str(exe), "scan", td, "-o", "json", *OFFLINE])
        if p.returncode != 0:
            fail(f"`airom scan` exited {p.returncode}\n{p.stdout}{p.stderr}")
        try:
            inv = json.loads(p.stdout)
        except json.JSONDecodeError as e:
            fail(f"`airom scan -o json` did not emit JSON: {e}\n{p.stdout[:400]}")

    found = {c["name"] for c in inv.get("components", [])}
    missing = {"openai", "langchain"} - found
    if missing:
        fail(f"scan missed {sorted(missing)}; found {sorted(found)}")
    print(f"  scan: found {sorted(found)}")

    tool = inv.get("tool", {})
    if expected not in str(tool.get("version", "")):
        fail(f"the AIBOM records tool.version {tool.get('version')!r}, expected {expected!r}")

    print(f"ok: {exe} works on {sys.platform}")


if __name__ == "__main__":
    main()
