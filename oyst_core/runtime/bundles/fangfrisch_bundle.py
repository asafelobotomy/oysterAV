"""Fangfrisch private-venv runtime installer."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from oyst_core.runtime.manifest import record_artifact, runtime_bin_dir, runtime_root
from oyst_core.runtime.progress import ProgressCallback, emit_progress


def install_fangfrisch_runtime(*, on_progress: ProgressCallback | None = None) -> dict[str, object]:
    """Install fangfrisch into a private venv under the runtime root."""
    dest_root = runtime_root() / "fangfrisch"
    bin_link = runtime_bin_dir() / "fangfrisch"
    venv_bin = dest_root / "bin" / "fangfrisch"
    if venv_bin.is_file() and os.access(venv_bin, os.X_OK):
        _ensure_fangfrisch_link(venv_bin, bin_link)
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": "fangfrisch already installed", "path": str(venv_bin)}

    emit_progress(on_progress, "venv", 10)
    if dest_root.exists():
        shutil.rmtree(dest_root)
    create = subprocess.run(
        [sys.executable, "-m", "venv", str(dest_root)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if create.returncode != 0:
        return {
            "ok": False,
            "message": (create.stderr or create.stdout or "venv creation failed")[:400],
        }

    pip = dest_root / "bin" / "pip"
    if not pip.is_file():
        return {"ok": False, "message": "pip missing after venv creation"}

    emit_progress(on_progress, "pip", 40)
    install = subprocess.run(
        [str(pip), "install", "--disable-pip-version-check", "fangfrisch==1.9.2"],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if install.returncode != 0 or not venv_bin.is_file():
        detail = (install.stderr or install.stdout or "pip install fangfrisch failed").strip()
        return {"ok": False, "message": detail[:500]}

    _ensure_fangfrisch_link(venv_bin, bin_link)
    record_artifact("fangfrisch", dest_root, source="pip-venv")
    emit_progress(on_progress, "install", 100)
    return {
        "ok": True,
        "message": f"Installed fangfrisch to private runtime ({dest_root})",
        "path": str(venv_bin),
    }


def _ensure_fangfrisch_link(venv_bin: Path, bin_link: Path) -> None:
    if bin_link.exists() or bin_link.is_symlink():
        bin_link.unlink()
    bin_link.symlink_to(venv_bin)
    if not os.access(venv_bin, os.X_OK):
        venv_bin.chmod(venv_bin.stat().st_mode | 0o111)
