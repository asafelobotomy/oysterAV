"""Chkrootkit / rkhunter / unhide runtime bundle installers."""

from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from oyst_core.runtime.checksums import require_checksum_for_key
from oyst_core.runtime.download import download_file
from oyst_core.runtime.manifest import record_artifact, runtime_bin_dir, runtime_root
from oyst_core.runtime.progress import ProgressCallback, emit_progress
from oyst_core.runtime.resolver import copy_system_tool, resolve_tool

CHKROOTKIT_TARBALL = (
    "https://deb.debian.org/debian/pool/main/c/chkrootkit/chkrootkit_0.58b.orig.tar.gz"
)
RKHUNTER_TARBALL = (
    "https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz"
)
UNHIDE_VERSION = "v20240510"
UNHIDE_TARBALL = f"https://codeload.github.com/YJesus/Unhide/tar.gz/refs/tags/{UNHIDE_VERSION}"


def install_chkrootkit_runtime(*, on_progress: ProgressCallback | None = None) -> dict[str, object]:
    existing = resolve_tool("chkrootkit")
    if existing.path and existing.source == "runtime":
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": "chkrootkit already in runtime"}
    emit_progress(on_progress, "install", 5)
    copied = copy_system_tool("chkrootkit")
    if copied:
        record_artifact("chkrootkit", copied, source="system-copy")
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": f"Linked chkrootkit from system to {copied}"}
    work = Path(tempfile.mkdtemp(prefix="oyst-chkrootkit-"))
    try:
        tarball = work / "chkrootkit.tar.gz"
        download_file(
            CHKROOTKIT_TARBALL,
            tarball,
            expected_sha256=require_checksum_for_key("chkrootkit"),
            on_progress=on_progress,
        )
        emit_progress(on_progress, "extract", 55)
        extract = work / "extract"
        extract.mkdir()
        with tarfile.open(tarball, "r:gz") as archive:
            archive.extractall(extract, filter="data")
        src_dirs = list(extract.glob("chkrootkit-*"))
        if not src_dirs:
            return {"ok": False, "message": "chkrootkit source not found"}
        dest = runtime_root() / "chkrootkit"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src_dirs[0], dest)
        emit_progress(on_progress, "build", 70)
        build = subprocess.run(
            ["make", "sense"],
            cwd=str(dest),
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if build.returncode != 0:
            return {
                "ok": False,
                "message": (build.stderr or build.stdout or "chkrootkit build failed")[:300],
            }
        bin_path = dest / "chkrootkit"
        if bin_path.is_file():
            link = runtime_bin_dir() / "chkrootkit"
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(bin_path)
            record_artifact("chkrootkit", bin_path, source=CHKROOTKIT_TARBALL)
            emit_progress(on_progress, "install", 100)
            return {"ok": True, "message": "Built chkrootkit runtime", "path": str(bin_path)}
        return {"ok": False, "message": "chkrootkit binary missing after build"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def install_rkhunter_runtime(*, on_progress: ProgressCallback | None = None) -> dict[str, object]:
    existing = resolve_tool("rkhunter")
    if existing.path and existing.source == "runtime":
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": "rkhunter already in runtime"}
    emit_progress(on_progress, "install", 5)
    copied = copy_system_tool("rkhunter")
    if copied:
        record_artifact("rkhunter", copied, source="system-copy")
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": f"Linked rkhunter from system to {copied}"}
    work = Path(tempfile.mkdtemp(prefix="oyst-rkhunter-"))
    try:
        tarball = work / "rkhunter.tar.gz"
        download_file(
            RKHUNTER_TARBALL,
            tarball,
            expected_sha256=require_checksum_for_key("rkhunter-1.4.6"),
            on_progress=on_progress,
        )
        emit_progress(on_progress, "extract", 55)
        extract = work / "extract"
        extract.mkdir()
        with tarfile.open(tarball, "r:gz") as archive:
            archive.extractall(extract, filter="data")
        src_dirs = list(extract.glob("rkhunter-*"))
        if not src_dirs:
            return {"ok": False, "message": "rkhunter source not found"}
        dest = runtime_root() / "rkhunter"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src_dirs[0], dest)
        emit_progress(on_progress, "build", 70)
        installer = dest / "installer.sh"
        if installer.is_file():
            install_res = subprocess.run(
                ["bash", str(installer), "--layout", "custom", str(dest / "install")],
                cwd=str(dest),
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            if install_res.returncode != 0:
                return {
                    "ok": False,
                    "message": (install_res.stderr or install_res.stdout or "installer failed")[
                        :300
                    ],
                }
        candidates = (
            list((dest / "install").rglob("rkhunter")) if (dest / "install").is_dir() else []
        )
        candidates.extend(dest.rglob("rkhunter"))
        for candidate in candidates:
            if candidate.is_file():
                link = runtime_bin_dir() / "rkhunter"
                if link.exists() or link.is_symlink():
                    link.unlink()
                link.symlink_to(candidate)
                record_artifact("rkhunter", candidate, source=RKHUNTER_TARBALL)
                emit_progress(on_progress, "install", 100)
                return {"ok": True, "message": "Installed rkhunter runtime", "path": str(candidate)}
        return {"ok": False, "message": "rkhunter binary not found after install"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def install_unhide_runtime(*, on_progress: ProgressCallback | None = None) -> dict[str, object]:
    existing = (
        resolve_tool("unhide-linux")
        if resolve_tool("unhide-linux").path
        else resolve_tool("unhide")
    )
    if existing.path and existing.source == "runtime":
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": "unhide already in runtime"}
    emit_progress(on_progress, "install", 5)
    for tool in ("unhide-linux", "unhide"):
        copied = copy_system_tool(tool)
        if copied:
            record_artifact("unhide", copied, source="system-copy")
            emit_progress(on_progress, "install", 100)
            return {"ok": True, "message": f"Linked {tool} from system"}
    work = Path(tempfile.mkdtemp(prefix="oyst-unhide-"))
    try:
        tarball = work / "unhide.tar.gz"
        download_file(
            UNHIDE_TARBALL,
            tarball,
            expected_sha256=require_checksum_for_key(f"unhide-{UNHIDE_VERSION}"),
            on_progress=on_progress,
        )
        emit_progress(on_progress, "extract", 55)
        extract = work / "extract"
        extract.mkdir()
        with tarfile.open(tarball, "r:gz") as archive:
            archive.extractall(extract, filter="data")
        src_dirs = list(extract.glob("unhide-*")) + list(extract.glob("Unhide-*"))
        if not src_dirs:
            return {"ok": False, "message": "unhide source not found in tarball"}
        dest = runtime_root() / "unhide"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src_dirs[0], dest)
        emit_progress(on_progress, "build", 70)
        build = subprocess.run(
            ["make"],
            cwd=str(dest),
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if build.returncode != 0:
            return {
                "ok": False,
                "message": (build.stderr or build.stdout or "unhide build failed")[:300],
            }
        for candidate in (dest / "unhide-linux", dest / "unhide"):
            if candidate.is_file():
                candidate.chmod(candidate.stat().st_mode | 0o111)
                link = runtime_bin_dir() / candidate.name
                if link.exists() or link.is_symlink():
                    link.unlink()
                link.symlink_to(candidate)
                record_artifact("unhide", candidate, version=UNHIDE_VERSION, source=UNHIDE_TARBALL)
                emit_progress(on_progress, "install", 100)
                return {"ok": True, "message": "Built unhide runtime", "path": str(candidate)}
        return {"ok": False, "message": "unhide binary not found after build"}
    finally:
        shutil.rmtree(work, ignore_errors=True)
