"""Non-ClamAV scanner runtime bundles."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from oyst_core.privileged.runner import which
from oyst_core.runtime.checksums import require_checksum_for_key
from oyst_core.runtime.download import download_file
from oyst_core.runtime.manifest import (
    record_artifact,
    runtime_bin_dir,
    runtime_maldet_prefix,
    runtime_root,
)
from oyst_core.runtime.progress import ProgressCallback, emit_progress
from oyst_core.runtime.resolver import copy_system_tool, resolve_tool

LYNIS_VERSION = "3.1.7"
LYNIS_TARBALL = f"https://codeload.github.com/CISOfy/lynis/tar.gz/refs/tags/{LYNIS_VERSION}"
# Upstream publishes over FTP only; integrity is enforced via in-repo SHA-256 pin.
CHKROOTKIT_TARBALL = "ftp://ftp.chkrootkit.org/pub/seg/pac/chkrootkit.tar.gz"
RKHUNTER_TARBALL = (
    "https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz"
)
UNHIDE_VERSION = "v20240510"
UNHIDE_TARBALL = f"https://codeload.github.com/YJesus/Unhide/tar.gz/refs/tags/{UNHIDE_VERSION}"


def _copy_system_lynis_tree() -> Path | None:
    """Copy distro lynis script plus include/db trees into the runtime."""
    lynis_bin = which("lynis")
    if not lynis_bin:
        return None
    include = Path("/usr/share/lynis/include")
    db = Path("/usr/share/lynis/db")
    if not include.is_dir() or not db.is_dir():
        return None
    dest_root = runtime_root() / "lynis"
    if dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True)
    dest_bin = dest_root / "lynis"
    shutil.copy2(lynis_bin, dest_bin)
    dest_bin.chmod(dest_bin.stat().st_mode | 0o111)
    shutil.copytree(include, dest_root / "include")
    shutil.copytree(db, dest_root / "db")
    return dest_bin


def install_lynis_runtime(*, on_progress: ProgressCallback | None = None) -> dict[str, object]:
    dest_root = runtime_root() / "lynis"
    if (dest_root / "lynis").is_file():
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": "lynis already installed", "path": str(dest_root)}
    existing = resolve_tool("lynis")
    if existing.path and existing.source == "runtime":
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": "lynis already in runtime"}
    emit_progress(on_progress, "install", 5)
    copied = _copy_system_lynis_tree()
    if copied:
        record_artifact("lynis", copied, source="system-copy")
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": f"Linked lynis from system to {copied}"}
    work = Path(tempfile.mkdtemp(prefix="oyst-lynis-"))
    try:
        tarball = work / "lynis.tar.gz"
        download_file(
            LYNIS_TARBALL,
            tarball,
            expected_sha256=require_checksum_for_key("lynis-3.1.7"),
            on_progress=on_progress,
        )
        emit_progress(on_progress, "extract", 70)
        extract = work / "extract"
        extract.mkdir()
        with tarfile.open(tarball, "r:gz") as archive:
            archive.extractall(extract, filter="data")
        src_dirs = list(extract.glob("lynis-*"))
        if not src_dirs:
            return {"ok": False, "message": "lynis source not found in tarball"}
        if dest_root.exists():
            shutil.rmtree(dest_root)
        shutil.copytree(src_dirs[0], dest_root)
        lynis_bin = dest_root / "lynis"
        lynis_bin.chmod(lynis_bin.stat().st_mode | 0o111)
        record_artifact("lynis", lynis_bin, version=LYNIS_VERSION, source=LYNIS_TARBALL)
        emit_progress(on_progress, "install", 100)
        return {"ok": True, "message": "Installed lynis runtime", "path": str(lynis_bin)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def install_maldet_runtime_tree(source_dir: Path) -> Path:
    """Install maldet from tarball extract into the private runtime prefix."""
    dest = runtime_maldet_prefix()
    files_dir = source_dir / "files"
    if not files_dir.is_dir():
        msg = f"maldet files/ directory missing in {source_dir}"
        raise FileNotFoundError(msg)

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    shutil.copytree(files_dir, dest, dirs_exist_ok=True)
    for subdir in ("clean", "pub", "quarantine", "sess", "sigs", "tmp"):
        (dest / subdir).mkdir(exist_ok=True)

    maldet_bin = dest / "maldet"
    if not maldet_bin.is_file():
        msg = f"maldet binary missing after staging files to {dest}"
        raise FileNotFoundError(msg)

    maldet_bin.chmod(maldet_bin.stat().st_mode | 0o111)
    _patch_maldet_runtime_paths(dest)

    link = runtime_bin_dir() / "maldet"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(maldet_bin.resolve())
    return dest


def _patch_maldet_runtime_paths(dest: Path) -> None:
    """Point upstream maldet scripts/config at the runtime install root."""
    inspath = str(dest)
    replacements = (
        "inspath='/usr/local/maldetect'",
        'inspath="/usr/local/maldetect"',
        "inspath=/usr/local/maldetect",
    )
    targets = [dest / "maldet", dest / "internals" / "internals.conf"]
    for target in targets:
        if not target.is_file():
            continue
        text = target.read_text(encoding="utf-8")
        for old in replacements:
            if old in text:
                if old.startswith("inspath='") or old.startswith('inspath="'):
                    quote = "'" if old.startswith("inspath='") else '"'
                    text = text.replace(old, f"inspath={quote}{inspath}{quote}")
                else:
                    text = text.replace(old, f"inspath={inspath}")
        target.write_text(text, encoding="utf-8")


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
        [str(pip), "install", "--upgrade", "pip", "fangfrisch"],
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
