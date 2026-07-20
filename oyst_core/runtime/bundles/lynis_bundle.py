"""Lynis + maldet runtime bundle installers."""

from __future__ import annotations

import shutil
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
from oyst_core.runtime.resolver import resolve_tool

LYNIS_VERSION = "3.1.7"
LYNIS_TARBALL = f"https://codeload.github.com/CISOfy/lynis/tar.gz/refs/tags/{LYNIS_VERSION}"


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
