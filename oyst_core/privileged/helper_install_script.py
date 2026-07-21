"""Sealed maldet tarball extraction + install.sh execution for oyst-helper."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from oyst_core.privileged.helper_validate import (
    _SHA256_HEX_RE,
    resolve_trusted_binary,
)


def _secure_exec_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _tarball_path_ok(path: Path) -> None:
    name = path.name
    if not (name.endswith(".tar.gz") or name.endswith(".tgz")):
        raise ValueError("install-script requires a .tar.gz tarball")
    if not any(p.startswith("oyst-maldet-") for p in path.parts):
        raise ValueError("tarball must be under an oyst-maldet-* temp directory")
    under_tmp = False
    for root in (Path("/tmp").resolve(), Path("/var/tmp").resolve()):  # nosec B108
        try:
            path.relative_to(root)
            under_tmp = True
            break
        except ValueError:
            continue
    if not under_tmp:
        raise ValueError("tarball must be under /tmp or /var/tmp")


def open_maldet_tarball_fd(path: str, expected_sha256: str) -> int:
    """Open tarball with O_NOFOLLOW and verify SHA-256; return seekable fd."""
    if not _SHA256_HEX_RE.fullmatch(expected_sha256 or ""):
        raise ValueError("install-script requires a 64-char sha256 hex digest")
    tarball = Path(path).resolve()
    _tarball_path_ok(tarball)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(tarball), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("tarball must be a regular file")
        if st.st_mode & 0o002:
            raise ValueError("world-writable tarball refused")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        if digest.hexdigest() != expected_sha256.lower():
            raise ValueError("tarball sha256 mismatch")
        os.lseek(fd, 0, os.SEEK_SET)
    except Exception:
        os.close(fd)
        raise
    return fd


def seal_and_run_install_tarball(tarball_path: str, expected_sha256: str) -> int:
    """Re-verify tarball SHA, extract under root seal dir, run install.sh."""
    fd = open_maldet_tarball_fd(tarball_path, expected_sha256)
    os.close(fd)

    seal_dir = "/var/tmp" if Path("/var/tmp").is_dir() else None  # nosec B108
    seal_root = Path(tempfile.mkdtemp(prefix="oyst-seal-", dir=seal_dir))
    try:
        os.chmod(seal_root, 0o700)
        extract_dir = seal_root / "extract"
        extract_dir.mkdir()
        with tarfile.open(tarball_path, "r:gz") as archive:
            archive.extractall(extract_dir, filter="data")
        install_dirs = list(extract_dir.glob("maldetect-*"))
        if not install_dirs:
            print("maldetect directory not found in sealed tarball", file=sys.stderr)
            return 2
        sealed_script = install_dirs[0] / "install.sh"
        if not sealed_script.is_file() or sealed_script.is_symlink():
            print("install.sh missing in sealed extract", file=sys.stderr)
            return 2
        bash = resolve_trusted_binary("bash")
        proc = subprocess.run(
            [bash, str(sealed_script)],
            cwd=str(install_dirs[0]),
            check=False,
            env=_secure_exec_env(),
        )
        return proc.returncode
    finally:
        shutil.rmtree(seal_root, ignore_errors=True)


def seal_and_run_install_script(_script_path: str, _expected_sha256: str) -> int:
    """Legacy install.sh-only seal removed (A-02); use tarball path."""
    raise ValueError(
        "install-script requires a maldet tarball path and tarball sha256 "
        "(not install.sh); reinstall oysterAV / update callers",
    )


__all__ = [
    "open_maldet_tarball_fd",
    "seal_and_run_install_script",
    "seal_and_run_install_tarball",
]
