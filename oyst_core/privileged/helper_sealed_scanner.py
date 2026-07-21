"""Sealed execution of oysterAV runtime scanner binaries via oyst-helper."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from oyst_core.privileged.helper_validate import (
    _SHA256_HEX_RE,
    ALLOWED_SCANNER_BINARIES,
    _validate_scanner_argv,
)

_SEAL_DIR = Path("/var/lib/oysterav/sealed")
_RUNTIME_PATH_RE = re.compile(
    r"^.*/\.local/share/oysterav/runtime/[^/]+/(?:bin/)?(?P<name>[a-z0-9._+-]+)$"
)


def _secure_exec_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _open_nofollow_regular(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("sealed source must be a regular file")
        if st.st_mode & 0o002:
            raise ValueError("refuse world-writable sealed source")
    except Exception:
        os.close(fd)
        raise
    return fd


def _sha256_fd(fd: int) -> str:
    h = hashlib.sha256()
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def validate_sealed_source(path: str, basename: str, expected_sha256: str) -> Path:
    """Validate userspace path for sealed scanner exec."""
    base = os.path.basename(basename)
    if base not in ALLOWED_SCANNER_BINARIES:
        raise ValueError(f"sealed basename not allowed: {base}")
    if not _SHA256_HEX_RE.match(expected_sha256):
        raise ValueError("invalid sha256 for sealed source")
    src = Path(path)
    if src.is_symlink():
        raise ValueError("refuse sealed symlink source")
    text = str(src)
    match = _RUNTIME_PATH_RE.match(text)
    if not match or match.group("name") != base:
        raise ValueError("sealed source must be under oysterAV runtime for basename")
    return src


def seal_and_run_scanner(path: str, basename: str, expected_sha256: str, argv: list[str]) -> int:
    """Hash-verify runtime scanner, copy to root-owned seal dir, exec sealed copy."""
    src = validate_sealed_source(path, basename, expected_sha256)
    base = os.path.basename(basename)
    # Same argv allowlist as oyst-helper `run` (A-01).
    validated = _validate_scanner_argv(base, [base, *argv])
    argv_tail = validated[1:]
    fd = _open_nofollow_regular(src)
    try:
        digest = _sha256_fd(fd)
    finally:
        os.close(fd)
    if digest.lower() != expected_sha256.lower():
        print("sealed scanner sha256 mismatch", file=sys.stderr)
        return 2
    _SEAL_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(_SEAL_DIR, 0o700)
    sealed = _SEAL_DIR / os.path.basename(basename)
    if sealed.exists() or sealed.is_symlink():
        sealed.unlink()
    shutil.copy2(str(src), str(sealed), follow_symlinks=False)
    os.chmod(sealed, 0o700)
    os.chown(sealed, 0, 0)
    # Re-verify sealed copy
    sealed_fd = _open_nofollow_regular(sealed)
    try:
        sealed_digest = _sha256_fd(sealed_fd)
    finally:
        os.close(sealed_fd)
    if sealed_digest.lower() != expected_sha256.lower():
        sealed.unlink(missing_ok=True)
        print("sealed copy sha256 mismatch", file=sys.stderr)
        return 2
    proc = subprocess.run([str(sealed), *argv_tail], check=False, env=_secure_exec_env())
    return proc.returncode


__all__ = ["seal_and_run_scanner", "validate_sealed_source"]
