"""Root-owned file writes that refuse symlink follow.

Writes are atomic: content goes to a temp file created inside the target's
parent directory (opened via an ``O_NOFOLLOW`` component walk) and is then
``os.replace``d over the target, so a crash never leaves a truncated polkit
rule or ``clamd.conf`` behind, and a FIFO/device/symlink target is refused
before anything is opened or truncated.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC
_TMP_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC


def _open_dir_nofollow(path: Path) -> int:
    """Open an absolute directory walking each component with O_NOFOLLOW.

    Fails (ELOOP/ENOTDIR) if any component is, or is swapped for, a symlink.
    """
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
    except BaseException:
        os.close(fd)
        raise
    return fd


def _existing_regular(dir_fd: int, name: str, target: Path) -> os.stat_result | None:
    """lstat ``name`` in ``dir_fd``: None when absent, else it must be a regular file."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"refusing non-regular file: {target}")
    return st


def _write_all(fd: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        written += os.write(fd, data[written:])


def write_text_nofollow(
    path: Path | str,
    text: str,
    *,
    mode: int = 0o644,
    preserve_mode: bool = False,
) -> None:
    """Atomically write ``text`` to ``path`` without following symlinks.

    When ``preserve_mode`` is True and ``path`` already exists as a regular
    file, keep its permission bits (``st_mode & 0o7777``) instead of ``mode``.
    New files still use ``mode``. An existing file's owner/group is kept.
    """
    target = Path(os.path.abspath(path))
    if not target.name:
        raise OSError(f"refusing to write a directory path: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    dir_fd = _open_dir_nofollow(target.parent)
    tmp_name = f".{target.name}.oysterav-{secrets.token_hex(8)}.tmp"
    try:
        existing = _existing_regular(dir_fd, target.name, target)
        final_mode = mode
        if preserve_mode and existing is not None:
            final_mode = existing.st_mode & 0o7777
        fd = os.open(tmp_name, _TMP_FLAGS, 0o600, dir_fd=dir_fd)
        try:
            _write_all(fd, text.encode("utf-8"))
            if existing is not None and (existing.st_uid, existing.st_gid) != (
                os.geteuid(),
                os.getegid(),
            ):
                try:
                    os.fchown(fd, existing.st_uid, existing.st_gid)
                except PermissionError:
                    if os.geteuid() == 0:
                        raise
            os.fchmod(fd, final_mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        # Re-check right before the swap: never replace a non-regular entry.
        _existing_regular(dir_fd, target.name, target)
        os.replace(tmp_name, target.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        tmp_name = ""
        os.fsync(dir_fd)
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
        os.close(dir_fd)
