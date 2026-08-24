"""Root-owned file writes that refuse symlink follow."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def write_text_nofollow(
    path: Path | str,
    text: str,
    *,
    mode: int = 0o644,
    preserve_mode: bool = False,
) -> None:
    """Write ``text`` to ``path`` without following symlinks (Linux O_NOFOLLOW).

    When ``preserve_mode`` is True and ``path`` already exists as a regular
    file, keep its permission bits (``st_mode & 0o7777``) instead of ``mode``.
    New files still use ``mode``.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    final_mode = mode
    if preserve_mode:
        try:
            existing = os.lstat(str(target))
            if stat.S_ISREG(existing.st_mode) and not stat.S_ISLNK(existing.st_mode):
                final_mode = existing.st_mode & 0o7777
        except OSError:
            pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(target), flags, mode)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"refusing non-regular file: {target}")
        data = text.encode("utf-8")
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        os.fchmod(fd, final_mode)
    finally:
        os.close(fd)
