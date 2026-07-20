"""Root-owned file writes that refuse symlink follow."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def write_text_nofollow(path: Path | str, text: str, *, mode: int = 0o644) -> None:
    """Write ``text`` to ``path`` without following symlinks (Linux O_NOFOLLOW)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
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
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
