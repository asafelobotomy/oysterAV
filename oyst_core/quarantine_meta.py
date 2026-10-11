"""Quarantine entry metadata: original mode/owner/mtime, restored safely.

Restore never widens access: setuid/setgid/sticky and group/other write bits
are always dropped (mask 0o755). Legacy or tampered metadata falls back to
0600. Ownership is recorded for display only; restore runs unprivileged.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import stat
from typing import Any

RESTORE_MODE_MASK = 0o755
LEGACY_RESTORE_MODE = 0o600


def capture_metadata(st: os.stat_result) -> str:
    """JSON metadata from the fstat of the (no-follow) opened source file."""
    return json.dumps(
        {
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "size": st.st_size,
            "mtime": st.st_mtime,
        }
    )


def read_metadata(conn: sqlite3.Connection, entry_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT metadata FROM entries WHERE id = ?", (entry_id,)).fetchone()
    if not row or not row[0]:
        return {}
    try:
        data = json.loads(row[0])
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def restore_mode(meta: dict[str, Any]) -> int:
    mode = meta.get("mode")
    if isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o7777:
        return LEGACY_RESTORE_MODE
    # Owner must keep read/write so the user can manage the restored file.
    return (mode & RESTORE_MODE_MASK) | 0o600


def apply_restored_metadata(dest_fd: int, meta: dict[str, Any]) -> None:
    """chmod (masked) and restore mtime on the freshly written restore fd."""
    os.fchmod(dest_fd, restore_mode(meta))
    mtime = meta.get("mtime")
    if isinstance(mtime, (int, float)) and not isinstance(mtime, bool) and mtime >= 0:
        with contextlib.suppress(OSError, OverflowError, ValueError):
            os.utime(dest_fd, (mtime, mtime))
