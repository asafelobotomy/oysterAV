"""Decide whether an oyst-helper's embedded ``oyst_core`` site root is root-trusted.

A helper that does ``sys.path.insert(0, <dir>)`` executes whatever Python lives
in ``<dir>`` as root. That is only safe when no unprivileged user can change
``<dir>``, its package tree, or any ancestor directory (an owned ancestor allows
renaming the tree away and swapping in another).
"""

from __future__ import annotations

import ast
import os
import stat
from pathlib import Path

HELPER_PATH = Path("/usr/lib/oysterav/oyst-helper")


def _dir_is_root_locked(st: os.stat_result) -> bool:
    return st.st_uid == 0 and not (st.st_mode & 0o022)


def untrusted_site_reason(site_root: Path) -> str | None:
    """Return why ``site_root`` is unsafe to import as root, or None if it is safe."""
    try:
        resolved = site_root.resolve(strict=True)
    except OSError as exc:
        return f"cannot resolve {site_root}: {exc}"
    for ancestor in (resolved, *resolved.parents):
        try:
            st = ancestor.stat()
        except OSError as exc:
            return f"cannot stat {ancestor}: {exc}"
        if not _dir_is_root_locked(st):
            return f"{ancestor} is not root-owned or is group/world-writable"
    pkg = resolved / "oyst_core"
    for dirpath, dirnames, filenames in os.walk(pkg, followlinks=False):
        for name in (*dirnames, *filenames):
            entry = Path(dirpath) / name
            try:
                st = entry.lstat()
            except OSError as exc:
                return f"cannot stat {entry}: {exc}"
            if stat.S_ISLNK(st.st_mode):
                return f"{entry} is a symlink"
            if st.st_uid != 0 or st.st_mode & 0o022:
                return f"{entry} is not root-owned or is group/world-writable"
    return None


def parse_helper_site_root(text: str) -> str | None:
    """Extract the ``sys.path.insert(0, '<dir>')`` argument from a helper script."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("sys.path.insert("):
            continue
        try:
            call = ast.parse(stripped, mode="eval").body
        except SyntaxError:
            return ""
        if (
            isinstance(call, ast.Call)
            and len(call.args) == 2
            and isinstance(call.args[1], ast.Constant)
            and isinstance(call.args[1].value, str)
        ):
            return call.args[1].value
        return ""
    return None


def helper_untrusted_site_reason(helper: Path = HELPER_PATH) -> str | None:
    """Return why the installed helper's embedded site is untrusted, or None if fine.

    A helper without an embedded site root (distro install) is trusted here; an
    unparseable insert is treated as untrusted.
    """
    try:
        text = helper.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"cannot read {helper}: {exc}"
    site = parse_helper_site_root(text)
    if site is None:
        return None
    if not site:
        return f"{helper} has an unparseable sys.path insert"
    return untrusted_site_reason(Path(site))


__all__ = [
    "HELPER_PATH",
    "helper_untrusted_site_reason",
    "parse_helper_site_root",
    "untrusted_site_reason",
]
