#!/usr/bin/env python3
"""Sync VERSION into pyproject.toml and package __version__ strings.

VERSION is the single source of truth for the application release version.
RUNTIME_VERSION in oyst_core.runtime.manifest is intentionally separate.

Usage:
  python scripts/sync_version.py          # write synced files
  python scripts/sync_version.py --check  # exit 1 on drift
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "VERSION"
PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_INITS = (
    ROOT / "oyst_core" / "__init__.py",
    ROOT / "oysterav" / "__init__.py",
)

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[a-zA-Z0-9.+\-]+)?$")


def read_version() -> str:
    text = VERSION_FILE.read_text(encoding="utf-8").strip()
    if not text or not VERSION_RE.match(text):
        raise SystemExit(f"Invalid VERSION in {VERSION_FILE}: {text!r}")
    return text


def _replace_pyproject(version: str, content: str) -> str:
    updated, n = re.subn(
        r'(?m)^version\s*=\s*"[^"]*"',
        f'version = "{version}"',
        content,
        count=1,
    )
    if n != 1:
        raise SystemExit('Could not find project version = "..." in pyproject.toml')
    return updated


def _replace_init(version: str, content: str) -> str:
    updated, n = re.subn(
        r'(?m)^__version__\s*=\s*"[^"]*"',
        f'__version__ = "{version}"',
        content,
        count=1,
    )
    if n != 1:
        raise SystemExit('Could not find __version__ = "..." in package init')
    return updated


def current_versions() -> dict[str, str]:
    py = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]*)"', py)
    if not m:
        raise SystemExit("pyproject.toml missing version")
    found: dict[str, str] = {"pyproject.toml": m.group(1)}
    for path in PACKAGE_INITS:
        text = path.read_text(encoding="utf-8")
        im = re.search(r'(?m)^__version__\s*=\s*"([^"]*)"', text)
        if not im:
            raise SystemExit(f"{path} missing __version__")
        found[str(path.relative_to(ROOT))] = im.group(1)
    return found


def sync(version: str) -> list[Path]:
    changed: list[Path] = []
    py_text = PYPROJECT.read_text(encoding="utf-8")
    new_py = _replace_pyproject(version, py_text)
    if new_py != py_text:
        PYPROJECT.write_text(new_py, encoding="utf-8")
        changed.append(PYPROJECT)
    for path in PACKAGE_INITS:
        text = path.read_text(encoding="utf-8")
        new_text = _replace_init(version, text)
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
            changed.append(path)
    return changed


def check(version: str) -> None:
    found = current_versions()
    drift = {k: v for k, v in found.items() if v != version}
    if drift:
        lines = [f"VERSION is {version}, but these differ:"]
        for k, v in drift.items():
            lines.append(f"  {k}: {v}")
        lines.append("Run: python scripts/sync_version.py")
        raise SystemExit("\n".join(lines))
    print(f"OK: version {version} is in sync")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify VERSION matches pyproject and package __version__ (no writes)",
    )
    args = parser.parse_args(argv)
    version = read_version()
    if args.check:
        check(version)
        return 0
    changed = sync(version)
    if changed:
        for path in changed:
            print(f"updated {path.relative_to(ROOT)}")
    else:
        print(f"already in sync: {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
