#!/usr/bin/env python3
"""Enforce the production Python 400-line hard limit (with growth ratchet).

Scope: oyst_core/, oyst_cli/, oysterav/ (*.py).
Tests and scripts are measured in audits but not gated here.

Rules:
  1. Any file over LIMIT that is not in the allowlist fails.
  2. Allowlisted files may stay over LIMIT but must not grow past their ceiling.
  3. Stale allowlist entries (missing file, or file now ≤ LIMIT) fail so debt shrinks.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = Path(__file__).resolve().parent / "loc_allowlist.json"
SCOPES = ("oyst_core", "oyst_cli", "oysterav")
LIMIT = 400


def count_lines(path: Path) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def iter_prod_py() -> list[Path]:
    files: list[Path] = []
    for scope in SCOPES:
        base = ROOT / scope
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            files.append(path)
    return files


def load_allowlist() -> dict[str, int]:
    raw = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    if int(raw.get("limit", LIMIT)) != LIMIT:
        raise SystemExit(
            f"allowlist limit {raw.get('limit')!r} != script LIMIT {LIMIT}",
        )
    files = raw.get("files")
    if not isinstance(files, dict):
        raise SystemExit("loc_allowlist.json: 'files' must be an object of path→max_lines")
    out: dict[str, int] = {}
    for path, ceiling in files.items():
        out[str(path)] = int(ceiling)
    return out


def build_allowlist_payload(files: list[Path]) -> dict[str, object]:
    over = {
        path.relative_to(ROOT).as_posix(): count_lines(path)
        for path in files
        if count_lines(path) > LIMIT
    }
    return {
        "limit": LIMIT,
        "comment": (
            "Grandfathered production files over the 400-line hard limit. "
            "Ceilings freeze growth; remove an entry once the file is ≤400."
        ),
        "files": dict(sorted(over.items(), key=lambda item: (-item[1], item[0]))),
    }


def check(allowlist: dict[str, int]) -> int:
    files = iter_prod_py()
    by_rel = {path.relative_to(ROOT).as_posix(): count_lines(path) for path in files}
    errors: list[str] = []

    for rel, ceiling in sorted(allowlist.items()):
        if rel not in by_rel:
            errors.append(f"stale allowlist entry (missing file): {rel}")
            continue
        lines = by_rel[rel]
        if lines <= LIMIT:
            errors.append(
                f"stale allowlist entry (now {lines} ≤ {LIMIT}, remove it): {rel}",
            )
        elif lines > ceiling:
            errors.append(
                f"allowlisted file grew {lines} > ceiling {ceiling}: {rel}",
            )

    for rel, lines in sorted(by_rel.items(), key=lambda item: (-item[1], item[0])):
        if lines <= LIMIT:
            continue
        if rel not in allowlist:
            errors.append(f"over {LIMIT}-line hard limit ({lines} lines): {rel}")

    if errors:
        print(f"LOC check FAILED ({len(errors)} issue(s); hard limit={LIMIT}):", file=sys.stderr)
        for msg in errors:
            print(f"  - {msg}", file=sys.stderr)
        print(
            "\nSplit oversized modules, or (only when intentional) raise a "
            f"ceiling in {ALLOWLIST_PATH.relative_to(ROOT)}.",
            file=sys.stderr,
        )
        return 1

    over = sum(1 for lines in by_rel.values() if lines > LIMIT)
    print(
        f"LOC check OK: {len(by_rel)} production files; "
        f"hard limit={LIMIT}; grandfathered over-limit={over}",
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-allowlist",
        action="store_true",
        help="Rewrite loc_allowlist.json from current over-limit files (ceilings=current LOC)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print over-limit and near-limit files, then exit 0",
    )
    args = parser.parse_args()
    files = iter_prod_py()

    if args.write_allowlist:
        payload = build_allowlist_payload(files)
        ALLOWLIST_PATH.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {ALLOWLIST_PATH.relative_to(ROOT)} ({len(payload['files'])} files)")
        return 0

    if args.report:
        measured = [(path.relative_to(ROOT).as_posix(), count_lines(path)) for path in files]
        measured.sort(key=lambda item: (-item[1], item[0]))
        over = [(p, n) for p, n in measured if n > LIMIT]
        near = [(p, n) for p, n in measured if LIMIT - 50 < n <= LIMIT]
        print(f"Hard limit: {LIMIT}")
        print(f"Production files: {len(measured)}")
        print(f"Over limit: {len(over)}")
        for path, lines in over:
            print(f"  {lines:5d}  {path}")
        print(f"Near limit (>{LIMIT - 50}): {len(near)}")
        for path, lines in near:
            print(f"  {lines:5d}  {path}")
        return 0

    return check(load_allowlist())


if __name__ == "__main__":
    raise SystemExit(main())
