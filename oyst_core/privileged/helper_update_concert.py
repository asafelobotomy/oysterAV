"""Update-all concert: package upgrades + rkhunter update/propupd (one polkit prompt)."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import Any

from oyst_core.privileged.helper_clamd import _parse_flag, _parse_multi
from oyst_core.privileged.helper_setup_harden import _has_bool, _run_cmd, _step
from oyst_core.privileged.helper_validate import (
    _validate_package_name,
    _validate_run_argv,
    resolve_trusted_argv,
)


def _family_upgrade_argv(family: str, packages: list[str]) -> list[str]:
    pkgs = [_validate_package_name(p) for p in packages]
    if not pkgs:
        raise ValueError("no packages to upgrade")
    if family == "arch":
        return _validate_run_argv(["pacman", "-Sy", "--noconfirm", *pkgs])
    if family == "fedora":
        return _validate_run_argv(["dnf", "install", "-y", *pkgs])
    if family in ("debian", "ubuntu"):
        return _validate_run_argv(["apt-get", "install", "-y", *pkgs])
    raise ValueError(f"unsupported upgrade family: {family}")


def _upgrade_packages(argv: Sequence[str]) -> list[dict[str, Any]]:
    family = _parse_flag(argv, "family") or ""
    packages: list[str] = []
    for item in _parse_multi(argv, "upgrade"):
        packages.extend(p.strip() for p in item.split(",") if p.strip())
    if not packages:
        return []
    try:
        cmd = resolve_trusted_argv(_family_upgrade_argv(family, packages))
        rc, detail = _run_cmd(cmd)
        return [
            _step(
                "packages",
                ok=rc == 0,
                message=detail or ("upgraded" if rc == 0 else "failed"),
                soft_fail=rc != 0,
            ),
        ]
    except (OSError, ValueError) as exc:
        return [_step("packages", ok=False, message=str(exc), soft_fail=True)]


def _rkhunter_step(flag: str, step_id: str, argv_tail: list[str]) -> dict[str, Any]:
    try:
        cmd = resolve_trusted_argv(["rkhunter", *argv_tail])
        rc, detail = _run_cmd(cmd)
        ok = rc == 0
        return _step(
            step_id,
            ok=ok,
            message=detail or ("ok" if ok else f"exit {rc}"),
            soft_fail=not ok,
        )
    except (OSError, ValueError) as exc:
        return _step(step_id, ok=False, message=str(exc), soft_fail=True)


def run_update_concert(argv: Sequence[str]) -> int:
    """Execute elevated Update-all steps; print JSON ``{\"steps\": [...]}``."""
    steps: list[dict[str, Any]] = []
    steps.extend(_upgrade_packages(argv))
    if _has_bool(argv, "rkh-update"):
        steps.append(_rkhunter_step("rkh-update", "rkhunter-update", ["--update"]))
    if _has_bool(argv, "rkh-propupd"):
        steps.append(_rkhunter_step("rkh-propupd", "rkhunter-propupd", ["--propupd"]))
    if not steps:
        print("update-concert: no elevated steps requested", file=sys.stderr)
        return 2
    print(json.dumps({"steps": steps}, separators=(",", ":")))
    hard_fail = [s for s in steps if not s.get("ok") and not s.get("soft_fail")]
    return 1 if hard_fail else 0


__all__ = ["run_update_concert"]
