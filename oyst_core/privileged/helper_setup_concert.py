"""Single-auth setup concert: packs + propupd + harden + linger (one polkit prompt)."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import Any

from oyst_core.privileged.helper_clamd import _parse_flag, _parse_multi
from oyst_core.privileged.helper_install_script import seal_and_run_install_tarball
from oyst_core.privileged.helper_setup_harden import (
    _has_bool,
    _run_cmd,
    _step,
    collect_harden_steps,
)
from oyst_core.privileged.helper_validate import (
    _validate_package_name,
    _validate_run_argv,
    _validate_username,
    resolve_trusted_argv,
)


def _family_install_argv(family: str, packages: list[str]) -> list[str]:
    pkgs = [_validate_package_name(p) for p in packages]
    if not pkgs:
        raise ValueError("no packages to install")
    if family == "arch":
        return _validate_run_argv(["pacman", "-Sy", "--noconfirm", *pkgs])
    if family == "fedora":
        return _validate_run_argv(["dnf", "install", "-y", *pkgs])
    if family in ("debian", "ubuntu"):
        return _validate_run_argv(["apt-get", "install", "-y", *pkgs])
    raise ValueError(f"unsupported install family: {family}")


def _install_official_packs(argv: Sequence[str]) -> list[dict[str, Any]]:
    family = _parse_flag(argv, "family") or ""
    steps: list[dict[str, Any]] = []
    for item in _parse_multi(argv, "install"):
        # packname:pkg1,pkg2
        name, _, pkgs_raw = item.partition(":")
        name = name.strip()
        packages = [p.strip() for p in pkgs_raw.split(",") if p.strip()]
        if not name or not packages:
            steps.append(
                _step(
                    f"install-{name or 'unknown'}",
                    ok=False,
                    message="invalid --install=pack:pkg,...",
                    soft_fail=True,
                ),
            )
            continue
        try:
            cmd = resolve_trusted_argv(_family_install_argv(family, packages))
            rc, detail = _run_cmd(cmd)
            steps.append(
                _step(
                    f"install-{name}",
                    ok=rc == 0,
                    message=detail or ("installed" if rc == 0 else "failed"),
                    soft_fail=rc != 0,
                ),
            )
        except (OSError, ValueError) as exc:
            steps.append(
                _step(f"install-{name}", ok=False, message=str(exc), soft_fail=True),
            )
    return steps


def _install_maldet(argv: Sequence[str]) -> list[dict[str, Any]]:
    tarball = _parse_flag(argv, "maldet-tarball")
    sha = _parse_flag(argv, "maldet-sha")
    # Legacy flags (pre-A-02) — reject explicitly.
    if _parse_flag(argv, "maldet-script"):
        return [
            _step(
                "install-maldet",
                ok=False,
                message="maldet-script is removed; use --maldet-tarball= and --maldet-sha=",
                soft_fail=True,
            ),
        ]
    if not tarball and not sha:
        return []
    if not tarball or not sha:
        return [
            _step(
                "install-maldet",
                ok=False,
                message="maldet requires --maldet-tarball= and --maldet-sha=",
                soft_fail=True,
            ),
        ]
    try:
        rc = seal_and_run_install_tarball(tarball, sha)
        return [
            _step(
                "install-maldet",
                ok=rc == 0,
                message="maldet installed" if rc == 0 else "maldet install failed",
                soft_fail=rc != 0,
            ),
        ]
    except (OSError, ValueError) as exc:
        return [_step("install-maldet", ok=False, message=str(exc), soft_fail=True)]


def _propupd(argv: Sequence[str]) -> list[dict[str, Any]]:
    if not _has_bool(argv, "propupd"):
        return []
    try:
        cmd = resolve_trusted_argv(_validate_run_argv(["rkhunter", "--propupd"]))
        rc, detail = _run_cmd(cmd)
        return [
            _step(
                "rkhunter-propupd",
                ok=rc == 0,
                message=(detail or ("ok" if rc == 0 else "failed"))[:200],
                soft_fail=rc != 0,
            ),
        ]
    except (OSError, ValueError) as exc:
        return [_step("rkhunter-propupd", ok=False, message=str(exc), soft_fail=True)]


def _linger(argv: Sequence[str]) -> list[dict[str, Any]]:
    user = _parse_flag(argv, "linger-user")
    if not user:
        return []
    try:
        validated = _validate_username(user)
        cmd = resolve_trusted_argv(
            _validate_run_argv(["loginctl", "enable-linger", validated]),
        )
        rc, detail = _run_cmd(cmd)
        return [
            _step(
                "linger",
                ok=rc == 0,
                message=detail or ("linger enabled" if rc == 0 else "failed"),
                soft_fail=rc != 0,
            ),
        ]
    except (OSError, ValueError) as exc:
        return [_step("linger", ok=False, message=str(exc), soft_fail=True)]


def run_setup_concert(argv: Sequence[str]) -> int:
    """Run pack install + propupd + harden + linger; print JSON steps."""
    steps: list[dict[str, Any]] = []
    try:
        steps.extend(_install_official_packs(argv))
        steps.extend(_install_maldet(argv))
        steps.extend(_propupd(argv))
        steps.extend(collect_harden_steps(argv))
        steps.extend(_linger(argv))
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        print(json.dumps({"steps": steps, "error": str(exc)}))
        return 2
    print(json.dumps({"steps": steps}))
    return 0


__all__ = ["run_setup_concert"]
