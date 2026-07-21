"""Single-auth first-run harden steps for oyst-helper (shared by setup-harden/concert)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from typing import Any

from oyst_core.packs.firewall import FirewallPack
from oyst_core.packs.firewall_ops import FirewallOps
from oyst_core.packs.rkhunter_disable_tests import apply_disable_tests_overlay
from oyst_core.privileged.helper_clamd import (
    _ensure_disable_cache,
    _ensure_virusevent,
    _parse_flag,
    _parse_multi,
    _validate_conf_path,
    _validate_wrapper_cmd,
)
from oyst_core.privileged.helper_clamd_unit import ensure_fdpass_dropin, restart_clam_stack
from oyst_core.privileged.helper_firewall import _build_firewalld_argv, _build_ufw_argv
from oyst_core.privileged.helper_services import _build_systemctl_argv
from oyst_core.privileged.helper_validate import resolve_trusted_argv
from oyst_core.privileged.validators import validate_unit


def _secure_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _has_bool(argv: Sequence[str], name: str) -> bool:
    return f"--{name}" in argv


def _step(
    name: str,
    *,
    ok: bool,
    message: str = "",
    skipped: bool = False,
    soft_fail: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {"step": name, "ok": ok}
    if message:
        out["message"] = message
    if skipped:
        out["skipped"] = True
    if soft_fail and not ok and not skipped:
        out["soft_fail"] = True
    return out


def _run_cmd(cmd: list[str]) -> tuple[int, str]:
    resolved = resolve_trusted_argv(cmd)
    proc = subprocess.run(
        resolved,
        check=False,
        capture_output=True,
        text=True,
        env=_secure_env(),
    )
    detail = (proc.stderr or proc.stdout or "").strip()
    return proc.returncode, detail


def _ufw_status_text() -> str:
    rc, out = _run_cmd(["ufw", "status", "verbose"])
    if rc == 0 and out:
        return out
    _, numbered = _run_cmd(["ufw", "status", "numbered"])
    return numbered


def _firewalld_ssh_ok() -> bool:
    rc, out = _run_cmd(["firewall-cmd", "--list-all"])
    if rc != 0:
        rc, out = _run_cmd(["firewall-cmd", "--list-services"])
    text = (out or "").lower()
    return "ssh" in text or "22/tcp" in text or "22:tcp" in text


def ensure_firewall_as_root(*, force_lockout: bool = False) -> dict[str, Any]:
    """SSH-safe UFW/firewalld enable (already root; no nested pkexec)."""
    det = FirewallPack().detect()
    if det.get("conflict"):
        return _step(
            "firewall-ensure",
            ok=False,
            message="Multiple firewall managers active; resolve UFW vs firewalld first",
            soft_fail=True,
        )
    active = str(det.get("active", "none"))
    if active in ("ufw", "firewalld"):
        return _step(
            "firewall-ensure",
            ok=True,
            skipped=True,
            message=f"{active} already active",
        )
    if det.get("ufw"):
        return _ensure_ufw(force_lockout=force_lockout)
    if det.get("firewalld"):
        return _ensure_firewalld(force_lockout=force_lockout)
    return _step(
        "firewall-ensure",
        ok=True,
        skipped=True,
        message="no UFW or firewalld binary installed",
    )


def _ensure_ufw(*, force_lockout: bool) -> dict[str, Any]:
    before = _ufw_status_text()
    ssh_ok = FirewallOps.parse_ssh_open(before)
    if not ssh_ok and not force_lockout:
        cmd = _build_ufw_argv(["allow", "--port", "22", "--proto", "tcp"])
        rc, detail = _run_cmd(cmd)
        if rc != 0:
            return _step(
                "firewall-ensure",
                ok=False,
                message=f"could not add SSH allow before enable: {detail}",
                soft_fail=True,
            )
        ssh_ok = FirewallOps.parse_ssh_open(_ufw_status_text())
    if not ssh_ok and not force_lockout:
        return _step(
            "firewall-ensure",
            ok=False,
            message="SSH allow rule not detected; use --force-lockout-risk to proceed",
            soft_fail=True,
        )
    rc, detail = _run_cmd(_build_ufw_argv(["enable"]))
    if rc != 0:
        return _step(
            "firewall-ensure",
            ok=False,
            message=detail or "ufw enable failed",
            soft_fail=True,
        )
    return _step("firewall-ensure", ok=True, message="ufw enabled")


def _ensure_firewalld(*, force_lockout: bool) -> dict[str, Any]:
    rc, detail = _run_cmd(_build_systemctl_argv(["enable-now", "firewalld"]))
    if rc != 0:
        return _step(
            "firewall-ensure",
            ok=False,
            message=detail or "firewalld enable failed",
            soft_fail=True,
        )
    if not force_lockout:
        cmd = _build_firewalld_argv(["add-service", "ssh", "--zone", "public"])
        rc, detail = _run_cmd(cmd)
        if rc != 0 and not _firewalld_ssh_ok():
            return _step(
                "firewall-ensure",
                ok=False,
                message=(
                    "firewalld started but SSH service not confirmed; "
                    "use --force-lockout-risk to proceed"
                ),
                soft_fail=True,
            )
        _run_cmd(_build_firewalld_argv(["reload"]))
        if not _firewalld_ssh_ok():
            return _step(
                "firewall-ensure",
                ok=False,
                message="SSH allow not detected after enabling firewalld",
                soft_fail=True,
            )
    return _step("firewall-ensure", ok=True, message="firewalld enabled")


def collect_harden_steps(argv: Sequence[str]) -> list[dict[str, Any]]:
    """Apply harden flags as root; return step dicts (no JSON print)."""
    steps: list[dict[str, Any]] = []
    need_restart = False
    clamd_enable = _parse_flag(argv, "clamd-enable")
    fdpass_unit = _parse_flag(argv, "fdpass-unit")
    ve_conf = _parse_flag(argv, "ve-conf")
    ve_cmd = _parse_flag(argv, "ve-cmd")
    dc_conf = _parse_flag(argv, "dc-conf")
    rkh_raw = _parse_flag(argv, "rkh-tests")
    do_rkh = _has_bool(argv, "rkh") or rkh_raw is not None
    with_firewall = _has_bool(argv, "with-firewall")
    force_lockout = _has_bool(argv, "force-lockout")
    clamd_unit = _parse_flag(argv, "clamd-unit")
    clamonacc_unit = _parse_flag(argv, "clamonacc-unit")
    sockets = _parse_multi(argv, "socket") or None

    if clamd_enable:
        try:
            unit = validate_unit(clamd_enable)
            rc, detail = _run_cmd(_build_systemctl_argv(["enable-now", unit]))
            steps.append(
                _step(
                    "harden-clamd",
                    ok=rc == 0,
                    message=detail or ("ok" if rc == 0 else "failed"),
                    soft_fail=rc != 0,
                ),
            )
        except ValueError as exc:
            steps.append(_step("harden-clamd", ok=False, message=str(exc), soft_fail=True))

    if fdpass_unit:
        try:
            ensure_fdpass_dropin(fdpass_unit)
            steps.append(
                _step("harden-fdpass", ok=True, message=f"fdpass ensured for {fdpass_unit}"),
            )
        except (OSError, ValueError) as exc:
            steps.append(_step("harden-fdpass", ok=False, message=str(exc), soft_fail=True))

    if ve_conf and ve_cmd:
        try:
            conf = _validate_conf_path(ve_conf)
            cmd = _validate_wrapper_cmd(ve_cmd)
            _ensure_virusevent(conf, cmd)
            need_restart = True
            steps.append(_step("harden-virusevent", ok=True, message="VirusEvent ensured"))
        except (OSError, ValueError) as exc:
            steps.append(
                _step("harden-virusevent", ok=False, message=str(exc), soft_fail=True),
            )

    if dc_conf:
        try:
            conf = _validate_conf_path(dc_conf)
            _ensure_disable_cache(conf)
            need_restart = True
            steps.append(_step("harden-disable-cache", ok=True, message="DisableCache yes"))
        except (OSError, ValueError) as exc:
            steps.append(
                _step("harden-disable-cache", ok=False, message=str(exc), soft_fail=True),
            )

    if need_restart:
        try:
            restart_clam_stack(clamd_unit, clamonacc_unit, sockets=sockets)
        except (OSError, ValueError) as exc:
            steps.append(
                _step("harden-restart-stack", ok=False, message=str(exc), soft_fail=True),
            )

    if do_rkh:
        try:
            tests = [t for t in (rkh_raw or "").split(",") if t.strip()]
            result = apply_disable_tests_overlay(tests)
            steps.append(
                _step(
                    "harden-rkhunter-defaults",
                    ok=bool(result.get("ok")),
                    message=str(result.get("message") or "defaults overlay updated"),
                    soft_fail=not bool(result.get("ok")),
                ),
            )
        except (OSError, ValueError) as exc:
            steps.append(
                _step("harden-rkhunter-defaults", ok=False, message=str(exc), soft_fail=True),
            )

    if with_firewall:
        steps.append(ensure_firewall_as_root(force_lockout=force_lockout))
    return steps


def run_setup_harden(argv: Sequence[str]) -> int:
    """Apply prepared harden flags as root; print JSON ``{"steps": [...]}``."""
    steps: list[dict[str, Any]] = []
    try:
        steps = collect_harden_steps(argv)
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        print(json.dumps({"steps": steps, "error": str(exc)}))
        return 2
    print(json.dumps({"steps": steps}))
    return 0


__all__ = [
    "collect_harden_steps",
    "ensure_firewall_as_root",
    "run_setup_harden",
]
