"""SSH-safe UFW / firewalld enable helpers used by firewall lifecycle."""

from __future__ import annotations

from typing import Any

from oyst_core.packs.firewall import invalidate_firewall_detect_cache
from oyst_core.packs.firewall_ops import FirewallOps
from oyst_core.privileged.helper_firewall import _build_firewalld_argv, _build_ufw_argv
from oyst_core.privileged.helper_services import _build_systemctl_argv


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


def ufw_status_text(run_cmd: Any) -> str:
    rc, out = run_cmd(["ufw", "status", "verbose"])
    if rc == 0 and out:
        return str(out)
    _, numbered = run_cmd(["ufw", "status", "numbered"])
    return str(numbered or "")


def firewalld_ssh_ok(run_cmd: Any) -> bool:
    rc, _ = run_cmd(["firewall-cmd", "--query-service=ssh"])
    if rc == 0:
        return True
    rc, out = run_cmd(["firewall-cmd", "--list-all"])
    if rc != 0:
        rc, out = run_cmd(["firewall-cmd", "--list-services"])
    return FirewallOps.parse_ssh_open(out or "")


def ensure_ufw(*, force_lockout: bool, run_cmd: Any) -> dict[str, Any]:
    before = ufw_status_text(run_cmd)
    ssh_ok = FirewallOps.parse_ssh_open(before)
    if not ssh_ok and not force_lockout:
        cmd = _build_ufw_argv(["allow", "--port", "22", "--proto", "tcp"])
        rc, detail = run_cmd(cmd)
        if rc != 0:
            return _step(
                "firewall-ensure",
                ok=False,
                message=f"could not add SSH allow before enable: {detail}",
                soft_fail=True,
            )
        ssh_ok = FirewallOps.parse_ssh_open(ufw_status_text(run_cmd))
    if not ssh_ok and not force_lockout:
        return _step(
            "firewall-ensure",
            ok=False,
            message="SSH allow rule not detected; use --force-lockout-risk to proceed",
            soft_fail=True,
        )
    rc, detail = run_cmd(_build_ufw_argv(["enable"]))
    if rc != 0:
        return _step(
            "firewall-ensure",
            ok=False,
            message=detail or "ufw enable failed",
            soft_fail=True,
        )
    invalidate_firewall_detect_cache()
    return _step("firewall-ensure", ok=True, message="ufw enabled")


def ensure_firewalld(*, force_lockout: bool, run_cmd: Any) -> dict[str, Any]:
    rc, detail = run_cmd(_build_systemctl_argv(["enable-now", "firewalld"]))
    if rc != 0:
        return _step(
            "firewall-ensure",
            ok=False,
            message=detail or "firewalld enable failed",
            soft_fail=True,
        )
    if not force_lockout:
        run_cmd(_build_firewalld_argv(["add-service", "ssh", "--zone", "public"]))
        run_cmd(_build_firewalld_argv(["reload"]))
        if not firewalld_ssh_ok(run_cmd):
            run_cmd(_build_systemctl_argv(["stop", "firewalld"]))
            invalidate_firewall_detect_cache()
            return _step(
                "firewall-ensure",
                ok=False,
                message=(
                    "firewalld started but SSH service not confirmed; "
                    "stopped firewalld — use --force-lockout-risk to proceed"
                ),
                soft_fail=True,
            )
    invalidate_firewall_detect_cache()
    return _step("firewall-ensure", ok=True, message="firewalld enabled")


__all__ = ["ensure_firewalld", "ensure_ufw", "firewalld_ssh_ok", "ufw_status_text"]
