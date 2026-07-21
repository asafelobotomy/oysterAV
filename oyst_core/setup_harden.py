"""First-run safe host hardenings (ADR-008 Phase 4.2 — no OnAccessPrevention)."""

from __future__ import annotations

import json
from typing import Any

from oyst_core.audit import SecurityAudit
from oyst_core.config import load_config
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.packs.clamd_ensure import _append_restart_flags, fdpass_status
from oyst_core.packs.clamd_onaccess import discover_clamd_conf_paths, probe_onaccess_prevention
from oyst_core.packs.firewall import FirewallPack
from oyst_core.packs.rkhunter_disable_tests import (
    DEFAULTS_OVERLAY_PATH,
    build_disable_tests_overlay_text,
    validate_disable_tests,
)
from oyst_core.privilege.recipes import build_harden_plan
from oyst_core.privilege.run import run_privilege_concert
from oyst_core.privileged.runner import which
from oyst_core.virusevent import (
    install_wrapper,
    recommended_virus_event_command,
    virusevent_status,
    wrapper_path,
)

_STEP_ORDER = (
    "harden-clamd",
    "harden-fdpass",
    "harden-virusevent",
    "harden-disable-cache",
    "harden-restart-stack",
    "harden-rkhunter-defaults",
    "firewall-ensure",
)


def _ordered(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name = {str(s.get("step")): s for s in steps}
    ordered = [by_name[name] for name in _STEP_ORDER if name in by_name]
    extras = [s for s in steps if str(s.get("step")) not in _STEP_ORDER]
    return [*ordered, *extras]


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


def _parse_helper_steps(stdout: str) -> list[dict[str, Any]]:
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    raw = payload.get("steps") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return []
    return [s for s in raw if isinstance(s, dict)]


def _prepare_clamd(argv: list[str], local: list[dict[str, Any]]) -> None:
    pack = ClamAVPack()
    status = pack.clamd_status()
    if status.get("running"):
        local.append(
            _step("harden-clamd", ok=True, skipped=True, message="clamd already running"),
        )
        return
    unit = str(status.get("unit") or pack.clamd_unit() or "")
    if not unit:
        local.append(_step("harden-clamd", ok=False, message="no clamd unit", soft_fail=True))
        return
    argv.append(f"--clamd-enable={unit}")


def _prepare_fdpass(argv: list[str], local: list[dict[str, Any]]) -> None:
    st = fdpass_status()
    if not st.get("unit"):
        local.append(
            _step(
                "harden-fdpass",
                ok=True,
                skipped=True,
                message=str(st.get("message") or "no distro unit"),
            ),
        )
        return
    if st.get("fdpass"):
        local.append(
            _step(
                "harden-fdpass",
                ok=True,
                skipped=True,
                message=str(st.get("message") or "already has --fdpass"),
            ),
        )
        return
    argv.append(f"--fdpass-unit={st['unit']}")


def _prepare_virusevent(argv: list[str], local: list[dict[str, Any]]) -> None:
    try:
        install_wrapper(force=False)
    except (OSError, ValueError, RuntimeError) as exc:
        local.append(_step("harden-virusevent", ok=False, message=str(exc), soft_fail=True))
        return
    status = virusevent_status()
    if status.get("handoff"):
        local.append(
            _step(
                "harden-virusevent",
                ok=False,
                message=str(status.get("message") or "foreign VirusEvent — hand off"),
                soft_fail=True,
            ),
        )
        return
    if status.get("owned_by_oysterav") and status.get("configured"):
        local.append(
            _step(
                "harden-virusevent",
                ok=True,
                skipped=True,
                message="VirusEvent already oysterAV-owned",
            ),
        )
        return
    conf = status.get("conf_path")
    if not conf:
        local.append(
            _step("harden-virusevent", ok=False, message="no readable clamd conf", soft_fail=True),
        )
        return
    argv.append(f"--ve-conf={conf}")
    argv.append(f"--ve-cmd={recommended_virus_event_command(wrapper_path())}")


def _prepare_disable_cache(argv: list[str], local: list[dict[str, Any]]) -> None:
    probe = probe_onaccess_prevention()
    if probe.get("disable_cache") is True:
        local.append(
            _step(
                "harden-disable-cache",
                ok=True,
                skipped=True,
                message="DisableCache already yes",
            ),
        )
        return
    conf = probe.get("conf_path")
    if not conf:
        paths = discover_clamd_conf_paths()
        conf = str(paths[0]) if paths else None
    if not conf:
        local.append(
            _step(
                "harden-disable-cache",
                ok=False,
                message="no readable clamd conf",
                soft_fail=True,
            ),
        )
        return
    sidecars = probe.get("conflict_sidecars")
    if isinstance(sidecars, list) and sidecars:
        local.append(
            _step(
                "harden-disable-cache",
                ok=False,
                message=f"package conflict sidecars present: {', '.join(str(s) for s in sidecars)}",
                soft_fail=True,
            ),
        )
        return
    argv.append(f"--dc-conf={conf}")


def _prepare_rkhunter(argv: list[str], local: list[dict[str, Any]]) -> None:
    if not which("rkhunter"):
        local.append(
            _step(
                "harden-rkhunter-defaults",
                ok=True,
                skipped=True,
                message="rkhunter not installed",
            ),
        )
        return
    tests = validate_disable_tests(load_config().rkhunter.disable_tests)
    desired = build_disable_tests_overlay_text(tests)
    try:
        if (
            DEFAULTS_OVERLAY_PATH.is_file()
            and DEFAULTS_OVERLAY_PATH.read_text(encoding="utf-8") == desired
        ):
            local.append(
                _step(
                    "harden-rkhunter-defaults",
                    ok=True,
                    skipped=True,
                    message="DISABLE_TESTS overlay already current",
                ),
            )
            return
    except OSError:
        pass
    argv.append("--rkh")
    if tests:
        argv.append(f"--rkh-tests={','.join(tests)}")


def _prepare_firewall(
    argv: list[str],
    local: list[dict[str, Any]],
    *,
    with_firewall: bool,
    force_lockout: bool,
) -> None:
    if not with_firewall:
        return
    det = FirewallPack().detect()
    if det.get("conflict"):
        local.append(
            _step(
                "firewall-ensure",
                ok=False,
                message="Multiple firewall managers active; resolve UFW vs firewalld first",
                soft_fail=True,
            ),
        )
        return
    active = str(det.get("active", "none"))
    if active in ("ufw", "firewalld"):
        local.append(
            _step("firewall-ensure", ok=True, skipped=True, message=f"{active} already active"),
        )
        return
    if not det.get("ufw") and not det.get("firewalld"):
        local.append(
            _step(
                "firewall-ensure",
                ok=True,
                skipped=True,
                message="no UFW or firewalld binary installed",
            ),
        )
        return
    argv.append("--with-firewall")
    if force_lockout:
        argv.append("--force-lockout")


def prepare_harden_argv(
    *,
    with_firewall: bool = False,
    force_lockout: bool = False,
    include: frozenset[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Build local skip/soft-fail steps and helper argv for harden concert.

    ``include`` limits which harden step ids run (None = all safe hardenings).
    """
    local: list[dict[str, Any]] = []
    argv: list[str] = []
    want = include

    def _want(step: str) -> bool:
        return want is None or step in want

    if _want("harden-clamd"):
        _prepare_clamd(argv, local)
    if _want("harden-fdpass"):
        _prepare_fdpass(argv, local)
    if _want("harden-virusevent"):
        _prepare_virusevent(argv, local)
    if _want("harden-disable-cache"):
        _prepare_disable_cache(argv, local)
    if _want("harden-rkhunter-defaults"):
        _prepare_rkhunter(argv, local)
    if _want("firewall-ensure"):
        _prepare_firewall(
            argv,
            local,
            with_firewall=with_firewall,
            force_lockout=force_lockout,
        )
    if any(a.startswith(("--ve-", "--dc-")) for a in argv):
        _append_restart_flags(argv, probe=probe_onaccess_prevention())
    return local, argv


def apply_safe_hardenings(
    *,
    confirm: bool = True,
    with_firewall: bool = False,
    force_lockout: bool = False,
    include: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """Apply safe ClamAV/rkhunter(/firewall) defaults via one polkit prompt.

    Does not touch OnAccessPrevention — that stays Real-time after path selection.
    """
    if not confirm:
        return [_step("harden", ok=False, message="--confirm required", soft_fail=True)]

    try:
        local, argv = prepare_harden_argv(
            with_firewall=with_firewall,
            force_lockout=force_lockout,
            include=include,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        return [_step("harden", ok=False, message=str(exc), soft_fail=True)]

    if not argv:
        return _ordered(local)

    plan = build_harden_plan(argv, step_ids=sorted(include) if include is not None else None)
    helper_steps = run_privilege_concert(plan, timeout=600)
    ok = bool(helper_steps) and all(
        s.get("ok") or s.get("skipped") or s.get("soft_fail") for s in helper_steps
    )
    if helper_steps and not any(s.get("ok") or s.get("skipped") for s in helper_steps):
        err = str(helper_steps[0].get("message") or "setup-harden failed")
        SecurityAudit().log("setup.harden", "concert", success=False, data={"error": err})
        return _ordered([*local, *helper_steps])
    SecurityAudit().log(
        "setup.harden",
        "concert",
        success=ok,
        data={"steps": [s.get("step") for s in helper_steps]},
    )
    return _ordered([*local, *helper_steps])


def parse_helper_steps(stdout: str) -> list[dict[str, Any]]:
    """Public alias for parsing setup-harden/concert JSON stdout."""
    return _parse_helper_steps(stdout)


__all__ = ["apply_safe_hardenings", "parse_helper_steps", "prepare_harden_argv"]
