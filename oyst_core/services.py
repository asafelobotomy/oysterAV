"""Logical service lifecycle orchestration for oysterAV."""

from __future__ import annotations

from typing import Literal

from oyst_core.audit import SecurityAudit
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.runner import run_command

ServiceName = Literal[
    "clamd",
    "clamonacc",
    "freshclam-timer",
    "fail2ban",
    "maldet-monitor",
    "schedule-linger",
]

SERVICE_NAMES: tuple[ServiceName, ...] = (
    "clamd",
    "clamonacc",
    "freshclam-timer",
    "fail2ban",
    "maldet-monitor",
    "schedule-linger",
)


def _systemctl_probe(unit: str) -> dict[str, object]:
    active = False
    enabled = False
    try:
        active_res = run_command(["systemctl", "is-active", unit], timeout=15)
        active = active_res.stdout.strip() == "active"
        enabled_res = run_command(["systemctl", "is-enabled", unit], timeout=15)
        enabled = enabled_res.stdout.strip() in ("enabled", "enabled-runtime", "static")
    except (ValueError, OSError):
        pass
    return {"unit": unit, "active": active, "enabled": enabled}


def _freshclam_timer_unit() -> str:
    """Pick the best available freshclam unit (Arch once-timer preferred when present)."""
    for unit in (
        "clamav-freshclam-once.timer",
        "clamav-freshclam.timer",
        "clamav-freshclam.service",
        "clamav-freshclam",
    ):
        if _unit_file_exists(unit):
            # systemctl accepts short name for .service units already in allowlist
            if unit == "clamav-freshclam.service":
                return "clamav-freshclam"
            return unit
    return "clamav-freshclam-once.timer"


def _unit_file_exists(unit: str) -> bool:
    try:
        res = run_command(["systemctl", "list-unit-files", unit], timeout=15)
        if res.returncode != 0:
            return False
        # Match the unit as a whole token (avoid clamav-freshclam matching once.timer lines)
        for line in (res.stdout or "").splitlines():
            first = line.split(None, 1)[0] if line.strip() else ""
            if first == unit:
                return True
    except (ValueError, OSError):
        return False
    return False


def _clamonacc_systemd_unit() -> str | None:
    for unit in ("clamav-clamonacc", "clamav-clamonacc.service"):
        probe = unit if unit.endswith(".service") else f"{unit}.service"
        if _unit_file_exists(probe) or _unit_file_exists(unit):
            return "clamav-clamonacc"
    return None


def _systemctl_set(unit: str, *, on: bool, boot: bool) -> tuple[bool, str]:
    if on:
        action = "enable-now" if boot else "start"
    else:
        action = "disable-now" if boot else "stop"
    res = run_privileged_helper("systemctl", [action, unit])
    ok = res.returncode == 0
    msg = (res.stdout or res.stderr or "").strip() or ("ok" if ok else "failed")
    return ok, msg


def services_status() -> dict[str, object]:
    """Return status for all logical services."""
    from oyst_core.packs.clamav import ClamAVPack
    from oyst_core.packs.clamonacc import ClamonaccPack
    from oyst_core.packs.fail2ban import Fail2banPack
    from oyst_core.packs.maldet import MaldetPack
    from oyst_core.schedule_util import get_linger_status

    clam = ClamAVPack()
    clamd = clam.clamd_status()
    clamonacc_pack = ClamonaccPack()
    clamonacc_doc = clamonacc_pack.doctor()
    clamonacc_unit = _clamonacc_systemd_unit()
    fresh_unit = _freshclam_timer_unit()
    fresh = _systemctl_probe(fresh_unit)
    f2b_doc = Fail2banPack().doctor()
    f2b_details = f2b_doc.details if isinstance(f2b_doc.details, dict) else {}
    f2b_unit = _systemctl_probe("fail2ban")
    maldet = MaldetPack().monitor_status()
    linger = get_linger_status()

    clamonacc_running = bool(
        (clamonacc_doc.details or {}).get("running")
        if isinstance(clamonacc_doc.details, dict)
        else False
    )
    clamonacc_enabled = bool(load_clamonacc_enabled())
    if clamonacc_unit:
        unit_probe = _systemctl_probe(clamonacc_unit)
        clamonacc_running = clamonacc_running or bool(unit_probe.get("active"))
        clamonacc_enabled = clamonacc_enabled or bool(unit_probe.get("enabled"))

    services: dict[str, object] = {
        "clamd": {
            "name": "clamd",
            "kind": "systemctl",
            "running": bool(clamd.get("running") or clamd.get("active")),
            "enabled": bool(clamd.get("enabled")),
            "unit": clamd.get("unit"),
            "details": clamd,
        },
        "clamonacc": {
            "name": "clamonacc",
            "kind": "systemctl" if clamonacc_unit else "process",
            "running": clamonacc_running,
            "enabled": clamonacc_enabled,
            "unit": clamonacc_unit,
            "details": clamonacc_doc.model_dump(),
        },
        "freshclam-timer": {
            "name": "freshclam-timer",
            "kind": "systemctl",
            "running": bool(fresh.get("active")),
            "enabled": bool(fresh.get("enabled")),
            "unit": fresh_unit,
            "details": fresh,
        },
        "fail2ban": {
            "name": "fail2ban",
            "kind": "systemctl",
            "running": bool(f2b_details.get("running") or f2b_unit.get("active")),
            "enabled": bool(f2b_unit.get("enabled")),
            "unit": "fail2ban",
            "details": {"doctor": f2b_doc.model_dump(), "unit": f2b_unit},
        },
        "maldet-monitor": {
            "name": "maldet-monitor",
            "kind": "systemctl",
            "running": bool(maldet.get("running")),
            "enabled": bool(maldet.get("enabled")),
            "unit": "maldet",
            "details": maldet,
        },
        "schedule-linger": {
            "name": "schedule-linger",
            "kind": "loginctl",
            "running": bool(linger.get("linger")),
            "enabled": bool(linger.get("linger")),
            "details": linger,
        },
    }
    return {"services": services, "names": list(SERVICE_NAMES)}


def load_clamonacc_enabled() -> bool:
    from oyst_core.config import load_config

    return bool(load_config().clamonacc.enabled)


def set_service(
    name: str,
    state: Literal["on", "off"],
    *,
    boot: bool = False,
) -> dict[str, object]:
    """Turn a logical service on or off."""
    if name not in SERVICE_NAMES:
        return {
            "ok": False,
            "name": name,
            "message": f"unknown service: {name} (expected one of {', '.join(SERVICE_NAMES)})",
        }

    on = state == "on"
    audit = SecurityAudit()

    if name == "clamd":
        from oyst_core.packs.clamav import ClamAVPack

        clam = ClamAVPack()
        unit = clam.clamd_unit()
        if on:
            ok, msg = _systemctl_set(unit, on=True, boot=boot)
            if ok and not clam.clamd_running():
                ok, msg = False, f"{unit} started but clamd process not detected"
        elif boot:
            ok, msg = _systemctl_set(unit, on=False, boot=True)
        else:
            ok, msg = clam.clamd_stop()
        audit.log("services.set", name, success=ok, data={"state": state, "boot": boot})
        return {"ok": ok, "name": name, "state": state, "boot": boot, "message": msg}

    if name == "clamonacc":
        from oyst_core.packs.clamonacc import ClamonaccPack

        clamonacc = ClamonaccPack()
        ok, msg = clamonacc.enable() if on else clamonacc.disable()
        audit.log("services.set", name, success=ok, data={"state": state})
        return {"ok": ok, "name": name, "state": state, "boot": boot, "message": msg}

    if name == "freshclam-timer":
        unit = _freshclam_timer_unit()
        ok, msg = _systemctl_set(unit, on=on, boot=boot or unit.endswith(".timer"))
        audit.log(
            "services.set",
            name,
            success=ok,
            data={"state": state, "boot": boot, "unit": unit},
        )
        return {
            "ok": ok,
            "name": name,
            "state": state,
            "boot": boot,
            "unit": unit,
            "message": msg,
        }

    if name == "fail2ban":
        ok, msg = _systemctl_set("fail2ban", on=on, boot=boot)
        audit.log("services.set", name, success=ok, data={"state": state, "boot": boot})
        return {"ok": ok, "name": name, "state": state, "boot": boot, "message": msg}

    if name == "maldet-monitor":
        from oyst_core.packs.maldet import MaldetPack

        maldet = MaldetPack()
        ok, msg = maldet.monitor_start() if on else maldet.monitor_stop()
        audit.log("services.set", name, success=ok, data={"state": state})
        return {"ok": ok, "name": name, "state": state, "boot": boot, "message": msg}

    if name == "schedule-linger":
        from oyst_core.schedule_util import disable_linger, enable_linger

        if on:
            result = enable_linger()
        else:
            result = disable_linger()
        ok = bool(result.get("ok"))
        msg = str(result.get("message") or ("ok" if ok else "failed"))
        audit.log("services.set", name, success=ok, data={"state": state})
        return {"ok": ok, "name": name, "state": state, "boot": boot, "message": msg}

    return {"ok": False, "name": name, "message": f"unhandled service: {name}"}
