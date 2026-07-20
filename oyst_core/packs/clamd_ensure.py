"""ADR-008 Phase 4: orchestrate safe ClamAV host co-control ensures."""

from __future__ import annotations

from pathlib import Path

from oyst_core.audit import SecurityAudit
from oyst_core.config import load_config
from oyst_core.packs.clamd_onaccess import (
    discover_clamd_conf_paths,
    probe_onaccess_prevention,
)
from oyst_core.packs.clamonacc import ClamonaccPack
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.helper_clamd import DENIED_INCLUDE_PREFIXES, FDPASS_DROPIN_NAME
from oyst_core.privileged.runner import run_command
from oyst_core.virusevent import (
    install_wrapper,
    recommended_virus_event_command,
    virusevent_status,
    wrapper_path,
)


def _dropin_path(unit: str) -> Path:
    return Path(f"/etc/systemd/system/{unit}.service.d") / FDPASS_DROPIN_NAME


def _fdpass_present(unit: str) -> bool:
    path = _dropin_path(unit)
    if path.is_file():
        try:
            return "--fdpass" in path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    try:
        res = run_command(
            ["systemctl", "show", unit, "-p", "ExecStart", "--value"],
            timeout=15,
        )
        return "--fdpass" in (res.stdout or "")
    except (ValueError, OSError):
        return False


def fdpass_status(*, unit: str | None = None) -> dict[str, object]:
    resolved = unit or ClamonaccPack()._systemd_unit()
    if not resolved:
        return {
            "ok": True,
            "unit": None,
            "dropin": None,
            "fdpass": False,
            "message": "no distro clamonacc unit — process mode already uses --fdpass",
        }
    present = _fdpass_present(resolved)
    return {
        "ok": True,
        "unit": resolved,
        "dropin": str(_dropin_path(resolved)),
        "fdpass": present,
        "message": "fdpass ensured" if present else "fdpass drop-in missing",
    }


def ensure_fdpass(*, confirm: bool = False) -> dict[str, object]:
    if not confirm:
        return {"ok": False, "error": "--confirm required"}
    unit = ClamonaccPack()._systemd_unit()
    if not unit:
        return {
            "ok": True,
            "skipped": True,
            "message": "no distro unit; process-mode start already passes --fdpass",
        }
    if fdpass_status(unit=unit).get("fdpass"):
        return {"ok": True, "changed": False, "unit": unit, "message": "already has --fdpass"}
    res = run_privileged_helper("clamd-cocontrol", ["ensure-fdpass", f"--unit={unit}"])
    ok = res.returncode == 0
    SecurityAudit().log(
        "clamonacc.ensure_fdpass",
        unit,
        success=ok,
        data={"stderr": (res.stderr or "")[:500]},
    )
    return {
        "ok": ok,
        "changed": ok,
        "unit": unit,
        "dropin": str(_dropin_path(unit)),
        "message": (res.stderr or res.stdout or ("ensured" if ok else "failed")).strip(),
    }


def _clamd_unit() -> str | None:
    for unit in ("clamav-daemon", "clamd@scan"):
        try:
            listed = run_command(["systemctl", "list-unit-files", unit], timeout=15)
        except (ValueError, OSError):
            continue
        if listed.returncode != 0:
            continue
        needle = unit if "@" not in unit else unit.split("@", 1)[0]
        if needle in (listed.stdout or ""):
            return unit
    return None


def _append_restart_flags(argv: list[str], *, probe: dict[str, object] | None = None) -> None:
    clamd = _clamd_unit()
    clamonacc = ClamonaccPack()._systemd_unit()
    if clamd:
        argv.append(f"--clamd-unit={clamd}")
    if clamonacc:
        argv.append(f"--clamonacc-unit={clamonacc}")
    sock = None
    if probe:
        sock = probe.get("local_socket")
    if isinstance(sock, str) and sock.startswith("/"):
        argv.append(f"--socket={sock}")


def ensure_virusevent(*, confirm: bool = False, force_wrapper: bool = False) -> dict[str, object]:
    if not confirm:
        return {"ok": False, "error": "--confirm required"}
    wrapper = install_wrapper(force=force_wrapper)
    status = virusevent_status()
    if status.get("handoff"):
        return {
            "ok": False,
            "handoff": True,
            "error": status.get("message") or "foreign VirusEvent — hand off",
            "status": status,
        }
    if status.get("owned_by_oysterav") and status.get("configured"):
        return {
            "ok": True,
            "changed": False,
            "message": "VirusEvent already oysterAV-owned",
            "status": status,
            "wrapper": wrapper,
        }
    conf = status.get("conf_path")
    if not conf:
        return {"ok": False, "error": "no readable clamd conf", "status": status}
    cmd = recommended_virus_event_command(wrapper_path())
    argv = ["ensure-virusevent", f"--conf={conf}", f"--cmd={cmd}"]
    _append_restart_flags(argv, probe=probe_onaccess_prevention())
    res = run_privileged_helper("clamd-cocontrol", argv)
    ok = res.returncode == 0
    SecurityAudit().log(
        "clamav.ensure_virusevent",
        str(conf),
        success=ok,
        data={"cmd": cmd, "stderr": (res.stderr or "")[:500]},
    )
    return {
        "ok": ok,
        "changed": ok,
        "conf_path": conf,
        "virus_event": cmd,
        "wrapper": wrapper,
        "message": (res.stderr or res.stdout or ("ensured" if ok else "failed")).strip(),
        "status": virusevent_status() if ok else status,
    }


def _allowed_include(path: str) -> bool:
    expanded = str(Path(path).expanduser().resolve())
    if expanded == "/" or expanded in DENIED_INCLUDE_PREFIXES:
        return False
    for prefix in DENIED_INCLUDE_PREFIXES:
        if prefix != "/" and (expanded == prefix or expanded.startswith(prefix + "/")):
            return False
    return True


def ensure_prevention(*, confirm: bool = False) -> dict[str, object]:
    if not confirm:
        return {"ok": False, "error": "--confirm required"}
    cfg = load_config()
    if not cfg.clamonacc.prevention:
        return {
            "ok": False,
            "error": "clamonacc.prevention is false — set true before ensure-prevention",
        }
    probe = probe_onaccess_prevention()
    if probe.get("classification") == "impossible":
        return {
            "ok": False,
            "handoff": True,
            "error": "kernel lacks fanotify access permissions",
            "probe": probe,
        }
    if probe.get("mount_paths"):
        return {
            "ok": False,
            "handoff": True,
            "error": "OnAccessMountPath present — hand off",
            "probe": probe,
        }
    if probe.get("classification") == "blocking":
        return {
            "ok": True,
            "changed": False,
            "message": "host already blocking",
            "probe": probe,
        }
    conf = probe.get("conf_path")
    if not conf:
        paths = discover_clamd_conf_paths()
        if not paths:
            return {"ok": False, "error": "no readable clamd conf", "probe": probe}
        conf = str(paths[0])
    user = str(probe.get("user") or "clamav")
    includes = [str(Path(p).expanduser().resolve()) for p in cfg.clamonacc.paths]
    includes = [p for p in includes if _allowed_include(p)]
    if not includes:
        return {
            "ok": False,
            "error": "no safe OnAccessIncludePath values "
            "(configure clamonacc.paths under /home/…; never /)",
            "probe": probe,
        }
    argv = ["ensure-prevention", f"--conf={conf}", f"--user={user}"]
    argv.extend(f"--include={p}" for p in includes)
    _append_restart_flags(argv, probe=probe)
    res = run_privileged_helper("clamd-cocontrol", argv)
    ok = res.returncode == 0
    SecurityAudit().log(
        "clamonacc.ensure_prevention",
        str(conf),
        success=ok,
        data={"includes": includes, "stderr": (res.stderr or "")[:500]},
    )
    return {
        "ok": ok,
        "changed": ok,
        "conf_path": conf,
        "includes": includes,
        "user": user,
        "message": (res.stderr or res.stdout or ("ensured" if ok else "failed")).strip(),
        "probe": probe_onaccess_prevention() if ok else probe,
    }


def ensure_disable_cache(*, confirm: bool = False) -> dict[str, object]:
    if not confirm:
        return {"ok": False, "error": "--confirm required"}
    probe = probe_onaccess_prevention()
    if probe.get("disable_cache") is True:
        return {
            "ok": True,
            "changed": False,
            "message": "DisableCache already yes",
            "probe": probe,
        }
    conf = probe.get("conf_path")
    if not conf:
        paths = discover_clamd_conf_paths()
        if not paths:
            return {"ok": False, "error": "no readable clamd conf", "probe": probe}
        conf = str(paths[0])
    sidecars = probe.get("conflict_sidecars")
    if isinstance(sidecars, list) and sidecars:
        return {
            "ok": False,
            "handoff": True,
            "error": f"package conflict sidecars present: {', '.join(str(s) for s in sidecars)}",
            "probe": probe,
        }
    argv = ["ensure-disable-cache", f"--conf={conf}"]
    _append_restart_flags(argv, probe=probe)
    res = run_privileged_helper("clamd-cocontrol", argv)
    ok = res.returncode == 0
    SecurityAudit().log(
        "clamav.ensure_disable_cache",
        str(conf),
        success=ok,
        data={"stderr": (res.stderr or "")[:500]},
    )
    return {
        "ok": ok,
        "changed": ok,
        "conf_path": conf,
        "message": (res.stderr or res.stdout or ("ensured" if ok else "failed")).strip(),
        "probe": probe_onaccess_prevention() if ok else probe,
    }


__all__ = [
    "ensure_disable_cache",
    "ensure_fdpass",
    "ensure_prevention",
    "ensure_virusevent",
    "fdpass_status",
]
