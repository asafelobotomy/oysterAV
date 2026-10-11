"""Re-probe harden argv after pack install in setup-concert (ORD-01)."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from oyst_core.privileged.helper_clamd import _parse_flag
from oyst_core.privileged.helper_validate import resolve_trusted_argv

# Only names validate_unit() allowlists: Debian/Arch ship clamav-daemon,
# Fedora/RHEL ship clamd@.service (instance clamd@scan). A bare "clamd" would
# be probed and then rejected by the helper's unit validator.
_CLAMD_UNITS = ("clamav-daemon", "clamd@scan")
_CLAMONACC_UNIT = "clamav-clamonacc"
_CONF_CANDIDATES = (
    "/etc/clamav/clamd.conf",
    "/etc/clamd.conf",
    "/etc/clamd.d/scan.conf",
)
_VE_CMD = "/usr/lib/oysterav/oyst-virusevent"


def _secure_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _unit_listed(unit: str) -> bool:
    try:
        cmd = resolve_trusted_argv(["systemctl", "list-unit-files", unit])
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            env=_secure_env(),
        )
    except (OSError, ValueError):
        return False
    if proc.returncode != 0:
        return False
    needle = unit if "@" not in unit else unit.split("@", 1)[0]
    for line in (proc.stdout or "").splitlines():
        first = line.split(None, 1)[0] if line.strip() else ""
        if first in (unit, f"{unit}.service") or (needle and needle in first):
            return True
    return False


def probe_clamd_unit() -> str | None:
    for unit in _CLAMD_UNITS:
        if _unit_listed(unit):
            return unit
    return None


def probe_clamonacc_unit() -> str | None:
    return _CLAMONACC_UNIT if _unit_listed(_CLAMONACC_UNIT) else None


def probe_clamd_conf() -> str | None:
    for path in _CONF_CANDIDATES:
        try:
            if Path(path).is_file() and os.access(path, os.R_OK):
                return path
        except OSError:
            continue
    return None


def _flag_present(argv: Sequence[str], name: str) -> bool:
    prefix = f"--{name}"
    return any(item == prefix or item.startswith(f"{prefix}=") for item in argv)


def _successful_install_names(steps: Sequence[dict[str, Any]]) -> list[str]:
    return [
        str(step.get("step") or "")
        for step in steps
        if step.get("ok") and str(step.get("step") or "").startswith("install-")
    ]


def _pack_installed(names: Sequence[str], pack: str) -> bool:
    needle = f"install-{pack}"
    return any(name == needle or pack in name for name in names)


def augment_harden_argv_after_install(
    argv: Sequence[str],
    install_steps: Sequence[dict[str, Any]],
) -> list[str]:
    """Append missing harden flags when clamav/clamonacc/rkhunter just installed."""
    out = list(argv)
    names = _successful_install_names(install_steps)

    if _pack_installed(names, "clamav") and not _flag_present(out, "clamd-enable"):
        unit = probe_clamd_unit()
        if unit:
            out.append(f"--clamd-enable={unit}")
            if not _flag_present(out, "clamd-unit"):
                out.append(f"--clamd-unit={unit}")

    if _pack_installed(names, "clamonacc") and not _flag_present(out, "fdpass-unit"):
        unit = probe_clamonacc_unit()
        if unit:
            out.append(f"--fdpass-unit={unit}")

    if _pack_installed(names, "clamav"):
        need_ve = not _flag_present(out, "ve-conf")
        need_dc = not _flag_present(out, "dc-conf")
        if need_ve or need_dc:
            conf = probe_clamd_conf()
            if conf:
                if need_ve:
                    out.append(f"--ve-conf={conf}")
                    if not _flag_present(out, "ve-cmd") and Path(_VE_CMD).is_file():
                        out.append(f"--ve-cmd={_VE_CMD}")
                if need_dc:
                    out.append(f"--dc-conf={conf}")

    if _pack_installed(names, "rkhunter") and not _flag_present(out, "rkh"):
        if _parse_flag(out, "rkh-tests") is None:
            out.append("--rkh")

    return out


__all__ = [
    "augment_harden_argv_after_install",
    "probe_clamd_conf",
    "probe_clamd_unit",
    "probe_clamonacc_unit",
]
