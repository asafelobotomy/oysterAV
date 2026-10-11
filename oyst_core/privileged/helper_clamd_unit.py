"""systemd unit helpers for ClamAV co-control (ADR-008 Phase 4.1)."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from oyst_core.privileged.helper_validate import resolve_trusted_argv
from oyst_core.privileged.safe_write import write_text_nofollow
from oyst_core.privileged.validators import validate_unit

FDPASS_DROPIN_NAME = "oysterav-fdpass.conf"
# Only clamonacc units may receive the clamonacc ExecStart drop-in.
FDPASS_UNITS = frozenset({"clamav-clamonacc"})
_CLAMONACC_BIN_PREFIXES = ("/usr/bin/", "/usr/sbin/")
_ARGV_RE = re.compile(r"argv\[\]=(.+?)\s*;", re.DOTALL)
_PATH_RE = re.compile(r"path=([^ ;\n]+)")
_CLAMD_SOCKETS = (
    "/run/clamav/clamd.ctl",
    "/run/clamav/clamd.sock",
    "/var/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.sock",
)
_WAIT_TIMEOUT_SEC = 30.0
_WAIT_POLL_SEC = 0.5

# Arch/systemd ConditionPathExistsGlob=/var/lib/clamav/daily.{c[vl]d,inc}
_HOST_DAILY_SIGNATURES = (
    Path("/var/lib/clamav/daily.cvd"),
    Path("/var/lib/clamav/daily.cld"),
    Path("/var/lib/clamav/daily.inc"),
)


def host_daily_signatures_present() -> bool:
    """True when host CVD/CLD exists so clamav-daemon ConditionPathExistsGlob passes."""
    return any(path.is_file() for path in _HOST_DAILY_SIGNATURES)


def ensure_host_daily_signatures() -> str:
    """Download official ClamAV DBs as root when missing. Returns status message."""
    if host_daily_signatures_present():
        return "signatures present"
    cmd = resolve_trusted_argv(["freshclam"])
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        env=_secure_exec_env(),
        timeout=1800,
    )
    detail = (proc.stdout or proc.stderr or "").strip()
    if proc.returncode != 0 and not host_daily_signatures_present():
        raise ValueError(detail or "freshclam failed; virus definitions still missing")
    # Best-effort: keep signatures current after first download.
    try:
        _run_systemctl(["enable", "--now", "clamav-freshclam"])
    except ValueError:
        try:
            _run_systemctl(["enable", "--now", "clamav-freshclam.timer"])
        except ValueError:
            pass
    if not host_daily_signatures_present():
        raise ValueError(detail or "freshclam finished but daily signatures still missing")
    return detail or "freshclam updated signatures"


def _secure_exec_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _run_systemctl(args: list[str]) -> None:
    cmd = resolve_trusted_argv(["systemctl", *args])
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        env=_secure_exec_env(),
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "systemctl failed").strip()
        raise ValueError(detail)


def _systemctl_show(unit: str, prop: str) -> str:
    cmd = resolve_trusted_argv(["systemctl", "show", unit, "-p", prop, "--value"])
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        env=_secure_exec_env(),
    )
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def parse_systemctl_exec_start(raw: str) -> list[str]:
    """Parse ``systemctl show -p ExecStart --value`` into argv tokens."""
    text = raw.strip()
    if not text:
        return []
    match = _ARGV_RE.search(text)
    if match:
        return shlex.split(match.group(1).strip())
    if text.startswith("{"):
        path_m = _PATH_RE.search(text)
        if path_m:
            return [path_m.group(1)]
        return []
    return shlex.split(text)


def _validate_clamonacc_argv(argv: list[str]) -> list[str]:
    if not argv:
        raise ValueError("empty ExecStart for clamonacc unit")
    binary = Path(argv[0])
    name = binary.name
    if name != "clamonacc":
        raise ValueError(f"ExecStart binary is not clamonacc: {argv[0]}")
    text = str(binary)
    if not any(text.startswith(p) for p in _CLAMONACC_BIN_PREFIXES):
        raise ValueError(f"clamonacc binary path not allowlisted: {argv[0]}")
    for arg in argv:
        if any(ch in arg for ch in ("\n", "\r", ";", "|", "&", "`", "$", '"', "'", "\\")):
            raise ValueError(f"ExecStart arg contains disallowed characters: {arg}")
        if " " in arg or "\t" in arg:
            raise ValueError(f"ExecStart arg must not contain whitespace: {arg}")
    return list(argv)


def _resolve_clamonacc_bin() -> str:
    for candidate in ("/usr/bin/clamonacc", "/usr/sbin/clamonacc", shutil.which("clamonacc")):
        if candidate and Path(candidate).is_file():
            path = Path(candidate).resolve()
            if not str(path).startswith(_CLAMONACC_BIN_PREFIXES):
                continue
            return str(path)
    raise ValueError("clamonacc binary not found under /usr/bin or /usr/sbin")


def build_fdpass_dropin_body(vendor_argv: list[str] | None) -> str:
    """Build oysterAV fdpass drop-in text, preserving vendor argv when possible."""
    if vendor_argv:
        argv = list(vendor_argv)
        if "--fdpass" not in argv:
            argv.append("--fdpass")
        exec_line = " ".join(_validate_clamonacc_argv(argv))
    else:
        exec_line = f"{_resolve_clamonacc_bin()} -F --fdpass"
    return (
        "# Managed by oysterAV (ADR-008 Phase 4.1). Do not edit by hand.\n"
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart={exec_line}\n"
    )


def _unit_file_listed(unit: str) -> bool:
    try:
        cmd = resolve_trusted_argv(["systemctl", "list-unit-files", unit])
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            env=_secure_exec_env(),
        )
    except (OSError, ValueError):
        return False
    if proc.returncode != 0:
        return False
    needle = unit if "@" not in unit else unit.split("@", 1)[0]
    return needle in (proc.stdout or "")


def validate_fdpass_unit(unit: str) -> str:
    """Allowlisted unit that is also a clamonacc unit (fdpass drop-in target)."""
    cleaned = validate_unit(unit)
    if cleaned not in FDPASS_UNITS:
        raise ValueError(f"unit not allowed for fdpass drop-in: {unit}")
    return cleaned


def ensure_fdpass_dropin(unit: str, *, sockets: list[str] | None = None) -> None:
    unit = validate_fdpass_unit(unit)
    # Soft-preflight: signatures + clamd up before touching clamonacc (ORD-04/05).
    ensure_host_daily_signatures()
    if _unit_file_listed("clamav-daemon"):
        enable_clam_stack("clamav-daemon", None, sockets=sockets)

    raw = _systemctl_show(unit, "ExecStart")
    vendor: list[str] | None = None
    if raw.strip():
        try:
            parsed = parse_systemctl_exec_start(raw)
            if not parsed:
                raise ValueError("vendor ExecStart non-empty but parsed empty")
            vendor = _validate_clamonacc_argv(parsed)
        except ValueError as exc:
            # Fail closed: never strip to a minimal drop-in when vendor was present.
            raise ValueError(
                f"vendor ExecStart present but invalid — refusing stripped fdpass drop-in: {exc}",
            ) from exc

    dropin_dir = Path(f"/etc/systemd/system/{unit}.service.d")
    dropin_dir.mkdir(parents=True, exist_ok=True)
    dropin = dropin_dir / FDPASS_DROPIN_NAME

    if vendor and "--fdpass" in vendor:
        body = build_fdpass_dropin_body(vendor)
        if dropin.is_file() and dropin.read_text(encoding="utf-8") == body:
            _run_systemctl(["daemon-reload"])
            return
        # Already has fdpass — refresh managed drop-in only if missing/outdated.
        if dropin.is_file() and "--fdpass" in dropin.read_text(encoding="utf-8", errors="replace"):
            _run_systemctl(["daemon-reload"])
            return

    body = build_fdpass_dropin_body(vendor)
    if dropin.is_file() and dropin.read_text(encoding="utf-8") == body:
        _run_systemctl(["daemon-reload"])
        return
    write_text_nofollow(dropin, body, mode=0o644)
    _run_systemctl(["daemon-reload"])
    _run_systemctl(["restart", unit])


def _socket_ready(extra: list[str] | None = None) -> bool:
    for sock in (*(extra or ()), *_CLAMD_SOCKETS):
        try:
            if Path(sock).exists():
                return True
        except OSError:
            continue
    return False


def wait_for_clamd_ready(
    *,
    sockets: list[str] | None = None,
    timeout_sec: float = _WAIT_TIMEOUT_SEC,
) -> None:
    """Block until a clamd socket appears or timeout (ADR-008 restart order)."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if _socket_ready(sockets):
            return
        time.sleep(_WAIT_POLL_SEC)
    raise ValueError(
        f"clamd socket not ready within {int(timeout_sec)}s after restart "
        "(check LocalSocket / unit logs)",
    )


def restart_clam_stack(
    clamd_unit: str | None,
    clamonacc_unit: str | None,
    *,
    sockets: list[str] | None = None,
) -> None:
    if clamd_unit:
        ensure_host_daily_signatures()
        _run_systemctl(["restart", validate_unit(clamd_unit)])
        wait_for_clamd_ready(sockets=sockets)
    if clamonacc_unit:
        _run_systemctl(["restart", validate_unit(clamonacc_unit)])


def enable_clam_stack(
    clamd_unit: str | None,
    clamonacc_unit: str | None,
    *,
    sockets: list[str] | None = None,
) -> None:
    """One helper invocation: signatures (if needed) + enable --now clamd then clamonacc."""
    if not clamd_unit and not clamonacc_unit:
        raise ValueError("enable-stack requires --clamd-unit and/or --clamonacc-unit")
    if clamd_unit:
        ensure_host_daily_signatures()
        _run_systemctl(["enable", "--now", validate_unit(clamd_unit)])
        wait_for_clamd_ready(sockets=sockets)
    if clamonacc_unit:
        _run_systemctl(["enable", "--now", validate_unit(clamonacc_unit)])


__all__ = [
    "FDPASS_DROPIN_NAME",
    "FDPASS_UNITS",
    "build_fdpass_dropin_body",
    "enable_clam_stack",
    "ensure_fdpass_dropin",
    "ensure_host_daily_signatures",
    "host_daily_signatures_present",
    "parse_systemctl_exec_start",
    "restart_clam_stack",
    "validate_fdpass_unit",
    "wait_for_clamd_ready",
]
