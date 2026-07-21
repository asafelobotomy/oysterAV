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


def ensure_fdpass_dropin(unit: str) -> None:
    unit = validate_unit(unit)
    dropin_dir = Path(f"/etc/systemd/system/{unit}.service.d")
    dropin_dir.mkdir(parents=True, exist_ok=True)
    dropin = dropin_dir / FDPASS_DROPIN_NAME

    raw = _systemctl_show(unit, "ExecStart")
    vendor: list[str] | None = None
    if raw:
        try:
            vendor = parse_systemctl_exec_start(raw)
            _validate_clamonacc_argv(vendor)
        except ValueError:
            vendor = None

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
        _run_systemctl(["restart", validate_unit(clamd_unit)])
        wait_for_clamd_ready(sockets=sockets)
    if clamonacc_unit:
        _run_systemctl(["restart", validate_unit(clamonacc_unit)])


__all__ = [
    "FDPASS_DROPIN_NAME",
    "build_fdpass_dropin_body",
    "ensure_fdpass_dropin",
    "parse_systemctl_exec_start",
    "restart_clam_stack",
    "wait_for_clamd_ready",
]
