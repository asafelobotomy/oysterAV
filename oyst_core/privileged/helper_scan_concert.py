"""Scan-privileged concert: run integrity/audit scanners in one polkit session."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from oyst_core.packs.rkhunter_disable_tests import apply_disable_tests_overlay
from oyst_core.privileged.helper_clamd import _parse_flag, _parse_multi
from oyst_core.privileged.helper_setup_harden import _has_bool, _step
from oyst_core.privileged.helper_validate import resolve_trusted_argv, resolve_trusted_binary

_JOB_ID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")
_UNHIDE_MODES = frozenset({"sys", "brute", "quick", "check", "fork", "proc", "reverse"})
_ALLOWED_PACKS = frozenset({"rkhunter", "chkrootkit", "unhide", "lynis"})
# Root-owned under /var/lib (not world-writable /var/tmp).
_REPORT_ROOT = Path("/var/lib/oysterav/scan-reports")
_REPORT_DIR_OWNER = 0  # tests patch to the test uid


def _caller_uid() -> int | None:
    for key in ("PKEXEC_UID", "SUDO_UID"):
        raw = os.environ.get(key)
        if raw and raw.isdigit():
            return int(raw)
    return None


def _validate_job_id(raw: str) -> str:
    cleaned = raw.strip()
    if not _JOB_ID_RE.fullmatch(cleaned):
        raise ValueError(f"invalid job id: {raw}")
    return cleaned


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_root_owned_dir(name: str, *, dir_fd: int | None, mode: int) -> int:
    """Open (creating if missing) a root-owned dir without following symlinks.

    Refuses user-owned or group/world-writable entries. Traverse bits are set on
    the fd (fchmod), never via a path, so a swapped entry cannot redirect them.
    """
    try:
        os.mkdir(name, mode, dir_fd=dir_fd)
    except FileExistsError:
        pass
    fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if st.st_uid != _REPORT_DIR_OWNER:
            raise ValueError(f"report dir must be root-owned: {name}")
        if st.st_mode & 0o022:
            raise ValueError(f"report dir must not be group- or world-writable: {name}")
        if stat.S_IMODE(st.st_mode) != mode:
            os.fchmod(fd, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_report_dir(job_id: str) -> int:
    """Return an fd for ``<root>/<job_id>``: every level root-owned, others may traverse.

    The unprivileged caller reads reports (orchestrator_scan_concert), so the
    root and parent are 0711 and the job dir 0755 — but none is caller-owned,
    so the caller cannot rename or replace report entries.
    """
    fd = os.open(str(_REPORT_ROOT.parent.parent), _DIR_FLAGS)
    try:
        for name, mode in (
            (_REPORT_ROOT.parent.name, 0o711),
            (_REPORT_ROOT.name, 0o711),
            (job_id, 0o755),
        ):
            child = _open_root_owned_dir(name, dir_fd=fd, mode=mode)
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def _write_report(job_id: str, pack: str, text: str) -> str:
    name = f"{pack}.out"
    dir_fd = _open_report_dir(job_id)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"refusing non-regular report file: {name}")
        data = text.encode("utf-8")
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        uid = _caller_uid()
        if uid is not None:
            os.fchown(fd, uid, -1)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return str(_REPORT_ROOT / job_id / name)


def _secure_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _run_trusted(basename: str, argv_tail: list[str]) -> tuple[int, str]:
    cmd = resolve_trusted_argv([basename, *argv_tail])
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        env=_secure_env(),
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def run_scan_privileged_steps(argv: Sequence[str]) -> list[dict[str, Any]]:
    job_raw = _parse_flag(argv, "job-id")
    if not job_raw:
        raise ValueError("scan-concert requires --job-id=")
    job_id = _validate_job_id(job_raw)
    packs_raw = [p for p in _parse_multi(argv, "pack")]
    unknown = [p for p in packs_raw if p not in _ALLOWED_PACKS]
    if unknown:
        raise ValueError(f"unknown scan-concert pack(s): {', '.join(unknown)}")
    packs = [p for p in packs_raw if p in _ALLOWED_PACKS]
    if not packs:
        raise ValueError("scan-concert requires --pack= for allowed scanners")
    unhide_mode = _parse_flag(argv, "unhide-mode") or "sys"
    if unhide_mode not in _UNHIDE_MODES:
        raise ValueError(f"invalid unhide mode: {unhide_mode}")

    steps: list[dict[str, Any]] = []
    if _has_bool(argv, "rkh-overlay") and "rkhunter" in packs:
        try:
            result = apply_disable_tests_overlay([])
            steps.append(
                _step(
                    "rkhunter-overlay",
                    ok=bool(result.get("ok")),
                    message=str(result.get("message") or "overlay"),
                    soft_fail=not bool(result.get("ok")),
                ),
            )
        except (OSError, ValueError) as exc:
            steps.append(_step("rkhunter-overlay", ok=False, message=str(exc), soft_fail=True))

    for pack in packs:
        try:
            if pack == "rkhunter":
                rc, out = _run_trusted("rkhunter", ["--check", "--sk", "--rwo"])
                ok = rc in (0, 1)
            elif pack == "chkrootkit":
                rc, out = _run_trusted("chkrootkit", [])
                ok = rc in (0, 1)
            elif pack == "unhide":
                base = "unhide"
                try:
                    resolve_trusted_binary("unhide-linux")
                    base = "unhide-linux"
                except ValueError:
                    pass
                rc, out = _run_trusted(base, [unhide_mode])
                ok = rc == 0
            else:  # lynis
                rc, out = _run_trusted("lynis", ["audit", "system", "--no-colors", "--quick"])
                ok = rc == 0
            report = _write_report(job_id, pack, out)
            step = _step(
                f"scan-{pack}",
                ok=ok,
                message=("ok" if ok else f"exit {rc}")[:200],
                soft_fail=not ok,
            )
            step["report_path"] = report
            step["pack"] = pack
            steps.append(step)
        except (OSError, ValueError) as exc:
            steps.append(_step(f"scan-{pack}", ok=False, message=str(exc), soft_fail=True))
    return steps


def run_scan_concert(argv: Sequence[str]) -> int:
    steps: list[dict[str, Any]] = []
    try:
        steps = run_scan_privileged_steps(argv)
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        print(json.dumps({"steps": steps, "error": str(exc)}))
        return 2
    print(json.dumps({"steps": steps}))
    return 0


__all__ = ["run_scan_concert", "run_scan_privileged_steps"]
