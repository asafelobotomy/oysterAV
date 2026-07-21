"""Scan-privileged concert: run integrity/audit scanners in one polkit session."""

from __future__ import annotations

import json
import os
import re
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
_REPORT_ROOT = Path("/var/tmp/oysterav-scan")  # nosec B108 — root-owned reports dir


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


def _report_dir(job_id: str) -> Path:
    _REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(_REPORT_ROOT, 0o755)  # nosec B103 — traverse to per-job dirs
    path = _REPORT_ROOT / job_id
    path.mkdir(parents=True, exist_ok=True)
    uid = _caller_uid()
    if uid is not None:
        os.chown(path, uid, -1)
    os.chmod(path, 0o700)
    return path


def _write_report(job_id: str, pack: str, text: str) -> str:
    dest = _report_dir(job_id) / f"{pack}.out"
    dest.write_text(text, encoding="utf-8", errors="replace")
    uid = _caller_uid()
    if uid is not None:
        os.chown(dest, uid, -1)
    os.chmod(dest, 0o600)
    return str(dest)


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
