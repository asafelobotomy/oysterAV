"""oyst-helper sysctl-harden apply|revert: oysterAV's one sysctl drop-in (runs as root).

The caller passes only the action. The file's keys and values come from this root-owned
install (``oyst_core.hardening_fix``), and only that file is ever written or removed.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence

from oyst_core.hardening_fix import ACTIONS, DROPIN, HEADER, dropin_text
from oyst_core.privileged.helper_clamd_unit import _secure_exec_env
from oyst_core.privileged.helper_validate import resolve_trusted_binary
from oyst_core.privileged.safe_write import write_text_nofollow


def _sysctl(args: list[str]) -> int:
    proc = subprocess.run(
        [resolve_trusted_binary("sysctl"), *args],
        check=False,
        env=_secure_exec_env(),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print((proc.stderr or proc.stdout).strip()[:500], file=sys.stderr)
    return proc.returncode


def run_sysctl_harden(argv: Sequence[str]) -> int:
    if len(argv) != 1 or argv[0] not in ACTIONS:
        print("usage: oyst-helper sysctl-harden apply|revert", file=sys.stderr)
        return 2
    try:
        if argv[0] == "apply":
            write_text_nofollow(DROPIN, dropin_text(), mode=0o644)
            return _sysctl(["-p", str(DROPIN)])
        if DROPIN.is_symlink() or not DROPIN.is_file():
            return 0
        if not DROPIN.read_text(encoding="utf-8", errors="replace").startswith(HEADER):
            print(f"{DROPIN} wasn't written by oysterAV; leaving it", file=sys.stderr)
            return 2
        DROPIN.unlink()
        # Re-apply the distro's own files; values only oysterAV set stay until a reboot.
        return _sysctl(["--system"])
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
