"""Run integrity scanners as root via root-owned system binaries only."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from oyst_core.privileged.helper import run_privileged
from oyst_core.privileged.helper_validate import resolve_trusted_binary
from oyst_core.privileged.runner import CommandResult
from oyst_core.runtime.manifest import runtime_root

_RUNTIME_NEED_SYSTEM = (
    "{name} is installed in the oysterAV runtime, but privileged scans require "
    "a system package: runtime copies are user-writable and are never executed "
    "as root. Install {name} from your distro/AUR."
)


def _is_under_runtime(path: Path) -> bool:
    try:
        path.resolve().relative_to(runtime_root().resolve())
        return True
    except (OSError, ValueError):
        return False


def privileged_scanner_unavailable_message(name: str) -> str:
    return _RUNTIME_NEED_SYSTEM.format(name=name)


def run_privileged_scanner(
    binary_path: str,
    argv_tail: Sequence[str] = (),
    *,
    timeout: int = 7200,
) -> CommandResult:
    """Run the root-owned system copy of a scanner; never a runtime copy."""
    base = Path(binary_path).name
    try:
        trusted = resolve_trusted_binary(base)
        return run_privileged([trusted, *argv_tail], timeout=timeout)
    except ValueError:
        pass
    # Runtime copies live in a user-writable tree; running them as root would let
    # any user-level compromise escalate (the old run-sealed path trusted a
    # caller-computed digest). Only root-owned system binaries qualify.
    src = Path(binary_path)
    if src.is_file() and _is_under_runtime(src):
        return CommandResult(1, "", privileged_scanner_unavailable_message(base))
    return CommandResult(1, "", f"{base} not available as a trusted system binary")
