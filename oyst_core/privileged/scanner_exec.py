"""Run integrity scanners via system trusted binary or sealed runtime copy."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

from oyst_core.privileged.helper import resolve_helper_path, run_privileged
from oyst_core.privileged.helper_validate import (
    _validate_scanner_argv,
    resolve_trusted_binary,
)
from oyst_core.privileged.runner import CommandResult, run_install_command, which
from oyst_core.runtime.manifest import runtime_root

_RUNTIME_NEED_SYSTEM = (
    "{name} is installed in the oysterAV runtime, but privileged scans require "
    "a system package (or a sealed helper run). Install {name} from your "
    "distro/AUR, or reinstall the privileged helper after upgrading oysterAV."
)


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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
    """Prefer system trusted binary; else seal+exec runtime path via helper."""
    base = Path(binary_path).name
    try:
        trusted = resolve_trusted_binary(base)
        return run_privileged([trusted, *argv_tail], timeout=timeout)
    except ValueError:
        pass

    src = Path(binary_path)
    if not src.is_file() or not _is_under_runtime(src):
        return CommandResult(
            1,
            "",
            f"{base} not available as a trusted system binary",
        )

    helper = resolve_helper_path()
    pkexec = which("pkexec")
    if not helper or not pkexec:
        return CommandResult(
            1,
            "",
            privileged_scanner_unavailable_message(base),
        )
    digest = _file_sha256(src)
    try:
        validated = _validate_scanner_argv(base, [base, *argv_tail])
        sealed_tail = validated[1:]
        return run_install_command(
            ["pkexec", helper, "run-sealed", str(src), base, digest, *sealed_tail],
            timeout=timeout,
        )
    except (ValueError, OSError) as exc:
        msg = str(exc)
        if "unknown subcommand" in msg or "run-sealed" in msg:
            return CommandResult(1, "", privileged_scanner_unavailable_message(base))
        return CommandResult(1, "", msg)
