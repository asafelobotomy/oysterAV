"""Tests for privileged scanner exec routing (system vs sealed)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from oyst_core.privileged.runner import CommandResult
from oyst_core.privileged.scanner_exec import run_privileged_scanner


def test_run_privileged_scanner_prefers_system_binary() -> None:
    with (
        patch(
            "oyst_core.privileged.scanner_exec.resolve_trusted_binary",
            return_value="/usr/bin/rkhunter",
        ),
        patch(
            "oyst_core.privileged.scanner_exec.run_privileged",
            return_value=CommandResult(0, "ok", ""),
        ) as run_priv,
    ):
        res = run_privileged_scanner("/unused/rkhunter", ["--check", "--sk"])
    assert res.returncode == 0
    run_priv.assert_called_once()
    assert run_priv.call_args[0][0][0] == "/usr/bin/rkhunter"


def test_run_privileged_scanner_sealed_validates_argv(tmp_path: Path) -> None:
    runtime = (
        tmp_path / "home" / "u" / ".local" / "share" / "oysterav" / "runtime" / "x86_64" / "bin"
    )
    runtime.mkdir(parents=True)
    bin_path = runtime / "chkrootkit"
    bin_path.write_bytes(b"#!/bin/sh\n")
    with (
        patch(
            "oyst_core.privileged.scanner_exec.resolve_trusted_binary",
            side_effect=ValueError("missing"),
        ),
        patch(
            "oyst_core.privileged.scanner_exec.runtime_root",
            return_value=runtime.parent.parent,
        ),
        patch("oyst_core.privileged.scanner_exec.resolve_helper_path", return_value="/usr/lib/x"),
        patch("oyst_core.privileged.scanner_exec.which", return_value="/usr/bin/pkexec"),
        patch(
            "oyst_core.privileged.scanner_exec.run_install_command",
            return_value=CommandResult(0, "", ""),
        ) as run_cmd,
    ):
        res = run_privileged_scanner(str(bin_path), [])
    assert res.returncode == 0
    argv = run_cmd.call_args[0][0]
    assert "run-sealed" in argv
    assert "chkrootkit" in argv


def test_run_privileged_scanner_rejects_bad_sealed_argv(tmp_path: Path) -> None:
    runtime = (
        tmp_path / "home" / "u" / ".local" / "share" / "oysterav" / "runtime" / "x86_64" / "bin"
    )
    runtime.mkdir(parents=True)
    bin_path = runtime / "chkrootkit"
    bin_path.write_bytes(b"x")
    with (
        patch(
            "oyst_core.privileged.scanner_exec.resolve_trusted_binary",
            side_effect=ValueError("missing"),
        ),
        patch(
            "oyst_core.privileged.scanner_exec.runtime_root",
            return_value=runtime.parent.parent,
        ),
        patch("oyst_core.privileged.scanner_exec.resolve_helper_path", return_value="/usr/lib/x"),
        patch("oyst_core.privileged.scanner_exec.which", return_value="/usr/bin/pkexec"),
    ):
        res = run_privileged_scanner(str(bin_path), ["--evil"])
    assert res.returncode == 1
    assert "argument" in (res.stderr or "").lower() or "no arguments" in (res.stderr or "")
