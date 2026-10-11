"""Tests for privileged scanner exec routing (system binaries only)."""

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


def test_run_privileged_scanner_never_runs_runtime_copy_as_root(tmp_path: Path) -> None:
    """User-writable runtime binaries must never reach pkexec (audit P2)."""
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
        patch("oyst_core.privileged.scanner_exec.run_privileged") as run_priv,
        patch("oyst_core.privileged.runner.subprocess.run") as sp_run,
    ):
        res = run_privileged_scanner(str(bin_path), [])
    assert res.returncode == 1
    assert "system package" in res.stderr
    run_priv.assert_not_called()
    sp_run.assert_not_called()


def test_run_privileged_scanner_missing_everywhere() -> None:
    with patch(
        "oyst_core.privileged.scanner_exec.resolve_trusted_binary",
        side_effect=ValueError("missing"),
    ):
        res = run_privileged_scanner("/nonexistent/rkhunter", [])
    assert res.returncode == 1
    assert "trusted system binary" in res.stderr
