"""Tests for install command allowlist basename resolution."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from oyst_core.privileged.runner import (
    _command_basename,
    run_command,
    run_install_command,
)


def test_command_basename_resolves_full_paru_path() -> None:
    assert _command_basename(["/usr/bin/paru", "-S", "chkrootkit"]) == "paru"


def test_command_basename_pkexec_paru() -> None:
    assert _command_basename(["pkexec", "/usr/bin/paru", "-S", "maldet"]) == "paru"


def test_install_command_rejects_unknown_binary_path() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        run_install_command(["/tmp/oyst-maldet/extract/maldetect-1.6.6/install.sh"])


def test_run_command_scrubs_secret_env() -> None:
    captured: dict[str, str] = {}

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs.get("env") or {})

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return Proc()

    with (
        patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "s3cr3t", "LANG": "C"}, clear=False),
        patch("oyst_core.privileged.runner.subprocess.run", side_effect=fake_run),
    ):
        run_command(["pgrep", "-x", "clamd"])
    assert "AWS_SECRET_ACCESS_KEY" not in captured
    assert captured.get("PATH")
    assert captured.get("LANG") == "C"
