"""Tests for install command allowlist basename resolution."""

from __future__ import annotations

import pytest

from oyst_core.privileged.runner import _command_basename, run_install_command


def test_command_basename_resolves_full_paru_path() -> None:
    assert _command_basename(["/usr/bin/paru", "-S", "chkrootkit"]) == "paru"


def test_command_basename_pkexec_paru() -> None:
    assert _command_basename(["pkexec", "/usr/bin/paru", "-S", "maldet"]) == "paru"


def test_install_command_rejects_unknown_binary_path() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        run_install_command(["/tmp/oyst-maldet/extract/maldetect-1.6.6/install.sh"])
