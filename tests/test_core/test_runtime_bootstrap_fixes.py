"""Regressions from the 2026-11-26 "9/10 steps OK" bootstrap and Update-all failures."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.packs.rkhunter_result import (
    clean_rkhunter_output,
    rkhunter_detail,
    update_ok,
    update_summary,
)
from oyst_core.runtime.bundles import rootkit_bundles
from oyst_core.runtime_full_bootstrap import _install_step

_NOISE = (
    "grep: warning: stray \\ before -\n"
    "egrep: warning: egrep is obsolescent; using grep -E\n"
    "  \x1b[1;32mNo update\x1b[0;39m ]\n"
)


def test_clean_rkhunter_output_drops_grep_noise_and_colour() -> None:
    assert clean_rkhunter_output(_NOISE) == "No update ]"


def test_rkhunter_detail_prefers_report_over_noise() -> None:
    assert rkhunter_detail("Checking file mirrors.dat", _NOISE * 30).startswith(
        "Checking file mirrors.dat"
    )
    assert rkhunter_detail("", "grep: warning: stray \\ before +") == ""


@pytest.mark.parametrize(("rc", "ok"), [(0, True), (2, True), (1, False), (3, False)])
def test_rkhunter_update_exit_codes(rc: int, ok: bool) -> None:
    assert update_ok(rc) is ok
    assert update_summary(rc, "")


def test_rkhunter_pack_update_treats_exit_2_as_success() -> None:
    from oyst_core.packs.rkhunter import RKHunterPack
    from oyst_core.privileged.runner import CommandResult

    with patch(
        "oyst_core.packs.rkhunter.run_privileged",
        return_value=CommandResult(2, "mirrors.dat [ Updated ]", _NOISE),
    ):
        ok, msg = RKHunterPack().update()
    assert ok is True
    assert "updated" in msg
    assert "stray" not in msg


@pytest.mark.parametrize("pack", ["unhide", "chkrootkit"])
def test_root_only_pack_build_failure_is_advisory(pack: str) -> None:
    step = _install_step({"pack": pack, "ok": False, "message": "make: no makefile"})
    assert step["ok"] is False
    assert step["advisory"] is True
    assert "system" in step["message"]


def test_other_pack_install_failure_still_fails() -> None:
    step = _install_step({"pack": "clamav", "ok": False, "message": "boom"})
    assert step["ok"] is False
    assert "advisory" not in step


def test_chkrootkit_runtime_complete_needs_helpers(tmp_path: Path) -> None:
    (tmp_path / "chkrootkit").write_text("#!/bin/sh\n", encoding="utf-8")
    assert not rootkit_bundles.chkrootkit_runtime_complete(tmp_path)
    for helper in rootkit_bundles.CHKROOTKIT_HELPERS:
        (tmp_path / helper).write_bytes(b"")
    assert rootkit_bundles.chkrootkit_runtime_complete(tmp_path)


def test_build_unhide_uses_compiler_not_make(tmp_path: Path) -> None:
    """unhide ships no Makefile; `make` failed with 'No targets specified'."""
    for name in (
        "unhide-linux.c",
        "unhide-linux-procfs.c",
        "unhide-output.c",
        "unhide-tcp.c",
        "unhide-tcp-fast.c",
    ):
        (tmp_path / name).write_text("", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    with patch.object(rootkit_bundles.subprocess, "run", side_effect=fake_run):
        assert rootkit_bundles.build_unhide(tmp_path).returncode == 0
    assert [c[-1] for c in calls] == ["unhide-linux", "unhide-tcp"]
    assert "make" not in calls[0][0]
    assert "unhide-linux-procfs.c" in calls[0]
    assert "-pthread" in calls[0]
    assert "--static" not in calls[0]


_UNHIDE_STUB = """#include <stdio.h>
#include "unhide-output.h"
int main(void) { return say(); }
"""


@pytest.mark.skipif(shutil.which("cc") is None, reason="needs a C compiler")
def test_build_unhide_compiles_real_sources(tmp_path: Path) -> None:
    (tmp_path / "unhide-output.h").write_text("int say(void);\n", encoding="utf-8")
    (tmp_path / "unhide-output.c").write_text("int say(void) { return 0; }\n", encoding="utf-8")
    (tmp_path / "unhide-linux.c").write_text(_UNHIDE_STUB, encoding="utf-8")
    (tmp_path / "unhide-tcp.c").write_text(_UNHIDE_STUB, encoding="utf-8")
    (tmp_path / "unhide-tcp-fast.c").write_text("int fast(void) { return 1; }\n", encoding="utf-8")
    res = rootkit_bundles.build_unhide(tmp_path)
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "unhide-linux").is_file()
    assert (tmp_path / "unhide-tcp").is_file()
